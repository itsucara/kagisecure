//! `create_test_login`'s `bind` (ADR-0048 §9, Phase 3): the login and two bindings in an
//! environment of the test-login vault, in one transaction, after one `add_variables` sheet.
//!
//! What these assert: the bind asks the person once, on the `add_variables` sheet, even where the
//! create itself needs nobody; a denial writes nothing at all; the environment is created in the
//! test-login vault when missing and the bindings point at the login's fields; a run of those
//! variables rides the grace window; rebuilding an environment around an existing login binds it
//! again (`exists`), and a binding already in place asks nobody; variable names taken by other
//! bindings, and malformed names, are refused before anyone is asked.

mod agent_fill_support;

use std::collections::BTreeMap;
use std::time::Duration;

use agent_fill_support::{Fixture, Human, agent_call, code, fixture};
use kagisecure_agent::approval::{ApprovalKind, Decision};
use kagisecure_core::model::{TestLoginPolicy, VarSource};
use kagisecure_core::proto::{ItemId, Outcome};
use kagisecure_core::vault::Vault;
use kagisecure_ipc::protocol::{
    Delivery, OutputMode, Request, Response, TestLoginBind, TestLoginBinding, TestLoginStatus,
    VariableRequest,
};

const LOCAL: &str = "http://localhost:47800";
const WAIT: Duration = Duration::from_secs(5);

fn set_policy(fx: &Fixture) {
    fx.handle
        .transact(WAIT, |tx| {
            tx.ensure_agent_test_vault("test")?;
            tx.set_test_login_policy(
                TestLoginPolicy {
                    enabled: true,
                    auto_domains: Vec::new(),
                    unknown: BTreeMap::new(),
                },
                "test",
            )
        })
        .expect("unlocked")
        .expect("policy");
}

fn bind(environment: &str, user: &str, credential: &str) -> TestLoginBind {
    TestLoginBind {
        environment: environment.to_owned(),
        username_var: user.to_owned(),
        credential_var: credential.to_owned(),
    }
}

fn create(fx: &Fixture, username: &str, bind: Option<TestLoginBind>) -> Response {
    agent_call(
        &fx.agent_endpoint,
        &Request::CreateTestLogin {
            app: "shop".to_owned(),
            purpose: "buyer".to_owned(),
            username: username.to_owned(),
            websites: vec![LOCAL.to_owned()],
            generator: None,
            tags: Vec::new(),
            reason: None,
            bind,
        },
    )
}

fn sheets(human: &Human, kind: ApprovalKind) -> usize {
    human.seen().iter().filter(|r| r.kind == kind).count()
}

fn created(reply: &Response) -> (TestLoginStatus, ItemId, Option<TestLoginBinding>) {
    match reply {
        Response::TestLoginCreated {
            status,
            item_id,
            binding,
            ..
        } => (*status, *item_id, binding.as_deref().cloned()),
        other => panic!("expected a test login, got {other:?}"),
    }
}

fn test_vault_items(fx: &Fixture) -> usize {
    let vault = Vault::open_with_password(fx.path(), b"pw").expect("open");
    let id = vault.agent_test_vault().map(|v| v.id);
    vault
        .items()
        .iter()
        .filter(|i| Some(i.vault_id) == id)
        .count()
}

#[test]
fn a_bind_is_one_add_variables_sheet_and_one_transaction() {
    let fx = fixture();
    set_policy(&fx);
    let human = Human::approving(&fx.queue);

    let reply = create(
        &fx,
        "seed@example.test",
        Some(bind("shop-e2e", "SHOP_USER", "SHOP_PASS")),
    );
    let (status, id, binding) = created(&reply);
    assert_eq!(status, TestLoginStatus::Created);
    let binding = binding.expect("a binding");
    assert_eq!(binding.environment, "shop-e2e");
    assert_eq!(binding.username_var, "SHOP_USER");
    assert_eq!(binding.credential_var, "SHOP_PASS");

    // One sheet, the add_variables one, naming the environment and both variables; the create at
    // loopback asked nobody.
    let seen = human.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].kind, ApprovalKind::AddVariables);
    assert_eq!(seen[0].environment_name.as_deref(), Some("shop-e2e"));
    assert_eq!(seen[0].environment_id, None, "a new environment");
    assert_eq!(seen[0].variables, ["SHOP_USER", "SHOP_PASS"]);

    // On disk: the environment in the test-login vault, visible to agents, bound to the login's
    // username and password fields.
    let vault = Vault::open_with_password(fx.path(), b"pw").expect("open");
    let test_vault = vault.agent_test_vault().unwrap().id;
    let env = vault
        .environments()
        .iter()
        .find(|e| e.id == binding.environment_id)
        .expect("created");
    assert_eq!(env.vault_id, test_vault);
    assert!(env.agent_visible);
    let item = vault.item_by_id(&id).unwrap();
    let username_field = item
        .fields
        .iter()
        .find(|f| f.label == "username")
        .unwrap()
        .id;
    let field_of = |name: &str| match &env.var(name).unwrap().source {
        VarSource::ItemField { item, field } => (*item, *field),
        _ => panic!("{name} is not bound to a field"),
    };
    assert_eq!(field_of("SHOP_USER"), (id, username_field));
    assert_eq!(field_of("SHOP_PASS"), (id, item.primary_secret.unwrap()));

    // Audited with the agent's full identity: the create, the environment, the bindings.
    let entries = fx.on_disk();
    for tool in ["create_test_login", "create_environment", "add_variables"] {
        let entry = entries
            .iter()
            .find(|e| e.tool == tool && e.outcome == Outcome::Allowed)
            .unwrap_or_else(|| panic!("no {tool} entry"));
        assert!(
            entry.actor.starts_with("mcp \"example-agent\""),
            "{tool}: {}",
            entry.actor
        );
    }

    // A run of exactly those variables rides the grace window (§9).
    let cwd = fx.dir.path().canonicalize().unwrap();
    let ran = agent_call(
        &fx.agent_endpoint,
        &Request::RunWithEnv {
            environment_id: binding.environment_id,
            command: "/usr/bin/true".to_owned(),
            args: Vec::new(),
            cwd: cwd.to_string_lossy().into_owned(),
            variables: None,
            timeout_seconds: 5,
            output: OutputMode::None,
            delivery: Delivery::Environment,
        },
    );
    assert!(matches!(ran, Response::Ran { .. }), "{ran:?}");
    let runs: Vec<bool> = human
        .seen()
        .iter()
        .filter(|r| r.kind == ApprovalKind::RunWithEnv)
        .map(|r| r.rides_grace)
        .collect();
    assert_eq!(runs, [true]);
}

#[test]
fn a_denied_bind_writes_nothing_at_all() {
    let fx = fixture();
    set_policy(&fx);
    let human = Human::new(&fx.queue, |r| {
        Some(if r.kind == ApprovalKind::AddVariables {
            Decision::Deny
        } else {
            Decision::AllowOnce
        })
    });
    let reply = create(&fx, "seed@example.test", Some(bind("shop-e2e", "U", "P")));
    assert_eq!(code(&reply), Some("USER_DENIED"), "{reply:?}");
    assert_eq!(sheets(&human, ApprovalKind::AddVariables), 1);
    assert_eq!(test_vault_items(&fx), 0, "no login");
    let vault = Vault::open_with_password(fx.path(), b"pw").expect("open");
    assert!(
        !vault.environments().iter().any(|e| e.name == "shop-e2e"),
        "no environment"
    );
    // The reservation went back: a create without bind still goes through.
    assert_eq!(
        created(&create(&fx, "seed@example.test", None)).0,
        TestLoginStatus::Created
    );
}

#[test]
fn rebuilding_an_environment_binds_the_existing_login_again() {
    let fx = fixture();
    set_policy(&fx);
    let human = Human::approving(&fx.queue);
    let (_, id, first) = created(&create(
        &fx,
        "seed@example.test",
        Some(bind("e2e-1", "U", "P")),
    ));
    let first = first.unwrap();

    // The environment is rebuilt under another name: the same login, bound again.
    let (status, again, second) = created(&create(
        &fx,
        "seed@example.test",
        Some(bind("e2e-2", "U", "P")),
    ));
    assert_eq!(status, TestLoginStatus::Exists);
    assert_eq!(again, id);
    let second = second.unwrap();
    assert_ne!(second.environment_id, first.environment_id);
    assert_eq!(sheets(&human, ApprovalKind::AddVariables), 2);
    assert_eq!(test_vault_items(&fx), 1, "no second login");

    // Asked again with the binding already in place: `exists`, nothing written, nobody asked.
    let audit_before = fx.on_disk().len();
    let (status, _, third) = created(&create(
        &fx,
        "seed@example.test",
        Some(bind("e2e-2", "U", "P")),
    ));
    assert_eq!(status, TestLoginStatus::Exists);
    assert_eq!(third.unwrap().environment_id, second.environment_id);
    assert_eq!(sheets(&human, ApprovalKind::AddVariables), 2);
    let new_entries: Vec<_> = fx.on_disk().into_iter().skip(audit_before).collect();
    assert!(
        new_entries
            .iter()
            .all(|e| e.detail.as_deref() == Some("TEST_LOGIN_EXISTS")),
        "{new_entries:?}"
    );
}

#[test]
fn taken_and_malformed_variable_names_are_refused_before_anyone_is_asked() {
    let fx = fixture();
    set_policy(&fx);
    let human = Human::approving(&fx.queue);

    for bad in [
        bind("e2e", "SAME", "SAME"),
        bind("e2e", "1BAD", "P"),
        bind("", "U", "P"),
        bind("two\nlines", "U", "P"),
    ] {
        assert_eq!(
            code(&create(&fx, "seed@example.test", Some(bad.clone()))),
            Some("INVALID_ARGUMENT"),
            "{bad:?}"
        );
    }

    // An environment in the test-login vault whose variable SHOP_USER is someone else's.
    let test_vault = fx
        .handle
        .with(|v| v.agent_test_vault().unwrap().id)
        .unwrap();
    let Response::Environment { environment } = agent_call(
        &fx.agent_endpoint,
        &Request::CreateEnvironment {
            vault_id: Some(test_vault),
            name: "shop-e2e".to_owned(),
            description: None,
        },
    ) else {
        panic!("create_environment")
    };
    let added = agent_call(
        &fx.agent_endpoint,
        &Request::AddVariables {
            environment_id: environment.id,
            variables: vec![VariableRequest {
                name: "SHOP_USER".to_owned(),
                bind_to: None,
                hint: None,
            }],
        },
    );
    assert!(
        matches!(added, Response::AddedVariables { .. }),
        "{added:?}"
    );
    let asked = human.seen().len();

    let reply = create(
        &fx,
        "seed@example.test",
        Some(bind("shop-e2e", "SHOP_USER", "SHOP_PASS")),
    );
    assert_eq!(code(&reply), Some("INVALID_ARGUMENT"), "{reply:?}");
    assert_eq!(human.seen().len(), asked, "nobody was asked");
    assert_eq!(test_vault_items(&fx), 0, "nothing was created");

    // Free names in the same environment: bound there, with the environment's id on the sheet.
    let (_, _, binding) = created(&create(
        &fx,
        "seed@example.test",
        Some(bind("shop-e2e", "SHOP_LOGIN", "SHOP_PASS")),
    ));
    assert_eq!(binding.unwrap().environment_id, environment.id);
    let last = human.seen().pop().unwrap();
    assert_eq!(last.kind, ApprovalKind::AddVariables);
    assert_eq!(last.environment_id, Some(environment.id.to_string()));
}
