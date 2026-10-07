//! Agent test logins, end to end below the sheet (ADR-0048 Phase 1a): a raw IPC client on the
//! agent socket plays the sidecar, a thread on the approval queue plays the person, and a scripted
//! duplex client on the extension socket plays the browser for the login fill.
//!
//! What these assert: the switch answers before anything is looked up; a create at an allowed
//! origin raises no sheet and one anywhere else always does; a denial creates nothing and is
//! audited with the agent's full identity; a test user is reused as `exists`; the cap and the
//! rate limit hold across reconnects; the seal is set on create and a password edit breaks it, so
//! the next fill needs the person again; and a test-vault item is never matched for the person.

mod agent_fill_support;

use std::collections::BTreeMap;
use std::time::Duration;

use agent_fill_support::{
    Fixture, Human, OnDeliver, PAGE, ServiceWorker, Tab, agent_call, both, code, fixture,
};
use kagisecure_agent::TestLoginNotice;
use kagisecure_agent::approval::{ApprovalKind, Decision};
use kagisecure_core::model::{Category, FieldValue, Item, Secret, TestLoginPolicy};
use kagisecure_core::proto::{ItemId, Outcome};
use kagisecure_core::vault::Vault;
use kagisecure_extension_ipc::protocol::{
    PageContext, Request as ExtRequest, Response as ExtResponse,
};
use kagisecure_extension_ipc::{Client as ExtClient, PINNED_EXTENSION_IDS};
use kagisecure_ipc::protocol::{Request, Response, TestLoginGenerator, TestLoginStatus};

const LOCAL: &str = "http://localhost:47800";
const PARTNER: &str = "https://staging.example-partner.com";
const WAIT: Duration = Duration::from_secs(5);

/// Create the test-login vault and set its policy, the way Settings does.
fn set_policy(fx: &Fixture, enabled: bool, domains: &[&str]) {
    fx.handle
        .transact(WAIT, |tx| {
            tx.ensure_agent_test_vault("test")?;
            tx.set_test_login_policy(
                TestLoginPolicy {
                    enabled,
                    auto_domains: domains.iter().map(|d| (*d).to_owned()).collect(),
                    unknown: BTreeMap::new(),
                },
                "test",
            )
        })
        .expect("unlocked")
        .expect("policy");
}

fn create_request(username: &str, websites: &[&str]) -> Request {
    Request::CreateTestLogin {
        app: "shop".to_owned(),
        purpose: "buyer".to_owned(),
        username: username.to_owned(),
        websites: websites.iter().map(|w| (*w).to_owned()).collect(),
        generator: None,
        tags: vec!["e2e".to_owned()],
        reason: Some("checkout tests".to_owned()),
        bind: None,
    }
}

/// `create_test_login` on a fresh connection — every call is a reconnect.
fn create(fx: &Fixture, username: &str, websites: &[&str]) -> Response {
    agent_call(&fx.agent_endpoint, &create_request(username, websites))
}

fn list(fx: &Fixture) -> Response {
    agent_call(
        &fx.agent_endpoint,
        &Request::ListTestLogins {
            website: None,
            tag: None,
            query: None,
            limit: 50,
            cursor: None,
        },
    )
}

fn created_id(reply: &Response) -> ItemId {
    match reply {
        Response::TestLoginCreated {
            status: TestLoginStatus::Created,
            item_id,
            ..
        } => *item_id,
        other => panic!("expected a created test login, got {other:?}"),
    }
}

/// The items in the test-login vault as the file on disk holds them.
fn test_vault_items(fx: &Fixture) -> Vec<String> {
    let vault = Vault::open_with_password(fx.path(), b"pw").expect("open");
    let Some(test_vault) = vault.agent_test_vault().map(|v| v.id) else {
        return Vec::new();
    };
    vault
        .items()
        .iter()
        .filter(|i| i.vault_id == test_vault)
        .map(|i| i.id.to_string())
        .collect()
}

fn entries(fx: &Fixture, tool: &str) -> Vec<kagisecure_core::audit::AuditEntry> {
    fx.on_disk()
        .into_iter()
        .filter(|e| e.tool == tool)
        .collect()
}

#[test]
fn the_switch_answers_test_logins_off_before_anything_is_looked_up() {
    let fx = fixture();
    // No test-login vault at all.
    assert_eq!(
        code(&create(&fx, "a@example.test", &[LOCAL])),
        Some("TEST_LOGINS_OFF")
    );
    assert_eq!(code(&list(&fx)), Some("TEST_LOGINS_OFF"));
    // The vault exists, the switch is off.
    set_policy(&fx, false, &[]);
    assert_eq!(
        code(&create(&fx, "a@example.test", &[LOCAL])),
        Some("TEST_LOGINS_OFF")
    );
    assert_eq!(code(&list(&fx)), Some("TEST_LOGINS_OFF"));
    assert!(test_vault_items(&fx).is_empty());

    // Arguments are checked first, and the generator only offers its menu.
    assert_eq!(code(&create(&fx, "", &[LOCAL])), Some("INVALID_ARGUMENT"));
    assert_eq!(
        code(&create(&fx, "a@example.test", &[])),
        Some("INVALID_ARGUMENT")
    );
    assert_eq!(
        code(&create(&fx, "a@example.test", &["ftp://localhost"])),
        Some("INVALID_ARGUMENT")
    );
    let mut short = create_request("a@example.test", &[LOCAL]);
    if let Request::CreateTestLogin { generator, .. } = &mut short {
        *generator = Some(TestLoginGenerator {
            length: 16,
            ..TestLoginGenerator::default()
        });
    }
    assert_eq!(
        code(&agent_call(&fx.agent_endpoint, &short)),
        Some("INVALID_ARGUMENT")
    );
}

#[test]
fn an_automatic_create_at_loopback_queues_nothing_and_is_sealed_and_attributed() {
    let fx = fixture();
    set_policy(&fx, true, &[]);
    let human = Human::approving(&fx.queue);

    let reply = create(&fx, "buyer1@example.test", &[LOCAL]);
    let id = created_id(&reply);
    let Response::TestLoginCreated {
        username,
        websites,
        title,
        ..
    } = &reply
    else {
        unreachable!()
    };
    assert_eq!(username, "buyer1@example.test");
    assert_eq!(websites, &[LOCAL.to_owned()]);
    assert_eq!(title, "test: shop / buyer #1");
    assert!(human.seen().is_empty(), "no sheet at an allowed origin");

    // On disk: in the test vault, sealed, with the composed title, tags and public purpose, and a
    // 32-character generated password.
    let vault = Vault::open_with_password(fx.path(), b"pw").expect("open");
    let item = vault.item_by_id(&id).expect("written");
    assert!(vault.in_agent_test_vault(item));
    assert!(vault.test_login_sealed(item));
    assert_eq!(
        item.tags,
        ["agent-test", "app:shop", "purpose:buyer", "e2e"]
    );
    assert!(item.agent_visible);
    let purpose = item.fields.iter().find(|f| f.label == "purpose").unwrap();
    assert_eq!(purpose.value.as_public(), Some("buyer"));
    let password = item.primary_secret_field().unwrap();
    assert_eq!(password.value.as_secret().unwrap().expose().len(), 32);

    // The audit entry names the agent in full, not the bare `mcp`.
    let created = entries(&fx, "create_test_login");
    let entry = created
        .iter()
        .find(|e| e.outcome == Outcome::Allowed)
        .unwrap();
    assert_eq!(
        entry.detail.as_deref(),
        Some("TEST_LOGIN_CREATED (automatic)")
    );
    assert!(
        entry.actor.starts_with("mcp \"example-agent\""),
        "{}",
        entry.actor
    );
    assert_eq!(entry.item_id, Some(id));

    // A passive notice, and the listing shows it with its username and no password.
    let notices = fx.test_logins.take_notices();
    assert!(matches!(
        &notices[..],
        [TestLoginNotice::Created { title, .. }] if title == "test: shop / buyer #1"
    ));
    let Response::TestLogins { items, .. } = list(&fx) else {
        panic!("list")
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].username, "buyer1@example.test");
    assert_eq!(items[0].purpose, "buyer");

    // The next one for the same app and purpose is #2.
    let second = create(&fx, "buyer2@example.test", &["http://127.0.0.1:47800"]);
    let Response::TestLoginCreated { title, .. } = second else {
        panic!("{second:?}")
    };
    assert_eq!(title, "test: shop / buyer #2");
}

#[test]
fn a_site_outside_the_allowed_origins_raises_the_sheet_and_a_denial_creates_nothing() {
    let fx = fixture();
    set_policy(&fx, true, &[]);
    {
        let human = Human::denying(&fx.queue);
        let reply = create(&fx, "partner@example.com", &[PARTNER]);
        assert_eq!(code(&reply), Some("USER_DENIED"));
        let seen = human.seen();
        assert_eq!(seen.len(), 1);
        let sheet = &seen[0];
        assert_eq!(sheet.kind, ApprovalKind::CreateTestLogin);
        assert!(!sheet.presence_only);
        let facts = sheet.agent_test_login.as_ref().expect("facts");
        assert_eq!(facts.websites[0].origin.emphasized, "example-partner.com");
        assert!(!facts.websites[0].not_https);
        assert_eq!(facts.title, "test: shop / buyer #1");
        assert_eq!(facts.generator, "32 characters, with symbols");
    }
    assert!(test_vault_items(&fx).is_empty(), "a denial creates nothing");
    let denied = entries(&fx, "create_test_login");
    let entry = denied
        .iter()
        .find(|e| e.outcome == Outcome::Denied)
        .unwrap();
    assert!(
        entry.actor.starts_with("mcp \"example-agent\""),
        "{}",
        entry.actor
    );
    assert_eq!(entry.detail.as_deref(), Some("USER_DENIED"));

    // Approved: created, and recorded as approved. Every later create there asks again.
    let human = Human::approving(&fx.queue);
    created_id(&create(&fx, "partner@example.com", &[PARTNER]));
    created_id(&create(&fx, "partner2@example.com", &[PARTNER]));
    assert_eq!(
        human.seen().len(),
        2,
        "no lease, no memory: a sheet every time"
    );
    assert!(
        entries(&fx, "create_test_login")
            .iter()
            .any(|e| e.detail.as_deref() == Some("TEST_LOGIN_CREATED (approved)"))
    );

    // Allowed by the person: no sheet any more.
    set_policy(&fx, true, &["example-partner.com"]);
    created_id(&create(&fx, "partner3@example.com", &[PARTNER]));
    assert_eq!(human.seen().len(), 2);

    // One site outside the list among allowed ones is enough for a sheet.
    created_id(&create(
        &fx,
        "mixed@example.com",
        &[LOCAL, "https://other.example.net"],
    ));
    assert_eq!(human.seen().len(), 3);
}

#[test]
fn an_unanswered_sheet_times_out_and_creates_nothing() {
    let fx = fixture();
    set_policy(&fx, true, &[]);
    let human = Human::new(&fx.queue, |_| None);
    let reply = create(&fx, "slow@example.com", &[PARTNER]);
    assert_eq!(code(&reply), Some("APPROVAL_TIMEOUT"));
    assert_eq!(human.seen().len(), 1);
    assert!(test_vault_items(&fx).is_empty());
}

#[test]
fn the_same_username_at_a_covered_website_is_reused_as_exists() {
    let fx = fixture();
    set_policy(&fx, true, &[]);
    let id = created_id(&create(&fx, "buyer1@example.test", &[LOCAL]));
    let _ = fx.test_logins.take_notices();

    let again = create(&fx, "buyer1@example.test", &[&format!("{LOCAL}/register")]);
    match again {
        Response::TestLoginCreated {
            status: TestLoginStatus::Exists,
            item_id,
            ..
        } => assert_eq!(item_id, id),
        other => panic!("expected exists, got {other:?}"),
    }
    assert_eq!(test_vault_items(&fx).len(), 1, "nothing written");
    assert!(
        fx.test_logins.take_notices().is_empty(),
        "nothing to notice"
    );

    // Another username is another test user.
    created_id(&create(&fx, "buyer2@example.test", &[LOCAL]));
}

#[test]
fn the_rate_limit_survives_a_reconnect_and_the_cap_holds() {
    let fx = fixture();
    set_policy(&fx, true, &[]);
    // Every call below is its own connection.
    for i in 0..10 {
        created_id(&create(&fx, &format!("user{i}@example.test"), &[LOCAL]));
    }
    let refused = create(&fx, "user10@example.test", &[LOCAL]);
    assert_eq!(code(&refused), Some("RATE_LIMITED"));
    // Reuse is never refused for the creates around it.
    assert!(matches!(
        create(&fx, "user0@example.test", &[LOCAL]),
        Response::TestLoginCreated {
            status: TestLoginStatus::Exists,
            ..
        }
    ));
    fx.clock.advance(Duration::from_secs(10 * 60));
    created_id(&create(&fx, "user10@example.test", &[LOCAL]));

    // Fill the vault to its 200 live items: the next create is refused with the cap's message.
    fx.handle
        .transact(WAIT, |tx| {
            let test_vault = tx.agent_test_vault().unwrap().id;
            for i in 0..190 {
                tx.add_item(Item::new(
                    test_vault,
                    Category::Login,
                    format!("filler {i}"),
                ));
            }
            Ok(())
        })
        .unwrap()
        .unwrap();
    fx.clock.advance(Duration::from_secs(10 * 60));
    let full = create(&fx, "one-more@example.test", &[LOCAL]);
    assert_eq!(code(&full), Some("RATE_LIMITED"));
    let Response::Error { message, .. } = full else {
        unreachable!()
    };
    assert!(message.contains("200"), "{message}");
}

#[test]
fn a_sealed_login_fills_without_a_sheet_until_its_password_is_edited() {
    let fx = fixture();
    set_policy(&fx, true, &["example.com"]);
    let human = Human::approving(&fx.queue);
    let id = created_id(&create(&fx, "alice@example.test", &[PAGE]));
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);

    let filled = fx.request_fill(&id.to_string(), PAGE, &both());
    assert!(matches!(filled, Response::FillResult { .. }), "{filled:?}");
    assert_eq!(
        human.sheets(),
        0,
        "a sealed test login at an allowed origin: no sheet"
    );
    let fills = sw.fills_at_least(1);
    assert!(
        matches!(&fills[..], [ExtResponse::Filled { .. }]),
        "{fills:?}"
    );
    let allowed = fx
        .on_disk()
        .into_iter()
        .find(|e| e.tool == "request_fill" && e.outcome == Outcome::Allowed)
        .expect("an Allowed entry");
    assert_eq!(
        allowed.detail.as_deref(),
        Some("TEST_LOGIN_FILL (automatic)")
    );
    assert!(
        allowed.actor.starts_with("mcp \"example-agent\""),
        "{}",
        allowed.actor
    );

    // The person types a real password into it: the seal breaks, and the fill is ordinary.
    fx.handle
        .transact(WAIT, |tx| {
            let item = tx.item_by_id_mut(&id).unwrap();
            let primary = item.primary_secret.unwrap();
            let field = item.fields.iter_mut().find(|f| f.id == primary).unwrap();
            field.value = FieldValue::Secret(Secret::from_string("a-real-password".to_owned()));
            Ok(())
        })
        .unwrap()
        .unwrap();
    sw.set(Tab::front(PAGE), OnDeliver::Redeem);
    let filled = fx.request_fill(&id.to_string(), PAGE, &both());
    assert!(matches!(filled, Response::FillResult { .. }), "{filled:?}");
    assert_eq!(
        human.sheets(),
        1,
        "an unsealed item needs the ADR-0036 sheet"
    );

    // And it no longer lists as a test login.
    let Response::TestLogins { items, .. } = list(&fx) else {
        panic!("list")
    };
    assert!(items.is_empty());
}

#[test]
fn a_sealed_login_at_an_origin_outside_the_list_takes_the_ordinary_sheet() {
    let fx = fixture();
    set_policy(&fx, true, &[]);
    let human = Human::new(&fx.queue, |r| {
        Some(if r.kind == ApprovalKind::CreateTestLogin {
            Decision::AllowOnce
        } else {
            Decision::Deny
        })
    });
    let id = created_id(&create(&fx, "alice@example.test", &[PAGE]));
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    let reply = fx.request_fill(&id.to_string(), PAGE, &both());
    assert_eq!(code(&reply), Some("USER_DENIED"));
    assert_eq!(human.sheets(), 1);
}

#[test]
fn a_test_vault_item_is_never_matched_for_the_person() {
    let fx = fixture();
    set_policy(&fx, true, &["example.com"]);
    let id = created_id(&create(&fx, "alice@example.test", &[PAGE]));

    let mut client = ExtClient::connect(&fx.extension_endpoint).expect("connect");
    let welcome = client
        .call(
            "1",
            &ExtRequest::Hello {
                extension_id: PINNED_EXTENSION_IDS[0].to_owned(),
                browser: "chrome".to_owned(),
                extension_version: "0.2.0".to_owned(),
                protocol_version: kagisecure_extension_ipc::PROTOCOL_VERSION,
                capabilities: vec![],
            },
        )
        .expect("hello");
    assert!(
        matches!(welcome, ExtResponse::Welcome { .. }),
        "{welcome:?}"
    );
    let matched = client
        .call(
            "2",
            &ExtRequest::Match {
                page: PageContext::top(PAGE),
            },
        )
        .expect("match");
    let ExtResponse::Matches { items, .. } = matched else {
        panic!("{matched:?}")
    };
    assert!(
        !items.iter().any(|i| i.item_id == id.to_string()),
        "a test login is never offered to the person"
    );
    assert!(
        items.iter().any(|i| i.item_id == fx.item),
        "the person's own login for the site still is"
    );
}

#[test]
fn a_run_whose_every_variable_is_a_sealed_test_login_rides_the_grace_window() {
    use kagisecure_ipc::protocol::{Delivery, FieldRef, OutputMode, VariableRequest};
    let fx = fixture();
    set_policy(&fx, true, &[]);
    let human = Human::approving(&fx.queue);
    let id = created_id(&create(&fx, "seed@example.test", &[LOCAL]));
    let (test_vault, username_field, password_field) = fx
        .handle
        .with(|vault| {
            let item = vault.item_by_id(&id).unwrap();
            let username = item
                .fields
                .iter()
                .find(|f| f.label == "username")
                .unwrap()
                .id;
            (
                vault.agent_test_vault().unwrap().id,
                username,
                item.primary_secret.unwrap(),
            )
        })
        .unwrap();

    let Response::Environment { environment } = agent_call(
        &fx.agent_endpoint,
        &Request::CreateEnvironment {
            vault_id: Some(test_vault),
            name: "shop / e2e".to_owned(),
            description: None,
        },
    ) else {
        panic!("create_environment")
    };
    let bind = |name: &str, field_id| VariableRequest {
        name: name.to_owned(),
        bind_to: Some(FieldRef {
            item_id: id,
            field_id,
        }),
        hint: None,
    };
    let added = agent_call(
        &fx.agent_endpoint,
        &Request::AddVariables {
            environment_id: environment.id,
            variables: vec![
                bind("TEST_USER", username_field),
                bind("TEST_PASSWORD", password_field),
                VariableRequest {
                    name: "OTHER".to_owned(),
                    bind_to: None,
                    hint: None,
                },
            ],
        },
    );
    assert!(
        matches!(added, Response::AddedVariables { .. }),
        "{added:?}"
    );

    let cwd = fx.dir.path().canonicalize().unwrap();
    let run = |variables: Option<Vec<String>>, delivery: Delivery| {
        agent_call(
            &fx.agent_endpoint,
            &Request::RunWithEnv {
                environment_id: environment.id,
                command: "/usr/bin/true".to_owned(),
                args: Vec::new(),
                cwd: cwd.to_string_lossy().into_owned(),
                variables,
                timeout_seconds: 5,
                output: OutputMode::None,
                delivery,
            },
        )
    };
    let runs = |h: &Human| -> Vec<bool> {
        h.seen()
            .iter()
            .filter(|r| r.kind == ApprovalKind::RunWithEnv)
            .map(|r| r.rides_grace)
            .collect()
    };
    // Stdin delivery keeps its single use; it rides the window all the same (ADR-0048 §9).
    let ran = run(
        Some(vec!["TEST_USER".to_owned(), "TEST_PASSWORD".to_owned()]),
        Delivery::Stdin,
    );
    assert!(matches!(ran, Response::Ran { .. }), "{ran:?}");
    assert_eq!(runs(&human), [true]);
    // Any other variable selected — here one still waiting for the user — and it is the ordinary
    // sheet.
    let _ = run(None, Delivery::Environment);
    assert_eq!(runs(&human), [true, false]);
}
