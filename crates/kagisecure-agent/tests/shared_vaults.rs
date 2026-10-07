//! Shared vaults served to agents (ADR-0035 §14, Phase 4), end to end through the real socket.
//!
//! A real personal vault with a real device key, a real shared vault beside it written with
//! `kagisecure-shared`, attached to the agent the way `kagisecure daemon` attaches it
//! ([`ReplicaSource::open_all`]), and raw IPC clients. The shared vault is set up with
//! `kagisecure_shared::admin` — this test plays the person at the app — which the agent's own
//! source may never name (`kagisecure-shared`'s lexical guard).

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::{Fixture, allow_session, error_code, fixture, with_ui};
use kagisecure_agent::{ReplicaSource, SharedAttachment};
use kagisecure_core::model::{Environment, Field, Item, Secret, VarSource};
use kagisecure_core::proto::{Category, EnvId, FieldId, ItemId, VarName, VaultId};
use kagisecure_ipc::protocol::{
    AgentFillField, ErrorCode, FieldRef, OutputMode, Request, Response, VariableRequest,
};
use kagisecure_shared::DeviceSecret;
use kagisecure_shared::admin::{create, visibility};
use kagisecure_shared::replica::Replica;
use kagisecure_shared::view::SharedView;
use kagisecure_shared::write::{put_env, put_item};

/// The one secret value in the shared vault. If these bytes reach a reply, a sheet or an audit
/// entry, a shared value reached the model's side of the boundary.
const SHARED_MARKER: &str = "K4G1-SH4R3D-C4N4RY-7d2e9b0c41a5f3e8";

const NOW: u64 = 1_800_000_000;

struct Shared {
    fx: Fixture,
    personal_path: PathBuf,
    replica_path: PathBuf,
    vault_id: VaultId,
    item_id: ItemId,
    field_id: FieldId,
    env_id: EnvId,
    /// A second handle on this device's key, for the test's own writes.
    device: DeviceSecret,
    attachments: Vec<SharedAttachment>,
}

/// The personal fixture, plus a shared vault "Ops" beside it holding an item whose one field is
/// [`SHARED_MARKER`] and an environment binding `TOKEN` to it — both made visible to this
/// computer's agents when `visible`.
fn shared_fixture(visible: bool, env_name: &str) -> Shared {
    let fx = fixture();
    let personal_path = fx.dir.path().join("test.kagivault");
    let device = DeviceSecret::generate().expect("device");
    let key = device.to_device_key("This computer", NOW).expect("key");
    fx.handle
        .transact(std::time::Duration::from_secs(5), |tx| {
            tx.add_device_key(key, "test")
        })
        .expect("unlocked")
        .expect("device key added");

    let mut replica = create::create(&personal_path, &device, "Ops", None, NOW).expect("create");
    let vault_id = *replica.vault_id();
    let mut item = Item::new(vault_id, Category::ApiCredential, "Deploy key");
    let field = Field::concealed("token", Secret::from_string(SHARED_MARKER.to_owned()));
    let field_id = field.id;
    item.fields.push(field);
    let item_id = item.id;
    put_item(&mut replica, &device, item, NOW).expect("item");
    let mut env = Environment::new(vault_id, env_name);
    env.set_var(
        VarName::new("TOKEN".to_owned()).expect("name"),
        VarSource::ItemField {
            item: item_id,
            field: field_id,
        },
    );
    let env_id = env.id;
    put_env(&mut replica, &device, env, NOW).expect("env");
    if visible {
        visibility::set_item(&mut replica, &device, item_id, true).expect("item visible");
        visibility::set_field(&mut replica, &device, item_id, field_id, true).expect("field");
        visibility::set_env(&mut replica, &device, env_id, true).expect("env visible");
    }
    let replica_path = replica.path().to_owned();
    drop(replica);

    let sources = fx
        .handle
        .with(|vault| ReplicaSource::open_all(&personal_path, vault))
        .expect("unlocked");
    assert_eq!(sources.len(), 1, "the device key opens its shared vault");
    let attachments = sources
        .into_iter()
        .map(|source| fx.handle.attach_shared(source))
        .collect();
    Shared {
        fx,
        personal_path,
        replica_path,
        vault_id,
        item_id,
        field_id,
        env_id,
        device,
        attachments,
    }
}

impl Shared {
    fn project(&self) -> String {
        self.fx.canonical_project().display().to_string()
    }

    fn write_env(&self, filename: &str) -> Request {
        Request::WriteEnvFile {
            environment_id: self.env_id,
            directory: self.project(),
            filename: filename.to_owned(),
            variables: None,
            overwrite: true,
            ttl_seconds: 900,
        }
    }

    /// A new version of the shared item, written as another process would.
    fn rotate(&self, value: &str, now: u64) {
        let mut replica = Replica::open(&self.replica_path, &self.device).expect("open");
        let mut item = Item::new(self.vault_id, Category::ApiCredential, "Deploy key");
        item.id = self.item_id;
        let mut field = Field::concealed("token", Secret::from_string(value.to_owned()));
        field.id = self.field_id;
        field.agent_visible = true;
        item.fields.push(field);
        item.agent_visible = true;
        put_item(&mut replica, &self.device, item, now).expect("rotate");
    }

    fn records(&self) -> (Vec<String>, [u8; 32]) {
        let replica = Replica::open(&self.replica_path, &self.device).expect("open");
        let ids = replica.records().map(|r| r.id().to_string()).collect();
        let view = SharedView::compute(
            replica.vault_id(),
            &replica.genesis(),
            &replica.envelopes(),
            &self.device,
        )
        .expect("view");
        (ids, view.roster().digest())
    }

    fn audit(&self) -> Vec<kagisecure_core::audit::AuditEntry> {
        self.fx
            .handle
            .with(|v| v.audit_entries().to_vec())
            .expect("unlocked")
    }
}

fn call(fx: &Fixture, request: &Request) -> Response {
    fx.client("shared-vaults").call(request).expect("call")
}

fn rendered(value: &impl std::fmt::Debug) -> String {
    format!("{value:?}")
}

/// ADR-0035 §14's canary: every tool an agent can call, on a shared vault holding the marker,
/// approved by the "human" — and the marker is in the `.env` file the human approved and nowhere
/// an agent, a sheet or the audit log can read it.
#[test]
fn a_value_in_a_shared_vault_never_reaches_the_model() {
    let shared = shared_fixture(true, "ops / prod");
    let fx = &shared.fx;
    let requests = [
        Request::ListVaults,
        Request::ListItems {
            vault_id: None,
            query: None,
            category: None,
            limit: 50,
            cursor: None,
        },
        Request::ListEnvironments { vault_id: None },
        Request::DescribeItem {
            item_id: shared.item_id,
        },
        shared.write_env(".env"),
        Request::RequestFill {
            item_id: shared.item_id,
            origin: "https://example.com".to_owned(),
            fields: vec![AgentFillField::Password],
        },
        Request::ListLeases,
        // The reply travels through the real client's `serde_json` decode
        // (`kagisecure_ipc::client::Client::call`), which is exactly where an `AuditEntry`'s
        // `prev` bytes once failed to decode ("invalid type: sequence, expected bytes") because
        // they went out as a JSON array and `prev`'s deserializer only accepted a byte string —
        // see `kagisecure_core::audit`'s `deserialize_prev`. Kept in the canary run, not just a
        // unit test, so a future reintroduction of that mismatch fails here too.
        Request::Audit {
            limit: 50,
            verify: true,
        },
    ];
    let (replies, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("shared-canary");
        let mut replies: Vec<Response> = requests
            .iter()
            .map(|r| {
                client
                    .call(r)
                    .unwrap_or_else(|e| panic!("{} failed: {e:?}", r.tool_name()))
            })
            .collect();
        #[cfg(unix)]
        replies.push(
            client
                .call(&Request::RunWithEnv {
                    environment_id: shared.env_id,
                    command: "/usr/bin/printenv".to_owned(),
                    args: vec!["TOKEN".to_owned()],
                    cwd: shared.project(),
                    variables: None,
                    timeout_seconds: 10,
                    output: OutputMode::Scrubbed,
                    delivery: kagisecure_ipc::protocol::Delivery::Environment,
                })
                .expect("call"),
        );
        replies
    });

    // The tools worked: the shared vault is listed, and the release happened.
    let listing = rendered(&replies);
    assert!(listing.contains("Deploy key"), "{listing}");
    assert!(listing.contains("ops / prod"), "{listing}");
    assert!(
        matches!(&replies[4], Response::WroteEnvFile { .. }),
        "{:?}",
        replies[4]
    );
    let written = std::fs::read_to_string(fx.canonical_project().join(".env")).expect(".env");
    assert!(
        written.contains(SHARED_MARKER),
        "the approved release put the value in the file"
    );

    // …and nowhere else.
    for reply in &replies {
        assert!(
            !rendered(reply).contains(SHARED_MARKER),
            "a reply: {reply:?}"
        );
        let json = serde_json::to_string(reply).expect("json");
        assert!(!json.contains(SHARED_MARKER), "a reply on the wire: {json}");
    }
    assert!(!seen.is_empty(), "the release asked the human");
    assert!(!rendered(&seen).contains(SHARED_MARKER), "a sheet");
    assert!(
        !rendered(&shared.audit()).contains(SHARED_MARKER),
        "the audit log"
    );
}

/// Everything starts hidden, as in the personal vault: a shared vault with nothing made visible
/// is not even listed, and its ids answer exactly like ids that name nothing.
#[test]
fn a_shared_vault_is_hidden_from_agents_until_this_computer_shows_something() {
    let shared = shared_fixture(false, "ops / prod");
    let fx = &shared.fx;
    let Response::Vaults { vaults } = call(fx, &Request::ListVaults) else {
        panic!("list_vaults")
    };
    assert!(vaults.iter().all(|v| !v.shared), "{vaults:?}");
    let Response::Environments { environments } =
        call(fx, &Request::ListEnvironments { vault_id: None })
    else {
        panic!("list_environments")
    };
    assert!(environments.iter().all(|e| e.id != shared.env_id));

    let hidden = call(
        fx,
        &Request::DescribeItem {
            item_id: shared.item_id,
        },
    );
    let absent = call(
        fx,
        &Request::DescribeItem {
            item_id: ItemId::new(),
        },
    );
    assert_eq!(hidden, absent, "hidden and absent are one answer");
    let (_, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        call(fx, &shared.write_env(".env"))
    });
    assert!(
        seen.is_empty(),
        "no sheet for an environment the agent cannot see"
    );
}

/// A shared release shows the source and what changed; is recorded in the personal vault's log
/// with the shared vault's id; is covered by its lease while nothing changes; and asks again —
/// lease or not — once another version of the value arrives.
#[test]
fn the_sheet_names_the_shared_vault_and_a_value_changed_since_approval() {
    let shared = shared_fixture(true, "ops / prod");
    let fx = &shared.fx;

    let (first, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        call(fx, &shared.write_env(".env"))
    });
    assert!(error_code(&first).is_none(), "{first:?}");
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].shared_source.as_deref(),
        Some("Shared vault “Ops” — 1 member")
    );
    assert_eq!(seen[0].changed_since_approval.len(), 1);
    assert!(
        seen[0].changed_since_approval[0]
            .starts_with("TOKEN is released from this computer for the first time"),
        "{:?}",
        seen[0].changed_since_approval
    );

    let entry = shared
        .audit()
        .into_iter()
        .rev()
        .find(|e| e.tool == "write_env_file")
        .expect("an entry");
    assert_eq!(entry.vault_id, Some(shared.vault_id), "decision 24");
    assert_eq!(entry.actor, "mcp");

    // Nothing changed: the lease covers it, and no sheet goes up.
    let (again, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        call(fx, &shared.write_env(".env"))
    });
    assert!(error_code(&again).is_none(), "{again:?}");
    assert!(seen.is_empty(), "the lease covered it: {seen:?}");

    // Another version of the value: the sheet again, lease or not, naming it.
    shared.rotate("rotated", NOW + 120);
    let (after, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        call(fx, &shared.write_env(".env"))
    });
    assert!(error_code(&after).is_none(), "{after:?}");
    assert_eq!(seen.len(), 1, "a changed value is shown to the human");
    assert!(
        seen[0].changed_since_approval[0].starts_with("TOKEN changed by you,"),
        "{:?}",
        seen[0].changed_since_approval
    );
    let written = std::fs::read_to_string(fx.canonical_project().join(".env")).expect(".env");
    assert!(written.contains("rotated"));
}

/// Agents read shared vaults and never write to them (decision 27): a visible shared vault or
/// environment is refused with `INVALID_ARGUMENT`, without a sheet; a hidden one is `NOT_FOUND`.
#[test]
fn agents_cannot_write_to_a_shared_vault() {
    let shared = shared_fixture(true, "ops / prod");
    let fx = &shared.fx;
    let (replies, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        vec![
            call(
                fx,
                &Request::CreateEnvironment {
                    vault_id: Some(shared.vault_id),
                    name: "new".to_owned(),
                    description: None,
                },
            ),
            call(
                fx,
                &Request::AddVariables {
                    environment_id: shared.env_id,
                    variables: vec![VariableRequest {
                        name: "OTHER".to_owned(),
                        bind_to: None,
                        hint: None,
                    }],
                },
            ),
        ]
    });
    for reply in &replies {
        assert_eq!(
            error_code(reply).as_deref(),
            Some("INVALID_ARGUMENT"),
            "{reply:?}"
        );
    }
    assert!(
        seen.is_empty(),
        "nobody is asked about a write that cannot happen"
    );

    // A personal environment cannot be bound into a shared vault either.
    let personal_env: EnvId = fx.env_id.parse().expect("env id");
    let (bound, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        call(
            fx,
            &Request::AddVariables {
                environment_id: personal_env,
                variables: vec![VariableRequest {
                    name: "FROM_SHARED".to_owned(),
                    bind_to: Some(FieldRef {
                        item_id: shared.item_id,
                        field_id: shared.field_id,
                    }),
                    hint: None,
                }],
            },
        )
    });
    assert_eq!(
        error_code(&bound).as_deref(),
        Some("NOT_FOUND"),
        "{bound:?}"
    );

    let hidden = shared_fixture(false, "ops / prod");
    let reply = call(
        &hidden.fx,
        &Request::CreateEnvironment {
            vault_id: Some(hidden.vault_id),
            name: "new".to_owned(),
            description: None,
        },
    );
    assert_eq!(
        error_code(&reply).as_deref(),
        Some("NOT_FOUND"),
        "{reply:?}"
    );
}

/// ADR-0035 §14: no agent can change who a vault is shared with. Every IPC message, with every
/// id pointed at the shared vault and a human approving everything, leaves the shared vault's
/// records — and so its roster — exactly as they were.
#[test]
fn no_ipc_message_changes_a_shared_roster() {
    let shared = shared_fixture(true, "ops / prod");
    let fx = &shared.fx;
    let before = shared.records();

    let requests = every_request(&shared);
    let (_, _) = with_ui(&fx.agent, allow_session(900, 10), || {
        for request in &requests {
            // A connection of its own for each: one reply this client cannot read must not keep
            // the next request from being sent.
            let _ = fx.client("roster").call(request);
        }
    });

    assert_eq!(shared.records(), before, "no record was written");
}

/// One of every request the protocol has, aimed at the shared vault. The `match` makes a new
/// variant a compile error here until it is added.
fn every_request(shared: &Shared) -> Vec<Request> {
    let all = vec![
        Request::ListVaults,
        Request::ListItems {
            vault_id: Some(shared.vault_id),
            query: None,
            category: None,
            limit: 50,
            cursor: None,
        },
        Request::ListEnvironments {
            vault_id: Some(shared.vault_id),
        },
        Request::DescribeItem {
            item_id: shared.item_id,
        },
        Request::CreateEnvironment {
            vault_id: Some(shared.vault_id),
            name: "roster".to_owned(),
            description: None,
        },
        Request::AddVariables {
            environment_id: shared.env_id,
            variables: vec![VariableRequest {
                name: "MORE".to_owned(),
                bind_to: Some(FieldRef {
                    item_id: shared.item_id,
                    field_id: shared.field_id,
                }),
                hint: None,
            }],
        },
        shared.write_env(".env"),
        Request::RunWithEnv {
            environment_id: shared.env_id,
            command: "/bin/echo".to_owned(),
            args: vec!["hello".to_owned()],
            cwd: shared.project(),
            variables: None,
            timeout_seconds: 5,
            output: OutputMode::Scrubbed,
            delivery: kagisecure_ipc::protocol::Delivery::Environment,
        },
        Request::RevokeEnvFile {
            lease_id: None,
            path: Some(format!("{}/.env", shared.project())),
        },
        Request::RequestFill {
            item_id: shared.item_id,
            origin: "https://example.com".to_owned(),
            fields: vec![AgentFillField::Password],
        },
        Request::CreateTestLogin {
            app: "shop".to_owned(),
            purpose: "buyer".to_owned(),
            username: "buyer1@example.test".to_owned(),
            websites: vec!["http://localhost:47800".to_owned()],
            generator: None,
            tags: Vec::new(),
            reason: None,
            bind: None,
        },
        Request::TrashTestLogins {
            website: Some("http://localhost:47800".to_owned()),
            tag: None,
            reason: "rebuild".to_owned(),
        },
        Request::ListTestLogins {
            website: None,
            tag: None,
            query: None,
            limit: 10,
            cursor: None,
        },
        Request::Audit {
            limit: 10,
            verify: false,
        },
        Request::ListLeases,
        Request::Hello {
            protocol: kagisecure_ipc::protocol::PROTOCOL_VERSION,
            client: common::client_info("roster"),
        },
        // Last: the one that locks.
        Request::Lock,
    ];
    for request in &all {
        match request {
            Request::Hello { .. }
            | Request::ListVaults
            | Request::ListItems { .. }
            | Request::ListEnvironments { .. }
            | Request::DescribeItem { .. }
            | Request::CreateEnvironment { .. }
            | Request::AddVariables { .. }
            | Request::WriteEnvFile { .. }
            | Request::RunWithEnv { .. }
            | Request::RevokeEnvFile { .. }
            | Request::RequestFill { .. }
            | Request::CreateTestLogin { .. }
            | Request::ListTestLogins { .. }
            | Request::TrashTestLogins { .. }
            | Request::Audit { .. }
            | Request::ListLeases
            | Request::Lock => {}
        }
    }
    all
}

/// Decision 89: a personal item or environment wins an id; two with the same name are both
/// listed, the shared one qualified by its vault's name.
#[test]
fn collisions_personal_wins_an_id_and_a_shared_name_is_qualified() {
    // The personal fixture's environment is called "acme / staging": so is the shared one.
    let shared = shared_fixture(true, "acme / staging");
    let fx = &shared.fx;
    let Response::Environments { environments } =
        call(fx, &Request::ListEnvironments { vault_id: None })
    else {
        panic!("list_environments")
    };
    let mut names: Vec<&str> = environments.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["acme / staging", "acme / staging (Ops)"]);

    // A shared item carrying the personal item's id: the personal one answers, the shared one
    // is not listed.
    let personal_item: ItemId = fx.item_id.parse().expect("item id");
    let mut replica = Replica::open(&shared.replica_path, &shared.device).expect("open");
    let mut copy = Item::new(shared.vault_id, Category::Login, "A copy that kept its id");
    copy.id = personal_item;
    put_item(&mut replica, &shared.device, copy, NOW + 1).expect("copy");
    visibility::set_item(&mut replica, &shared.device, personal_item, true).expect("visible");
    drop(replica);

    let Response::Item { item } = call(
        fx,
        &Request::DescribeItem {
            item_id: personal_item,
        },
    ) else {
        panic!("describe_item")
    };
    assert_ne!(
        item.vault_id, shared.vault_id,
        "the personal item wins its id"
    );
    let Response::Items { items, .. } = call(
        fx,
        &Request::ListItems {
            vault_id: None,
            query: None,
            category: None,
            limit: 200,
            cursor: None,
        },
    ) else {
        panic!("list_items")
    };
    assert!(!items.iter().any(|i| i.title == "A copy that kept its id"));
}

/// Locking the personal vault detaches every shared vault and drops its keys: nothing is served
/// from one afterwards.
#[test]
fn locking_detaches_every_shared_vault() {
    let shared = shared_fixture(true, "ops / prod");
    let fx = &shared.fx;
    assert_eq!(fx.handle.attached_shared(), vec![shared.vault_id]);
    let weak: std::sync::Weak<ReplicaSource> = {
        let sources = fx
            .handle
            .with(|vault| ReplicaSource::open_all(&shared.personal_path, vault))
            .expect("unlocked");
        let source = sources.into_iter().next().expect("one");
        let weak = Arc::downgrade(&source);
        // Replaces the fixture's attachment for the same vault.
        std::mem::forget(fx.handle.attach_shared(source));
        weak
    };
    assert!(weak.upgrade().is_some());
    drop(fx.handle.take());
    assert!(fx.handle.attached_shared().is_empty());
    assert!(weak.upgrade().is_none(), "the keys went with the lock");
    assert_eq!(
        error_code(&call(fx, &Request::ListVaults)).as_deref(),
        Some(ErrorCode::VaultLocked.as_str())
    );
    drop(shared.attachments);
}

/// Hiding a shared environment on this computer — as `kagisecure env agent-access --deny
/// --shared-vault` does from a terminal, in another process — takes effect on the very next
/// request.
#[test]
fn hiding_a_shared_environment_elsewhere_applies_to_the_next_request() {
    let shared = shared_fixture(true, "ops / prod");
    let fx = &shared.fx;
    let visible = |fx: &Fixture| {
        let Response::Environments { environments } =
            call(fx, &Request::ListEnvironments { vault_id: None })
        else {
            panic!("list_environments")
        };
        environments.iter().any(|e| e.id == shared.env_id)
    };
    assert!(visible(fx));
    let mut replica = Replica::open(&shared.replica_path, &shared.device).expect("open");
    visibility::set_env(&mut replica, &shared.device, shared.env_id, false).expect("hide");
    drop(replica);
    assert!(!visible(fx));
}
