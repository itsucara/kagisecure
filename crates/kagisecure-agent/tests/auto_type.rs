//! `request_type` (ADR-0050), over the real socket and through the real sidecar.
//!
//! An approved auto-type reaches the app's typist as values and the agent as field names only:
//! the sheet rides the grace window and names the target; a denial, a block, a host with no
//! typist, an item without the field and a target mismatch type nothing; a mismatch is one code;
//! the audit names the agent in full and the target bundle id; the unattended socket refuses it;
//! and the password reaches no byte the sidecar writes.
#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::{client_info, error_code, error_message, with_ui};
use kagisecure_agent::approval::{ApprovalKind, Decision};
use kagisecure_agent::auto_type::{AutoTypeBroker, TypeOutcome};
use kagisecure_agent::{Agent, AgentConfig, VaultHandle};
use kagisecure_core::audit::AuditEntry;
use kagisecure_core::model::{Category, Field, Item, Secret};
use kagisecure_core::proto::Outcome;
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_ipc::client::Client;
use kagisecure_ipc::protocol::{Request, Response, TypeField, TypeTarget};

/// The password. Never typed into anything but the fake typist.
const CANARY: &str = "AUT0-TYP3-C4N4RY-5e2d9a81f04b";
const USERNAME: &str = "alice@example.com";
const BUNDLE: &str = "com.example.Terminal";

struct Fx {
    _dir: tempfile::TempDir,
    agent: Agent,
    endpoint: kagisecure_ipc::Endpoint,
    broker: Arc<AutoTypeBroker>,
    login: String,
    bare: String,
}

fn fixture_with(broker: Option<Arc<AutoTypeBroker>>) -> Fx {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut options = CreateOptions::new().expect("options");
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
        kagisecure_core::crypto::kdf::MIN_M_KIB,
        kagisecure_core::crypto::kdf::MIN_T,
        1,
    )
    .expect("kdf");
    options.vault_name = "Personal".to_owned();
    let (mut vault, _) =
        Vault::create(dir.path().join("test.kagivault"), b"pw", &options).expect("create");
    let vault_id = vault.default_vault_id().expect("default vault");

    let mut login = Item::new(vault_id, Category::Login, "Staging server");
    login.fields.push(Field::public("username", USERNAME));
    login.fields.push(Field::concealed(
        "password",
        Secret::from_string(CANARY.to_owned()),
    ));
    login.fields.push(Field::totp(
        "one-time password",
        Secret::from_string("otpauth://totp/T:a?secret=JBSWY3DPEHPK3PXP&issuer=T".to_owned()),
    ));
    login.agent_visible = true;
    let mut bare = Item::new(vault_id, Category::Login, "No password");
    bare.fields.push(Field::public("username", "bob"));
    bare.agent_visible = true;
    let (login_id, bare_id) = (login.id.to_string(), bare.id.to_string());
    vault
        .transact(|tx| {
            tx.set_vault_agent_visible(vault_id, true);
            tx.add_item(login);
            tx.add_item(bare);
            Ok(())
        })
        .expect("save");

    let endpoint = kagisecure_ipc::Endpoint::for_instance(dir.path(), "agent.sock");
    let ready = broker
        .clone()
        .unwrap_or_else(|| Arc::new(AutoTypeBroker::new()));
    let agent = Agent::start(
        VaultHandle::new(vault),
        &AgentConfig {
            endpoint: Some(endpoint.clone()),
            queue: None,
            agent_fill: None,
            test_logins: None,
            auto_type: broker,
        },
    )
    .expect("bind");
    Fx {
        _dir: dir,
        agent,
        endpoint,
        broker: ready,
        login: login_id,
        bare: bare_id,
    }
}

fn fixture() -> Fx {
    let broker = Arc::new(AutoTypeBroker::new());
    broker.set_ready(true);
    fixture_with(Some(broker))
}

fn target() -> TypeTarget {
    TypeTarget {
        bundle_id: BUNDLE.to_owned(),
        team_id: Some("ABCDE12345".to_owned()),
        window_title: Some("ssh staging".to_owned()),
    }
}

fn request(item: &str, fields: &[TypeField]) -> Request {
    Request::RequestType {
        item_id: item.parse().expect("an item id"),
        fields: fields.to_vec(),
        target: target(),
        reason: Some("sign in to the staging box".to_owned()),
    }
}

fn call(fx: &Fx, request: &Request) -> Response {
    Client::connect(&fx.endpoint, client_info("type-test"))
        .expect("connect")
        .call(request)
        .expect("call")
}

/// What the fake typist saw: each job's target bundle id and its (field, value) pairs.
type Seen = Arc<std::sync::Mutex<Vec<(String, Vec<(TypeField, String)>)>>>;

/// Run `f` with a typist that answers every job with `outcome`, recording what it was handed.
fn with_typist<T: Send>(fx: &Fx, outcome: TypeOutcome, f: impl FnOnce() -> T) -> (T, Seen) {
    let seen: Seen = Arc::default();
    let stop = Arc::new(AtomicBool::new(false));
    let out = std::thread::scope(|scope| {
        let (seen, typist_stop, broker) = (Arc::clone(&seen), Arc::clone(&stop), &fx.broker);
        scope.spawn(move || {
            while !typist_stop.load(Ordering::SeqCst) {
                if let Some(job) = broker.next_job(Duration::from_millis(50)) {
                    let values = job
                        .values
                        .iter()
                        .map(|v| (v.field, v.value.expose().to_owned()))
                        .collect();
                    seen.lock()
                        .unwrap()
                        .push((job.target.bundle_id.clone(), values));
                    broker.finish(&job.id, outcome);
                }
            }
        });
        let out = f();
        stop.store(true, Ordering::SeqCst);
        out
    });
    (out, seen)
}

fn audit(fx: &Fx) -> Vec<AuditEntry> {
    match call(
        fx,
        &Request::Audit {
            limit: 1000,
            verify: false,
        },
    ) {
        Response::Audit { entries, .. } => entries
            .into_iter()
            .filter(|e| e.tool == "request_type")
            .collect(),
        other => panic!("audit: {other:?}"),
    }
}

#[test]
fn an_approved_auto_type_hands_the_typist_the_values_and_the_agent_only_names() {
    let fx = fixture();
    let req = request(&fx.login, &[TypeField::Password, TypeField::Username]);
    let ((reply, sheets), typed) = with_typist(&fx, TypeOutcome::Typed, || {
        with_ui(&fx.agent, Decision::AllowOnce, || call(&fx, &req))
    });

    match &reply {
        Response::Typed {
            fields_typed,
            bundle_id,
        } => {
            assert_eq!(fields_typed, &[TypeField::Username, TypeField::Password]);
            assert_eq!(bundle_id, BUNDLE);
        }
        other => panic!("expected Typed, got {other:?}"),
    }
    assert!(!format!("{reply:?}").contains(CANARY));

    // The typist got both values, username first: Tab goes between them.
    let typed = typed.lock().unwrap();
    assert_eq!(typed.len(), 1);
    assert_eq!(typed[0].0, BUNDLE);
    assert_eq!(
        typed[0].1,
        [
            (TypeField::Username, USERNAME.to_owned()),
            (TypeField::Password, CANARY.to_owned()),
        ]
    );

    // One sheet, for the grace window to answer when it is open; it names the target.
    assert_eq!(sheets.len(), 1);
    let sheet = &sheets[0];
    assert_eq!(sheet.kind, ApprovalKind::AutoType);
    assert!(sheet.rides_grace && !sheet.presence_only);
    assert_eq!(sheet.origin.as_deref(), Some(BUNDLE));
    let facts = sheet.auto_type.as_ref().expect("facts");
    assert_eq!(facts.bundle_id, BUNDLE);
    assert_eq!(facts.team_id.as_deref(), Some("ABCDE12345"));
    assert_eq!(facts.window_title.as_deref(), Some("ssh staging"));
    assert_eq!(facts.fields, ["username", "password"]);
    assert_eq!(facts.item_title, "Staging server");
    assert_eq!(facts.vault_name, "Personal");
    assert!(facts.agent.starts_with("mcp "));
    assert!(!format!("{sheet:?}").contains(CANARY));

    // Nothing minted.
    assert!(matches!(
        call(&fx, &Request::ListLeases),
        Response::Leases { leases } if leases.is_empty()
    ));

    // Audited before typing, with the agent's identity and the target.
    let entries = audit(&fx);
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0].outcome, Outcome::Allowed);
    assert_eq!(
        entries[0].detail.as_deref(),
        Some("AUTO_TYPE com.example.Terminal")
    );
    assert!(entries[0].actor.starts_with("mcp ") && entries[0].actor.contains("type-test"));
    assert_eq!(entries[0].variables, ["username", "password"]);
    assert_eq!(
        entries[0].item_id.map(|i| i.to_string()),
        Some(fx.login.clone())
    );
}

#[test]
fn a_one_time_code_is_typed_alone() {
    let fx = fixture();
    let req = request(&fx.login, &[TypeField::OneTimeCode]);
    let ((reply, _), typed) = with_typist(&fx, TypeOutcome::Typed, || {
        with_ui(&fx.agent, Decision::AllowOnce, || call(&fx, &req))
    });
    assert!(matches!(reply, Response::Typed { .. }), "{reply:?}");
    let typed = typed.lock().unwrap();
    let (field, code) = &typed[0].1[0];
    assert_eq!(*field, TypeField::OneTimeCode);
    assert!(code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()));

    let combined = call(
        &fx,
        &request(&fx.login, &[TypeField::OneTimeCode, TypeField::Password]),
    );
    assert_eq!(error_code(&combined).as_deref(), Some("INVALID_ARGUMENT"));
}

#[test]
fn a_mismatch_types_nothing_and_is_one_code() {
    let fx = fixture();
    let req = request(&fx.login, &[TypeField::Password]);
    for outcome in [
        TypeOutcome::TargetMismatch,
        TypeOutcome::FocusChanged { typed_any: false },
    ] {
        let ((reply, _), _) = with_typist(&fx, outcome, || {
            with_ui(&fx.agent, Decision::AllowOnce, || call(&fx, &req))
        });
        assert_eq!(error_code(&reply).as_deref(), Some("NO_MATCHING_TARGET"));
        assert!(error_message(&reply).unwrap().contains("Nothing was typed"));
    }
    // Two mismatch causes, one message: not an oracle for which check failed.
    let ((partway, _), _) = with_typist(&fx, TypeOutcome::FocusChanged { typed_any: true }, || {
        with_ui(&fx.agent, Decision::AllowOnce, || call(&fx, &req))
    });
    assert_eq!(error_code(&partway).as_deref(), Some("NO_MATCHING_TARGET"));
    assert!(
        error_message(&partway)
            .unwrap()
            .contains("Part of the value may have been typed")
    );

    let ((secure, _), _) = with_typist(&fx, TypeOutcome::SecureInput, || {
        with_ui(&fx.agent, Decision::AllowOnce, || call(&fx, &req))
    });
    assert_eq!(error_code(&secure).as_deref(), Some("TYPE_UNAVAILABLE"));

    // Each followed by a `Failed` entry naming why.
    let details: Vec<String> = audit(&fx)
        .into_iter()
        .filter(|e| e.outcome == Outcome::Failed)
        .filter_map(|e| e.detail)
        .collect();
    assert!(
        details.iter().any(|d| d.starts_with("NO_MATCHING_TARGET")),
        "{details:?}"
    );
    assert!(
        details
            .iter()
            .any(|d| d.starts_with("FOCUS_CHANGED_PARTWAY")),
        "{details:?}"
    );
    assert!(
        details.iter().any(|d| d.starts_with("SECURE_INPUT")),
        "{details:?}"
    );
}

#[test]
fn a_denial_types_nothing_and_deny_and_block_blocks_the_agent() {
    let fx = fixture();
    let req = request(&fx.login, &[TypeField::Password]);
    let ((denied, _), typed) = with_typist(&fx, TypeOutcome::Typed, || {
        with_ui(&fx.agent, Decision::Deny, || call(&fx, &req))
    });
    assert_eq!(error_code(&denied).as_deref(), Some("USER_DENIED"));
    assert!(typed.lock().unwrap().is_empty());

    let ((blocked, _), _) = with_typist(&fx, TypeOutcome::Typed, || {
        with_ui(&fx.agent, Decision::DenyAndBlock, || call(&fx, &req))
    });
    assert_eq!(error_code(&blocked).as_deref(), Some("USER_DENIED"));
    // The next one is refused before any sheet.
    let ((again, sheets), _) = with_typist(&fx, TypeOutcome::Typed, || {
        with_ui(&fx.agent, Decision::AllowOnce, || call(&fx, &req))
    });
    assert_eq!(error_code(&again).as_deref(), Some("USER_DENIED"));
    assert!(sheets.is_empty());
    assert!(audit(&fx).iter().all(|e| e.outcome != Outcome::Allowed));
}

#[test]
fn nothing_is_asked_without_a_ready_typist_or_a_value() {
    // `kagisecure daemon`: no broker at all.
    let none = fixture_with(None);
    let reply = call(&none, &request(&none.login, &[TypeField::Password]));
    assert_eq!(error_code(&reply).as_deref(), Some("TYPE_UNAVAILABLE"));

    // The app without the Accessibility permission: a broker that is not ready.
    let not_ready = fixture_with(Some(Arc::new(AutoTypeBroker::new())));
    let (reply, sheets) = with_ui(&not_ready.agent, Decision::AllowOnce, || {
        call(
            &not_ready,
            &request(&not_ready.login, &[TypeField::Password]),
        )
    });
    assert_eq!(error_code(&reply).as_deref(), Some("TYPE_UNAVAILABLE"));
    assert!(sheets.is_empty());

    // An item with no password, an unknown item, a malformed target.
    let fx = fixture();
    let (reply, sheets) = with_ui(&fx.agent, Decision::AllowOnce, || {
        call(&fx, &request(&fx.bare, &[TypeField::Password]))
    });
    assert_eq!(error_code(&reply).as_deref(), Some("NOTHING_TO_FILL"));
    assert!(sheets.is_empty());
    let unknown = call(
        &fx,
        &request(
            &kagisecure_core::proto::ItemId::new().to_string(),
            &[TypeField::Username],
        ),
    );
    assert_eq!(error_code(&unknown).as_deref(), Some("NOT_FOUND"));
    let bad = call(
        &fx,
        &Request::RequestType {
            item_id: fx.login.parse().unwrap(),
            fields: vec![TypeField::Username],
            target: TypeTarget {
                bundle_id: "com.example; rm -rf".to_owned(),
                team_id: None,
                window_title: None,
            },
            reason: None,
        },
    );
    assert_eq!(error_code(&bad).as_deref(), Some("INVALID_ARGUMENT"));
}

#[test]
fn an_untaken_job_is_not_typed_and_the_agent_is_told() {
    let broker = Arc::new(AutoTypeBroker::with_job_timeout(Duration::from_millis(100)));
    broker.set_ready(true);
    let fx = fixture_with(Some(broker));
    let (reply, _) = with_ui(&fx.agent, Decision::AllowOnce, || {
        call(&fx, &request(&fx.login, &[TypeField::Username]))
    });
    assert_eq!(error_code(&reply).as_deref(), Some("TYPE_UNAVAILABLE"));
    assert!(fx.broker.next_job(Duration::from_millis(1)).is_none());
}

// -------------------------------------------------------------------------------------------------
// The canary sweep through the real sidecar.
// -------------------------------------------------------------------------------------------------

fn sidecar() -> PathBuf {
    kagisecure_test_support::binary("kagisecure-mcp", kagisecure_agent::bundle::SIDECAR)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(A[((n >> shift) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

struct Raw {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
    seen: Vec<u8>,
    next: u64,
}

impl Raw {
    fn send(&mut self, v: &serde_json::Value) {
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{v}").unwrap();
        stdin.flush().unwrap();
    }

    fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.next += 1;
        let id = self.next;
        self.send(
            &serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        );
        loop {
            let mut line = String::new();
            assert!(
                self.stdout.read_line(&mut line).unwrap() > 0,
                "sidecar closed stdout"
            );
            self.seen.extend_from_slice(line.as_bytes());
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line)
                && v["id"].as_u64() == Some(id)
            {
                return v;
            }
        }
    }
}

#[test]
fn the_password_reaches_no_byte_the_sidecar_writes() {
    let fx = fixture();
    let mut child = Command::new(sidecar())
        .env("KAGISECURE_SOCKET", fx.endpoint.as_override())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kagisecure-mcp");
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let mut raw = Raw {
        child,
        stdout,
        seen: Vec::new(),
        next: 0,
    };
    raw.call(
        "initialize",
        serde_json::json!({"protocolVersion": "2025-11-25", "capabilities": {},
                           "clientInfo": {"name": "example-agent", "version": "0"}}),
    );
    raw.send(&serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));

    let item = fx.login.clone();
    let ((reply, _), typed) = with_typist(&fx, TypeOutcome::Typed, || {
        with_ui(&fx.agent, Decision::AllowOnce, || {
            raw.call(
                "tools/call",
                serde_json::json!({"name": "request_type", "arguments": {
                    "item_id": item,
                    "target": {"bundle_id": BUNDLE},
                }}),
            )
        })
    });
    // It happened: the typist was handed the password.
    assert!(
        typed.lock().unwrap()[0]
            .1
            .iter()
            .any(|(f, v)| *f == TypeField::Password && v == CANARY)
    );
    let result = &reply["result"]["structuredContent"];
    assert_eq!(result["status"], "typed", "{reply}");
    assert_eq!(
        result["fields_typed"],
        serde_json::json!(["username", "password"])
    );

    drop(raw.child.stdin.take());
    let mut rest = Vec::new();
    let _ = raw.stdout.read_to_end(&mut rest);
    raw.seen.extend_from_slice(&rest);
    let mut stderr = Vec::new();
    if let Some(mut e) = raw.child.stderr.take() {
        let _ = e.read_to_end(&mut stderr);
    }
    let _ = raw.child.wait();

    let mut haystack = String::from_utf8_lossy(&raw.seen).into_owned();
    haystack.push_str(&String::from_utf8_lossy(&stderr));
    for entry in audit(&fx) {
        haystack.push_str(&format!("{entry:?}"));
    }
    for (kind, form) in [
        ("raw", CANARY.to_owned()),
        ("hex", hex(CANARY.as_bytes())),
        ("base64", base64(CANARY.as_bytes())),
    ] {
        assert!(
            !haystack.contains(&form),
            "the password's {kind} form leaked"
        );
    }
}
