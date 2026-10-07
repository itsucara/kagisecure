//! `store_command_output` (ADR-0049), over the real socket and through the real sidecar.
//!
//! A command's standard output goes into a concealed field and nowhere else: every call is its
//! own approval, granted once whatever the UI answers; a denial, a failed command or output that
//! breaks the rules stores nothing; an existing value is never replaced; a stdin environment
//! reaches the command as ADR-0047's frame; the audit names the agent in full; and the value
//! reaches no byte the sidecar writes.
//!
//! Unix-only: the commands run here are unix binaries.
#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use common::{Fixture, MARKER, allow_session, error_code, error_message, fixture, with_ui};
use kagisecure_agent::approval::{ApprovalKind, Decision};
use kagisecure_core::audit::AuditEntry;
use kagisecure_core::model::{Field, Item, Secret};
use kagisecure_core::proto::{Category, ItemId, Outcome};
use kagisecure_core::vault::Vault;
use kagisecure_ipc::protocol::{
    NotStoredReason, Request, Response, StdinEnvironment, StoreStatus, StoreTarget,
};

/// The value the commands below print. Never in an argv: commands read it from a file, so the
/// sheet and the audit entry, which show the argv, cannot carry it.
const CANARY: &str = "ST0RE-C4N4RY-9b1e7d03c4a2f685";

fn vault_path(fx: &Fixture) -> PathBuf {
    fx.dir.path().join("test.kagivault")
}

/// The vault as committed to disk.
fn on_disk(fx: &Fixture) -> Vault {
    Vault::open_with_password(vault_path(fx), b"pw").expect("open the vault file")
}

/// A file in the project holding `contents`, for a command to print.
fn secret_file(fx: &Fixture, name: &str, contents: &[u8]) -> String {
    let path = fx.canonical_project().join(name);
    std::fs::write(&path, contents).expect("write");
    path.display().to_string()
}

fn store(fx: &Fixture, command: &str, args: &[&str], target: StoreTarget, label: &str) -> Request {
    Request::StoreCommandOutput {
        command: command.to_owned(),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
        cwd: fx.canonical_project().display().to_string(),
        timeout_seconds: 30,
        target,
        field_label: label.to_owned(),
        stdin_environment: None,
        reason: Some("set up the publishing credentials".to_owned()),
    }
}

fn new_item(title: &str) -> StoreTarget {
    StoreTarget::NewItem {
        title: title.to_owned(),
        category: None,
        vault_id: None,
    }
}

fn sh(fx: &Fixture, script: &str, target: StoreTarget, label: &str) -> Request {
    store(fx, "/bin/sh", &["-c", script], target, label)
}

fn call(fx: &Fixture, request: &Request) -> Response {
    fx.client("store-test").call(request).expect("call")
}

fn audit(fx: &Fixture) -> Vec<AuditEntry> {
    match call(
        fx,
        &Request::Audit {
            limit: 1000,
            verify: false,
        },
    ) {
        Response::Audit { entries, .. } => entries
            .into_iter()
            .filter(|e| e.tool == "store_command_output")
            .collect(),
        other => panic!("audit: {other:?}"),
    }
}

fn concealed(vault: &Vault, item: &ItemId, label: &str) -> Option<Vec<u8>> {
    vault
        .item_by_id(item)?
        .fields
        .iter()
        .find(|f| f.label == label)
        .and_then(|f| f.value.as_secret())
        .map(|s| s.expose().to_vec())
}

fn titled<'v>(vault: &'v Vault, title: &str) -> Option<&'v Item> {
    vault.items().iter().find(|i| i.title == title)
}

fn stored(reply: &Response) -> (ItemId, bool) {
    match reply {
        Response::StoredCommandOutput {
            status: StoreStatus::Stored,
            item_id: Some(id),
            item_created,
            ..
        } => (*id, *item_created),
        other => panic!("expected a stored output, got {other:?}"),
    }
}

fn not_stored(reply: &Response) -> NotStoredReason {
    match reply {
        Response::StoredCommandOutput {
            status: StoreStatus::NotStored,
            reason: Some(reason),
            item_id: None,
            ..
        } => *reason,
        other => panic!("expected nothing stored, got {other:?}"),
    }
}

#[test]
fn a_new_item_is_created_with_the_output_and_the_value_never_comes_back() {
    let fx = fixture();
    let file = secret_file(&fx, "client_secret.txt", format!("{CANARY}\n").as_bytes());
    let request = store(
        &fx,
        "/bin/cat",
        &[&file],
        new_item("Chrome Web Store API"),
        "client_secret",
    );
    let (reply, seen) = with_ui(&fx.agent, Decision::AllowOnce, || call(&fx, &request));

    let (item_id, created) = stored(&reply);
    assert!(created);
    assert!(
        !format!("{reply:?}").contains(CANARY),
        "the value came back"
    );

    // Committed, with one trailing newline removed, visible to agents so it can be bound.
    let vault = on_disk(&fx);
    assert_eq!(
        concealed(&vault, &item_id, "client_secret").as_deref(),
        Some(CANARY.as_bytes())
    );
    let item = vault.item_by_id(&item_id).expect("item");
    assert_eq!(item.title, "Chrome Web Store API");
    assert_eq!(item.category, Category::ApiCredential);
    assert!(
        item.urls.is_empty(),
        "a stored item is never an autofill target"
    );
    assert!(item.agent_visible && item.fields.iter().all(|f| f.agent_visible));
    assert_eq!(
        item.primary_secret_field().map(|f| f.label.as_str()),
        Some("client_secret")
    );

    // One sheet: the argv, the directory, the target; never presence-only, never in grace.
    assert_eq!(seen.len(), 1);
    let sheet = &seen[0];
    assert_eq!(sheet.kind, ApprovalKind::StoreCommandOutput);
    assert_eq!(sheet.command, ["/bin/cat".to_owned(), file.clone()]);
    assert!(sheet.directory.is_some());
    assert!(!sheet.presence_only && !sheet.rides_grace && !sheet.stdin_delivery);
    let facts = sheet.store_output.as_ref().expect("facts");
    assert_eq!(facts.item_title, "Chrome Web Store API");
    assert_eq!(facts.field_label, "client_secret");
    assert_eq!(facts.vault_name, "Personal");
    assert!(facts.item_id.is_none() && !facts.fills_empty_field);
    assert!(!format!("{sheet:?}").contains(CANARY));

    // Nothing minted.
    assert!(matches!(
        call(&fx, &Request::ListLeases),
        Response::Leases { leases } if leases.is_empty()
    ));

    // Audited with the agent's full identity: the run before it happened, then the write.
    let entries = audit(&fx);
    let details: Vec<&str> = entries.iter().filter_map(|e| e.detail.as_deref()).collect();
    assert!(
        details[0].starts_with("STORE_OUTPUT [\"/bin/cat\""),
        "{details:?}"
    );
    assert_eq!(details[1], "STORED");
    for entry in &entries {
        assert!(
            entry.actor.starts_with("mcp ") && entry.actor.len() > 4,
            "{}",
            entry.actor
        );
        assert!(entry.actor.contains("store-test"), "{}", entry.actor);
        assert_eq!(entry.outcome, Outcome::Allowed);
        assert!(!format!("{entry:?}").contains(CANARY));
    }
    assert_eq!(entries[1].item_id, Some(item_id));
}

#[test]
fn a_denial_stores_nothing_and_is_audited() {
    let fx = fixture();
    let before = on_disk(&fx).items().len();
    let (reply, seen) = with_ui(&fx.agent, Decision::Deny, || {
        call(&fx, &sh(&fx, "echo tok", new_item("Denied"), "token"))
    });
    assert_eq!(error_code(&reply).as_deref(), Some("USER_DENIED"));
    assert_eq!(seen.len(), 1);
    assert_eq!(on_disk(&fx).items().len(), before);
    let entries = audit(&fx);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].outcome, Outcome::Denied);
    assert!(entries[0].actor.contains("store-test"));
}

#[test]
fn every_call_asks_again_whatever_the_ui_answers() {
    let fx = fixture();
    let (_, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        stored(&call(&fx, &sh(&fx, "echo one", new_item("First"), "token")));
        stored(&call(
            &fx,
            &sh(&fx, "echo two", new_item("Second"), "token"),
        ));
    });
    assert_eq!(
        seen.len(),
        2,
        "a session answer must not cover the next store"
    );
}

#[test]
fn output_that_breaks_the_rules_stores_nothing() {
    let fx = fixture();
    let cases: [(&str, NotStoredReason); 6] = [
        ("echo tok; exit 3", NotStoredReason::ExitStatus),
        ("true", NotStoredReason::Empty),
        (
            "head -c 17000 /dev/zero | tr '\\0' a",
            NotStoredReason::TooLarge,
        ),
        ("printf 'a\\000b'", NotStoredReason::NulByte),
        ("printf 'a\\nb\\n'", NotStoredReason::MultiLine),
        ("printf '\\377\\376'", NotStoredReason::NotUtf8),
    ];
    let before = on_disk(&fx).items().len();
    with_ui(&fx.agent, Decision::AllowOnce, || {
        for (script, reason) in cases {
            let reply = call(&fx, &sh(&fx, script, new_item("Never"), "token"));
            assert_eq!(not_stored(&reply), reason, "{script}");
        }
        let mut slow = sh(&fx, "sleep 5; echo late", new_item("Never"), "token");
        if let Request::StoreCommandOutput {
            timeout_seconds, ..
        } = &mut slow
        {
            *timeout_seconds = 1;
        }
        let reply = call(&fx, &slow);
        assert_eq!(not_stored(&reply), NotStoredReason::TimedOut);
    });
    let vault = on_disk(&fx);
    assert_eq!(vault.items().len(), before);
    assert!(titled(&vault, "Never").is_none());
    let failed: Vec<String> = audit(&fx)
        .into_iter()
        .filter(|e| e.outcome == Outcome::Failed)
        .filter_map(|e| e.detail)
        .collect();
    for token in [
        "exit_status",
        "empty",
        "too_large",
        "nul_byte",
        "multi_line",
        "not_utf8",
    ] {
        assert!(
            failed.iter().any(|d| d == &format!("NOT_STORED {token}")),
            "{token}: {failed:?}"
        );
    }
}

#[test]
fn standard_error_comes_back_scrubbed_of_the_output() {
    let fx = fixture();
    let file = secret_file(&fx, "v.txt", format!("{CANARY}\n").as_bytes());
    let script = format!("cat {file}; echo \"diagnostic $(cat {file})\" >&2");
    let (reply, _) = with_ui(&fx.agent, Decision::AllowOnce, || {
        call(&fx, &sh(&fx, &script, new_item("Scrubbed"), "token"))
    });
    stored(&reply);
    let Response::StoredCommandOutput { stderr, .. } = &reply else {
        unreachable!()
    };
    assert!(
        stderr.contains("diagnostic [kagisecure:redacted:output]"),
        "{stderr}"
    );
    assert!(!stderr.contains(CANARY));
}

#[test]
fn an_existing_value_is_never_replaced_and_no_one_is_asked() {
    let fx = fixture();
    let item: ItemId = fx.item_id.parse().expect("id");
    for label in ["token", "TOKEN"] {
        let (reply, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
            call(
                &fx,
                &sh(
                    &fx,
                    "echo planted",
                    StoreTarget::Item { item_id: item },
                    label,
                ),
            )
        });
        assert_eq!(error_code(&reply).as_deref(), Some("INVALID_ARGUMENT"));
        assert!(error_message(&reply).unwrap().contains("never replaces"));
        assert!(
            seen.is_empty(),
            "nobody is asked about a write that cannot happen"
        );
    }
    assert_eq!(
        concealed(&on_disk(&fx), &item, "token").as_deref(),
        Some(MARKER.as_bytes())
    );
}

#[test]
fn a_field_is_added_to_an_existing_item_once_and_an_empty_one_is_filled() {
    let fx = fixture();
    let item: ItemId = fx.item_id.parse().expect("id");
    fx.handle
        .transact(std::time::Duration::from_secs(5), |tx| {
            let it = tx.item_by_id_mut(&item).expect("item");
            it.fields
                .push(Field::concealed("client_id", Secret::new(Vec::new())));
            Ok(())
        })
        .expect("unlocked")
        .expect("saved");

    let (replies, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        let target = || StoreTarget::Item { item_id: item };
        [
            call(&fx, &sh(&fx, "echo refresh-1", target(), "refresh_token")),
            call(&fx, &sh(&fx, "echo client-1", target(), "client_id")),
            // Now it holds a value: refused before any sheet.
            call(&fx, &sh(&fx, "echo refresh-2", target(), "refresh_token")),
        ]
    });
    assert_eq!(stored(&replies[0]), (item, false));
    assert_eq!(stored(&replies[1]), (item, false));
    assert_eq!(error_code(&replies[2]).as_deref(), Some("INVALID_ARGUMENT"));
    assert_eq!(seen.len(), 2);
    assert!(!seen[0].store_output.as_ref().unwrap().fills_empty_field);
    assert!(seen[1].store_output.as_ref().unwrap().fills_empty_field);

    let vault = on_disk(&fx);
    assert_eq!(
        concealed(&vault, &item, "refresh_token").as_deref(),
        Some(&b"refresh-1"[..])
    );
    assert_eq!(
        concealed(&vault, &item, "client_id").as_deref(),
        Some(&b"client-1"[..])
    );
    let it = vault.item_by_id(&item).unwrap();
    assert_eq!(
        it.primary_secret_field().map(|f| f.label.as_str()),
        Some("token"),
        "an added field never becomes the primary secret"
    );
    assert_eq!(
        it.fields
            .iter()
            .filter(|f| f.label == "refresh_token")
            .count(),
        1
    );
}

#[test]
fn the_autofill_password_of_an_item_with_websites_is_never_written() {
    let fx = fixture();
    let vault_id = fx.vault_id.parse().expect("vault id");
    let mut login = Item::new(vault_id, Category::Login, "Bank");
    login.urls = vec!["https://bank.example".to_owned()];
    login.fields.push(Field::public("username", "me"));
    login.agent_visible = true;
    login.set_agent_visible_all(true);
    let login_id = login.id;
    fx.handle
        .transact(std::time::Duration::from_secs(5), |tx| {
            tx.add_item(login);
            Ok(())
        })
        .expect("unlocked")
        .expect("saved");
    let (reply, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        call(
            &fx,
            &sh(
                &fx,
                "echo planted",
                StoreTarget::Item { item_id: login_id },
                "password",
            ),
        )
    });
    assert_eq!(error_code(&reply).as_deref(), Some("INVALID_ARGUMENT"));
    assert!(seen.is_empty());
    assert!(concealed(&on_disk(&fx), &login_id, "password").is_none());
}

#[test]
fn a_stdin_environment_reaches_the_command_as_the_frame_under_the_same_sheet() {
    let fx = fixture();
    let project = fx.canonical_project();
    let mut request = sh(
        &fx,
        "tee stdin.bin >&2; echo from-stdin-run",
        new_item("Refresh"),
        "refresh_token",
    );
    if let Request::StoreCommandOutput {
        stdin_environment, ..
    } = &mut request
    {
        *stdin_environment = Some(StdinEnvironment {
            environment_id: fx.env_id.parse().expect("env id"),
            variables: Some(vec!["TOKEN".to_owned()]),
        });
    }
    let (reply, seen) = with_ui(&fx.agent, allow_session(900, 10), || call(&fx, &request));
    let (item_id, _) = stored(&reply);
    assert_eq!(
        std::fs::read(project.join("stdin.bin")).expect("frame"),
        format!("TOKEN\0{MARKER}\0").as_bytes()
    );
    assert_eq!(
        concealed(&on_disk(&fx), &item_id, "refresh_token").as_deref(),
        Some(&b"from-stdin-run"[..])
    );
    // The injected value is scrubbed from the standard error that comes back.
    assert!(!format!("{reply:?}").contains(MARKER));

    assert_eq!(seen.len(), 1, "one sheet covers the values and the write");
    let sheet = &seen[0];
    assert_eq!(sheet.kind, ApprovalKind::StoreCommandOutput);
    assert!(sheet.stdin_delivery);
    assert_eq!(sheet.variables, ["TOKEN"]);
    assert_eq!(sheet.environment_name.as_deref(), Some("acme / staging"));
    assert!(!format!("{sheet:?}").contains(MARKER));
    assert!(matches!(
        call(&fx, &Request::ListLeases),
        Response::Leases { leases } if leases.is_empty()
    ));
    let first = &audit(&fx)[0];
    assert_eq!(first.variables, ["TOKEN"]);
    assert!(first.environment_id.is_some());
}

#[test]
fn bad_arguments_are_refused_before_anyone_is_asked() {
    let fx = fixture();
    let (replies, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        [
            call(&fx, &sh(&fx, "echo x", new_item("T"), "")),
            call(&fx, &sh(&fx, "echo x", new_item("T"), "two\nlines")),
            call(&fx, &sh(&fx, "echo x", new_item(""), "token")),
            call(
                &fx,
                &sh(
                    &fx,
                    "echo x",
                    StoreTarget::NewItem {
                        title: "T".to_owned(),
                        category: Some("login".to_owned()),
                        vault_id: None,
                    },
                    "token",
                ),
            ),
            call(
                &fx,
                &sh(
                    &fx,
                    "echo x",
                    StoreTarget::Item {
                        item_id: ItemId::new(),
                    },
                    "token",
                ),
            ),
        ]
    });
    for reply in &replies[..4] {
        assert_eq!(
            error_code(reply).as_deref(),
            Some("INVALID_ARGUMENT"),
            "{reply:?}"
        );
    }
    assert_eq!(error_code(&replies[4]).as_deref(), Some("NOT_FOUND"));
    assert!(seen.is_empty());
}

// -------------------------------------------------------------------------------------------------
// The sidecar canary sweep
// -------------------------------------------------------------------------------------------------

fn sidecar() -> PathBuf {
    kagisecure_test_support::binary("kagisecure-mcp", kagisecure_agent::bundle::SIDECAR)
}

/// A minimal JSON-RPC driver over the real sidecar's stdio, keeping every byte it wrote.
struct RawSidecar {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
    seen_stdout: Vec<u8>,
    next_id: u64,
}

impl RawSidecar {
    fn start(endpoint: &kagisecure_ipc::Endpoint) -> Self {
        let mut child = Command::new(sidecar())
            .env("KAGISECURE_SOCKET", endpoint.as_override())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawning kagisecure-mcp");
        let stdout = BufReader::new(child.stdout.take().expect("piped"));
        let mut this = Self {
            child,
            stdout,
            seen_stdout: Vec::new(),
            next_id: 0,
        };
        this.call(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "example-agent", "version": "0"}
            }),
        );
        let stdin = this.child.stdin.as_mut().expect("piped");
        writeln!(
            stdin,
            "{}",
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
        )
        .expect("write");
        this
    }

    fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.next_id += 1;
        let id = self.next_id;
        let stdin = self.child.stdin.as_mut().expect("piped");
        writeln!(
            stdin,
            "{}",
            serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
        )
        .expect("write");
        stdin.flush().expect("flush");
        loop {
            let mut line = String::new();
            let read = self.stdout.read_line(&mut line).expect("read");
            assert!(read > 0, "the sidecar closed its stdout");
            self.seen_stdout.extend_from_slice(line.as_bytes());
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            if value.get("id").and_then(serde_json::Value::as_u64) == Some(id) {
                return value;
            }
        }
    }

    fn tool(&mut self, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        self.call(
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
        )
    }

    fn finish(mut self) -> (Vec<u8>, Vec<u8>) {
        drop(self.child.stdin.take());
        let mut rest = Vec::new();
        let _ = self.stdout.read_to_end(&mut rest);
        self.seen_stdout.extend_from_slice(&rest);
        let mut stderr = Vec::new();
        if let Some(mut handle) = self.child.stderr.take() {
            let _ = handle.read_to_end(&mut stderr);
        }
        let _ = self.child.wait();
        (self.seen_stdout, stderr)
    }
}

fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, index) in [n >> 18, (n >> 12) & 0x3f, (n >> 6) & 0x3f, n & 0x3f]
            .iter()
            .enumerate()
        {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[*index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn hex(bytes: &[u8], upper: bool) -> String {
    bytes
        .iter()
        .map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect()
}

fn percent_encoded(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                char::from(*b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// The six forms `test_login_sidecar.rs` sweeps, named so a failure says which leaked.
fn assert_nowhere(haystack: &str, secret: &str, context: &str) {
    let bytes = secret.as_bytes();
    for (kind, form) in [
        ("raw", secret.to_owned()),
        ("base64", base64_standard(bytes)),
        ("lowercase hex", hex(bytes, false)),
        ("uppercase hex", hex(bytes, true)),
        ("percent-encoded", percent_encoded(bytes)),
        (
            "JSON-escaped",
            serde_json::to_string(secret)
                .unwrap()
                .trim_matches('"')
                .to_owned(),
        ),
    ] {
        assert!(
            !haystack.contains(&form),
            "the value's {kind} form reached {context}"
        );
    }
}

fn file_arg(path: &Path) -> String {
    path.display().to_string()
}

#[test]
fn the_stored_value_reaches_no_byte_the_sidecar_writes() {
    let fx = fixture();
    let good = fx.canonical_project().join("good.txt");
    std::fs::write(&good, format!("{CANARY}\n")).expect("write");
    let two_lines = fx.canonical_project().join("two.txt");
    std::fs::write(&two_lines, format!("{CANARY}\n{CANARY}\n")).expect("write");
    let cwd = file_arg(&fx.canonical_project());

    let ((stdout, stderr, item_id), _) = with_ui(&fx.agent, Decision::AllowOnce, || {
        let mut sidecar = RawSidecar::start(&fx.endpoint);
        let ok = sidecar.tool(
            "store_command_output",
            serde_json::json!({
                "command": "/bin/cat",
                "args": [file_arg(&good)],
                "cwd": cwd,
                "new_item": {"title": "Chrome Web Store API"},
                "field_label": "client_secret",
            }),
        );
        let body = &ok["result"]["structuredContent"];
        assert_eq!(body["status"], "stored", "{ok}");
        assert_eq!(body["item_created"], true);
        assert!(body.get("bytes").is_none() && body.get("length").is_none());
        let item_id = body["item_id"].as_str().expect("item id").to_owned();

        // Refused output, with the value on standard error as well.
        let refused = sidecar.tool(
            "store_command_output",
            serde_json::json!({
                "command": "/bin/sh",
                "args": ["-c", format!("cat {0}; cat {0} >&2", file_arg(&two_lines))],
                "cwd": cwd,
                "new_item": {"title": "Never"},
                "field_label": "token",
            }),
        );
        let body = &refused["result"]["structuredContent"];
        assert_eq!(body["status"], "not_stored", "{refused}");
        assert_eq!(body["reason"], "multi_line");

        let (stdout, stderr) = sidecar.finish();
        (stdout, stderr, item_id)
    });

    // It happened: the value is in the vault.
    let item: ItemId = item_id.parse().expect("id");
    assert_eq!(
        concealed(&on_disk(&fx), &item, "client_secret").as_deref(),
        Some(CANARY.as_bytes())
    );
    assert_nowhere(
        &String::from_utf8_lossy(&stdout),
        CANARY,
        "the sidecar's stdout",
    );
    assert_nowhere(
        &String::from_utf8_lossy(&stderr),
        CANARY,
        "the sidecar's stderr",
    );
    let audit_text = audit(&fx)
        .iter()
        .map(|e| serde_json::to_string(e).expect("serializes"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_nowhere(&audit_text, CANARY, "the audit log");
    assert!(audit_text.contains("example-agent"), "the agent is named");
}
