//! The ADR-0048 canary: a test login's generated password reaches no byte the sidecar writes —
//! not on create, not in the listing, not when a fill of it succeeds — and no audit text or
//! notice either (§6, "no tool returns the password, in any encoding, under any argument").
//!
//! Modelled on `agent_fill_sidecar.rs`: a real `kagisecure-mcp` process, speaking MCP over its own
//! stdio, talking to the library-hosted [`Agent`] and [`ExtensionAgent`], with a fake service
//! worker on the real extension socket. The password is generated inside the vault and returned by
//! no tool, so the test reads it the only way there is: from the vault file, with the vault's own
//! password, after the create committed. It first proves the fill *happened* (the extension's
//! `Filled` reply carries that password) and only then sweeps every byte the sidecar wrote, every
//! audit entry and every notice for it, in the six encodings `agent_fill_sidecar.rs` sweeps.

mod agent_fill_support;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use agent_fill_support::{Fixture, Human, OnDeliver, PAGE, ServiceWorker, Tab, fixture};
use kagisecure_core::model::TestLoginPolicy;
use kagisecure_core::proto::ItemId;
use kagisecure_core::vault::Vault;
use kagisecure_extension_ipc::protocol::Response as ExtResponse;

/// The sidecar binary, built on demand — see `kagisecure_test_support::binary` for why this goes
/// through a shared helper rather than a hardcoded `target/debug`.
fn sidecar() -> PathBuf {
    kagisecure_test_support::binary("kagisecure-mcp", kagisecure_agent::bundle::SIDECAR)
}

/// A minimal JSON-RPC driver over the real sidecar's stdio, keeping every byte of stdout it wrote
/// and, once it exits, of stderr too.
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
        this.notify("notifications/initialized");
        this
    }

    fn send(&mut self, value: &serde_json::Value) {
        let stdin = self.child.stdin.as_mut().expect("piped");
        writeln!(stdin, "{value}").expect("writing to the sidecar");
        stdin.flush().expect("flush");
    }

    fn notify(&mut self, method: &str) {
        self.send(&serde_json::json!({"jsonrpc": "2.0", "method": method}));
    }

    fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        }));
        loop {
            let mut line = String::new();
            let read = self
                .stdout
                .read_line(&mut line)
                .expect("reading the sidecar");
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

    /// Close stdin — which ends the sidecar's stdio transport — and return every byte it ever
    /// wrote to stdout and to stderr.
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

fn structured(reply: &serde_json::Value) -> &serde_json::Value {
    &reply["result"]["structuredContent"]
}

fn is_error(reply: &serde_json::Value) -> bool {
    reply["result"]["isError"].as_bool().unwrap_or(false)
}

// -------------------------------------------------------------------------------------------------
// The encoded-forms sweep
// -------------------------------------------------------------------------------------------------
//
// `kagisecure_core::inject::mask` widens its own needle set the same way, for the same reason: a
// value can reach a log line through a base64 dump, a hex dump, or a URL quoter without anyone
// meaning to leak it. Reimplemented here, tiny and self-contained, because those encoders are
// private to that crate and this suite must not gain a dependency just to call them.

/// Standard, padded Base64 of `bytes`.
fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let indices = [n >> 18, (n >> 12) & 0x3f, (n >> 6) & 0x3f, n & 0x3f];
        for (i, index) in indices.iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[*index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Hex of `bytes`, upper or lower case.
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

/// Percent-encoding of `bytes`, escaping everything outside the unreserved set.
fn percent_encoded(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(*byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Every byte-string form of `marker` a log line or a debugger could have produced without
/// meaning to: the raw value, its Base64, its hex in both cases, its percent-encoding, and the
/// body of its JSON string encoding. Named, not valued, in the pairs a caller iterates so that a
/// failing assertion can say *which* encoding leaked without printing the marker itself.
fn encoded_forms(marker: &str) -> Vec<(&'static str, String)> {
    let bytes = marker.as_bytes();
    let quoted = serde_json::to_string(marker).expect("a string always serializes");
    let json_escaped = quoted
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .expect("serde_json quotes a string")
        .to_owned();
    vec![
        ("raw", marker.to_owned()),
        ("base64", base64_standard(bytes)),
        ("lowercase hex", hex(bytes, false)),
        ("uppercase hex", hex(bytes, true)),
        ("percent-encoded", percent_encoded(bytes)),
        ("JSON-escaped", json_escaped),
    ]
}

/// [`assert_marker_nowhere`] for any secret, named `what` in the message instead of quoted.
fn assert_secret_nowhere(haystack: &str, secret: &str, what: &str, context: &str) {
    for (kind, form) in encoded_forms(secret) {
        assert!(
            !haystack.contains(form.as_str()),
            "the {what}'s {kind} form reached {context}"
        );
    }
}

/// Every audit entry, concatenated as the JSON it would be read back as, for the sweep above.
fn audit_text(fx: &Fixture) -> String {
    fx.on_disk()
        .iter()
        .map(|e| serde_json::to_string(e).expect("an audit entry serializes"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The generated password of `item`, read from the vault file — the test's own access, not any
/// tool's.
fn generated_password(fx: &Fixture, item: &str) -> String {
    let vault = Vault::open_with_password(fx.path(), b"pw").expect("open");
    let item = vault
        .item_by_id(&item.parse::<ItemId>().expect("an id"))
        .expect("the test login");
    assert!(vault.test_login_sealed(item));
    item.primary_secret_field()
        .and_then(|f| f.value.as_secret())
        .and_then(|s| s.expose_str())
        .expect("a generated password")
        .to_owned()
}

#[test]
fn a_test_logins_password_reaches_no_byte_the_sidecar_writes_and_no_log_or_notice() {
    let fx = fixture();
    fx.handle
        .transact(Duration::from_secs(5), |tx| {
            tx.ensure_agent_test_vault("test")?;
            tx.set_test_login_policy(
                TestLoginPolicy {
                    enabled: true,
                    auto_domains: vec!["example.com".to_owned()],
                    unknown: BTreeMap::new(),
                },
                "test",
            )
        })
        .expect("unlocked")
        .expect("policy");
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    let mut mcp = RawSidecar::start(&fx.agent_endpoint);

    let created = mcp.tool(
        "create_test_login",
        serde_json::json!({
            "app": "shop",
            "purpose": "buyer",
            "username": "alice@example.test",
            "websites": [PAGE],
            "generator": {"length": 48, "symbols": true},
        }),
    );
    assert!(!is_error(&created), "{created}");
    assert_eq!(structured(&created)["status"], "created", "{created}");
    let item = structured(&created)["item_id"]
        .as_str()
        .expect("an item id")
        .to_owned();
    let mut keys: Vec<String> = structured(&created)
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    assert_eq!(keys, ["item_id", "status", "title", "username", "websites"]);
    let password = generated_password(&fx, &item);
    assert_eq!(password.len(), 48);

    let listed = mcp.tool("list_test_logins", serde_json::json!({"tag": "app:shop"}));
    assert!(!is_error(&listed), "{listed}");
    assert_eq!(structured(&listed)["items"][0]["item_id"], item.as_str());

    let described = mcp.tool("describe_item", serde_json::json!({"item_id": item}));
    assert!(!is_error(&described), "{described}");

    let filled = mcp.tool(
        "request_fill",
        serde_json::json!({"item_id": item, "origin": PAGE, "fields": ["username", "password"]}),
    );
    assert!(!is_error(&filled), "{filled}");
    assert_eq!(
        human.sheets(),
        0,
        "a sealed test login at an allowed origin"
    );

    // Proof the password crossed — to the extension, in the one reply that carries a value.
    let fills = sw.fills_at_least(1);
    match &fills[..] {
        [
            ExtResponse::Filled {
                password: Some(value),
                ..
            },
        ] => assert_eq!(value.expose(), password),
        other => panic!("expected one fill, got {other:?}"),
    }

    let notices = format!("{:?}", fx.test_logins.take_notices());
    assert!(notices.contains("test: shop / buyer #1"), "{notices}");
    let (stdout, stderr) = mcp.finish();
    for (haystack, context) in [
        (
            String::from_utf8_lossy(&stdout).into_owned(),
            "the sidecar's stdout",
        ),
        (
            String::from_utf8_lossy(&stderr).into_owned(),
            "the sidecar's stderr",
        ),
        (audit_text(&fx), "the audit log"),
        (notices, "the notices"),
    ] {
        assert_secret_nowhere(&haystack, &password, "generated password", context);
    }

    drop(human);
    drop(sw);
    drop(fx.dir);
}
