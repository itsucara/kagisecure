//! The ADR-0036 canary: a **successful** agent fill still leaves the marker in no byte the
//! sidecar writes (§8.2, "the canary sweep gains `request_fill` — including a sweep in which the
//! fill *succeeds* and the marker must still appear in no byte the sidecar writes").
//!
//! `crates/kagisecure-agent/tests/sidecar.rs` proves the app-hosted-agent shape for
//! `write_env_file`, and `crates/kagisecure-agent/tests/agent_fill.rs` proves the broker's gates
//! against a raw IPC client standing in for the sidecar. This file combines both: a real
//! `kagisecure-mcp` process, speaking MCP over its own stdio, talking to the library-hosted
//! [`Agent`] and [`ExtensionAgent`] that share one [`AgentFillBroker`], with a fake service worker
//! (a real duplex client on the real extension socket) playing the browser side. `request_fill`'s
//! whole point is that the value crosses to the extension, never to the agent — so the test first
//! proves the fill *happened* (the extension's `Filled` reply carries the marker) and only then
//! sweeps every byte the sidecar itself wrote or recorded for the marker, in every encoding a log
//! line or a debugger might have produced it in without meaning to leak it (mirroring
//! `kagisecure_core::inject`'s masking net: the raw value, its Base64, its hex in both cases, its
//! percent-encoding, and its JSON-escaped form).

mod agent_fill_support;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use agent_fill_support::{
    CODE_SEED_B32, Fixture, Human, MARKER, OnDeliver, PAGE, Seen, ServiceWorker, Tab, fixture,
};
use kagisecure_core::proto::Outcome;
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

/// Assert none of `MARKER`'s encoded forms occur anywhere in `haystack`, which came from
/// `context`. The panic message never repeats the marker in any of its forms — only which
/// encoding it was found in — so a failure does not itself become a second leak.
fn assert_marker_nowhere(haystack: &str, context: &str) {
    assert_secret_nowhere(haystack, MARKER, "marker", context);
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

#[test]
fn a_successful_agent_fill_leaves_the_marker_in_no_byte_the_sidecar_writes() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    let mut mcp = RawSidecar::start(&fx.agent_endpoint);

    let reply = mcp.tool(
        "request_fill",
        serde_json::json!({
            "item_id": fx.item,
            "origin": PAGE,
            "fields": ["username", "password"],
        }),
    );
    assert!(!is_error(&reply), "the fill should have succeeded: {reply}");
    assert_eq!(
        structured(&reply)["fields_written"],
        serde_json::json!(["username", "password"]),
        "{reply}"
    );
    assert_eq!(
        structured(&reply)["fields_pending"],
        serde_json::json!([]),
        "{reply}"
    );

    // Proof the fill actually happened, not merely that it was approved: the extension's side of
    // the duplex client received the value, in the one reply that has always carried it.
    let fills = sw.fills_at_least(1);
    assert_eq!(fills.len(), 1, "{fills:?}");
    match &fills[0] {
        ExtResponse::Filled {
            item_id,
            username,
            password,
            ..
        } => {
            assert_eq!(item_id, &fx.item);
            assert_eq!(username.as_deref(), Some("alice"));
            assert_eq!(password.as_ref().map(|p| p.expose()), Some(MARKER));
        }
        other => panic!("expected the extension to be told about a fill, got {other:?}"),
    }

    // One approval, recorded before the release, naming the agent — none of it a value.
    let entries = fx.on_disk();
    let approved = entries
        .iter()
        .find(|e| e.tool == "request_fill" && e.outcome == Outcome::Allowed)
        .expect("an Allowed entry");
    assert_eq!(approved.detail.as_deref(), Some("AGENT_FILL_APPROVED"));

    // Not one byte of the marker, in any of the forms a log or a debugger might carry it in,
    // reached the sidecar's own streams or the audit log — even though the fill succeeded.
    let (stdout, stderr) = mcp.finish();
    assert_marker_nowhere(&String::from_utf8_lossy(&stdout), "the sidecar's stdout");
    assert_marker_nowhere(&String::from_utf8_lossy(&stderr), "the sidecar's stderr");
    assert_marker_nowhere(&audit_text(&fx), "the audit log");

    drop(human);
    drop(sw);
    drop(fx.dir);
}

#[test]
fn a_denied_agent_fill_leaves_the_marker_in_no_byte_anywhere() {
    let fx = fixture();
    let human = Human::denying(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    let mut mcp = RawSidecar::start(&fx.agent_endpoint);

    let reply = mcp.tool(
        "request_fill",
        serde_json::json!({
            "item_id": fx.item,
            "origin": PAGE,
            "fields": ["username", "password"],
        }),
    );
    assert!(is_error(&reply), "a denial is a tool-level error: {reply}");
    assert_eq!(structured(&reply)["code"], "USER_DENIED", "{reply}");

    // The human said no before delivery, so the extension was never even asked to redeem a grant,
    // and it never got a value.
    assert!(
        !sw.seen().iter().any(|s| matches!(s, Seen::Deliver { .. })),
        "nothing should be delivered after a denial: {:?}",
        sw.seen()
    );
    assert!(
        sw.fills().is_empty(),
        "the extension must never receive a value for a denied request"
    );

    let entries = fx.on_disk();
    assert!(
        entries
            .iter()
            .any(|e| e.tool == "request_fill" && e.outcome == Outcome::Denied),
        "the denial must be audited"
    );

    let (stdout, stderr) = mcp.finish();
    assert_marker_nowhere(&String::from_utf8_lossy(&stdout), "the sidecar's stdout");
    assert_marker_nowhere(&String::from_utf8_lossy(&stderr), "the sidecar's stderr");
    assert_marker_nowhere(&audit_text(&fx), "the audit log");

    drop(human);
    drop(sw);
    drop(fx.dir);
}

#[test]
fn a_successful_two_step_fill_leaves_the_marker_in_no_byte_the_sidecar_writes() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::identifier_only(PAGE), OnDeliver::Redeem);
    let mut mcp = RawSidecar::start(&fx.agent_endpoint);

    // Page one: the username now, the password pending.
    let first = mcp.tool(
        "request_fill",
        serde_json::json!({"item_id": fx.item, "origin": PAGE, "fields": ["username", "password"]}),
    );
    assert!(!is_error(&first), "{first}");
    assert_eq!(
        structured(&first)["fields_written"],
        serde_json::json!(["username"])
    );
    assert_eq!(
        structured(&first)["fields_pending"],
        serde_json::json!(["password"])
    );

    // Page two, from the same sidecar process: no second sheet, and the password lands.
    sw.set(Tab::next_page(PAGE), OnDeliver::Redeem);
    let second = mcp.tool(
        "request_fill",
        serde_json::json!({"item_id": fx.item, "origin": PAGE, "fields": ["password"]}),
    );
    assert!(!is_error(&second), "{second}");
    assert_eq!(
        structured(&second)["fields_written"],
        serde_json::json!(["password"])
    );
    assert_eq!(structured(&second)["fields_pending"], serde_json::json!([]));
    assert_eq!(human.sheets(), 1, "one approval for both pages");

    // Proof the password crossed — to the extension.
    let fills = sw.fills_at_least(1);
    match &fills[..] {
        [
            ExtResponse::Filled {
                password: Some(password),
                ..
            },
        ] => assert_eq!(password.expose(), MARKER),
        other => panic!("expected the password on page two, got {other:?}"),
    }

    let (stdout, stderr) = mcp.finish();
    assert_marker_nowhere(&String::from_utf8_lossy(&stdout), "the sidecar's stdout");
    assert_marker_nowhere(&String::from_utf8_lossy(&stderr), "the sidecar's stderr");
    assert_marker_nowhere(&audit_text(&fx), "the audit log");

    drop(human);
    drop(sw);
    drop(fx.dir);
}

#[test]
fn a_successful_code_fill_leaves_the_code_and_its_seed_in_no_byte_the_sidecar_writes() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::code(PAGE), OnDeliver::Redeem);
    let mut mcp = RawSidecar::start(&fx.agent_endpoint);

    let reply = mcp.tool(
        "request_fill",
        serde_json::json!({"item_id": fx.with_code, "origin": PAGE, "fields": ["one_time_code"]}),
    );
    assert!(
        !is_error(&reply),
        "the code fill should have succeeded: {reply}"
    );
    assert_eq!(
        structured(&reply)["fields_written"],
        serde_json::json!(["one_time_code"])
    );

    // Proof a code crossed — to the extension, in its `totp_code` reply.
    let fills = sw.fills_at_least(1);
    let code = match &fills[..] {
        [ExtResponse::TotpCode { code, .. }] => code.expose().to_owned(),
        other => panic!("expected a code for the extension, got {other:?}"),
    };
    assert_eq!(code.len(), 8, "an eight-digit code");

    let (stdout, stderr) = mcp.finish();
    let audit = audit_text(&fx);
    for (secret, what) in [
        (code.as_str(), "code"),
        (CODE_SEED_B32, "seed"),
        (MARKER, "marker"),
    ] {
        assert_secret_nowhere(
            &String::from_utf8_lossy(&stdout),
            secret,
            what,
            "the sidecar's stdout",
        );
        assert_secret_nowhere(
            &String::from_utf8_lossy(&stderr),
            secret,
            what,
            "the sidecar's stderr",
        );
        assert_secret_nowhere(&audit, secret, what, "the audit log");
    }

    drop(human);
    drop(sw);
    drop(fx.dir);
}
