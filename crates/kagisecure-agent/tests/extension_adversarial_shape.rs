//! Adversarial: the shape of what comes back, and the bytes that must never be in it.
//!
//! `extension.rs` guards the response shape with a `debug_assert!` on
//! `Response::carries_only`, which is compiled out of a release build. So the question this file
//! asks is not "does the assertion fire" but "**is the assertion load-bearing**": if the only
//! thing keeping a password out of a `["username"]` answer were a debug assertion, a shipped
//! build would leak. These tests therefore make their assertions on the serialized JSON the
//! browser would actually receive, and the suite is meant to be run under `--release` as well as
//! under `--test`.
//!
//! The second half is a canary sweep. One 32-byte marker is seeded as the login's password, and
//! every request shape this protocol admits — including several that are not valid requests at
//! all — is driven at the real listener over a real socket. The marker must appear in exactly one
//! place in the world: the single approved `Filled` reply. Not in an audit entry, not in an error
//! message, not in a `Matches` answer, not on any diagnostic stream.
//!
//! Requests are written as raw frames on a `UnixStream` rather than through
//! [`kagisecure_extension_ipc::Client`], because the interesting inputs — a wrong-case field
//! name, a duplicated one, a field that does not exist — cannot be expressed in the typed
//! `Request` at all. The framing itself is the crate's own [`kagisecure_extension_ipc::frame`],
//! so nothing below the JSON body is being faked.
//!
//! That is also why this file is Unix-only. TODO(windows): the same suite over a named pipe
//! needs a handle `frame::write` will accept — `OpenOptions` on the pipe path is the cheap
//! version — which is a rewrite of the harness rather than a `cfg`, and wants a machine that can
//! run it.

#![cfg(unix)]

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kagisecure_agent::approval::{
    APPROVAL_TIMEOUT_SECONDS, ApprovalQueue, ClientVerification, Decision,
};
use kagisecure_agent::extension::audit_detail;
use kagisecure_agent::{Endpoint, ExtensionAgent, ExtensionConfig, VaultHandle};
use kagisecure_core::model::{Field, Item, Secret};
use kagisecure_core::proto::Category;
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_extension_ipc::PINNED_EXTENSION_IDS;
use kagisecure_extension_ipc::frame;
use serde_json::{Value, json};

/// The one value in this vault that must never appear anywhere but a single approved reply.
const PASSWORD_CANARY: &str = "SH4PE-PW-C4N4RY-0b7d3f1a95e2c684";

/// A second canary on an item at a *different* origin, so that a leak through the wrong item is
/// distinguishable from a leak through the wrong field.
const ELSEWHERE_CANARY: &str = "SH4PE-ELSEWHERE-C4N4RY-42a9d0c7";

const SITE: &str = "https://shape.example";
const ELSEWHERE: &str = "https://elsewhere.example";

/// How many items are seeded at [`SITE`]; [`B-20`]'s sweep multiplies by this.
const ITEMS_AT_SITE: usize = 3;

/// How many username-only fills the sweep drives. ADR-0030 says every one of them is audited and
/// none of them carries a password; a thousand is enough that a leak on one path in a hundred
/// would be caught.
const SWEEP_FILLS: usize = 1000;

struct Fixture {
    _dir: tempfile::TempDir,
    handle: Arc<VaultHandle>,
    _agent: ExtensionAgent,
    queue: Arc<ApprovalQueue>,
    socket: PathBuf,
    /// Every item saved at [`SITE`], in creation order. All have a username and a password.
    item_ids: Vec<String>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("test.kagivault");

    let mut options = CreateOptions::new().expect("options");
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
        kagisecure_core::crypto::kdf::MIN_M_KIB,
        kagisecure_core::crypto::kdf::MIN_T,
        1,
    )
    .expect("kdf");
    options.vault_name = "Personal".to_owned();
    let (mut vault, _code) = Vault::create(&vault_path, b"pw", &options).expect("create");
    let vault_id = vault.default_vault_id().expect("default vault");

    let mut items = Vec::new();
    let mut item_ids = Vec::new();
    for index in 0..ITEMS_AT_SITE {
        let mut item = Item::new(vault_id, Category::Login, format!("Shape site {index}"));
        item.urls = vec![SITE.to_owned()];
        item.fields
            .push(Field::public("username", format!("user{index}")));
        item.fields.push(Field::concealed(
            "password",
            // Every item carries the same canary, so "no value crossed" is one string to search
            // for however many items the sweep walks.
            Secret::from_string(PASSWORD_CANARY.to_owned()),
        ));
        item_ids.push(item.id.to_string());
        items.push(item);
    }

    let mut elsewhere = Item::new(vault_id, Category::Login, "Somewhere else");
    elsewhere.urls = vec![ELSEWHERE.to_owned()];
    elsewhere.fields.push(Field::public("username", "nobody"));
    elsewhere.fields.push(Field::concealed(
        "password",
        Secret::from_string(ELSEWHERE_CANARY.to_owned()),
    ));

    vault
        .transact(|tx| {
            for item in items {
                tx.add_item(item);
            }
            tx.add_item(elsewhere);
            Ok(())
        })
        .expect("save");

    let socket = dir.path().join("extension.sock");
    let handle = VaultHandle::new(vault);
    let queue = Arc::new(ApprovalQueue::new());
    let agent = ExtensionAgent::start(
        Arc::clone(&handle),
        ExtensionConfig {
            // `#![cfg(unix)]` at the top of this file: it speaks `UnixStream` directly, so a
            // filesystem socket is the right endpoint here by construction.
            endpoint: Some(Endpoint::Path(socket.clone())),
            auto_approve: false,
            allow_unlaunched_host: true,
            ..ExtensionConfig::new(Arc::clone(&queue))
        },
    )
    .expect("extension agent");

    Fixture {
        _dir: dir,
        handle,
        _agent: agent,
        queue,
        socket,
        item_ids,
    }
}

/// Answer every approval with "allow for this session" until dropped.
struct Human {
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Human {
    fn approving(queue: &Arc<ApprovalQueue>) -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let queue = Arc::clone(queue);
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                let Some(request) = queue.next(Duration::from_millis(50)) else {
                    continue;
                };
                queue.resolve(
                    &request.id,
                    &Decision::AllowSession {
                        ttl_seconds: 300,
                        uses: 1,
                    },
                    ClientVerification {
                        verified: false,
                        evidence: "answered by the test's stand-in human".to_owned(),
                    },
                );
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Human {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A connection that speaks the app socket's own framing over raw JSON.
///
/// The point of going under the typed `Request` is that the attacks here are exactly the messages
/// the type system forbids: a field name that is not a variant, one that differs only in case,
/// the same one twice, and an empty list.
struct RawExtension {
    stream: UnixStream,
    next_id: u64,
}

impl RawExtension {
    fn connect(socket: &std::path::Path) -> Self {
        let stream = UnixStream::connect(socket).expect("connect to the extension socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(90)))
            .expect("read timeout");
        let mut this = Self { stream, next_id: 0 };
        let welcome = this.send(json!({
            "ask": "hello",
            "extension_id": PINNED_EXTENSION_IDS[0],
            "browser": "chrome",
            "extension_version": "0.1.0",
            "protocol_version": kagisecure_extension_ipc::PROTOCOL_VERSION,
        }));
        assert_eq!(
            welcome["reply"], "welcome",
            "the pinned extension id should be welcomed: {welcome}"
        );
        this
    }

    /// Send one request body and return the reply body as raw JSON.
    ///
    /// Panics if the app answered nothing, which is the right default for a request the app is
    /// expected to be able to read.
    fn send(&mut self, body: Value) -> Value {
        self.send_or_closed(body)
            .expect("the app closed the connection instead of answering")
    }

    /// Send one request body; `None` means the app closed the connection without a reply.
    ///
    /// A body the app cannot deserialize takes this branch, which is exactly what two of the
    /// tests below are about — so it has to be observable rather than a panic.
    fn send_or_closed(&mut self, body: Value) -> Option<Value> {
        self.next_id += 1;
        let id = format!("shape-{}", self.next_id);
        frame::write(
            &mut self.stream,
            &json!({ "ksx": 1, "id": id, "body": body }),
        )
        .ok()?;
        let reply: Value = frame::read(&mut self.stream).ok()?;
        assert_eq!(reply["id"], Value::String(id), "replies must correlate");
        Some(reply["body"].clone())
    }

    fn fill(&mut self, item_id: &str, fields: Value) -> Value {
        self.send(json!({
            "ask": "fill",
            "page": { "top_origin": SITE },
            "item_id": item_id,
            "fields": fields,
        }))
    }

    /// A fill whose reply may not arrive at all.
    fn fill_or_closed(&mut self, item_id: &str, fields: Value) -> Option<Value> {
        self.send_or_closed(json!({
            "ask": "fill",
            "page": { "top_origin": SITE },
            "item_id": item_id,
            "fields": fields,
        }))
    }
}

/// Every field list that is not a valid `Vec<FillField>` on the wire.
///
/// Wrong case, padded, unknown, and wrong-typed. None of them may produce a fill.
fn unparseable_field_lists() -> Vec<Value> {
    vec![
        json!(["Password"]),
        json!(["PASSWORD"]),
        json!(["Username"]),
        json!([" password"]),
        json!(["password "]),
        json!(["totp"]),
        json!(["secret"]),
        json!(["password", "totp"]),
        json!(["username", "recovery_code"]),
        json!([""]),
        json!([null]),
        json!([42]),
        json!(["password", "password", "everything"]),
    ]
}

fn audit_json(fixture: &Fixture) -> String {
    let entries = fixture
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .unwrap_or_default();
    serde_json::to_string(&entries).expect("audit json")
}

// ---------------------------------------------------------------------------
// B-22: the response carries exactly the approved fields, with no debug assertion helping.
// ---------------------------------------------------------------------------

#[test]
fn a_username_only_request_carries_no_password_in_the_bytes_on_the_wire() {
    let fixture = fixture();
    let _human = Human::approving(&fixture.queue);
    let mut extension = RawExtension::connect(&fixture.socket);

    let reply = extension.fill(&fixture.item_ids[0], json!(["username"]));
    assert_eq!(reply["reply"], "filled", "{reply}");
    assert_eq!(reply["username"], "user0");
    assert!(
        reply["password"].is_null(),
        "a username-only fill must not carry a password: {reply}"
    );

    // The assertion that survives `--release`: search the serialized bytes, not the typed value.
    let bytes = serde_json::to_string(&reply).expect("json");
    assert!(
        !bytes.contains(PASSWORD_CANARY),
        "the password reached the browser through a request that did not ask for it: {bytes}"
    );

    // And the converse, so the test cannot pass by the fill having silently failed.
    let both = extension.fill(&fixture.item_ids[0], json!(["username", "password"]));
    assert_eq!(both["password"], PASSWORD_CANARY, "{both}");
}

#[test]
fn a_password_only_request_carries_no_username() {
    let fixture = fixture();
    let _human = Human::approving(&fixture.queue);
    let mut extension = RawExtension::connect(&fixture.socket);

    let reply = extension.fill(&fixture.item_ids[0], json!(["password"]));
    assert_eq!(reply["reply"], "filled", "{reply}");
    assert_eq!(reply["password"], PASSWORD_CANARY);
    assert!(
        reply["username"].is_null(),
        "a password-only fill must not volunteer the username: {reply}"
    );
}

// ---------------------------------------------------------------------------
// B-21: field lists that are empty, duplicated, wrong-cased or unknown.
// ---------------------------------------------------------------------------

#[test]
fn an_empty_field_list_is_a_protocol_refusal_rather_than_a_full_fill() {
    let fixture = fixture();
    let _human = Human::approving(&fixture.queue);
    let mut extension = RawExtension::connect(&fixture.socket);

    let reply = extension.fill(&fixture.item_ids[0], json!([]));
    assert_eq!(reply["reply"], "error", "{reply}");
    assert_eq!(
        reply["code"], "PROTOCOL",
        "an empty list is a malformed request, not a request for everything: {reply}"
    );
    assert!(
        !serde_json::to_string(&reply)
            .unwrap()
            .contains(PASSWORD_CANARY)
    );
}

#[test]
fn a_duplicated_field_name_is_deduplicated_rather_than_filled_twice() {
    let fixture = fixture();
    let _human = Human::approving(&fixture.queue);
    let mut extension = RawExtension::connect(&fixture.socket);

    let reply = extension.fill(&fixture.item_ids[0], json!(["password", "password"]));
    assert_eq!(reply["reply"], "filled", "{reply}");
    assert_eq!(reply["password"], PASSWORD_CANARY);

    // The audit entry is where a duplicate would otherwise show: it lists the field names.
    let variables = fixture
        .handle
        .with(|vault| {
            vault
                .audit_entries()
                .iter()
                .filter(|e| e.tool == "fill_credential")
                .map(|e| e.variables.clone())
                .collect::<Vec<_>>()
        })
        .expect("unlocked");
    assert_eq!(
        variables,
        vec![vec!["password".to_owned()]],
        "the field names are deduplicated before the human and before the log"
    );
}

#[test]
fn a_field_name_this_protocol_does_not_define_never_produces_a_fill() {
    // The property that matters: a field name the app cannot parse — wrong case, padded, unknown,
    // or not a string at all — is never coerced into `password` and never widens the fill. The
    // app may answer with a refusal or drop the connection; what it may not do is fill.
    let fixture = fixture();
    let _human = Human::approving(&fixture.queue);

    for wrong in unparseable_field_lists() {
        // A fresh connection per case, because a request the app cannot read costs the
        // connection — see the test below.
        let mut extension = RawExtension::connect(&fixture.socket);
        if let Some(reply) = extension.fill_or_closed(&fixture.item_ids[0], wrong.clone()) {
            assert_ne!(
                reply["reply"], "filled",
                "{wrong} was coerced into a fill: {reply}"
            );
            assert!(
                !serde_json::to_string(&reply)
                    .unwrap()
                    .contains(PASSWORD_CANARY),
                "{wrong} leaked the value"
            );
        }
    }

    assert!(
        !audit_json(&fixture).contains(PASSWORD_CANARY),
        "no audit entry may contain a value"
    );
    let approved = fixture
        .handle
        .with(|vault| {
            vault
                .audit_entries()
                .iter()
                .filter(|e| e.detail.as_deref() == Some(audit_detail::FILL_APPROVED))
                .count()
        })
        .expect("unlocked");
    assert_eq!(approved, 0, "nothing in this sweep was ever approved");
}

#[test]
fn a_request_body_the_app_cannot_read_is_answered_rather_than_dropped() {
    // `frame::read` reports a body that fails to deserialize as `FrameError::InvalidBody`, which
    // carries the correlation id recovered independently of the target type. `serve_host` answers
    // that id with a `PROTOCOL` error and keeps serving, rather than treating a parse failure like
    // a broken wire. The Chromium path is shielded by `kagisecure-nmhost`, which decodes before
    // forwarding, but `SafariWebExtensionHandler` forwards the body as an opaque dictionary, so on
    // that socket a malformed body reaches here. An extension that got silence could not tell a
    // protocol mistake of its own from the app having crashed.
    let fixture = fixture();
    let _human = Human::approving(&fixture.queue);
    let mut extension = RawExtension::connect(&fixture.socket);

    let reply = extension
        .fill_or_closed(&fixture.item_ids[0], json!(["Password"]))
        .expect("the app should answer rather than close the port");
    assert_eq!(reply["reply"], "error", "{reply}");
    assert_eq!(reply["code"], "PROTOCOL", "{reply}");

    // And the connection is still usable afterwards, which is what makes the refusal legible.
    let after = extension.fill(&fixture.item_ids[0], json!(["username"]));
    assert_eq!(after["reply"], "filled", "{after}");
}

#[test]
fn a_fill_with_no_field_list_at_all_means_both_fields_and_therefore_asks_a_human() {
    // `fields` defaults to both, by design and with the reasoning written down in `FillField`.
    // What matters adversarially is that the default is the *prompting* branch, not the silent
    // username-only one: a request that omits the list must never be served without a sheet.
    let fixture = fixture();
    let _human = Human::approving(&fixture.queue);
    let mut extension = RawExtension::connect(&fixture.socket);

    let reply = extension.send(json!({
        "ask": "fill",
        "page": { "top_origin": SITE },
        "item_id": fixture.item_ids[0],
    }));
    assert_eq!(reply["reply"], "filled", "{reply}");

    let details = fixture
        .handle
        .with(|vault| {
            vault
                .audit_entries()
                .iter()
                .filter_map(|e| e.detail.clone())
                .collect::<Vec<_>>()
        })
        .expect("unlocked");
    assert!(
        details.contains(&audit_detail::FILL_APPROVED.to_owned()),
        "an omitted field list went through the approval path: {details:?}"
    );
    assert!(
        !details.contains(&audit_detail::FILL_USERNAME_ONLY.to_owned()),
        "an omitted field list must not fall into the no-sheet branch: {details:?}"
    );
}

// ---------------------------------------------------------------------------
// B-20: a thousand username-only fills, every one audited, no value crossing.
// ---------------------------------------------------------------------------

#[test]
fn a_thousand_username_only_fills_are_each_audited_and_none_carries_a_password() {
    let fixture = fixture();
    // Deliberately *no* human: a username-only fill must never reach the approval queue, so a
    // queue nobody is answering is the strongest possible statement. Anything that asked would
    // hang for the queue's full timeout and fail this test by taking minutes.
    let mut extension = RawExtension::connect(&fixture.socket);

    // Measured per fill, not over the whole sweep: a thousand fills that each save the vault
    // take tens of seconds on a loaded machine, so a total budget flakes, whereas one fill that
    // waited on the queue would take the full approval timeout on its own.
    let mut slowest = Duration::ZERO;
    for index in 0..SWEEP_FILLS {
        let item_id = &fixture.item_ids[index % ITEMS_AT_SITE];
        let started = std::time::Instant::now();
        let reply = extension.fill(item_id, json!(["username"]));
        slowest = slowest.max(started.elapsed());
        assert_eq!(reply["reply"], "filled", "sweep {index}: {reply}");
        assert!(reply["password"].is_null(), "sweep {index}: {reply}");
        assert!(
            !serde_json::to_string(&reply)
                .unwrap()
                .contains(PASSWORD_CANARY),
            "sweep {index} carried the password"
        );
    }
    assert!(
        slowest < Duration::from_secs(APPROVAL_TIMEOUT_SECONDS / 2),
        "a username-only fill took {slowest:?}, as if it had waited on an approval"
    );

    let (username_only, other) = fixture
        .handle
        .with(|vault| {
            let entries = vault.audit_entries();
            let username_only = entries
                .iter()
                .filter(|e| e.detail.as_deref() == Some(audit_detail::FILL_USERNAME_ONLY))
                .count();
            let other = entries
                .iter()
                .filter(|e| {
                    e.tool == "fill_credential"
                        && e.detail.as_deref() != Some(audit_detail::FILL_USERNAME_ONLY)
                })
                .count();
            (username_only, other)
        })
        .expect("unlocked");
    assert_eq!(
        username_only, SWEEP_FILLS,
        "one FILL_USERNAME_ONLY entry per fill, with none silently dropped"
    );
    assert_eq!(other, 0, "nothing in this sweep was an approved fill");

    assert!(
        !audit_json(&fixture).contains(PASSWORD_CANARY),
        "no audit entry may contain a value"
    );
    fixture
        .handle
        .with(|vault| vault.verify_audit().expect("the chain still verifies"));
}

// ---------------------------------------------------------------------------
// B-23: the canary sweep across every request shape, including malformed ones.
// ---------------------------------------------------------------------------

#[test]
fn no_request_shape_puts_the_password_anywhere_but_the_one_approved_reply() {
    let fixture = fixture();
    let _human = Human::approving(&fixture.queue);
    let mut extension = RawExtension::connect(&fixture.socket);
    let item = fixture.item_ids[0].clone();

    // Every shape this protocol admits, plus a good number it does not. None of these is the one
    // approved password fill, so none of their replies may carry the value.
    let shapes: Vec<Value> = vec![
        json!({ "ask": "status" }),
        json!({ "ask": "match", "page": { "top_origin": SITE } }),
        json!({ "ask": "match", "page": { "top_origin": ELSEWHERE } }),
        json!({ "ask": "match", "page": { "top_origin": "not a url" } }),
        json!({ "ask": "match", "page": { "top_origin": SITE, "frame_origin": ELSEWHERE } }),
        json!({ "ask": "fill", "page": { "top_origin": ELSEWHERE }, "item_id": item,
                "fields": ["password"] }),
        json!({ "ask": "fill", "page": { "top_origin": "http://shape.example" },
                "item_id": item, "fields": ["password"] }),
        json!({ "ask": "fill", "page": { "top_origin": SITE }, "item_id": "not-an-id",
                "fields": ["password"] }),
        json!({ "ask": "fill", "page": { "top_origin": SITE }, "item_id": "",
                "fields": ["password"] }),
        json!({ "ask": "fill", "page": { "top_origin": SITE }, "item_id": item,
                "fields": ["Password"] }),
        json!({ "ask": "fill", "page": { "top_origin": SITE }, "item_id": item, "fields": [] }),
        json!({ "ask": "fill", "page": {}, "item_id": item, "fields": ["password"] }),
        json!({ "ask": "fill" }),
        json!({ "ask": "totp", "page": { "top_origin": SITE }, "item_id": item }),
        json!({ "ask": "totp", "page": { "top_origin": ELSEWHERE }, "item_id": item }),
        json!({ "ask": "hello", "extension_id": "not-the-pinned-one", "browser": "chrome",
                "extension_version": "0.1.0", "protocol_version": 1 }),
        json!({ "ask": "nonsense" }),
        json!({ "ask": "fill", "page": { "top_origin": SITE }, "item_id": item,
                "fields": ["username"], "password": PASSWORD_CANARY }),
        json!({ "not": "a request at all" }),
        json!([]),
        json!("a bare string"),
        json!(null),
    ];

    let mut leaks = Vec::new();
    for shape in &shapes {
        // A fresh connection per shape: several of these are bodies the app cannot deserialize,
        // and such a body costs the connection (see B-21b above).
        let mut probe = RawExtension::connect(&fixture.socket);
        let Some(reply) = probe.send_or_closed(shape.clone()) else {
            continue;
        };
        let bytes = serde_json::to_string(&reply).expect("json");
        if bytes.contains(PASSWORD_CANARY) || bytes.contains(ELSEWHERE_CANARY) {
            leaks.push(format!("{shape} -> {bytes}"));
        }
    }
    assert!(
        leaks.is_empty(),
        "a value crossed on a request that was not an approved fill: {leaks:#?}"
    );

    // The one legitimate crossing, so the sweep cannot pass through a vault that never had a
    // value in it.
    let approved = extension.fill(&item, json!(["password"]));
    assert_eq!(approved["password"], PASSWORD_CANARY, "{approved}");

    // ...and it is still in exactly one place.
    let audit = audit_json(&fixture);
    for canary in [PASSWORD_CANARY, ELSEWHERE_CANARY] {
        assert!(
            !audit.contains(canary),
            "the audit log contains a value: {audit}"
        );
    }
    fixture
        .handle
        .with(|vault| vault.verify_audit().expect("the chain still verifies"));
}
