//! Cross-process: the real `kagisecure-nmhost` binary, framed the way Chrome frames it, talking
//! to a library-hosted extension listener over a real socket.
//!
//! This is the extension channel's counterpart to `sidecar.rs`, and it asserts the same class of
//! things one layer over: that the two halves agree on a wire format nobody hand-wrote twice, that
//! the origin rule refuses what it says it refuses, and — the one that matters — that the password
//! reaches the browser through **exactly one** message and appears in no audit entry and on no
//! standard error stream on the way.
//!
//! The approval is answered by the queue's own debug auto-approve, which resolves through
//! `ApprovalQueue::resolve` exactly as the app's sheet does. The parts that cannot be honest in a
//! test — a browser as the native host's parent — are the parts the *unit* tests cover with the
//! gate switched on.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use kagisecure_agent::approval::ApprovalQueue;
use kagisecure_agent::extension::audit_detail;
use kagisecure_agent::{Endpoint, ExtensionAgent, ExtensionConfig, VaultHandle};
use kagisecure_core::model::{Field, Item, Secret};
use kagisecure_core::proto::Category;
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_extension_ipc::protocol::{
    Envelope, ErrorCode, FillField, PageContext, Request, Response,
};
use kagisecure_extension_ipc::{PINNED_EXTENSION_IDS, nm};

/// A 32-byte marker, seeded as the login's password. If these bytes reach an audit entry or the
/// native host's stderr, the product has failed at the one thing it exists to do.
const MARKER: &str = "K4G1-F1LL-C4N4RY-3e91b7d2a08c46fa";

/// The origin the item is saved against.
const SITE: &str = "http://localhost:8765";

struct Fixture {
    _dir: tempfile::TempDir,
    handle: Arc<VaultHandle>,
    _agent: ExtensionAgent,
    endpoint: Endpoint,
    item_id: String,
    totp_item_id: String,
}

fn fixture() -> Fixture {
    fixture_with_auto_approve(true)
}

/// A fixture whose approval queue has **nobody answering it**.
///
/// With `auto_approve` off and no sheet, anything that reaches the human gate waits out the
/// queue's 60-second timeout. That is what makes it useful: a request that comes back promptly is
/// a request that never asked.
fn fixture_with_auto_approve(auto_approve: bool) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("test.kagivault");

    // Deliberately cheap KDF parameters: this vault exists for a second and protects nothing.
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

    let mut item = Item::new(vault_id, Category::Login, "Test site");
    item.urls = vec![SITE.to_owned()];
    item.fields.push(Field::public("username", "alice"));
    item.fields.push(Field::concealed(
        "password",
        Secret::from_string(MARKER.to_owned()),
    ));
    let item_id = item.id.to_string();

    let mut with_totp = Item::new(vault_id, Category::Login, "Test site with 2FA");
    with_totp.urls = vec![SITE.to_owned()];
    with_totp.fields.push(Field::public("username", "bob"));
    with_totp.fields.push(Field::concealed(
        "password",
        Secret::from_string("second-account".to_owned()),
    ));
    with_totp.fields.push(Field::totp(
        "one-time password",
        Secret::from_string(
            "otpauth://totp/Test:bob?secret=JBSWY3DPEHPK3PXP&issuer=Test".to_owned(),
        ),
    ));
    let totp_item_id = with_totp.id.to_string();

    // An item at a different origin, so a "no match" is a real absence rather than an empty vault.
    let mut elsewhere = Item::new(vault_id, Category::Login, "Somewhere else");
    elsewhere.urls = vec!["https://elsewhere.test".to_owned()];
    elsewhere.fields.push(Field::concealed(
        "password",
        Secret::from_string("x".to_owned()),
    ));

    vault
        .transact(|tx| {
            tx.add_item(item);
            tx.add_item(with_totp);
            tx.add_item(elsewhere);
            Ok(())
        })
        .expect("save");

    let endpoint = Endpoint::for_instance(dir.path(), "extension.sock");
    let handle = VaultHandle::new(vault);
    let agent = ExtensionAgent::start(
        Arc::clone(&handle),
        ExtensionConfig {
            endpoint: Some(endpoint.clone()),
            auto_approve,
            allow_unlaunched_host: true,
            ..ExtensionConfig::new(Arc::new(ApprovalQueue::new()))
        },
    )
    .expect("extension agent");

    Fixture {
        _dir: dir,
        handle,
        _agent: agent,
        endpoint,
        item_id,
        totp_item_id,
    }
}

/// The native host binary, built on demand — see `kagisecure_test_support::binary` for why this
/// goes through a shared helper rather than a hardcoded `target/debug`.
fn nmhost_binary() -> PathBuf {
    kagisecure_test_support::binary("kagisecure-nmhost", kagisecure_agent::bundle::NMHOST)
}

/// A stand-in for Chrome: spawn the host, write native-messaging frames at it, read them back.
///
/// Dropping one without [`Browser::close`] — which is what a failing assertion does — closes the
/// port and kills the host, so a failed test never leaves a `kagisecure-nmhost` behind.
struct Browser {
    child: Child,
    /// `None` once the port has been closed.
    stdin: Option<std::process::ChildStdin>,
    stdout: std::process::ChildStdout,
    next_id: u64,
}

impl Drop for Browser {
    fn drop(&mut self) {
        drop(self.stdin.take());
        // Both are no-ops for a host that `close` has already waited on.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Browser {
    fn launch(endpoint: &Endpoint) -> Self {
        let mut child = Command::new(nmhost_binary())
            // Chrome passes the extension's origin and the host name as argv; the host ignores
            // both, and passing them keeps the invocation honest.
            .arg(format!("chrome-extension://{}/", PINNED_EXTENSION_IDS[0]))
            .arg("com.kagisecure.nmhost")
            .env("KAGISECURE_EXTENSION_SOCKET", endpoint.as_override())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn kagisecure-nmhost");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        Self {
            child,
            stdin: Some(stdin),
            stdout,
            next_id: 0,
        }
    }

    /// Write one request and return its id, without waiting for the reply.
    fn send(&mut self, request: &Request) -> String {
        self.next_id += 1;
        let id = format!("req-{}", self.next_id);
        let stdin = self.stdin.as_mut().expect("the port is open");
        nm::write(stdin, &Envelope::new(&id, request)).expect("write native message");
        id
    }

    fn call(&mut self, request: &Request) -> Response {
        let id = self.send(request);
        let reply: Envelope<Response> = nm::read(&mut self.stdout).expect("read native message");
        assert_eq!(reply.id, id, "the host must correlate replies");
        reply.body
    }

    fn hello(&mut self) -> Response {
        self.call(&Request::Hello {
            extension_id: PINNED_EXTENSION_IDS[0].to_owned(),
            browser: "chrome".to_owned(),
            extension_version: "0.1.0".to_owned(),
            protocol_version: kagisecure_extension_ipc::PROTOCOL_VERSION,
            capabilities: vec![],
        })
    }

    /// Close the port and collect everything the host wrote to stderr.
    fn close(mut self) -> String {
        drop(self.stdin.take());
        let mut stderr = String::new();
        if let Some(mut handle) = self.child.stderr.take() {
            let _ = handle.read_to_string(&mut stderr);
        }
        let status = self.child.wait().expect("wait");
        assert!(
            status.success(),
            "the host should exit cleanly when the port closes, got {status}"
        );
        stderr
    }
}

fn page(origin: &str) -> PageContext {
    PageContext::top(origin)
}

#[test]
fn a_real_native_host_fills_a_matched_login_end_to_end() {
    let fixture = fixture();
    let mut browser = Browser::launch(&fixture.endpoint);

    match browser.hello() {
        Response::Welcome {
            protocol_version,
            unlocked,
            host_evidence,
            ..
        } => {
            assert_eq!(protocol_version, kagisecure_extension_ipc::PROTOCOL_VERSION);
            assert!(unlocked);
            assert!(
                !host_evidence.is_empty(),
                "the popup has to be able to say who it is talking to"
            );
        }
        other => panic!("expected a welcome, got {other:?}"),
    }

    // The match: metadata only, and the marker must not be in it.
    let matches = browser.call(&Request::Match { page: page(SITE) });
    let items = match &matches {
        Response::Matches { origin, items } => {
            assert_eq!(origin, SITE);
            items.clone()
        }
        other => panic!("expected matches, got {other:?}"),
    };
    assert_eq!(items.len(), 2, "two items are saved at this origin");
    let listed: Vec<&str> = items.iter().map(|i| i.title.as_str()).collect();
    assert!(listed.contains(&"Test site"));
    assert!(
        !listed.contains(&"Somewhere else"),
        "an item at another origin must not be offered"
    );
    assert_eq!(items[0].username.as_deref(), Some("alice"));
    assert!(
        !serde_json::to_string(&matches).unwrap().contains(MARKER),
        "a match answer must never carry a value"
    );

    // The fill: the one message that carries a password.
    let filled = browser.call(&Request::Fill {
        page: page(SITE),
        item_id: fixture.item_id.clone(),
        fields: vec![FillField::Username, FillField::Password],
    });
    match &filled {
        Response::Filled {
            item_id,
            username,
            password,
            ..
        } => {
            assert_eq!(item_id, &fixture.item_id);
            assert_eq!(username.as_deref(), Some("alice"));
            assert_eq!(
                password.as_ref().expect("a password").expose(),
                MARKER,
                "the value the browser gets must be the value in the vault"
            );
        }
        other => panic!("expected a fill, got {other:?}"),
    }

    let stderr = browser.close();
    assert!(
        !stderr.contains(MARKER),
        "the native host must never write a value to stderr: {stderr}"
    );

    // The audit trail: one allowed entry, naming the origin and the field names, and no value.
    let entries = fixture
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .expect("unlocked");
    let fills: Vec<_> = entries
        .iter()
        .filter(|e| e.tool == "fill_credential")
        .collect();
    assert_eq!(fills.len(), 1, "one fill, one entry");
    assert_eq!(
        fills[0].detail.as_deref(),
        Some(audit_detail::FILL_APPROVED)
    );
    assert_eq!(fills[0].target_path.as_deref(), Some(SITE));
    assert_eq!(
        fills[0].variables,
        vec!["username".to_owned(), "password".to_owned()],
        "field names, deduplicated and in form order"
    );
    assert!(fills[0].actor.contains("extension"), "{}", fills[0].actor);

    let audit_json = serde_json::to_string(&entries).expect("audit json");
    assert!(
        !audit_json.contains(MARKER),
        "no audit entry may contain a value"
    );
    fixture
        .handle
        .with(|vault| vault.verify_audit().expect("the chain still verifies"));
}

#[test]
fn a_fill_at_the_wrong_origin_is_refused_and_recorded() {
    let fixture = fixture();
    let mut browser = Browser::launch(&fixture.endpoint);
    browser.hello();

    // The item is saved at http://localhost:8765. Everything below is a different origin, and
    // each one is a different way of being different.
    for wrong in [
        "http://localhost:8766",  // a different port
        "https://localhost:8765", // a different scheme
        "http://127.0.0.1:8765",  // a different host that resolves to the same machine
        "http://evil.test",       // an unrelated site
    ] {
        let response = browser.call(&Request::Fill {
            page: page(wrong),
            item_id: fixture.item_id.clone(),
            fields: vec![FillField::Password],
        });
        match response {
            Response::Error { code, .. } => assert_eq!(
                code,
                ErrorCode::OriginMismatch,
                "{wrong} should be refused as a mismatch"
            ),
            other => panic!("{wrong} was not refused: {other:?}"),
        }
    }

    // And a match at the wrong origin offers nothing at all.
    match browser.call(&Request::Match {
        page: page("http://evil.test"),
    }) {
        Response::Matches { items, .. } => assert!(items.is_empty()),
        other => panic!("expected an empty match, got {other:?}"),
    }

    let stderr = browser.close();
    assert!(!stderr.contains(MARKER), "{stderr}");

    let entries = fixture
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .expect("unlocked");
    let mismatches: Vec<_> = entries
        .iter()
        .filter(|e| {
            e.detail
                .as_deref()
                .is_some_and(|d| d.starts_with(audit_detail::FILL_ORIGIN_MISMATCH))
        })
        .collect();
    assert_eq!(mismatches.len(), 4, "one entry per refused origin");
    assert!(
        entries.iter().all(|e| e.tool != "fill_credential"
            || e.detail.as_deref() != Some(audit_detail::FILL_APPROVED)),
        "nothing was approved"
    );
}

#[test]
fn a_cross_origin_iframe_is_matched_against_the_frame_not_the_page() {
    let fixture = fixture();
    let mut browser = Browser::launch(&fixture.endpoint);
    browser.hello();

    // The item's own origin, inside a frame on somebody else's page: allowed, because the frame
    // is what the credential belongs to.
    let allowed = browser.call(&Request::Fill {
        page: PageContext {
            top_origin: "https://aggregator.test".to_owned(),
            frame_origin: Some(SITE.to_owned()),
            top_origin_established: true,
        },
        item_id: fixture.item_id.clone(),
        fields: vec![FillField::Password],
    });
    assert!(
        matches!(allowed, Response::Filled { .. }),
        "got {allowed:?}"
    );

    // Somebody else's origin, inside a frame on the item's own page: refused, because a page does
    // not lend its trust to a third party's frame.
    let refused = browser.call(&Request::Fill {
        page: PageContext {
            top_origin: SITE.to_owned(),
            frame_origin: Some("https://evil.test".to_owned()),
            top_origin_established: true,
        },
        item_id: fixture.item_id.clone(),
        fields: vec![FillField::Password],
    });
    match refused {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::OriginMismatch),
        other => panic!("an attacker's frame was not refused: {other:?}"),
    }

    browser.close();
}

#[test]
fn a_totp_code_is_a_separate_second_action() {
    let fixture = fixture();
    let mut browser = Browser::launch(&fixture.endpoint);
    browser.hello();

    // A fill of the credential does not hand over a code.
    let filled = browser.call(&Request::Fill {
        page: page(SITE),
        item_id: fixture.totp_item_id.clone(),
        fields: vec![FillField::Username, FillField::Password],
    });
    let filled_json = serde_json::to_string(&filled).expect("json");
    assert!(matches!(filled, Response::Filled { .. }), "got {filled:?}");

    // Asking for the code is its own request, and its own audit entry.
    let code = match browser.call(&Request::Totp {
        page: page(SITE),
        item_id: fixture.totp_item_id.clone(),
    }) {
        Response::TotpCode {
            code,
            seconds_remaining,
            ..
        } => {
            assert!((1..=30).contains(&seconds_remaining), "{seconds_remaining}");
            code.expose().to_owned()
        }
        other => panic!("expected a code, got {other:?}"),
    };
    assert_eq!(code.len(), 6, "a six-digit code: {code}");
    assert!(code.chars().all(|c| c.is_ascii_digit()), "{code}");
    assert!(
        !filled_json.contains(&code),
        "the fill reply must not have carried the code"
    );

    // The item with no TOTP field says so rather than inventing one — and does it *before*
    // anybody is asked to approve anything, so there is no audit entry for a decision nobody made.
    match browser.call(&Request::Totp {
        page: page(SITE),
        item_id: fixture.item_id.clone(),
    }) {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::NoMatch),
        other => panic!("expected a refusal, got {other:?}"),
    }

    let stderr = browser.close();
    assert!(!stderr.contains(&code), "a code must not reach stderr");

    let entries = fixture
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .expect("unlocked");
    assert_eq!(
        entries.iter().filter(|e| e.tool == "totp_code").count(),
        1,
        "the code that was handed over is recorded; the impossible request is not a decision"
    );
    let audit_json = serde_json::to_string(&entries).expect("json");
    assert!(!audit_json.contains(&code), "no code in the audit log");
    assert!(!audit_json.contains(MARKER), "no password in the audit log");
}

#[test]
fn an_unpinned_extension_id_is_refused_before_anything_is_served() {
    let fixture = fixture();
    let mut browser = Browser::launch(&fixture.endpoint);

    match browser.call(&Request::Hello {
        extension_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        browser: "chrome".to_owned(),
        extension_version: "0.1.0".to_owned(),
        protocol_version: kagisecure_extension_ipc::PROTOCOL_VERSION,
        capabilities: vec![],
    }) {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::UnknownExtension),
        other => panic!("a stranger's extension was served: {other:?}"),
    }

    // And nothing works afterwards either — a refused hello is not a hello.
    match browser.call(&Request::Match { page: page(SITE) }) {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::Protocol),
        other => panic!("expected a protocol refusal, got {other:?}"),
    }

    browser.close();
}

#[test]
fn a_protocol_version_mismatch_is_a_legible_refusal_rather_than_a_dropped_port() {
    let fixture = fixture();
    let mut browser = Browser::launch(&fixture.endpoint);
    match browser.call(&Request::Hello {
        extension_id: PINNED_EXTENSION_IDS[0].to_owned(),
        browser: "chrome".to_owned(),
        extension_version: "9.9.9".to_owned(),
        protocol_version: kagisecure_extension_ipc::PROTOCOL_VERSION + 1,
        capabilities: vec![],
    }) {
        Response::Error { code, message } => {
            assert_eq!(code, ErrorCode::Protocol);
            assert!(message.contains("Update"), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    browser.close();
}

#[test]
fn locking_the_vault_stops_every_fill_at_once() {
    let fixture = fixture();
    let mut browser = Browser::launch(&fixture.endpoint);
    browser.hello();

    // A lease exists, from the auto-approved first fill.
    let _ = browser.call(&Request::Fill {
        page: page(SITE),
        item_id: fixture.item_id.clone(),
        fields: vec![FillField::Password],
    });
    assert_eq!(fixture._agent.fill_leases().len(), 1);

    drop(fixture.handle.take());
    assert!(
        fixture._agent.fill_leases().is_empty(),
        "locking must take every fill lease with it"
    );

    match browser.call(&Request::Fill {
        page: page(SITE),
        item_id: fixture.item_id.clone(),
        fields: vec![FillField::Password],
    }) {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::VaultLocked),
        other => panic!("a locked vault filled a password: {other:?}"),
    }
    match browser.call(&Request::Status) {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::VaultLocked),
        other => panic!("expected VAULT_LOCKED, got {other:?}"),
    }

    browser.close();
}

#[test]
fn a_second_fill_within_the_lease_is_recorded_as_confirmed_rather_than_approved() {
    // The debug auto-approver answers every request, presence-only ones included, so this pins
    // the audit vocabulary rather than the human gate — `extension_adversarial_presence.rs` is
    // where a presence prompt nobody answers is asserted to fill nothing.
    let fixture = fixture();
    let mut browser = Browser::launch(&fixture.endpoint);
    browser.hello();

    for _ in 0..3 {
        let response = browser.call(&Request::Fill {
            page: page(SITE),
            item_id: fixture.item_id.clone(),
            fields: vec![FillField::Password],
        });
        assert!(matches!(response, Response::Filled { .. }), "{response:?}");
    }
    browser.close();

    let entries = fixture
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .expect("unlocked");
    let details: Vec<&str> = entries
        .iter()
        .filter(|e| e.tool == "fill_credential")
        .filter_map(|e| e.detail.as_deref())
        .collect();
    assert_eq!(
        details,
        vec![
            audit_detail::FILL_APPROVED,
            audit_detail::FILL_CONFIRMED,
            audit_detail::FILL_CONFIRMED
        ],
        "the first fill is a review; the rest are fresh presence proofs under the review's memory"
    );
    assert!(
        !details.contains(&audit_detail::FILL_LEASED),
        "no fill goes ahead on a lease alone any more (ADR-0037)"
    );

    // A *different* item at the same origin is a fresh decision, not covered by the lease.
    let mut browser = Browser::launch(&fixture.endpoint);
    browser.hello();
    let _ = browser.call(&Request::Fill {
        page: page(SITE),
        item_id: fixture.totp_item_id.clone(),
        fields: vec![FillField::Password],
    });
    browser.close();

    let entries = fixture
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .expect("unlocked");
    let approvals = entries
        .iter()
        .filter(|e| e.detail.as_deref() == Some(audit_detail::FILL_APPROVED))
        .count();
    assert_eq!(approvals, 2, "two items, two approvals");
}

#[test]
fn a_native_host_with_no_browser_above_it_is_refused() {
    // The gate with the test affordance switched **off**, which is the direction that matters.
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("test.kagivault");
    let mut options = CreateOptions::new().expect("options");
    options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
        kagisecure_core::crypto::kdf::MIN_M_KIB,
        kagisecure_core::crypto::kdf::MIN_T,
        1,
    )
    .expect("kdf");
    let (vault, _code) = Vault::create(&vault_path, b"pw", &options).expect("create");
    let handle = VaultHandle::new(vault);
    let endpoint = Endpoint::for_instance(dir.path(), "gated.sock");
    let _agent = ExtensionAgent::start(
        Arc::clone(&handle),
        ExtensionConfig {
            endpoint: Some(endpoint.clone()),
            ..ExtensionConfig::new(Arc::new(ApprovalQueue::new()))
        },
    )
    .expect("agent");

    // The host's parent here is this test binary, not a browser.
    let mut browser = Browser::launch(&endpoint);
    match browser.hello() {
        Response::Error { code, message } => {
            assert_eq!(code, ErrorCode::UntrustedHost);
            assert!(message.contains("recognized browser"), "{message}");
        }
        other => panic!("an unlaunched host was served: {other:?}"),
    }
    browser.close();

    let entries = handle
        .with(|vault| vault.audit_entries().to_vec())
        .expect("unlocked");
    assert!(
        entries
            .iter()
            .any(|e| e.detail.as_deref() == Some(audit_detail::HOST_REFUSED)),
        "the refusal is recorded, so a user can see something tried"
    );
}

#[test]
fn the_native_host_survives_the_app_going_away_and_coming_back() {
    // Chrome keeps a native messaging port open for the life of the service worker; the app may
    // restart under it. A host that gave up on the first dead socket would leave the extension
    // dead until the user reloaded it.
    let fixture = fixture();
    let mut browser = Browser::launch(&fixture.endpoint);
    browser.hello();
    assert!(matches!(
        browser.call(&Request::Status),
        Response::Status { unlocked: true }
    ));

    // Simulate a restart: stop the listener, then bind a fresh one on the same path.
    drop(fixture._agent);
    std::thread::sleep(Duration::from_millis(60));
    let restarted = ExtensionAgent::start(
        Arc::clone(&fixture.handle),
        ExtensionConfig {
            endpoint: Some(fixture.endpoint.clone()),
            auto_approve: true,
            allow_unlaunched_host: true,
            ..ExtensionConfig::new(Arc::new(ApprovalQueue::new()))
        },
    )
    .expect("restart");

    // The session state went with the old connection. The host reconnects and says the
    // extension's hello again before forwarding the request (ADR-0036, implementation decision
    // 17), so the extension — which has no idea the app went away — is answered as before, not
    // told `PROTOCOL` until something makes it say hello itself. `call` checks the reply's id, so
    // the app's answer to the replayed hello reaching the browser would fail here too.
    assert!(
        matches!(
            browser.call(&Request::Status),
            Response::Status { unlocked: true }
        ),
        "a reconnected session has the extension's hello behind it"
    );
    assert!(matches!(browser.hello(), Response::Welcome { .. }));
    browser.close();
    drop(restarted);
}

#[test]
fn the_native_host_exits_when_the_port_closes_even_while_the_app_is_silent() {
    // The browser's half of the lifecycle. Closing stdin is how a browser ends a port, and a host
    // that only noticed between round trips would outlive the browser whenever the app was slow
    // to answer, or never did. An app that reads the request and then says nothing is the worst
    // case, so that is what listens here.
    let dir = tempfile::tempdir().expect("tempdir");
    let endpoint = Endpoint::for_instance(dir.path(), "silent.sock");
    let listener = kagisecure_extension_ipc::Listener::bind(&endpoint).expect("bind");
    let (received, request_arrived) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let app = std::thread::spawn(move || {
        let mut connection = listener.accept().expect("accept");
        let _ = connection
            .read_request()
            .expect("the host forwards the request");
        received.send(()).expect("test is waiting");
        // Hold the connection open, unanswered, until the test is done looking.
        let _ = released.recv();
    });

    let mut browser = Browser::launch(&endpoint);
    let _ = browser.send(&Request::Status);
    request_arrived
        .recv_timeout(Duration::from_secs(30))
        .expect("the request reached the app");

    // Chrome closes the port. The host is parked on a reply that will never come.
    drop(browser.stdin.take());
    let closed = std::time::Instant::now();
    let limit = Duration::from_secs(30);
    let status = loop {
        if let Some(status) = browser.child.try_wait().expect("try_wait") {
            break Some(status);
        }
        if closed.elapsed() > limit {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = release.send(());
    app.join().expect("app thread");

    let status = status.unwrap_or_else(|| {
        panic!("the host was still running {limit:?} after the browser closed its stdin")
    });
    assert!(
        status.success(),
        "a closed port is a clean exit, got {status}"
    );
}

#[test]
fn a_username_only_fill_needs_no_approval_and_carries_no_password() {
    // Identifier-first page one. The queue in this fixture has nobody answering it, so a request
    // that reached the human gate would sit there for the queue's full 60-second timeout; this
    // one comes back at once, which is the assertion that no sheet was raised (ADR-0030).
    let fixture = fixture_with_auto_approve(false);
    let mut browser = Browser::launch(&fixture.endpoint);
    browser.hello();

    let started = std::time::Instant::now();
    let filled = browser.call(&Request::Fill {
        page: page(SITE),
        item_id: fixture.item_id.clone(),
        fields: vec![FillField::Username],
    });
    let elapsed = started.elapsed();

    match &filled {
        Response::Filled {
            item_id,
            username,
            password,
            ..
        } => {
            assert_eq!(item_id, &fixture.item_id);
            assert_eq!(username.as_deref(), Some("alice"));
            assert!(
                password.is_none(),
                "a username-only fill must not carry the password"
            );
        }
        other => panic!("expected a fill, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(10),
        "a username-only fill must not wait on an approval nobody was asked for: {elapsed:?}"
    );
    // The canary, on the serialized message rather than on the fields: these are the bytes the
    // browser would receive.
    let json = serde_json::to_string(&filled).expect("json");
    assert!(!json.contains(MARKER), "{json}");

    let stderr = browser.close();
    assert!(!stderr.contains(MARKER), "{stderr}");

    let entries = fixture
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .expect("unlocked");
    let fills: Vec<_> = entries
        .iter()
        .filter(|e| e.tool == "fill_credential")
        .collect();
    assert_eq!(
        fills.len(),
        1,
        "served without a sheet is not served in silence"
    );
    assert_eq!(
        fills[0].detail.as_deref(),
        Some(audit_detail::FILL_USERNAME_ONLY)
    );
    assert_eq!(fills[0].variables, vec!["username".to_owned()]);
    assert_eq!(fills[0].target_path.as_deref(), Some(SITE));
    assert!(
        !serde_json::to_string(&entries).unwrap().contains(MARKER),
        "no audit entry may contain a value"
    );
}

#[test]
fn a_username_only_fill_mints_no_lease_for_the_password() {
    // The gate a username-only fill must not open: it authorizes nothing, so the password fill
    // that follows it on page two is still a fresh decision.
    let fixture = fixture();
    let mut browser = Browser::launch(&fixture.endpoint);
    browser.hello();

    let _ = browser.call(&Request::Fill {
        page: page(SITE),
        item_id: fixture.item_id.clone(),
        fields: vec![FillField::Username],
    });
    let _ = browser.call(&Request::Fill {
        page: page(SITE),
        item_id: fixture.item_id.clone(),
        fields: vec![FillField::Password],
    });
    browser.close();

    let entries = fixture
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .expect("unlocked");
    let details: Vec<&str> = entries
        .iter()
        .filter(|e| e.tool == "fill_credential")
        .filter_map(|e| e.detail.as_deref())
        .collect();
    assert_eq!(
        details,
        vec![
            audit_detail::FILL_USERNAME_ONLY,
            audit_detail::FILL_APPROVED
        ],
        "the password fill is approved on its own, not leased off the username fill"
    );
}

#[test]
fn a_fill_for_an_item_with_no_username_is_refused_rather_than_answered_empty() {
    let fixture = fixture();
    let mut browser = Browser::launch(&fixture.endpoint);
    browser.hello();

    // "Somewhere else" has a password and no username, and is saved at another origin; the item
    // with no username *here* is the TOTP one's opposite — so use the elsewhere item's origin.
    let matches = browser.call(&Request::Match {
        page: page("https://elsewhere.test"),
    });
    let item_id = match &matches {
        Response::Matches { items, .. } => items[0].item_id.clone(),
        other => panic!("expected matches, got {other:?}"),
    };

    let response = browser.call(&Request::Fill {
        page: page("https://elsewhere.test"),
        item_id,
        fields: vec![FillField::Username],
    });
    match response {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::NoMatch),
        other => panic!("expected a refusal, got {other:?}"),
    }
    browser.close();
}

/// ADR-0035 §14: a login in a shared vault is matched and filled exactly as a personal one —
/// the same origin rule, the same approval — and its fill is recorded in the personal vault's
/// log with the shared vault's id (decision 24). Browser fills a person starts do not depend on
/// agent visibility, for a shared item as for a personal one.
#[test]
fn a_shared_login_is_matched_and_filled_like_a_personal_one() {
    const SHARED_MARKER: &str = "K4G1-SH4R3D-F1LL-9c0b7a2e41d8f365";
    let fixture = fixture();
    let personal_path = fixture._dir.path().join("test.kagivault");
    let device = kagisecure_shared::DeviceSecret::generate().expect("device");
    let key = device.to_device_key("This computer", 1).expect("key");
    fixture
        .handle
        .transact(Duration::from_secs(5), |tx| tx.add_device_key(key, "test"))
        .expect("unlocked")
        .expect("device key");
    let mut replica =
        kagisecure_shared::admin::create::create(&personal_path, &device, "Team", None, 1)
            .expect("shared vault");
    let shared_vault = *replica.vault_id();
    let mut login = Item::new(shared_vault, Category::Login, "Team login");
    login.urls = vec![SITE.to_owned()];
    login.fields.push(Field::public("username", "team"));
    login.fields.push(Field::concealed(
        "password",
        Secret::from_string(SHARED_MARKER.to_owned()),
    ));
    let login_id = login.id.to_string();
    kagisecure_shared::write::put_item(&mut replica, &device, login, 2).expect("login");
    drop(replica);
    let sources = fixture
        .handle
        .with(|vault| kagisecure_agent::ReplicaSource::open_all(&personal_path, vault))
        .expect("unlocked");
    let _attached: Vec<_> = sources
        .into_iter()
        .map(|source| fixture.handle.attach_shared(source))
        .collect();

    let mut browser = Browser::launch(&fixture.endpoint);
    browser.hello();
    let Response::Matches { items, .. } = browser.call(&Request::Match { page: page(SITE) }) else {
        panic!("expected matches")
    };
    assert!(
        items
            .iter()
            .any(|i| i.item_id == login_id && i.title == "Team login"),
        "{items:?}"
    );

    let filled = browser.call(&Request::Fill {
        page: page(SITE),
        item_id: login_id.clone(),
        fields: vec![FillField::Username, FillField::Password],
    });
    match &filled {
        Response::Filled { password, .. } => assert_eq!(
            password.as_ref().expect("a password").expose(),
            SHARED_MARKER
        ),
        other => panic!("expected a fill, got {other:?}"),
    }
    browser.close();

    let entries = fixture
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .expect("unlocked");
    let fill = entries
        .iter()
        .rev()
        .find(|e| e.tool == "fill_credential")
        .expect("a fill entry");
    assert_eq!(fill.vault_id, Some(shared_vault));
    assert!(
        !serde_json::to_string(&entries)
            .expect("json")
            .contains(SHARED_MARKER)
    );
}
