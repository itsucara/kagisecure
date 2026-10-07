//! The Safari front end: a second socket, the same protocol, a different gate.
//!
//! What this file can test honestly, and what it cannot:
//!
//! * **Can**: that the Safari socket is a *different* socket, that it refuses a peer which is not
//!   this app's `.appex`, that the Chromium extension id does not pass on it, and that a fill
//!   granted through it produces the same reply and the same audit entry as one granted through
//!   the native-messaging socket. Everything here speaks the app-socket framing directly, which is
//!   exactly what `SafariWebExtensionHandler` does — there is no native messaging host in this
//!   path, so there is no second binary to spawn.
//! * **Cannot**: be the app extension. A test binary's executable is not
//!   `KagisecureSafariExtension.appex/Contents/MacOS/KagisecureSafariExtension`, and there is no
//!   honest way to make it one. So the identity gate is tested with the affordance **off** (the
//!   direction that matters) and everything above it with the affordance on, the same split
//!   `extension.rs` uses for the browser-ancestry gate. The real appex is exercised by
//!   `KagisecureTests/SafariExtensionTransportTests.swift` and by the manual pass in
//!   `docs/browser-extension.md` §8.

use std::sync::Arc;

use kagisecure_agent::approval::ApprovalQueue;
use kagisecure_agent::extension::audit_detail;
use kagisecure_agent::{ExtensionAgent, ExtensionConfig, VaultHandle};
use kagisecure_core::model::{Field, Item, Secret};
use kagisecure_core::proto::Category;
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_extension_ipc::protocol::{ErrorCode, FillField, PageContext, Request, Response};
use kagisecure_extension_ipc::{Client, PINNED_EXTENSION_IDS, SAFARI_EXTENSION_BUNDLE_ID};
use kagisecure_ipc::endpoint::Endpoint;

/// Seeded as the login's password. If it reaches an audit entry the product has failed.
const MARKER: &str = "S4F4R1-F1LL-C4N4RY-7d0a3e6b19c85f24";

/// The origin the item is saved against.
const SITE: &str = "https://safari.example";

struct Fixture {
    _dir: tempfile::TempDir,
    handle: Arc<VaultHandle>,
    agent: ExtensionAgent,
    nm_endpoint: Endpoint,
    safari_endpoint: Endpoint,
    item_id: String,
}

fn fixture(allow_unlaunched_host: bool) -> Fixture {
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

    let mut item = Item::new(vault_id, Category::Login, "Safari test site");
    item.urls = vec![SITE.to_owned()];
    item.fields.push(Field::public("username", "alice"));
    item.fields.push(Field::concealed(
        "password",
        Secret::from_string(MARKER.to_owned()),
    ));
    let item_id = item.id.to_string();
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .expect("save");

    let nm_endpoint = Endpoint::for_instance(dir.path(), "extension.sock");
    let safari_endpoint = Endpoint::for_instance(dir.path(), "safari.sock");
    let handle = VaultHandle::new(vault);
    let agent = ExtensionAgent::start(
        Arc::clone(&handle),
        ExtensionConfig {
            endpoint: Some(nm_endpoint.clone()),
            safari_endpoint: Some(safari_endpoint.clone()),
            auto_approve: true,
            allow_unlaunched_host,
            ..ExtensionConfig::new(Arc::new(ApprovalQueue::new()))
        },
    )
    .expect("extension agent");

    Fixture {
        _dir: dir,
        handle,
        agent,
        nm_endpoint,
        safari_endpoint,
        item_id,
    }
}

/// A stand-in for `SafariWebExtensionHandler`: connect, and speak the app-socket framing.
struct AppExtension {
    client: Client,
    next_id: u64,
}

impl AppExtension {
    fn connect(endpoint: &Endpoint) -> Self {
        Self {
            client: Client::connect(endpoint).expect("connect"),
            next_id: 0,
        }
    }

    fn call(&mut self, request: &Request) -> Response {
        self.next_id += 1;
        let id = format!("safari-{}", self.next_id);
        self.client.call(&id, request).expect("call")
    }

    fn hello_as(&mut self, extension_id: &str) -> Response {
        self.call(&Request::Hello {
            extension_id: extension_id.to_owned(),
            browser: "safari".to_owned(),
            extension_version: "0.1.0".to_owned(),
            protocol_version: kagisecure_extension_ipc::PROTOCOL_VERSION,
            capabilities: vec![],
        })
    }
}

#[test]
fn the_safari_socket_is_a_different_socket_from_the_native_messaging_one() {
    let fixture = fixture(true);
    assert_ne!(fixture.nm_endpoint, fixture.safari_endpoint);
    // A filesystem socket exists as a file; a named pipe does not. What both platforms can say
    // is that the listener reports itself as running on that endpoint.
    if let Some(path) = fixture.safari_endpoint.path() {
        assert!(path.exists(), "the Safari socket is bound");
    }
    let status = fixture.agent.status();
    assert!(status.running);
    assert!(status.safari_running);
    assert_eq!(status.safari_endpoint, fixture.safari_endpoint.to_string());
    assert!(fixture.agent.safari_unavailable().is_none());
}

#[test]
fn a_peer_that_is_not_this_apps_app_extension_is_refused_on_the_safari_socket() {
    // The gate with the test affordance switched **off**. This test binary is not an `.appex`, so
    // this is the production path, exercised by a peer that genuinely is not the extension.
    let fixture = fixture(false);
    let mut peer = AppExtension::connect(&fixture.safari_endpoint);
    match peer.hello_as(SAFARI_EXTENSION_BUNDLE_ID) {
        Response::Error { code, message } => {
            assert_eq!(code, ErrorCode::UntrustedHost);
            assert!(message.contains("Safari extension"), "{message}");
        }
        other => panic!("a stranger was served on the Safari socket: {other:?}"),
    }
    drop(peer);

    let entries = fixture
        .handle
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
fn the_chromium_extension_id_does_not_pass_on_the_safari_socket() {
    let fixture = fixture(true);
    let mut peer = AppExtension::connect(&fixture.safari_endpoint);
    match peer.hello_as(PINNED_EXTENSION_IDS[0]) {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::UnknownExtension),
        other => panic!("the Chromium id was accepted on the Safari socket: {other:?}"),
    }
}

#[test]
fn the_safari_bundle_id_does_not_pass_on_the_native_messaging_socket() {
    let fixture = fixture(true);
    let mut peer = AppExtension::connect(&fixture.nm_endpoint);
    match peer.hello_as(SAFARI_EXTENSION_BUNDLE_ID) {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::UnknownExtension),
        other => panic!("the Safari id was accepted on the native messaging socket: {other:?}"),
    }
}

#[test]
fn a_fill_through_the_safari_socket_carries_the_value_once_and_records_the_origin() {
    let fixture = fixture(true);
    let mut peer = AppExtension::connect(&fixture.safari_endpoint);
    assert!(matches!(
        peer.hello_as(SAFARI_EXTENSION_BUNDLE_ID),
        Response::Welcome { .. }
    ));

    match peer.call(&Request::Match {
        page: PageContext::top(SITE),
    }) {
        Response::Matches { origin, items } => {
            assert_eq!(origin, SITE);
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].item_id, fixture.item_id);
            assert_eq!(items[0].username.as_deref(), Some("alice"));
            assert!(
                !format!("{items:?}").contains(MARKER),
                "a match answer must never carry a value"
            );
        }
        other => panic!("expected matches, got {other:?}"),
    }

    match peer.call(&Request::Fill {
        page: PageContext::top(SITE),
        item_id: fixture.item_id.clone(),
        fields: vec![FillField::Username, FillField::Password],
    }) {
        Response::Filled {
            item_id,
            username,
            password,
            ..
        } => {
            assert_eq!(item_id, fixture.item_id);
            assert_eq!(username.as_deref(), Some("alice"));
            assert_eq!(password.expect("a password").expose(), MARKER);
        }
        other => panic!("expected a fill, got {other:?}"),
    }

    let entries = fixture
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .expect("unlocked");
    let fill = entries
        .iter()
        .find(|e| e.tool == "fill_credential")
        .expect("the fill is recorded");
    assert_eq!(fill.detail.as_deref(), Some(audit_detail::FILL_APPROVED));
    assert_eq!(fill.target_path.as_deref(), Some(SITE));
    // The actor quotes the self-reported id, as everywhere else. It does **not** say "Safari"
    // here: this test process is not the `.appex`, so the app established no browser for it, and
    // an audit entry that named one anyway would be recording a fact nobody checked. On a real
    // Safari connection the same string reads `extension "…" via Safari` — see
    // `KagisecureTests/SafariExtensionTransportTests.swift` and the manual pass.
    assert!(
        fill.actor.contains(SAFARI_EXTENSION_BUNDLE_ID),
        "the audit entry quotes the extension that asked: {}",
        fill.actor
    );
    assert!(
        !format!("{entries:?}").contains(MARKER),
        "no audit entry may contain the password"
    );
}

#[test]
fn a_fill_at_the_wrong_origin_is_refused_on_the_safari_socket_too() {
    let fixture = fixture(true);
    let mut peer = AppExtension::connect(&fixture.safari_endpoint);
    peer.hello_as(SAFARI_EXTENSION_BUNDLE_ID);
    match peer.call(&Request::Fill {
        page: PageContext::top("https://phishing.example"),
        item_id: fixture.item_id.clone(),
        fields: vec![FillField::Password],
    }) {
        Response::Error { code, .. } => assert_eq!(code, ErrorCode::OriginMismatch),
        other => panic!("a mismatched origin was filled: {other:?}"),
    }
}

#[test]
fn a_build_with_no_team_serves_chromium_and_says_why_it_does_not_serve_safari() {
    // The ad-hoc case: no team, so no App Group, so no Safari socket — and, crucially, the
    // Chromium front end still works. A Safari setup that could take autofill down for every
    // other browser would be a poor trade for a feature one browser cannot use.
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
    let agent = ExtensionAgent::start(
        Arc::clone(&handle),
        ExtensionConfig {
            endpoint: Some(Endpoint::for_instance(dir.path(), "extension.sock")),
            safari_endpoint: None,
            team_id: None,
            ..ExtensionConfig::new(Arc::new(ApprovalQueue::new()))
        },
    )
    .expect("agent");

    let status = agent.status();
    assert!(status.running, "Chromium is still served");
    // `KAGISECURE_SAFARI_SOCKET` would override this, and the suite does not set it.
    if std::env::var_os("KAGISECURE_SAFARI_SOCKET").is_none() {
        assert!(!status.safari_running);
        let reason = agent.safari_unavailable().expect("a reason");
        assert!(reason.contains("team identity"), "{reason}");
        assert_eq!(status.safari_endpoint, reason);
    }
}
