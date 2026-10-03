//! Audit before release on the browser channel (ADR-0040 step 8), over the real socket.
//!
//! A fill — a password, a one-time code, or a username alone — is a release: the value leaves in
//! the reply. So the `Allowed` entry recording it is on disk before the reply is written; when it
//! cannot be written the answer is `AUDIT_UNAVAILABLE` and nothing crosses, no fill lease survives,
//! and the refusal is queued for the next write. When entries are already waiting because a write
//! failed, nobody is shown a sheet or a presence prompt for a fill that would then be refused.
//!
//! The same file also pins the trash/archive rule: `fill` and `totp` answer an item in the trash or
//! the archive exactly as they answer an item that does not exist.
//!
//! Unix-only, like `audit_first.rs`: the way a save is broken (a directory where the vault file
//! was) needs a unix `rename(2)` to fail the way a full disk would, and the dropped-connection test
//! speaks the socket directly.
#![cfg(unix)]

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use kagisecure_agent::approval::{ApprovalQueue, ApprovalRequest, ClientVerification, Decision};
use kagisecure_agent::extension::audit_detail;
use kagisecure_agent::{ExtensionAgent, ExtensionConfig, VaultHandle};
use kagisecure_core::audit::AuditEntry;
use kagisecure_core::model::{Field, Item, Secret};
use kagisecure_core::proto::{Category, Outcome};
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_extension_ipc::frame;
use kagisecure_extension_ipc::protocol::{ErrorCode, FillField, PageContext, Request, Response};
use kagisecure_extension_ipc::{Client, PINNED_EXTENSION_IDS};
use kagisecure_ipc::endpoint::Endpoint;
use serde_json::json;

/// The login's password. Must never reach a reply that was refused.
const PASSWORD_CANARY: &str = "AF-PW-C4N4RY-5e0b9d27a31c84f6";

/// The TOTP seed's secret.
const TOTP_SEED_CANARY: &str = "JBSWY3DPEHPK3PXP";

/// The login's username.
const USERNAME: &str = "alice@audit-first.example";

/// The origin every item is saved against.
const SITE: &str = "https://audit-first.example";

struct Fixture {
    dir: tempfile::TempDir,
    handle: Arc<VaultHandle>,
    agent: ExtensionAgent,
    queue: Arc<ApprovalQueue>,
    endpoint: Endpoint,
    /// A login with a username, a password and a TOTP seed.
    item_id: String,
    /// The same kind of login, in the trash.
    trashed_id: String,
    /// The same kind of login, archived.
    archived_id: String,
}

impl Fixture {
    fn path(&self) -> PathBuf {
        self.dir.path().join("test.kagivault")
    }

    fn socket(&self) -> PathBuf {
        self.endpoint.path().expect("a unix socket").to_path_buf()
    }

    fn unsaved(&self) -> usize {
        self.handle
            .with(Vault::unsaved_audit_entries)
            .expect("unlocked")
    }
}

fn login(vault: &Vault, title: &str) -> Item {
    let mut item = Item::new(
        vault.default_vault_id().expect("default vault"),
        Category::Login,
        title,
    );
    item.urls = vec![SITE.to_owned()];
    item.fields.push(Field::public("username", USERNAME));
    item.fields.push(Field::concealed(
        "password",
        Secret::from_string(PASSWORD_CANARY.to_owned()),
    ));
    item.fields.push(Field::totp(
        "one-time password",
        Secret::from_string(format!(
            "otpauth://totp/AuditFirst:alice?secret={TOTP_SEED_CANARY}&issuer=AuditFirst"
        )),
    ));
    item
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

    let item = login(&vault, "Audit-first site");
    let mut trashed = login(&vault, "Audit-first site (trashed)");
    trashed.trashed_at = Some(kagisecure_core::unix_now());
    let mut archived = login(&vault, "Audit-first site (archived)");
    archived.archived = true;
    let (item_id, trashed_id, archived_id) = (
        item.id.to_string(),
        trashed.id.to_string(),
        archived.id.to_string(),
    );
    vault
        .transact(|tx| {
            tx.add_item(item);
            tx.add_item(trashed);
            tx.add_item(archived);
            Ok(())
        })
        .expect("save");

    let endpoint = Endpoint::for_instance(dir.path(), "extension.sock");
    let handle = VaultHandle::new(vault);
    let queue = Arc::new(ApprovalQueue::new());
    let agent = ExtensionAgent::start(
        Arc::clone(&handle),
        ExtensionConfig {
            endpoint: Some(endpoint.clone()),
            auto_approve: false,
            allow_unlaunched_host: true,
            ..ExtensionConfig::new(Arc::clone(&queue))
        },
    )
    .expect("extension agent");

    Fixture {
        dir,
        handle,
        agent,
        queue,
        endpoint,
        item_id,
        trashed_id,
        archived_id,
    }
}

/// The app's side of the queue: records every request, then answers it as `decide` says.
struct Human {
    seen: Arc<Mutex<Vec<ApprovalRequest>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Human {
    fn new(
        queue: &Arc<ApprovalQueue>,
        decide: impl Fn(&ApprovalRequest) -> Option<Decision> + Send + 'static,
    ) -> Self {
        let seen: Arc<Mutex<Vec<ApprovalRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let queue = Arc::clone(queue);
        let thread_seen = Arc::clone(&seen);
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                let Some(request) = queue.next(Duration::from_millis(50)) else {
                    continue;
                };
                thread_seen
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(request.clone());
                if let Some(decision) = decide(&request) {
                    queue.resolve(
                        &request.id,
                        &decision,
                        ClientVerification {
                            verified: false,
                            evidence: "answered by the test's stand-in human".to_owned(),
                        },
                    );
                }
            }
        });
        Self {
            seen,
            stop,
            thread: Some(thread),
        }
    }

    /// Present for everything: sheets allowed for the session, presence prompts confirmed.
    fn present(queue: &Arc<ApprovalQueue>) -> Self {
        Self::new(queue, |request| {
            Some(if request.presence_only {
                Decision::AllowOnce
            } else {
                Decision::AllowSession {
                    ttl_seconds: 300,
                    uses: 1,
                }
            })
        })
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    fn approvals(&self) -> Vec<ApprovalRequest> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Drop for Human {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A connected, pinned extension.
struct Extension {
    client: Client,
    next_id: u64,
}

impl Extension {
    fn connect(endpoint: &Endpoint) -> Self {
        let mut this = Self {
            client: Client::connect(endpoint).expect("connect"),
            next_id: 0,
        };
        match this.call(&Request::Hello {
            extension_id: PINNED_EXTENSION_IDS[0].to_owned(),
            browser: "chrome".to_owned(),
            extension_version: "0.1.0".to_owned(),
            protocol_version: kagisecure_extension_ipc::PROTOCOL_VERSION,
            capabilities: vec![],
        }) {
            Response::Welcome { .. } => this,
            other => panic!("expected a welcome, got {other:?}"),
        }
    }

    fn call(&mut self, request: &Request) -> Response {
        self.next_id += 1;
        let id = format!("audit-first-{}", self.next_id);
        self.client.call(&id, request).expect("call")
    }

    fn fill_at(&mut self, origin: &str, item_id: &str, fields: &[FillField]) -> Response {
        self.call(&Request::Fill {
            page: PageContext::top(origin),
            item_id: item_id.to_owned(),
            fields: fields.to_vec(),
        })
    }

    fn fill(&mut self, item_id: &str, fields: &[FillField]) -> Response {
        self.fill_at(SITE, item_id, fields)
    }

    fn totp_at(&mut self, origin: &str, item_id: &str) -> Response {
        self.call(&Request::Totp {
            page: PageContext::top(origin),
            item_id: item_id.to_owned(),
        })
    }

    fn totp(&mut self, item_id: &str) -> Response {
        self.totp_at(SITE, item_id)
    }
}

/// A directory where the vault file was: every write fails, as on a full disk. Returns the
/// file's bytes, for [`repair`].
fn break_saves(path: &Path) -> Vec<u8> {
    let bytes = std::fs::read(path).expect("read the vault");
    std::fs::remove_file(path).expect("remove the vault file");
    std::fs::create_dir(path).expect("put a directory in its place");
    bytes
}

fn repair(path: &Path, bytes: &[u8]) {
    std::fs::remove_dir(path).expect("remove the directory");
    std::fs::write(path, bytes).expect("put the vault file back");
}

/// The audit log as the file on disk holds it, read by a third party.
fn on_disk(path: &Path) -> Vec<AuditEntry> {
    let vault = Vault::open_with_password(path, b"pw").expect("open the vault file");
    vault.verify_audit().expect("the chain verifies");
    vault.audit_entries().to_vec()
}

fn code_of(response: &Response) -> Option<ErrorCode> {
    match response {
        Response::Error { code, .. } => Some(*code),
        _ => None,
    }
}

/// A reply, as the bytes the browser would receive, carries no value at all.
fn assert_carries_nothing(response: &Response, what: &str) {
    assert!(
        !matches!(
            response,
            Response::Filled { .. } | Response::TotpCode { .. }
        ),
        "{what}: a value-carrying message was sent: {response:?}"
    );
    let wire = serde_json::to_string(response).expect("json");
    for canary in [PASSWORD_CANARY, TOTP_SEED_CANARY, USERNAME] {
        assert!(!wire.contains(canary), "{what}: {canary} crossed: {wire}");
    }
}

// ---------------------------------------------------------------------------------------------
// Fail closed
// ---------------------------------------------------------------------------------------------

#[test]
fn an_approved_fill_whose_entry_cannot_be_written_crosses_nothing_and_keeps_no_lease() {
    let fx = fixture();
    let path = fx.path();
    let human = Human::present(&fx.queue);
    let mut extension = Extension::connect(&fx.endpoint);
    let bytes = break_saves(&path);

    let reply = extension.fill(&fx.item_id, &[FillField::Username, FillField::Password]);

    assert_eq!(
        human.count(),
        1,
        "nothing was waiting, so the human was asked"
    );
    assert_eq!(
        code_of(&reply),
        Some(ErrorCode::AuditUnavailable),
        "{reply:?}"
    );
    assert_carries_nothing(&reply, "the refused fill");
    assert!(
        fx.agent.fill_leases().is_empty(),
        "the human chose Allow for this session, but a fill that could not be recorded leaves \
         no review memory behind"
    );
    assert_eq!(fx.unsaved(), 1, "the refusal is queued, not lost");

    repair(&path, &bytes);
    fx.handle
        .flush(Duration::from_secs(5))
        .expect("unlocked")
        .expect("flushed");
    let entries = on_disk(&path);
    let fills: Vec<&AuditEntry> = entries
        .iter()
        .filter(|e| e.tool == "fill_credential")
        .collect();
    assert_eq!(fills.len(), 1, "{fills:?}");
    assert_eq!(fills[0].outcome, Outcome::Failed);
    assert_eq!(fills[0].detail.as_deref(), Some("AUDIT_UNAVAILABLE"));
    assert_eq!(fills[0].target_path.as_deref(), Some(SITE));
    assert!(
        !serde_json::to_string(&entries)
            .expect("json")
            .contains(PASSWORD_CANARY)
    );

    // Once the log can be written again, the same fill goes through — and is recorded first.
    match extension.fill(&fx.item_id, &[FillField::Password]) {
        Response::Filled { password, .. } => {
            assert_eq!(password.expect("a password").expose(), PASSWORD_CANARY);
        }
        other => panic!("a working log should let the fill through: {other:?}"),
    }
}

#[test]
fn a_username_only_fill_and_a_code_are_releases_too() {
    let fx = fixture();
    let path = fx.path();
    let human = Human::present(&fx.queue);
    let mut extension = Extension::connect(&fx.endpoint);
    let bytes = break_saves(&path);

    // No human for a username alone (ADR-0030), and still no value without a record (ADR-0040).
    let username_only = extension.fill(&fx.item_id, &[FillField::Username]);
    assert_eq!(
        code_of(&username_only),
        Some(ErrorCode::AuditUnavailable),
        "{username_only:?}"
    );
    assert_carries_nothing(&username_only, "the refused username-only fill");
    assert_eq!(human.count(), 0);

    repair(&path, &bytes);
    fx.handle
        .flush(Duration::from_secs(5))
        .expect("unlocked")
        .expect("flushed");
    let bytes = break_saves(&path);

    let code = extension.totp(&fx.item_id);
    assert_eq!(
        code_of(&code),
        Some(ErrorCode::AuditUnavailable),
        "{code:?}"
    );
    assert_carries_nothing(&code, "the refused one-time code");
    assert_eq!(human.count(), 1, "the code was approved, then refused");
    assert!(fx.agent.fill_leases().is_empty());

    repair(&path, &bytes);
    fx.handle
        .flush(Duration::from_secs(5))
        .expect("unlocked")
        .expect("flushed");
    let refused: Vec<(String, Outcome, Option<String>)> = on_disk(&path)
        .into_iter()
        .filter(|e| e.tool == "fill_credential" || e.tool == "totp_code")
        .map(|e| (e.tool, e.outcome, e.detail))
        .collect();
    assert_eq!(
        refused,
        vec![
            (
                "fill_credential".to_owned(),
                Outcome::Failed,
                Some("AUDIT_UNAVAILABLE".to_owned())
            ),
            (
                "totp_code".to_owned(),
                Outcome::Failed,
                Some("AUDIT_UNAVAILABLE".to_owned())
            ),
        ]
    );
}

#[test]
fn a_fill_blocked_by_another_writers_lock_crosses_nothing() {
    let fx = fixture();
    let path = fx.path();
    let _human = Human::present(&fx.queue);
    let mut extension = Extension::connect(&fx.endpoint);

    // Another process takes the write lock and keeps it past the listener's wait.
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        Vault::open_with_password(&holder_path, b"pw")
            .expect("a second process opens the vault")
            .transact(|_| {
                locked_tx.send(()).expect("signal");
                let _ = release_rx.recv_timeout(Duration::from_secs(30));
                Ok(())
            })
            .expect("the holder commits");
    });
    locked_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the holder has the lock");

    let reply = extension.fill(&fx.item_id, &[FillField::Password]);
    release_tx.send(()).expect("release");
    holder.join().expect("holder");

    assert_eq!(
        code_of(&reply),
        Some(ErrorCode::AuditUnavailable),
        "{reply:?}"
    );
    assert_carries_nothing(&reply, "the fill behind another writer's lock");
    assert!(fx.agent.fill_leases().is_empty());
    assert!(fx.unsaved() > 0);
}

// ---------------------------------------------------------------------------------------------
// Pre-flight
// ---------------------------------------------------------------------------------------------

#[test]
fn a_backlog_that_still_cannot_be_written_raises_no_sheet_and_no_presence_prompt() {
    let fx = fixture();
    let path = fx.path();
    let human = Human::present(&fx.queue);
    let mut extension = Extension::connect(&fx.endpoint);

    // A reviewed fill while the log works: a review memory now exists, so the next fill of the
    // same triple would be asked as a presence prompt.
    assert!(matches!(
        extension.fill(&fx.item_id, &[FillField::Password]),
        Response::Filled { .. }
    ));
    assert_eq!(human.count(), 1);
    assert_eq!(fx.agent.fill_leases().len(), 1);

    let bytes = break_saves(&path);
    // A refusal is recorded best-effort and left queued: the backlog.
    let mismatch = extension.fill_at(
        "https://elsewhere.example",
        &fx.item_id,
        &[FillField::Password],
    );
    assert_eq!(code_of(&mismatch), Some(ErrorCode::OriginMismatch));
    assert_eq!(fx.unsaved(), 1);

    // Would be a presence prompt (lease), a full sheet (no lease for these fields), and a code.
    let under_lease = extension.fill(&fx.item_id, &[FillField::Password]);
    let full_sheet = extension.fill(&fx.item_id, &[FillField::Username, FillField::Password]);
    let code = extension.totp(&fx.item_id);

    assert_eq!(
        human.count(),
        1,
        "nobody may be asked for a fill that would then be refused: {:?}",
        human.approvals()
    );
    for (reply, what) in [
        (&under_lease, "under a lease"),
        (&full_sheet, "needing a sheet"),
        (&code, "a one-time code"),
    ] {
        assert_eq!(
            code_of(reply),
            Some(ErrorCode::AuditUnavailable),
            "{what}: {reply:?}"
        );
        assert_carries_nothing(reply, what);
    }
    assert_eq!(
        fx.agent.fill_leases().len(),
        1,
        "the earlier review's memory is not this call's to revoke"
    );

    repair(&path, &bytes);
    fx.handle
        .flush(Duration::from_secs(5))
        .expect("unlocked")
        .expect("flushed");
    let unavailable = on_disk(&path)
        .into_iter()
        .filter(|e| e.detail.as_deref() == Some("AUDIT_UNAVAILABLE"))
        .count();
    assert_eq!(unavailable, 3, "each refusal was recorded");
}

// ---------------------------------------------------------------------------------------------
// Durable before the reply
// ---------------------------------------------------------------------------------------------

#[test]
fn the_allowed_entry_is_on_disk_when_the_reply_arrives() {
    let fx = fixture();
    let path = fx.path();
    let _human = Human::present(&fx.queue);
    let mut extension = Extension::connect(&fx.endpoint);

    for (fields, detail) in [
        (
            vec![FillField::Username, FillField::Password],
            audit_detail::FILL_APPROVED,
        ),
        (
            vec![FillField::Username, FillField::Password],
            audit_detail::FILL_CONFIRMED,
        ),
        (vec![FillField::Username], audit_detail::FILL_USERNAME_ONLY),
    ] {
        let reply = extension.fill(&fx.item_id, &fields);
        assert!(matches!(reply, Response::Filled { .. }), "{reply:?}");
        // Read by a third party the instant the reply is in hand — before this process could
        // have written anything after answering.
        let entries = on_disk(&path);
        let last = entries.last().expect("an entry");
        assert_eq!(last.tool, "fill_credential");
        assert_eq!(last.outcome, Outcome::Allowed);
        assert_eq!(last.detail.as_deref(), Some(detail));
        assert_eq!(last.target_path.as_deref(), Some(SITE));
        assert_eq!(
            last.item_id.map(|id| id.to_string()),
            Some(fx.item_id.clone())
        );
    }

    let reply = extension.totp(&fx.item_id);
    assert!(matches!(reply, Response::TotpCode { .. }), "{reply:?}");
    let last = on_disk(&path).pop().expect("an entry");
    assert_eq!(
        (last.tool.as_str(), last.outcome),
        ("totp_code", Outcome::Allowed)
    );
    assert_eq!(fx.unsaved(), 0, "nothing was left to write after the reply");
}

#[test]
fn a_reply_that_cannot_be_delivered_is_recorded_after_its_allowed_entry() {
    let fx = fixture();
    let path = fx.path();
    let (dropped_tx, dropped_rx) = mpsc::channel::<()>();
    let dropped_rx = Mutex::new(dropped_rx);
    let human = Human::new(&fx.queue, move |_| {
        // The human answers only after the browser side has gone away.
        let _ = dropped_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .recv_timeout(Duration::from_secs(10));
        Some(Decision::AllowOnce)
    });

    let mut stream = UnixStream::connect(fx.socket()).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    frame::write(
        &mut stream,
        &json!({ "ksx": 1, "id": "h", "body": {
            "ask": "hello",
            "extension_id": PINNED_EXTENSION_IDS[0],
            "browser": "chrome",
            "extension_version": "0.1.0",
            "protocol_version": kagisecure_extension_ipc::PROTOCOL_VERSION,
        }}),
    )
    .expect("hello");
    let welcome: serde_json::Value = frame::read(&mut stream).expect("welcome");
    assert_eq!(welcome["body"]["reply"], "welcome");
    frame::write(
        &mut stream,
        &json!({ "ksx": 1, "id": "f", "body": {
            "ask": "fill",
            "page": { "top_origin": SITE },
            "item_id": fx.item_id,
            "fields": ["password"],
        }}),
    )
    .expect("fill");
    // Wait for the sheet to be up, then go away before it is answered.
    let deadline = Instant::now() + Duration::from_secs(10);
    while human.count() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    stream.shutdown(std::net::Shutdown::Both).expect("shutdown");
    drop(stream);
    dropped_tx.send(()).expect("signal");

    let deadline = Instant::now() + Duration::from_secs(10);
    let entries = loop {
        let entries = on_disk(&path);
        if entries.iter().any(|e| {
            e.detail
                .as_deref()
                .is_some_and(|d| d.starts_with("REPLY_FAILED"))
        }) || Instant::now() > deadline
        {
            break entries;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let fills: Vec<&AuditEntry> = entries
        .iter()
        .filter(|e| e.tool == "fill_credential")
        .collect();
    assert_eq!(fills.len(), 2, "{fills:?}");
    assert_eq!(fills[0].outcome, Outcome::Allowed);
    assert_eq!(fills[1].outcome, Outcome::Failed);
    assert_eq!(
        fills[1].detail.as_deref(),
        Some(format!("REPLY_FAILED (entry {})", fills[0].seq).as_str())
    );
}

// ---------------------------------------------------------------------------------------------
// Trash and archive
// ---------------------------------------------------------------------------------------------

#[test]
fn a_trashed_or_archived_item_is_answered_exactly_like_one_that_does_not_exist() {
    let fx = fixture();
    let human = Human::present(&fx.queue);
    let mut extension = Extension::connect(&fx.endpoint);
    let absent = uuid_like_absent_id();
    let audit_before = on_disk(&fx.path()).len();

    type Ask = fn(&mut Extension, &str) -> Response;
    let asks: [(&str, Ask); 6] = [
        ("password fill", |x, id| {
            x.fill(id, &[FillField::Username, FillField::Password])
        }),
        ("username-only fill", |x, id| {
            x.fill(id, &[FillField::Username])
        }),
        ("one-time code", |x, id| x.totp(id)),
        // At a page the item is not saved for: an existing item would be ORIGIN_MISMATCH and an
        // audit entry; a hidden one must still look like nothing at all.
        ("fill elsewhere", |x, id| {
            x.fill_at("https://elsewhere.example", id, &[FillField::Password])
        }),
        ("username elsewhere", |x, id| {
            x.fill_at("https://elsewhere.example", id, &[FillField::Username])
        }),
        ("code elsewhere", |x, id| {
            x.totp_at("https://elsewhere.example", id)
        }),
    ];
    for (what, ask) in asks {
        let for_absent = serde_json::to_string(&ask(&mut extension, &absent)).expect("json");
        assert!(for_absent.contains("NO_MATCH"), "{what}: {for_absent}");
        for (hidden, id) in [("trashed", &fx.trashed_id), ("archived", &fx.archived_id)] {
            let reply = serde_json::to_string(&ask(&mut extension, id)).expect("json");
            assert_eq!(
                reply, for_absent,
                "{what} of a {hidden} item must be indistinguishable from a missing one"
            );
        }
    }
    assert_eq!(human.count(), 0, "nobody is asked about a hidden item");
    assert_eq!(
        on_disk(&fx.path()).len(),
        audit_before,
        "and nothing is recorded that a missing item would not have produced"
    );
    assert!(fx.agent.fill_leases().is_empty());

    // `match` hides them too, which is the rule the fill now shares.
    match extension.call(&Request::Match {
        page: PageContext::top(SITE),
    }) {
        Response::Matches { items, .. } => {
            let ids: Vec<&str> = items.iter().map(|i| i.item_id.as_str()).collect();
            assert_eq!(ids, vec![fx.item_id.as_str()]);
        }
        other => panic!("expected matches, got {other:?}"),
    }
}

#[test]
fn an_item_trashed_while_the_sheet_is_up_is_not_filled() {
    let fx = fixture();
    let path = fx.path();
    let item_id = fx.item_id.clone();
    // The human approves — but another process moved the item to the trash while the sheet was
    // up. The request-start sync saw it live; the release's own transaction must not.
    let _human = Human::new(&fx.queue, move |_| {
        Vault::open_with_password(&path, b"pw")
            .expect("another process opens the vault")
            .transact(|tx| {
                tx.find_item_mut(&item_id)?.trashed_at = Some(kagisecure_core::unix_now());
                Ok(())
            })
            .expect("trashed");
        Some(Decision::AllowSession {
            ttl_seconds: 300,
            uses: 1,
        })
    });
    let mut extension = Extension::connect(&fx.endpoint);
    let absent =
        serde_json::to_string(&extension.fill(&uuid_like_absent_id(), &[FillField::Password]))
            .expect("json");

    let reply = extension.fill(&fx.item_id, &[FillField::Password]);
    assert_carries_nothing(&reply, "a fill of an item trashed under the sheet");
    assert_eq!(serde_json::to_string(&reply).expect("json"), absent);
    assert!(
        fx.agent.fill_leases().is_empty(),
        "a fill that did not happen leaves no review memory"
    );
    let entries = on_disk(&fx.path());
    assert!(
        !entries
            .iter()
            .any(|e| e.tool == "fill_credential" && e.outcome == Outcome::Allowed),
        "no Allowed entry for a fill that did not happen"
    );
    let last = entries.last().expect("an entry");
    assert_eq!(
        (last.tool.as_str(), last.outcome, last.detail.as_deref()),
        ("fill_credential", Outcome::Failed, Some("NO_MATCH"))
    );
}

/// A fill names its item by id and nothing else. A title, an id prefix or an id in another
/// spelling is answered exactly like an id that names nothing — the same reply, nobody asked,
/// nothing recorded — and stays so after a trashed item with the same title appears, which is what
/// used to turn "not found" into "ambiguous" and the lookup into an oracle for the trash.
#[test]
fn a_title_or_id_prefix_is_no_item_even_beside_a_trashed_namesake() {
    let fx = fixture();
    let human = Human::present(&fx.queue);
    let mut extension = Extension::connect(&fx.endpoint);
    let audit_before = on_disk(&fx.path()).len();

    type Ask = fn(&mut Extension, &str) -> Response;
    let asks: [(&str, Ask); 3] = [
        ("password fill", |x, id| {
            x.fill(id, &[FillField::Username, FillField::Password])
        }),
        ("username-only fill", |x, id| {
            x.fill(id, &[FillField::Username])
        }),
        ("one-time code", |x, id| x.totp(id)),
    ];
    let references = [
        "Audit-first site".to_owned(),
        fx.item_id[..8].to_owned(),
        fx.item_id.to_uppercase(),
        format!("{{{}}}", fx.item_id),
    ];
    let answers = |extension: &mut Extension| -> Vec<String> {
        let mut out = Vec::new();
        for (what, ask) in asks {
            let absent =
                serde_json::to_string(&ask(extension, &uuid_like_absent_id())).expect("json");
            assert!(absent.contains("NO_MATCH"), "{what}: {absent}");
            for reference in &references {
                let reply = serde_json::to_string(&ask(extension, reference)).expect("json");
                assert_eq!(
                    reply, absent,
                    "{what} by {reference:?} must be answered like an item that does not exist"
                );
                out.push(reply);
            }
        }
        out
    };
    let alone = answers(&mut extension);

    // A trashed namesake of the live item. Through a title lookup, this is what made the same
    // request answer "ambiguous" instead of "not found".
    fx.handle
        .transact(Duration::from_secs(5), |tx| {
            let vault_id = tx.default_vault_id()?;
            let mut namesake = Item::new(vault_id, Category::Login, "Audit-first site");
            namesake.urls = vec![SITE.to_owned()];
            namesake.trashed_at = Some(kagisecure_core::unix_now());
            tx.add_item(namesake);
            Ok(())
        })
        .expect("unlocked")
        .expect("saved");
    let with_namesake = answers(&mut extension);
    assert_eq!(
        alone, with_namesake,
        "a trashed item with the same title must change nothing a request can observe"
    );

    assert_eq!(
        human.count(),
        0,
        "nobody is asked about something that is not an id"
    );
    let entries = on_disk(&fx.path());
    assert!(
        entries[audit_before..]
            .iter()
            .all(|e| e.tool != "fill_credential" && e.tool != "totp_code"),
        "and nothing is recorded that a missing item would not have produced"
    );

    // A fill by the id itself still works (a username alone: no sheet), and its entry names the
    // item by that id.
    let reply = extension.fill(&fx.item_id, &[FillField::Username]);
    assert!(matches!(reply, Response::Filled { .. }), "{reply:?}");
    let last = on_disk(&fx.path()).pop().expect("an entry");
    assert_eq!(last.tool, "fill_credential");
    assert_eq!(
        last.item_id.map(|id| id.to_string()),
        Some(fx.item_id.clone())
    );
}

/// An item id nothing in the fixture has.
fn uuid_like_absent_id() -> String {
    let fixture_vault_id = kagisecure_core::model::VaultId::new();
    Item::new(fixture_vault_id, Category::Login, "absent")
        .id
        .to_string()
}
