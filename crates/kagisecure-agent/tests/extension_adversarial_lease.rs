//! Adversarial: what a fill lease is allowed to excuse, and what it must not.
//!
//! The extension channel is the one channel that carries a secret value, and a live fill lease is
//! the one thing that lets a value cross without the full sheet — never without a fresh biometric
//! since ADR-0037, which `extension_adversarial_presence.rs` holds. So the interesting question
//! here is **how far one lease's review reaches**: across a different secret on the same item,
//! across a mutation of the item made while the sheet was up, and across a vault lock that lands
//! between the human's answer and the read of the field. A request the lease reaches is asked as
//! presence-only; one it does not reach gets the full sheet, and the assertions below tell the two
//! apart by `ApprovalRequest::presence_only` rather than by counting alone.
//!
//! Everything here drives the real [`ExtensionAgent`] over a real local socket with the real
//! [`kagisecure_extension_ipc::Client`], against a real on-disk vault. The only thing standing in
//! for a human is a responder thread that answers the real [`ApprovalQueue`] through
//! `resolve`, exactly as the app's sheet does — so an approval that is never raised is visible
//! here as a request that was never delivered, which is the whole measurement.
//!
//! The one boundary that is *not* real is the browser-ancestry gate: a test binary's parent is
//! `cargo`. That gate is covered with the affordance off in `extension.rs`; here it is on, so
//! that the code above it can be reached at all.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kagisecure_agent::approval::{ApprovalQueue, ApprovalRequest, ClientVerification, Decision};
use kagisecure_agent::extension::audit_detail;
use kagisecure_agent::{ExtensionAgent, ExtensionConfig, VaultHandle};
use kagisecure_core::model::{Field, Item, Secret};
use kagisecure_core::proto::Category;
use kagisecure_core::vault::{CreateOptions, Vault};
use kagisecure_extension_ipc::protocol::{ErrorCode, FillField, PageContext, Request, Response};
use kagisecure_extension_ipc::{Client, PINNED_EXTENSION_IDS};
use kagisecure_ipc::endpoint::Endpoint;

/// Seeded as the login's password. If these bytes reach an audit entry, a lease decision or an
/// error message, the product has failed at the one thing it exists to do.
const PASSWORD_CANARY: &str = "L34SE-PW-C4N4RY-51f0c8a37b2d94e6";

/// The TOTP seed's own canary lives in the generated code, which changes every 30 seconds, so the
/// seed string is the thing asserted absent instead.
const TOTP_SEED_CANARY: &str = "JBSWY3DPEHPK3PXP";

/// The origin both items are saved against.
const SITE: &str = "https://lease.example";

/// The origin an attacker's page would be served from.
const OTHER_SITE: &str = "https://attacker.example";

struct Fixture {
    _dir: tempfile::TempDir,
    handle: Arc<VaultHandle>,
    agent: ExtensionAgent,
    queue: Arc<ApprovalQueue>,
    endpoint: Endpoint,
    /// A login with a password *and* a TOTP seed: the item that makes the scoping question real.
    item_id: String,
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

    let mut item = Item::new(vault_id, Category::Login, "Lease test site");
    item.urls = vec![SITE.to_owned()];
    item.fields.push(Field::public("username", "alice"));
    item.fields.push(Field::concealed(
        "password",
        Secret::from_string(PASSWORD_CANARY.to_owned()),
    ));
    item.fields.push(Field::totp(
        "one-time password",
        Secret::from_string(format!(
            "otpauth://totp/Lease:alice?secret={TOTP_SEED_CANARY}&issuer=Lease"
        )),
    ));
    let item_id = item.id.to_string();
    vault
        .transact(|tx| {
            tx.add_item(item);
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
        _dir: dir,
        handle,
        agent,
        queue,
        endpoint,
        item_id,
    }
}

/// A stand-in for the human at the sheet that also keeps the receipts.
///
/// Every request it answers is recorded, so a test can assert *how many* approvals a sequence
/// raised and what each one said it was for. A lease that silently covers a second kind of secret
/// shows up here as a missing entry rather than as a passing test.
struct Human {
    seen: Arc<Mutex<Vec<ApprovalRequest>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Human {
    /// Answer every approval with the given decision, forever, on a background thread.
    fn answering(queue: &Arc<ApprovalQueue>, decision: Decision) -> Self {
        Self::answering_with(queue, move |_| decision.clone())
    }

    fn answering_with(
        queue: &Arc<ApprovalQueue>,
        decide: impl Fn(&ApprovalRequest) -> Decision + Send + 'static,
    ) -> Self {
        let seen: Arc<Mutex<Vec<ApprovalRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let queue = Arc::clone(queue);
        let thread_seen = Arc::clone(&seen);
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                let Some(request) = queue.next(Duration::from_millis(50)) else {
                    continue;
                };
                let decision = decide(&request);
                thread_seen
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(request.clone());
                queue.resolve(
                    &request.id,
                    &decision,
                    ClientVerification {
                        verified: false,
                        evidence: "answered by the test's stand-in human".to_owned(),
                    },
                );
            }
        });
        Self {
            seen,
            stop,
            thread: Some(thread),
        }
    }

    fn approvals(&self) -> Vec<ApprovalRequest> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
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

/// A connected, pinned extension speaking the app socket directly.
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
        let id = format!("adv-{}", self.next_id);
        self.client.call(&id, request).expect("call")
    }

    fn fill(&mut self, origin: &str, item_id: &str, fields: &[FillField]) -> Response {
        self.call(&Request::Fill {
            page: PageContext::top(origin),
            item_id: item_id.to_owned(),
            fields: fields.to_vec(),
        })
    }

    fn totp(&mut self, origin: &str, item_id: &str) -> Response {
        self.call(&Request::Totp {
            page: PageContext::top(origin),
            item_id: item_id.to_owned(),
        })
    }
}

fn audit_json(fixture: &Fixture) -> String {
    let entries = fixture
        .handle
        .with(|vault| vault.audit_entries().to_vec())
        .unwrap_or_default();
    serde_json::to_string(&entries).expect("audit json")
}

fn details(fixture: &Fixture) -> Vec<String> {
    fixture
        .handle
        .with(|vault| {
            vault
                .audit_entries()
                .iter()
                .filter_map(|e| e.detail.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// D-3 / B-01, B-02: the lease is keyed on (origin, item_id) and carries no field set.
// ---------------------------------------------------------------------------

#[test]
// FIXED (D-3): a fill lease now carries the approved field names and covers nothing else.
// UNVERIFIED — this machine cannot run test binaries.
fn a_password_lease_does_not_also_release_the_one_time_code() {
    let fixture = fixture();
    let human = Human::answering(
        &fixture.queue,
        Decision::AllowSession {
            ttl_seconds: 300,
            uses: 1,
        },
    );
    let mut extension = Extension::connect(&fixture.endpoint);

    // The user approves a password fill, for this item, at this origin, and chooses
    // "Allow for this session" — which mints a lease.
    let filled = extension.fill(SITE, &fixture.item_id, &[FillField::Password]);
    assert!(
        matches!(filled, Response::Filled { .. }),
        "the approved password fill should succeed: {filled:?}"
    );
    assert_eq!(human.count(), 1, "the password fill raised one approval");
    let first = &human.approvals()[0];
    assert_eq!(
        first.fill_fields,
        vec!["password".to_owned()],
        "the sheet named the password and only the password"
    );
    assert_eq!(fixture.agent.fill_leases().len(), 1, "a lease was minted");

    // The same item, the same origin, a *different secret*. The user has approved nothing about
    // the one-time code, and the sheet that would ask about it says "one-time password", not
    // "password" — so this must raise a fresh approval.
    let code = extension.totp(SITE, &fixture.item_id);
    assert!(
        matches!(code, Response::TotpCode { .. }),
        "precondition: the item has a working one-time password: {code:?}"
    );
    assert_eq!(
        human.count(),
        2,
        "a one-time code is a different secret from a password: approving one must not release \
         the other under the same lease"
    );
    assert_eq!(
        human.approvals()[1].fill_fields,
        vec!["one-time password".to_owned()],
        "the second sheet names the one-time password"
    );
    assert!(
        !human.approvals()[1].presence_only,
        "and it is the full sheet: the password's review says nothing about the code"
    );
    assert!(
        !details(&fixture).contains(&audit_detail::FILL_LEASED.to_owned()),
        "no crossing here was authorized by a lease"
    );
    assert!(
        !details(&fixture).contains(&audit_detail::FILL_CONFIRMED.to_owned()),
        "nor confirmed under one: both crossings were full reviews"
    );
}

#[test]
// FIXED (D-3), the other direction. UNVERIFIED — never executed.
fn a_one_time_code_lease_does_not_also_release_the_password() {
    let fixture = fixture();
    let human = Human::answering(
        &fixture.queue,
        Decision::AllowSession {
            ttl_seconds: 300,
            uses: 1,
        },
    );
    let mut extension = Extension::connect(&fixture.endpoint);

    let code = extension.totp(SITE, &fixture.item_id);
    assert!(
        matches!(code, Response::TotpCode { .. }),
        "the approved TOTP request should succeed: {code:?}"
    );
    assert_eq!(human.count(), 1);

    let filled = extension.fill(SITE, &fixture.item_id, &[FillField::Password]);
    assert_eq!(
        human.count(),
        2,
        "approving a one-time code must not release the password under the same lease"
    );
    assert!(
        !human.approvals()[1].presence_only,
        "the password gets its own full sheet, not a presence prompt borrowed from the code"
    );
    if let Response::Filled { password, .. } = &filled {
        assert!(
            password.is_some(),
            "once a second approval is raised and granted, the password may cross"
        );
    }
}

#[test]
fn a_lease_never_reaches_a_second_item_or_a_second_origin() {
    // The narrow half of the same key: the parts that *are* scoped correctly today. Kept
    // un-ignored so a future widening of the key — "one lease per origin" — fails here loudly.
    let fixture = fixture();
    let human = Human::answering(
        &fixture.queue,
        Decision::AllowSession {
            ttl_seconds: 300,
            uses: 1,
        },
    );
    let mut extension = Extension::connect(&fixture.endpoint);

    extension.fill(SITE, &fixture.item_id, &[FillField::Password]);
    assert_eq!(human.count(), 1);

    // A second origin for the same item: refused by the origin rule before any human is asked,
    // so the lease is not even reached.
    match extension.fill(OTHER_SITE, &fixture.item_id, &[FillField::Password]) {
        Response::Error { code, message } => {
            assert_eq!(code, ErrorCode::OriginMismatch);
            assert!(
                !message.contains(PASSWORD_CANARY),
                "a refusal must not quote the value"
            );
        }
        other => panic!("a fill at another origin must be refused: {other:?}"),
    }
    assert_eq!(
        human.count(),
        1,
        "an origin mismatch is never a question for a human"
    );

    // A second item at the same origin is a second decision.
    let second_id = fixture
        .handle
        .with_mut(|vault| {
            let vault_id = vault.default_vault_id().expect("default vault");
            let mut other = Item::new(vault_id, Category::Login, "Second account");
            other.urls = vec![SITE.to_owned()];
            other.fields.push(Field::public("username", "bob"));
            other.fields.push(Field::concealed(
                "password",
                Secret::from_string("second-account-password".to_owned()),
            ));
            let id = other.id.to_string();
            vault
                .transact(|tx| {
                    tx.add_item(other);
                    Ok(())
                })
                .expect("save");
            id
        })
        .expect("unlocked");

    extension.fill(SITE, &second_id, &[FillField::Password]);
    assert_eq!(
        human.count(),
        2,
        "a second account at the same site is a second fingerprint"
    );
    assert!(
        !human.approvals()[1].presence_only,
        "and a second full review, not a presence prompt under the first account's lease"
    );
}

// ---------------------------------------------------------------------------
// B-26: the expiry comparison is strict, so `now == expires_at` is already dead.
// ---------------------------------------------------------------------------

#[test]
fn a_lease_granted_for_the_shortest_possible_life_is_not_reusable_after_it() {
    // The store compares `expires_at > now`, so the instant of expiry refuses. Driving that
    // through the socket means granting a one-second lease and asking again after it: a second
    // approval must be raised rather than the dead lease answering.
    let fixture = fixture();
    let human = Human::answering(
        &fixture.queue,
        Decision::AllowSession {
            ttl_seconds: 1,
            uses: 1,
        },
    );
    let mut extension = Extension::connect(&fixture.endpoint);

    extension.fill(SITE, &fixture.item_id, &[FillField::Password]);
    assert_eq!(human.count(), 1);

    // Past the whole second, including the boundary instant itself.
    std::thread::sleep(Duration::from_millis(1_300));
    assert_eq!(
        fixture.agent.fill_leases().len(),
        0,
        "an expired lease does not appear in the leases table"
    );

    extension.fill(SITE, &fixture.item_id, &[FillField::Password]);
    assert_eq!(
        human.count(),
        2,
        "once the lease has expired the next fill asks again"
    );
    assert!(
        !human.approvals()[1].presence_only,
        "with the full sheet: a dead lease is no memory of a review"
    );
}

// ---------------------------------------------------------------------------
// B-24: the vault locks between the human's answer and the read of the field.
// ---------------------------------------------------------------------------

#[test]
// FIXED (B-24): the lease is minted only while the vault is still unlocked, under the store's
// own lock. UNVERIFIED — never executed.
fn a_vault_that_locks_while_the_sheet_is_up_yields_no_value_and_no_surviving_lease() {
    let fixture = fixture();
    // The human presses "Allow for this session" — but the vault locks first, in the same
    // instant, which is what a screen lock or a sleep does under a sheet that is already up.
    let handle_for_lock = Arc::clone(&fixture.handle);
    let human = Human::answering_with(&fixture.queue, move |_| {
        drop(handle_for_lock.take());
        Decision::AllowSession {
            ttl_seconds: 300,
            uses: 1,
        }
    });
    let mut extension = Extension::connect(&fixture.endpoint);

    let response = extension.fill(SITE, &fixture.item_id, &[FillField::Password]);
    assert_eq!(human.count(), 1, "the approval was raised and answered");
    match &response {
        Response::Error { code, message } => {
            assert_eq!(
                *code,
                ErrorCode::VaultLocked,
                "a fill whose vault locked under it must say so"
            );
            assert!(!message.contains(PASSWORD_CANARY));
        }
        other => panic!("a locked vault must not fill: {other:?}"),
    }
    assert!(
        !serde_json::to_string(&response)
            .expect("json")
            .contains(PASSWORD_CANARY),
        "no value may cross after the vault has gone"
    );
    assert!(!fixture.handle.is_unlocked(), "the vault is locked");
    assert_eq!(
        fixture.agent.fill_leases().len(),
        0,
        "a lease minted after the key was taken away is a lease over nothing, and must not \
         outlive the lock"
    );
}

// ---------------------------------------------------------------------------
// B-04: the item is re-read after the approval; what if it changed while the sheet was up?
// ---------------------------------------------------------------------------

#[test]
fn an_item_whose_websites_change_while_the_sheet_is_up_does_not_fill_the_page_it_no_longer_covers()
{
    let fixture = fixture();
    // While the human is looking at a sheet that says "Lease test site — https://lease.example",
    // the item's saved websites are rewritten to point somewhere else entirely. The question is
    // whether the value that crosses still belongs to the item-and-origin pair on the sheet.
    let handle_for_edit = Arc::clone(&fixture.handle);
    let item_id = fixture.item_id.clone();
    let human = Human::answering_with(&fixture.queue, move |_| {
        handle_for_edit.with_mut(|vault| {
            let _ = vault.transact(|tx| {
                if let Ok(item) = tx.find_item_mut(&item_id) {
                    item.urls = vec![OTHER_SITE.to_owned()];
                }
                Ok(())
            });
        });
        Decision::AllowSession {
            ttl_seconds: 300,
            uses: 1,
        }
    });
    let mut extension = Extension::connect(&fixture.endpoint);

    let response = extension.fill(SITE, &fixture.item_id, &[FillField::Password]);
    assert_eq!(human.count(), 1);

    // Either answer is defensible; filling something *else* is not. What must hold is that the
    // value, if one crossed, is the password of the item the sheet named, and that the audit
    // entry records the origin the sheet showed.
    match &response {
        Response::Filled {
            item_id, password, ..
        } => {
            assert_eq!(item_id, &fixture.item_id, "the item on the sheet");
            assert_eq!(
                password.as_ref().expect("a password").expose(),
                PASSWORD_CANARY,
                "the value must be the one belonging to the item that was approved"
            );
            let fills = fixture
                .handle
                .with(|vault| {
                    vault
                        .audit_entries()
                        .iter()
                        .filter(|e| e.tool == "fill_credential")
                        .map(|e| e.target_path.clone())
                        .collect::<Vec<_>>()
                })
                .expect("unlocked");
            assert_eq!(
                fills,
                vec![Some(SITE.to_owned())],
                "the audit entry names the origin the human was shown"
            );
        }
        Response::Error { code, message } => {
            assert_eq!(*code, ErrorCode::OriginMismatch);
            assert!(!message.contains(PASSWORD_CANARY));
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert!(!audit_json(&fixture).contains(PASSWORD_CANARY));
}

#[test]
fn an_item_whose_password_changes_while_the_sheet_is_up_never_fills_another_items_secret() {
    let fixture = fixture();
    // A hostile edit during the approval window cannot make *another* item's value cross, because
    // the item id was fixed before the sheet went up. It can change this item's own password, and
    // the honest answer is the value at the moment of the crossing — but it must be a value of
    // this item, and it must never be the TOTP seed.
    const ROTATED: &str = "ROT4TED-DUR1NG-THE-SHEET-9c4e0b71";
    let handle_for_edit = Arc::clone(&fixture.handle);
    let item_id = fixture.item_id.clone();
    let human = Human::answering_with(&fixture.queue, move |_| {
        handle_for_edit.with_mut(|vault| {
            let _ = vault.transact(|tx| {
                if let Ok(item) = tx.find_item_mut(&item_id)
                    && let Some(field) = item
                        .fields
                        .iter_mut()
                        .find(|f| f.label.eq_ignore_ascii_case("password"))
                {
                    *field = Field::concealed("password", Secret::from_string(ROTATED.to_owned()));
                }
                Ok(())
            });
        });
        Decision::AllowOnce
    });
    let mut extension = Extension::connect(&fixture.endpoint);

    let response = extension.fill(SITE, &fixture.item_id, &[FillField::Password]);
    assert_eq!(human.count(), 1, "one crossing, one approval");
    match &response {
        Response::Filled { password, .. } => {
            let crossed = password.as_ref().expect("a password").expose().to_owned();
            assert!(
                crossed == ROTATED || crossed == PASSWORD_CANARY,
                "the value must be one of this item's own passwords, got something else"
            );
            assert_ne!(
                crossed, TOTP_SEED_CANARY,
                "a TOTP seed must never be filled into a password box"
            );
        }
        Response::Error { message, .. } => {
            assert!(!message.contains(PASSWORD_CANARY));
            assert!(!message.contains(ROTATED));
        }
        other => panic!("unexpected: {other:?}"),
    }

    let json = audit_json(&fixture);
    assert!(!json.contains(PASSWORD_CANARY));
    assert!(!json.contains(ROTATED));
    assert!(!json.contains(TOTP_SEED_CANARY));
}

// ---------------------------------------------------------------------------
// B-05: the item is renamed while the sheet is up.
// ---------------------------------------------------------------------------

#[test]
fn a_rename_during_the_approval_window_does_not_make_the_audit_entry_name_something_else() {
    let fixture = fixture();
    const IMPOSTOR_TITLE: &str = "Totally Different Bank";
    let handle_for_edit = Arc::clone(&fixture.handle);
    let item_id = fixture.item_id.clone();
    let human = Human::answering_with(&fixture.queue, move |_| {
        handle_for_edit.with_mut(|vault| {
            let _ = vault.transact(|tx| {
                if let Ok(item) = tx.find_item_mut(&item_id) {
                    item.title = IMPOSTOR_TITLE.to_owned();
                }
                Ok(())
            });
        });
        Decision::AllowSession {
            ttl_seconds: 300,
            uses: 1,
        }
    });
    let mut extension = Extension::connect(&fixture.endpoint);

    extension.fill(SITE, &fixture.item_id, &[FillField::Password]);
    assert_eq!(human.count(), 1);
    assert_eq!(
        human.approvals()[0].item_title.as_deref(),
        Some("Lease test site"),
        "the sheet was raised with the title the item had when it was raised"
    );

    // The lease is the durable record of that decision, and it is what the Leases table shows the
    // user afterwards. It must not have acquired the impostor's name.
    let leases = fixture.agent.fill_leases();
    assert_eq!(leases.len(), 1);
    assert_eq!(
        leases[0].item_title, "Lease test site",
        "the leases table must name what the human agreed to, not what the item was renamed to \
         while they were agreeing"
    );

    // The audit entry identifies the item by id, which a rename cannot move.
    let fills = fixture
        .handle
        .with(|vault| {
            vault
                .audit_entries()
                .iter()
                .filter(|e| e.tool == "fill_credential")
                .map(|e| e.item_id.map(|i| i.to_string()))
                .collect::<Vec<_>>()
        })
        .expect("unlocked");
    assert_eq!(fills, vec![Some(fixture.item_id.clone())]);
}
