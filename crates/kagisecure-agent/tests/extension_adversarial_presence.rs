//! Adversarial: no secret crosses to a browser without a fresh proof that a human is there.
//!
//! # The attack this file exists for
//!
//! The content script's last gate is `event.isTrusted`, which proves only that page script did not
//! dispatch the event. Input synthesized over the DevTools protocol — what Playwright's
//! `page.mouse.click` sends, and what a browser-automation agent sends — is trusted. So is input
//! injected at the OS level through Quartz events or Accessibility. Before ADR-0037 a live fill
//! lease returned early from the approval path, with no sheet and no LocalAuthentication check, so
//! such an agent could click the in-page icon a minute after the human's first login and receive
//! the password with nobody at the keyboard.
//!
//! What stands in for "nobody at the keyboard" here is a responder thread that answers the real
//! [`ApprovalQueue`] exactly as the app does, and that **denies every presence prompt**: in the
//! app a presence prompt is a `LAContext.evaluatePolicy` sheet, and without a finger, the login
//! password or a watch it can only come back cancelled or unavailable — which the app turns into
//! a denial. An approval that is never raised is visible here as a request that never reached the
//! responder, which is the whole measurement.
//!
//! Everything else is real: the [`ExtensionAgent`], a local socket, the pinned
//! [`kagisecure_extension_ipc::Client`] handshake, an on-disk vault and its audit log. The one
//! boundary that is not real is the browser-ancestry gate, covered with the affordance off in
//! `extension.rs`.

use std::sync::atomic::{AtomicBool, Ordering};
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

/// Seeded as the login's password. If these bytes reach the wire, the audit log or an error
/// message without a fresh human proof, the fix has failed.
const PASSWORD_CANARY: &str = "PR3S-PW-C4N4RY-0d7e2a91c46b58f3";

/// The TOTP seed's secret, asserted absent everywhere.
const TOTP_SEED_CANARY: &str = "JBSWY3DPEHPK3PXP";

/// The origin the item is saved against.
const SITE: &str = "https://presence.example";

struct Fixture {
    _dir: tempfile::TempDir,
    handle: Arc<VaultHandle>,
    agent: ExtensionAgent,
    queue: Arc<ApprovalQueue>,
    endpoint: Endpoint,
    /// A login with a username, a password and a TOTP seed.
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

    let mut item = Item::new(vault_id, Category::Login, "Presence test site");
    item.urls = vec![SITE.to_owned()];
    item.fields.push(Field::public("username", "alice"));
    item.fields.push(Field::concealed(
        "password",
        Secret::from_string(PASSWORD_CANARY.to_owned()),
    ));
    item.fields.push(Field::totp(
        "one-time password",
        Secret::from_string(format!(
            "otpauth://totp/Presence:alice?secret={TOTP_SEED_CANARY}&issuer=Presence"
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

/// The app's side of the queue, with a script for what the person at the keyboard does.
///
/// Every request it takes off the queue is recorded before it is answered, so a test can assert
/// how many approvals a sequence raised and what each said. `decide` returning `None` means
/// "leave it unanswered": the request stays on the queue until something else — a lock, or the
/// 60-second timeout — ends it.
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

    /// A human who reviews every full sheet and allows it for the session — and is **not there**
    /// for any presence prompt. This is the attack: the first login was real, everything after it
    /// is an automation agent clicking the icon.
    fn reviews_once_then_leaves(queue: &Arc<ApprovalQueue>) -> Self {
        Self::new(queue, |request| {
            Some(if request.presence_only {
                Decision::Deny
            } else {
                Decision::AllowSession {
                    ttl_seconds: 300,
                    uses: 1,
                }
            })
        })
    }

    /// A human who is present for everything: sheets are allowed for the session, presence
    /// prompts are confirmed.
    fn always_present(queue: &Arc<ApprovalQueue>) -> Self {
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

    fn approvals(&self) -> Vec<ApprovalRequest> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
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

/// A connected, pinned extension speaking the app socket directly — what the service worker is,
/// from the app's side, whoever is driving the browser.
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
        let id = format!("presence-{}", self.next_id);
        self.client.call(&id, request).expect("call")
    }

    fn fill_in(&mut self, page: PageContext, item_id: &str, fields: &[FillField]) -> Response {
        self.call(&Request::Fill {
            page,
            item_id: item_id.to_owned(),
            fields: fields.to_vec(),
        })
    }

    fn fill(&mut self, item_id: &str, fields: &[FillField]) -> Response {
        self.fill_in(PageContext::top(SITE), item_id, fields)
    }

    fn totp(&mut self, item_id: &str) -> Response {
        self.call(&Request::Totp {
            page: PageContext::top(SITE),
            item_id: item_id.to_owned(),
        })
    }
}

/// Audit `(tool, detail)` pairs, in order.
fn audit(fixture: &Fixture) -> Vec<(String, String)> {
    fixture
        .handle
        .with(|vault| {
            vault
                .audit_entries()
                .iter()
                .map(|e| (e.tool.clone(), e.detail.clone().unwrap_or_default()))
                .collect()
        })
        .unwrap_or_default()
}

fn details(fixture: &Fixture) -> Vec<String> {
    audit(fixture).into_iter().map(|(_, d)| d).collect()
}

fn audit_json(fixture: &Fixture) -> String {
    fixture
        .handle
        .with(|vault| serde_json::to_string(vault.audit_entries()).expect("audit json"))
        .unwrap_or_default()
}

/// Assert a reply, as the bytes the browser would receive, carries nothing secret.
fn assert_carries_no_secret(response: &Response, what: &str) {
    assert!(
        !matches!(
            response,
            Response::Filled { .. } | Response::TotpCode { .. }
        ),
        "{what}: a value-carrying message was sent: {response:?}"
    );
    let wire = serde_json::to_string(response).expect("json");
    assert!(
        !wire.contains(PASSWORD_CANARY),
        "{what}: the password crossed: {wire}"
    );
    assert!(
        !wire.contains("\"password\""),
        "{what}: a password field is on the wire: {wire}"
    );
    assert!(
        !wire.contains(TOTP_SEED_CANARY),
        "{what}: the seed crossed: {wire}"
    );
}

// ---------------------------------------------------------------------------------------------
// The attack
// ---------------------------------------------------------------------------------------------

#[test]
fn a_trusted_click_under_a_live_lease_fills_nothing_without_a_fresh_human_proof() {
    let fixture = fixture();
    let human = Human::reviews_once_then_leaves(&fixture.queue);
    let mut extension = Extension::connect(&fixture.endpoint);
    let fields = [FillField::Username, FillField::Password];

    // The human's own login: a full sheet, "Allow for this session", and the password crosses.
    match extension.fill(&fixture.item_id, &fields) {
        Response::Filled { password, .. } => assert_eq!(
            password.as_ref().expect("a password").expose(),
            PASSWORD_CANARY,
            "precondition: the reviewed fill works"
        ),
        other => panic!("the human's own fill should succeed: {other:?}"),
    }
    assert_eq!(
        fixture.agent.fill_leases().len(),
        1,
        "a review memory exists"
    );

    // The "synthetic click": the same request from the same page, a moment later, with nobody at
    // the keyboard. Before ADR-0037 this returned the password without asking anyone.
    let replayed = extension.fill(&fixture.item_id, &fields);

    let approvals = human.approvals();
    assert_eq!(
        approvals.len(),
        2,
        "the replay must reach the human gate rather than be answered by the lease"
    );
    let (review, presence) = (&approvals[0], &approvals[1]);
    assert!(!review.presence_only, "the first fill was a full review");
    assert!(
        presence.presence_only,
        "the replay is asked as a presence prompt, not waved through"
    );
    assert_eq!(presence.origin, review.origin, "for the same origin");
    assert_eq!(presence.item_id, review.item_id, "for the same item");
    assert_eq!(
        presence.fill_fields, review.fill_fields,
        "for the same fields"
    );
    assert_eq!(presence.origin.as_deref(), Some(SITE));

    match &replayed {
        Response::Error { code, message } => {
            assert_eq!(*code, ErrorCode::UserDenied, "no finger, no fill");
            assert!(!message.contains(PASSWORD_CANARY));
        }
        other => panic!("a fill with no human present crossed a value: {other:?}"),
    }
    assert_carries_no_secret(&replayed, "the replayed fill");

    let details = details(&fixture);
    assert_eq!(
        details,
        vec![
            audit_detail::FILL_APPROVED.to_owned(),
            audit_detail::FILL_DENIED.to_owned()
        ],
        "one reviewed fill, one refused replay"
    );
    assert!(!details.contains(&audit_detail::FILL_CONFIRMED.to_owned()));
    assert!(!details.contains(&audit_detail::FILL_LEASED.to_owned()));
    assert!(!audit_json(&fixture).contains(PASSWORD_CANARY));
}

#[test]
fn a_presence_prompt_nobody_answers_before_the_vault_locks_fills_nothing() {
    let fixture = fixture();
    // The review is answered; the presence prompt is not — the machine goes to sleep or the
    // screen locks under it, which in the app is `AgentService.stop` and `agent_stop` sweeping the
    // queue with the key.
    let handle_for_lock = Arc::clone(&fixture.handle);
    let queue_for_lock = Arc::clone(&fixture.queue);
    let human = Human::new(&fixture.queue, move |request| {
        if request.presence_only {
            drop(handle_for_lock.take());
            queue_for_lock.deny_all();
            None
        } else {
            Some(Decision::AllowSession {
                ttl_seconds: 300,
                uses: 1,
            })
        }
    });
    let mut extension = Extension::connect(&fixture.endpoint);

    assert!(matches!(
        extension.fill(&fixture.item_id, &[FillField::Password]),
        Response::Filled { .. }
    ));

    let replayed = extension.fill(&fixture.item_id, &[FillField::Password]);
    assert_eq!(human.count(), 2, "the replay reached the gate");
    assert!(human.approvals()[1].presence_only);
    match &replayed {
        Response::Error { code, .. } => assert_eq!(*code, ErrorCode::VaultLocked),
        other => panic!("an unanswered presence prompt crossed a value: {other:?}"),
    }
    assert_carries_no_secret(&replayed, "the fill whose vault locked");
    assert!(!fixture.handle.is_unlocked());
    assert!(
        fixture.agent.fill_leases().is_empty(),
        "the lock took the review memory with it"
    );
}

#[test]
fn a_trusted_click_for_the_one_time_code_under_a_live_lease_needs_its_own_touch() {
    let fixture = fixture();
    let human = Human::reviews_once_then_leaves(&fixture.queue);
    let mut extension = Extension::connect(&fixture.endpoint);

    let code = match extension.totp(&fixture.item_id) {
        Response::TotpCode { code, .. } => code.expose().to_owned(),
        other => panic!("the human's own code request should succeed: {other:?}"),
    };
    assert_eq!(code.len(), 6);

    let replayed = extension.totp(&fixture.item_id);
    assert_eq!(
        human.count(),
        2,
        "the replayed code request reached the gate"
    );
    let presence = &human.approvals()[1];
    assert!(presence.presence_only);
    assert_eq!(presence.fill_fields, vec!["one-time password".to_owned()]);
    match &replayed {
        Response::Error { code, .. } => assert_eq!(*code, ErrorCode::UserDenied),
        other => panic!("a one-time code crossed with no human present: {other:?}"),
    }
    assert_carries_no_secret(&replayed, "the replayed code request");

    assert_eq!(
        audit(&fixture),
        vec![
            (
                "totp_code".to_owned(),
                audit_detail::FILL_APPROVED.to_owned()
            ),
            ("totp_code".to_owned(), audit_detail::FILL_DENIED.to_owned()),
        ]
    );
}

#[test]
fn the_password_touch_does_not_pay_for_the_one_time_code() {
    // "TOTP gets its own touch": a presence confirmation for the password, moments ago, is not a
    // presence confirmation for the code. Each crossing is its own `ask`.
    let fixture = fixture();
    let human = Human::always_present(&fixture.queue);
    let mut extension = Extension::connect(&fixture.endpoint);

    extension.fill(&fixture.item_id, &[FillField::Password]);
    extension.fill(&fixture.item_id, &[FillField::Password]);
    extension.totp(&fixture.item_id);
    extension.totp(&fixture.item_id);

    let asked: Vec<(Vec<String>, bool)> = human
        .approvals()
        .into_iter()
        .map(|r| (r.fill_fields, r.presence_only))
        .collect();
    assert_eq!(
        asked,
        vec![
            (vec!["password".to_owned()], false),
            (vec!["password".to_owned()], true),
            (vec!["one-time password".to_owned()], false),
            (vec!["one-time password".to_owned()], true),
        ],
        "four crossings, four prompts: a review and a touch for each secret"
    );
}

// ---------------------------------------------------------------------------------------------
// What a presence confirmation can and cannot do
// ---------------------------------------------------------------------------------------------

#[test]
fn a_presence_confirmation_never_mints_or_extends_a_lease() {
    let fixture = fixture();
    // A UI that answers a presence prompt with "Allow for this session" and the longest TTL there
    // is — a bug, or a compromised app build. The queue must treat it as once.
    let human = Human::new(&fixture.queue, |request| {
        Some(if request.presence_only {
            Decision::AllowSession {
                ttl_seconds: 900,
                uses: 99,
            }
        } else {
            Decision::AllowSession {
                ttl_seconds: 120,
                uses: 1,
            }
        })
    });
    let mut extension = Extension::connect(&fixture.endpoint);

    assert!(matches!(
        extension.fill(&fixture.item_id, &[FillField::Password]),
        Response::Filled { .. }
    ));
    let minted = fixture.agent.fill_leases();
    assert_eq!(minted.len(), 1);
    let expires_at = minted[0].expires_at;

    // Across a second boundary, so an extension would show up as a later `expires_at`.
    std::thread::sleep(Duration::from_millis(1_100));
    assert!(matches!(
        extension.fill(&fixture.item_id, &[FillField::Password]),
        Response::Filled { .. }
    ));
    assert_eq!(human.count(), 2);
    assert!(human.approvals()[1].presence_only);

    let after = fixture.agent.fill_leases();
    assert_eq!(after.len(), 1, "no second lease");
    assert_eq!(
        after[0].expires_at, expires_at,
        "a presence confirmation must not push the review memory's expiry out"
    );
    assert_eq!(
        details(&fixture),
        vec![
            audit_detail::FILL_APPROVED.to_owned(),
            audit_detail::FILL_CONFIRMED.to_owned()
        ]
    );
}

#[test]
fn allow_once_leaves_no_memory_so_the_next_fill_is_a_full_review() {
    let fixture = fixture();
    let human = Human::new(&fixture.queue, |_| Some(Decision::AllowOnce));
    let mut extension = Extension::connect(&fixture.endpoint);

    extension.fill(&fixture.item_id, &[FillField::Password]);
    extension.fill(&fixture.item_id, &[FillField::Password]);
    assert!(fixture.agent.fill_leases().is_empty());
    let presence: Vec<bool> = human.approvals().iter().map(|r| r.presence_only).collect();
    assert_eq!(presence, vec![false, false]);
}

#[test]
fn a_framed_fill_under_a_live_lease_always_gets_the_full_sheet() {
    // A lease minted at a top-level login must not turn a frame of the same origin, embedded in
    // somebody else's page, into a sheet-less prompt: the sheet is what says "inside a frame on
    // another site", and a presence prompt cannot say it.
    let fixture = fixture();
    let human = Human::always_present(&fixture.queue);
    let mut extension = Extension::connect(&fixture.endpoint);

    extension.fill(&fixture.item_id, &[FillField::Password]);
    assert_eq!(fixture.agent.fill_leases().len(), 1);

    let framed = PageContext {
        top_origin: "https://aggregator.example".to_owned(),
        frame_origin: Some(SITE.to_owned()),
        top_origin_established: true,
    };
    extension.fill_in(framed, &fixture.item_id, &[FillField::Password]);

    let unestablished = PageContext {
        top_origin: SITE.to_owned(),
        frame_origin: Some(SITE.to_owned()),
        top_origin_established: false,
    };
    extension.fill_in(unestablished, &fixture.item_id, &[FillField::Password]);

    let asked = human.approvals();
    assert_eq!(asked.len(), 3);
    assert!(
        !asked[1].presence_only,
        "a cross-origin embedder gets the sheet"
    );
    assert_eq!(
        asked[1].top_origin.as_deref(),
        Some("https://aggregator.example")
    );
    assert!(
        !asked[2].presence_only,
        "a top frame the browser did not establish gets the sheet, even when it claims the origin"
    );
    assert!(asked[2].top_origin_unknown);
}

#[test]
fn every_field_set_that_crosses_a_secret_delivers_exactly_one_approval() {
    // With a review memory and without one, each of these requests reaches the queue once — not
    // zero times (the bug), and not twice (a sheet and then a prompt for the same crossing).
    // The username alone crosses nothing and reaches it zero times (ADR-0030).
    let sets: [&[FillField]; 2] = [
        &[FillField::Password],
        &[FillField::Username, FillField::Password],
    ];
    for fields in sets {
        let fixture = fixture();
        let human = Human::always_present(&fixture.queue);
        let mut extension = Extension::connect(&fixture.endpoint);
        for round in 1..=3 {
            let before = human.count();
            let response = extension.fill(&fixture.item_id, fields);
            assert!(
                matches!(response, Response::Filled { .. }),
                "{fields:?}, round {round}: {response:?}"
            );
            assert_eq!(
                human.count(),
                before + 1,
                "{fields:?}, round {round}: one crossing, one approval"
            );
        }
        let presence: Vec<bool> = human.approvals().iter().map(|r| r.presence_only).collect();
        assert_eq!(presence, vec![false, true, true], "{fields:?}");
    }

    let world = fixture();
    let human = Human::always_present(&world.queue);
    let mut extension = Extension::connect(&world.endpoint);
    for round in 1..=3 {
        let before = human.count();
        assert!(matches!(
            extension.totp(&world.item_id),
            Response::TotpCode { .. }
        ));
        assert_eq!(human.count(), before + 1, "one-time code, round {round}");
    }

    let world = fixture();
    let human = Human::always_present(&world.queue);
    let mut extension = Extension::connect(&world.endpoint);
    assert!(matches!(
        extension.fill(&world.item_id, &[FillField::Username]),
        Response::Filled { .. }
    ));
    assert_eq!(human.count(), 0, "a username alone crosses no secret");
}
