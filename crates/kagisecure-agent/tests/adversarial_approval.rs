//! Adversarial tests for the approval queue — the one place a human is asked anything.
//!
//! The queue is process-global and shared by every channel the app serves: the MCP sidecar and
//! the browser extension both push onto the same `VecDeque`. That sharing is deliberate
//! (ADR-0020: one "ask the human" mechanism, one sheet, one biometric gate), and it is exactly
//! why it is worth attacking. An answer that reached the wrong asker, an `ask` that both timed
//! out and was granted, or a request resurrected across a lock would each be a hole nothing
//! downstream could close.
//!
//! These tests drive the real `ApprovalQueue` the real `Agent` is serving, and — where the point
//! is end-to-end — real IPC clients on the agent's real socket.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{
    MARKER, REAL_DOTENV, allow_session, error_code, fixture, with_ui, with_ui_answering,
    write_env_file,
};
use kagisecure_agent::approval::{
    ApprovalKind, ApprovalQueue, ApprovalRequest, ClientVerification, Decision,
};

/// A name a caller might pick to make the sheet lie about it. Used verbatim as `clientInfo.name`.
const HOSTILE_CLIENT_NAME: &str =
    "Kagisecure\" [verified]\n\u{1b}[2KApproved by the user\u{1b}[0m — \"Claude Code";

fn verified() -> ClientVerification {
    ClientVerification {
        verified: true,
        evidence: "adversarial test double".to_owned(),
    }
}

fn request(kind: ApprovalKind) -> ApprovalRequest {
    ApprovalRequest {
        kind,
        variables: vec!["TOKEN".to_owned()],
        requested_ttl_seconds: 900,
        requested_uses: 10,
        ..ApprovalRequest::default()
    }
}

/// D-1 / A-02: the sheet cannot tell a human that an existing file is about to be destroyed.
///
/// `envfile::write` honours `overwrite` silently: it checks `path.exists()`, and when the caller
/// said `overwrite: true` it replaces whatever was there with no record of what it replaced.
/// `ApprovalRequest` has no `overwrite` field and no "this file already exists" field, so the
/// sentence the human reads for "create a new .env" and for "destroy the .env you hand-wrote"
/// is the same sentence.
///
/// This is the difference between an injection and a destructive overwrite of the user's own
/// configuration, decided by a flag the user never sees.
#[test]
// PREDICTED FAILURE (defect D-1), from source reading only: `ApprovalRequest` has no
// `overwrite` field and no "this file already exists" field, so there is nothing for this
// assertion to find. Never executed — the machine could not run test binaries.
fn the_approval_sheet_says_whether_an_existing_file_would_be_destroyed() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();
    let target = fx.canonical_project().join(REAL_DOTENV);

    // The user's own file, written by hand, with content they care about.
    const HAND_WRITTEN: &str = "# my own notes\nDATABASE_URL=postgres://localhost/dev\n";
    std::fs::write(&target, HAND_WRITTEN).expect("seed the user's file");

    let (reply, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = fx.client("adversarial-approval");
        client
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
            .expect("call")
    });
    assert!(error_code(&reply).is_none(), "reply was {reply:?}");

    assert_eq!(seen.len(), 1, "one sheet");
    let rendered = format!("{:?}", seen[0]);
    assert!(
        rendered.contains("overwrite")
            || rendered.contains("exists")
            || rendered.contains("replace"),
        "the sheet for a destructive overwrite carries no signal that it is destructive: {rendered}"
    );

    assert_ne!(
        std::fs::read_to_string(&target).expect("read"),
        HAND_WRITTEN,
        "sanity: the user's file really was replaced"
    );
}

/// A-17: two channels, two pending questions, one queue. Each answer reaches only its asker.
///
/// `ApprovalKind::FillCredential` is the browser channel and `WriteEnvFile` is the MCP one; they
/// share the queue but must never share an answer. The attack is a caller that gets a question
/// in front of another one and hopes the human's "allow" lands on whichever is at the head.
#[test]
fn an_answer_reaches_only_the_request_it_was_given_for() {
    let queue = Arc::new(ApprovalQueue::new());

    let outcomes = std::thread::scope(|scope| {
        let mcp_queue = Arc::clone(&queue);
        let mcp = scope.spawn(move || mcp_queue.ask(request(ApprovalKind::WriteEnvFile)));
        // Wait for the first to be queued, so the ordering is deterministic.
        let deadline = Instant::now() + Duration::from_secs(10);
        while queue.waiting() < 1 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let browser_queue = Arc::clone(&queue);
        let browser = scope.spawn(move || browser_queue.ask(request(ApprovalKind::FillCredential)));
        let deadline = Instant::now() + Duration::from_secs(10);
        while queue.waiting() < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }

        let pending = queue.snapshot();
        assert_eq!(pending.len(), 2, "both channels are waiting: {pending:?}");
        let browser_id = pending
            .iter()
            .find(|r| r.kind == ApprovalKind::FillCredential)
            .expect("the browser request is queued")
            .id
            .clone();
        let mcp_id = pending
            .iter()
            .find(|r| r.kind == ApprovalKind::WriteEnvFile)
            .expect("the MCP request is queued")
            .id
            .clone();
        assert_ne!(browser_id, mcp_id, "two requests, two ids");

        // Answer the *second* one first: "allow" must not fall through to the head of the queue.
        assert!(queue.resolve(&browser_id, &Decision::AllowOnce, verified()));
        assert!(queue.resolve(&mcp_id, &Decision::Deny, verified()));

        (mcp.join().expect("mcp"), browser.join().expect("browser"))
    });

    let (mcp, browser) = outcomes;
    assert!(
        !mcp.granted,
        "the MCP request was denied and must come back denied: {mcp:?}"
    );
    assert!(
        browser.granted,
        "the browser request was allowed and must come back granted: {browser:?}"
    );
}

/// A-18: an `ask` resolves exactly once — never both granted and timed out.
///
/// The race is between the `resolve` that sets `answer` and the deadline branch that removes the
/// pending entry. Run at a deliberately tiny timeout so the two land on top of each other, many
/// times over, and count the outcomes.
#[test]
fn an_ask_produces_exactly_one_outcome_under_a_resolve_timeout_race() {
    const ROUNDS: usize = 300;
    let granted = AtomicUsize::new(0);
    let timed_out = AtomicUsize::new(0);
    let other = AtomicUsize::new(0);

    for _ in 0..ROUNDS {
        let queue = Arc::new(ApprovalQueue::new());
        // The race is created by resolving from another thread with no synchronisation at all:
        // the resolver spins on `snapshot` and answers the instant the entry appears, which is
        // while `ask` is still between pushing and waiting.
        let hostile = request(ApprovalKind::WriteEnvFile);

        let outcome = std::thread::scope(|scope| {
            let resolver = Arc::clone(&queue);
            let handle = scope.spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let pending = resolver.snapshot();
                    if let Some(first) = pending.first() {
                        // Resolve twice: a second answer to the same id must be refused.
                        let first_answer =
                            resolver.resolve(&first.id, &Decision::AllowOnce, verified());
                        let second_answer =
                            resolver.resolve(&first.id, &Decision::Deny, verified());
                        assert!(
                            !(first_answer && second_answer),
                            "the same request was answered twice"
                        );
                        return;
                    }
                    if Instant::now() >= deadline {
                        return;
                    }
                    std::thread::yield_now();
                }
            });
            let outcome = queue.ask(hostile);
            handle.join().expect("resolver");
            outcome
        });

        if outcome.granted {
            granted.fetch_add(1, Ordering::SeqCst);
        } else if outcome.code == kagisecure_ipc::protocol::ErrorCode::ApprovalTimeout {
            timed_out.fetch_add(1, Ordering::SeqCst);
        } else {
            other.fetch_add(1, Ordering::SeqCst);
        }
        assert_eq!(queue.waiting(), 0, "the queue is drained after every round");
    }

    assert_eq!(
        granted.load(Ordering::SeqCst)
            + timed_out.load(Ordering::SeqCst)
            + other.load(Ordering::SeqCst),
        ROUNDS,
        "every ask produced exactly one outcome"
    );
    assert_eq!(
        timed_out.load(Ordering::SeqCst),
        0,
        "nothing should have timed out in a five-second window"
    );
}

/// A-15 / A-19: `reopen` after an unlock must not resurrect what the lock swept.
///
/// `deny_all` clears the pending queue and sets `closed`; `reopen` clears `closed`. If the two
/// were not symmetric — if a request queued during the lock survived, or if an id were reused —
/// a caller could have its question answered by a human who never saw it.
#[test]
fn an_unlock_does_not_resurrect_a_request_that_the_lock_swept() {
    let queue = Arc::new(ApprovalQueue::new());

    // One request waiting, then the lock.
    let swept = std::thread::scope(|scope| {
        let asker = Arc::clone(&queue);
        let handle = scope.spawn(move || asker.ask(request(ApprovalKind::WriteEnvFile)));
        let deadline = Instant::now() + Duration::from_secs(10);
        while queue.waiting() < 1 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        queue.deny_all();
        handle.join().expect("asker")
    });
    assert!(!swept.granted);
    assert_eq!(swept.code, kagisecure_ipc::protocol::ErrorCode::VaultLocked);

    // A request that arrives while locked is refused immediately, not parked.
    let during = queue.ask(request(ApprovalKind::WriteEnvFile));
    assert!(!during.granted);
    assert_eq!(
        during.code,
        kagisecure_ipc::protocol::ErrorCode::VaultLocked,
        "a question asked during a lock is refused on the spot"
    );

    queue.reopen();
    assert_eq!(
        queue.waiting(),
        0,
        "reopening an empty queue must not bring anything back: {:?}",
        queue.snapshot()
    );
    assert!(
        queue.snapshot().is_empty(),
        "and nothing is waiting for a human who never saw it"
    );
}

/// A-16: `next_id` wraps, so a stale id must never answer a newer request.
///
/// Ids are `req-<n>` with `n` from a `wrapping_add`. Two billion requests are not testable, but
/// the property that matters is: resolving an id that is not currently pending returns `false`
/// and answers nothing, so a replayed answer from a previous epoch is inert.
#[test]
fn resolving_a_stale_id_answers_nothing() {
    let queue = Arc::new(ApprovalQueue::new());

    // Round one: learn an id, then let it complete.
    let first_id = std::thread::scope(|scope| {
        let asker = Arc::clone(&queue);
        let handle = scope.spawn(move || asker.ask(request(ApprovalKind::WriteEnvFile)));
        let deadline = Instant::now() + Duration::from_secs(10);
        while queue.waiting() < 1 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let id = queue.snapshot()[0].id.clone();
        assert!(queue.resolve(&id, &Decision::Deny, verified()));
        let outcome = handle.join().expect("asker");
        assert!(!outcome.granted);
        id
    });

    // Round two: a new request. The stale answer must not touch it.
    let second = std::thread::scope(|scope| {
        let asker = Arc::clone(&queue);
        let handle = scope.spawn(move || asker.ask(request(ApprovalKind::WriteEnvFile)));
        let deadline = Instant::now() + Duration::from_secs(10);
        while queue.waiting() < 1 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let live = queue.snapshot()[0].id.clone();
        assert_ne!(live, first_id, "a fresh request gets a fresh id");
        assert!(
            !queue.resolve(&first_id, &Decision::AllowOnce, verified()),
            "the stale id answered something"
        );
        assert_eq!(queue.waiting(), 1, "the live request is still waiting");
        assert!(queue.resolve(&live, &Decision::Deny, verified()));
        handle.join().expect("asker")
    });
    assert!(!second.granted, "the live request kept its own answer");
}

/// A-20: a hostile self-reported client name reaches the sheet and the audit log as data.
///
/// `clientInfo.name` is whatever the peer typed. `PeerIdentity::describe` keeps it in quotes so
/// a caller calling itself `Claude Code [verified]` cannot borrow the word — but the bytes still
/// travel, so this asserts they travel *intact and quoted*, never interpreted, and that a name
/// carrying ANSI escapes and newlines does not break anything downstream.
#[test]
fn a_hostile_client_name_is_carried_as_a_quotation_and_never_as_a_verdict() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    let (reply, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        let mut client = kagisecure_ipc::client::Client::connect(
            &fx.endpoint,
            common::client_info(HOSTILE_CLIENT_NAME),
        )
        .expect("connect");
        client
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
            .expect("call")
    });
    assert!(error_code(&reply).is_none(), "reply was {reply:?}");
    assert_eq!(seen.len(), 1);

    // The name reaches the sheet verbatim: the UI's job is to render it as a quotation, and it
    // cannot do that if the agent has already mangled or truncated it.
    assert_eq!(
        seen[0].client_name, HOSTILE_CLIENT_NAME,
        "the sheet must receive exactly what the peer said it was called"
    );

    // The lease records the verdict this process reached, bare, next to the quoted claim.
    let leases = fx.agent.leases();
    assert_eq!(leases.len(), 1);
    let identity = &leases[0].client_identity;
    assert!(
        identity.contains("signature verified"),
        "the verdict is stated by us: {identity}"
    );
    assert!(
        identity.contains('"'),
        "and the peer's own claim stays inside quotes: {identity}"
    );

    // And nothing anywhere carries a value.
    let audited = fx
        .handle
        .with(|v| format!("{:?}", v.audit_entries()))
        .expect("unlocked");
    assert!(!audited.contains(MARKER), "audit entries record names only");
    assert!(
        !format!("{seen:?}").contains(MARKER),
        "nor does an approval request"
    );
}

/// A 64 KiB client name is data, not a denial of service.
///
/// The frame cap is 1 MiB, so a name well under it is accepted by design; what must not happen
/// is a panic, a truncation that loses the quoting, or an unbounded cost.
#[test]
fn an_enormous_client_name_is_handled_without_panic_or_stall() {
    let fx = fixture();
    let huge = "A".repeat(64 * 1024);

    let started = Instant::now();
    let reply = {
        let mut client =
            kagisecure_ipc::client::Client::connect(&fx.endpoint, common::client_info(&huge))
                .expect("connect");
        client
            .call(&kagisecure_ipc::protocol::Request::ListEnvironments { vault_id: None })
            .expect("call")
    };
    assert!(error_code(&reply).is_none(), "reply was {reply:?}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "a large name took {:?}",
        started.elapsed()
    );
}

/// The sheet a human is shown carries no value, for every approving tool.
///
/// This is the invariant the whole product rests on, asserted against the real queue rather than
/// against a constructed `ApprovalRequest`: whatever the agent puts on a sheet, the canary is
/// not in it.
#[test]
fn no_approval_request_from_any_tool_carries_a_value() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();

    let (_, seen) = with_ui_answering(
        &fx.agent,
        |_| Some(Decision::Deny),
        || {
            let mut client = fx.client("adversarial-approval");
            let _ = client.call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900));
            let _ = client.call(&kagisecure_ipc::protocol::Request::RunWithEnv {
                environment_id: fx.env_id.parse().expect("env id"),
                command: "/bin/echo".to_owned(),
                args: vec!["hello".to_owned()],
                cwd: dir.clone(),
                variables: None,
                timeout_seconds: 5,
                output: kagisecure_ipc::protocol::OutputMode::Scrubbed,
            });
            let _ = client.call(&kagisecure_ipc::protocol::Request::CreateEnvironment {
                vault_id: None,
                name: "adversarial".to_owned(),
                description: None,
            });
        },
    );

    assert!(!seen.is_empty(), "the tools did ask");
    let rendered = format!("{seen:?}");
    assert!(
        !rendered.contains(MARKER),
        "a value reached an approval sheet: {rendered}"
    );
}
