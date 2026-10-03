//! What is left of the approval-fatigue limits (ADR-0036 §9, as amended on 2026-10-03): Deny and
//! block, and the one-flow-at-a-time slot. The sheet budget, sticky denials and the block after a
//! second origin mismatch were removed; the tests below pin that they are gone.
//!
//! Every test here counts the **sheets** the stand-in human was shown, not only the codes the
//! agent was answered. Time is the broker's manual clock ([`kagisecure_agent::AgentFillClock`]),
//! so thirty minutes pass without being waited out.

mod agent_fill_support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use agent_fill_support::{
    Fixture, Human, LOOK_ALIKE, OnDeliver, PAGE, SAVED, ServiceWorker, SidecarChild, Tab, both,
    code, fixture, request_fill_at,
};
use kagisecure_agent::approval::Decision;
use kagisecure_agent::extension::agent_fill::DENY_AND_BLOCK;
use kagisecure_agent::{AgentFillBlockReason, AgentFillNotice};
use kagisecure_ipc::protocol::{AgentFillField, Response};

/// An item id that names nothing, spelled like a real one.
const ABSENT: &str = "00000000-0000-4000-8000-000000000000";

/// A site the human might have open in another browser, saved for nothing.
const ELSEWHERE: &str = "https://private.test";

fn fill(fx: &Fixture) -> Response {
    fx.request_fill(&fx.item, PAGE, &both())
}

fn filled(reply: &Response) -> bool {
    matches!(reply, Response::FillResult { .. })
}

/// The detail of every `request_fill` entry on disk, in order.
fn details(fx: &Fixture) -> Vec<String> {
    fx.fill_entries().into_iter().map(|(_, d)| d).collect()
}

/// How many `request_fill` entries on disk carry `detail`.
fn count(fx: &Fixture, detail: &str) -> usize {
    details(fx).iter().filter(|d| *d == detail).count()
}

/// The key this test process's requests are limited under: its parent's executable, as the
/// kernel reports it.
fn own_key() -> String {
    let parent = kagisecure_extension_ipc::peer::parent_pid(std::process::id()).expect("a parent");
    kagisecure_ipc::server::executable_for_pid(parent).expect("its executable")
}

/// A human who answers the first sheet with `first` and every later one with `then`.
fn human_answering(fx: &Fixture, first: Option<Decision>, then: Decision) -> Human {
    let answered = AtomicUsize::new(0);
    Human::new(&fx.queue, move |_| {
        if answered.fetch_add(1, Ordering::SeqCst) == 0 {
            first.clone()
        } else {
            Some(then.clone())
        }
    })
}

#[test]
fn a_burst_raises_one_sheet_at_a_time() {
    let fx = fixture();
    // A human who takes their time over the first sheet.
    let human = Human::new(&fx.queue, |_| {
        std::thread::sleep(Duration::from_millis(800));
        Some(Decision::AllowOnce)
    });
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);

    std::thread::scope(|scope| {
        let first = scope.spawn(|| fill(&fx));
        let deadline = Instant::now() + Duration::from_secs(5);
        while fx.queue.waiting() == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        // Four more at once, while the first sheet is up: none is queued behind it.
        let started = Instant::now();
        let burst: Vec<_> = (0..4).map(|_| scope.spawn(|| fill(&fx))).collect();
        for reply in burst {
            let reply = reply.join().expect("burst");
            assert_eq!(code(&reply), Some("RATE_LIMITED"), "{reply:?}");
        }
        assert!(
            started.elapsed() < Duration::from_millis(700),
            "answered at once, not after the first sheet"
        );
        assert!(filled(&first.join().expect("first")));
    });

    assert_eq!(human.sheets(), 1, "one sheet, and no queue of them");
    assert_eq!(count(&fx, "AGENT_FILL_BUSY"), 4);
    assert!(
        fx.broker.take_notices().is_empty(),
        "being second is not news for the human"
    );
}

#[test]
fn there_is_no_sheet_budget() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);

    for n in 1..=6 {
        assert!(filled(&fill(&fx)), "sheet {n}");
        fx.clock.advance(Duration::from_secs(10));
    }
    assert_eq!(human.sheets(), 6);
    assert_eq!(count(&fx, "AGENT_FILL_RATE_LIMITED"), 0);
    assert!(fx.broker.take_notices().is_empty());
}

#[test]
fn a_denial_does_not_stick() {
    let fx = fixture();
    let human = Human::denying(&fx.queue);
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);

    assert_eq!(code(&fill(&fx)), Some("USER_DENIED"));
    assert_eq!(code(&fill(&fx)), Some("USER_DENIED"));
    assert_eq!(human.sheets(), 2, "the identical request is asked again");
    assert_eq!(count(&fx, "AGENT_FILL_BLOCKED"), 0);
}

#[test]
fn deny_and_block_survives_a_lock() {
    let fx = fixture();
    let human = Human::new(&fx.queue, |_| Some(Decision::DenyAndBlock));
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);

    assert_eq!(code(&fill(&fx)), Some("USER_DENIED"));
    assert_eq!(human.sheets(), 1);
    assert_eq!(
        details(&fx),
        ["AGENT_FILL_DENIED (agent blocked)".to_owned()]
    );
    let blocks = fx.broker.blocks();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].key, own_key());
    assert_eq!(blocks[0].agent_name, "example-agent");
    assert_eq!(blocks[0].reason, AgentFillBlockReason::DeniedAndBlocked);
    let remaining = blocks[0].remaining.expect("a timed block");
    assert!(
        remaining <= DENY_AND_BLOCK && remaining > DENY_AND_BLOCK - Duration::from_secs(60),
        "{remaining:?}"
    );
    // Every request from the agent, not only the one denied — before its item is looked up.
    assert_eq!(
        code(&fx.request_fill(ABSENT, PAGE, &both())),
        Some("USER_DENIED")
    );
    assert_eq!(human.sheets(), 1);
    drop(human);

    // The vault locks and is unlocked again: new handle, new listeners, the same process-wide
    // broker — as the app does it.
    let (_handle, again) = fx.lock_and_unlock_again();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::connect(
        &again.extension_endpoint,
        Tab::front(PAGE),
        OnDeliver::Redeem,
    );
    let ask = || {
        request_fill_at(
            &again.agent_endpoint,
            "example-agent",
            &fx.item,
            PAGE,
            &both(),
        )
    };

    assert_eq!(
        code(&ask()),
        Some("USER_DENIED"),
        "a relock is no fresh start"
    );
    assert_eq!(human.sheets(), 0);
    assert_eq!(sw.locates(), 0);
    assert_eq!(
        details(&fx).last().map(String::as_str),
        Some("AGENT_FILL_BLOCKED")
    );
    assert_eq!(fx.broker.blocks().len(), 1);

    fx.clock.advance(DENY_AND_BLOCK);
    assert!(filled(&ask()), "thirty minutes on, the block has lifted");
    assert_eq!(human.sheets(), 1);
    assert!(fx.broker.blocks().is_empty());
}

#[test]
fn origin_mismatches_are_reported_but_never_block() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(LOOK_ALIKE), OnDeliver::Redeem);

    for _ in 0..3 {
        assert_eq!(code(&fill(&fx)), Some("NO_MATCHING_TAB"));
    }
    assert_eq!(human.sheets(), 0);
    assert_eq!(
        details(&fx),
        vec!["AGENT_FILL_ORIGIN_MISMATCH".to_owned(); 3]
    );
    let notices = fx.broker.take_notices();
    assert_eq!(notices.len(), 3, "{notices:?}");
    assert!(
        notices
            .iter()
            .all(|n| matches!(n, AgentFillNotice::OriginMismatch { .. }))
    );
    assert!(fx.broker.blocks().is_empty());

    sw.set(Tab::front(PAGE), OnDeliver::Redeem);
    assert!(filled(&fill(&fx)));
    assert_eq!(human.sheets(), 1);
}

#[test]
fn a_claim_mismatch_on_a_saved_site_neither_notifies_nor_escalates() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);

    // The tab is on a saved site; the agent's bookkeeping is off by a subdomain, three times.
    for _ in 0..3 {
        let reply = fx.request_fill(&fx.item, SAVED, &both());
        assert_eq!(code(&reply), Some("NO_MATCHING_TAB"));
    }
    assert_eq!(human.sheets(), 0);
    assert_eq!(details(&fx), vec!["AGENT_FILL_NO_TARGET".to_owned(); 3]);
    assert!(fx.broker.take_notices().is_empty());
    assert!(fx.broker.blocks().is_empty());
    assert!(filled(&fill(&fx)), "and the agent is not blocked");
    assert_eq!(human.sheets(), 1);
}

#[test]
fn a_mismatch_in_another_browser_is_not_recorded_or_counted() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    // The agent's browser: a saved site, but not the origin it claims.
    let agents = ServiceWorker::start(
        &fx,
        Tab::front("https://www.example.com"),
        OnDeliver::Redeem,
    );
    // The human's other browser, in front on a site nothing is saved for.
    let _humans = ServiceWorker::start(&fx, Tab::front(ELSEWHERE), OnDeliver::Redeem);

    for _ in 0..3 {
        assert_eq!(code(&fill(&fx)), Some("NO_MATCHING_TAB"));
    }
    assert_eq!(human.sheets(), 0);
    let entries: Vec<_> = fx
        .on_disk()
        .into_iter()
        .filter(|e| e.tool == "request_fill")
        .collect();
    assert_eq!(entries.len(), 3);
    for entry in &entries {
        assert_eq!(entry.detail.as_deref(), Some("AGENT_FILL_NO_TARGET"));
        assert_eq!(entry.target_path, None);
        let json = serde_json::to_string(entry).expect("json");
        assert!(!json.contains("private.test"), "{json}");
    }
    assert!(
        fx.broker.take_notices().is_empty(),
        "the human's own browsing is not reported"
    );
    assert!(
        fx.broker.blocks().is_empty(),
        "nor counted against the agent"
    );

    agents.set(Tab::front(PAGE), OnDeliver::Redeem);
    assert!(filled(&fill(&fx)));
    assert_eq!(human.sheets(), 1);
}

#[test]
fn a_single_in_front_mismatch_is_still_reported() {
    // The agent's browser is the only one with a tab in front.
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let _agents = ServiceWorker::start(&fx, Tab::front(LOOK_ALIKE), OnDeliver::Redeem);
    let _idle = ServiceWorker::start(&fx, Tab::nothing(), OnDeliver::Redeem);
    for _ in 0..2 {
        assert_eq!(code(&fill(&fx)), Some("NO_MATCHING_TAB"));
    }
    assert_eq!(fx.broker.take_notices().len(), 2);
    assert!(fx.broker.blocks().is_empty());
    assert_eq!(human.sheets(), 0);

    // Beside another browser's tab, a mismatch at the very origin the agent claimed is still its
    // own: recorded and reported.
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let _agents = ServiceWorker::start(&fx, Tab::front(LOOK_ALIKE), OnDeliver::Redeem);
    let _humans = ServiceWorker::start(&fx, Tab::front(ELSEWHERE), OnDeliver::Redeem);
    for _ in 0..2 {
        let reply = fx.request_fill(&fx.item, LOOK_ALIKE, &both());
        assert_eq!(code(&reply), Some("NO_MATCHING_TAB"));
    }
    assert!(fx.broker.blocks().is_empty());
    assert_eq!(human.sheets(), 0);
    for entry in fx
        .on_disk()
        .into_iter()
        .filter(|e| e.tool == "request_fill")
    {
        assert_eq!(entry.target_path.as_deref(), Some(LOOK_ALIKE));
        let json = serde_json::to_string(&entry).expect("json");
        assert!(!json.contains("private.test"), "{json}");
    }
    let notices = fx.broker.take_notices();
    assert_eq!(notices.len(), 2, "{notices:?}");
}

#[test]
fn a_block_is_keyed_on_the_parent_executable_not_the_reported_name() {
    let fx = fixture();
    // The first sheet is denied and blocked; any later one is approved.
    let human = human_answering(&fx, Some(Decision::DenyAndBlock), Decision::AllowOnce);
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    assert_eq!(code(&fill(&fx)), Some("USER_DENIED"));
    assert_eq!(human.sheets(), 1);

    // Another name, and another parent it claims for itself: the kernel says it is the same.
    let renamed = request_fill_at(
        &fx.agent_endpoint,
        "a-different-agent",
        &fx.item,
        PAGE,
        &both(),
    );
    assert_eq!(code(&renamed), Some("USER_DENIED"), "{renamed:?}");
    assert_eq!(human.sheets(), 1);

    // The same name, started by another program — this test binary rather than whatever
    // started it: another agent, which the block does not cover.
    let mut child = SidecarChild::spawn(&fx.agent_endpoint, "example-agent");
    let reply = child.request_fill(&fx.item, PAGE);
    assert_eq!(reply["status"], "filled", "{reply}");
    assert_eq!(human.sheets(), 2);

    let blocks = fx.broker.blocks();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].key, own_key());
}

#[test]
fn unblock_lifts_a_block() {
    let fx = fixture();
    let human = human_answering(&fx, Some(Decision::DenyAndBlock), Decision::AllowOnce);
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    assert_eq!(code(&fill(&fx)), Some("USER_DENIED"));
    let username = [AgentFillField::Username];
    assert_eq!(
        code(&fx.request_fill(&fx.no_password, PAGE, &username)),
        Some("USER_DENIED")
    );
    assert_eq!(human.sheets(), 1);

    assert!(!fx.broker.unblock("/no/such/agent"));
    assert!(fx.broker.unblock(&own_key()));
    assert!(fx.broker.blocks().is_empty());
    assert!(
        filled(&fx.request_fill(&fx.no_password, PAGE, &username)),
        "unblocked, the agent may ask again"
    );
    assert_eq!(human.sheets(), 2);
    // Denials do not stick, so the request that was denied is simply asked again.
    assert!(filled(&fill(&fx)));
    assert_eq!(human.sheets(), 3);
}
