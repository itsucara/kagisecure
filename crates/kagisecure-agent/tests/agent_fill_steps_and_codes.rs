//! ADR-0036 Phase 3: identifier-first sign-ins (§7.3), one-time codes (§7.4) and the tripwire's
//! follow-up (§8.3), against the real broker, a real vault, the real MCP and extension sockets, a
//! stand-in for the human and a stand-in for the service worker (`agent_fill_support`).
//!
//! What is asserted is what the human sees — how many sheets — what the agent is told, what the
//! browser receives, and what the audit log on disk says.

mod agent_fill_support;

use std::time::{Duration, Instant};

use agent_fill_support::{
    Fixture, Human, MARKER, OnDeliver, PAGE, ServiceWorker, SidecarChild, Tab, both, code,
    code_uri, fixture, fixture_with, request_fill_at,
};
use kagisecure_agent::approval::ApprovalKind;
use kagisecure_agent::{AgentFillNotice, AgentFillTimings};
use kagisecure_core::audit::AuditEntry;
use kagisecure_core::model::{Field, Secret};
use kagisecure_core::proto::Outcome;
use kagisecure_extension_ipc::protocol::{
    AgentFillFailure, AgentFillField as PageField, Response as ExtResponse,
};
use kagisecure_ipc::protocol::{AgentFillField, Response};

const PASSWORD: [AgentFillField; 1] = [AgentFillField::Password];
const CODE: [AgentFillField; 1] = [AgentFillField::OneTimeCode];

fn written(response: &Response) -> (Vec<AgentFillField>, Vec<AgentFillField>) {
    match response {
        Response::FillResult {
            fields_written,
            fields_pending,
        } => (fields_written.clone(), fields_pending.clone()),
        other => panic!("expected a fill result, got {other:?}"),
    }
}

/// Every agent-fill entry on disk: `request_fill`, and `totp_code` for a one-time code.
fn fill_entries(fx: &Fixture) -> Vec<AuditEntry> {
    fx.on_disk()
        .into_iter()
        .filter(|e| e.tool == "request_fill" || e.tool == "totp_code")
        .collect()
}

fn details(fx: &Fixture) -> Vec<String> {
    fill_entries(fx)
        .into_iter()
        .map(|e| e.detail.unwrap_or_default())
        .collect()
}

/// Wait up to five seconds for an entry whose detail is `detail`.
fn eventually_recorded(fx: &Fixture, detail: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if details(fx).iter().any(|d| d == detail) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The agent-fill sheets the human saw, as (fields, two-step).
fn sheets_seen(human: &Human) -> Vec<(Vec<AgentFillField>, bool)> {
    human
        .seen()
        .into_iter()
        .filter(|r| r.kind == ApprovalKind::AgentFill)
        .map(|r| {
            let facts = r.agent_fill.expect("an agent-fill sheet carries its facts");
            (facts.fields, facts.two_step)
        })
        .collect()
}

/// Step one of an identifier-first sign-in at [`PAGE`]: approved, the username written, the
/// password pending. Returns step one's `Allowed` entry.
fn step_one(fx: &Fixture, sw: &ServiceWorker) -> AuditEntry {
    sw.set(Tab::identifier_only(PAGE), OnDeliver::Redeem);
    let first = fx.request_fill(&fx.item, PAGE, &both());
    assert_eq!(
        written(&first),
        (
            vec![AgentFillField::Username],
            vec![AgentFillField::Password]
        ),
        "step one writes the username and says the password is still to come"
    );
    let fills = sw.fills_at_least(1);
    assert!(
        matches!(
            &fills[..],
            [ExtResponse::Filled { username: Some(u), password: None, .. }] if u == "alice"
        ),
        "page one gets the username and nothing else: {fills:?}"
    );
    assert_eq!(fx.broker.pending_steps(), 1);
    fill_entries(fx)
        .into_iter()
        .rev()
        .find(|e| e.outcome == Outcome::Allowed)
        .expect("step one's Allowed entry")
}

#[test]
fn an_identifier_first_grant_fills_the_password_on_the_next_page_without_a_second_sheet() {
    // Page two in a new document, and page two as the same document with its form swapped in
    // place: both are the same sign-in in the same tab (implementation decision 38).
    for page_two in [Tab::next_page(PAGE), Tab::front(PAGE)] {
        let fx = fixture();
        let human = Human::approving(&fx.queue);
        let sw = ServiceWorker::start(&fx, Tab::identifier_only(PAGE), OnDeliver::Redeem);

        let first = step_one(&fx, &sw);
        assert_eq!(
            sheets_seen(&human),
            [(both(), true)],
            "one sheet, which says it is a two-page sign-in"
        );
        assert_eq!(
            first.detail.as_deref(),
            Some("AGENT_FILL_APPROVED (step 1 of 2)")
        );
        assert_eq!(first.variables, ["username"]);

        sw.set(page_two, OnDeliver::Redeem);
        let second = fx.request_fill(&fx.item, PAGE, &PASSWORD);
        assert_eq!(written(&second), (vec![AgentFillField::Password], vec![]));
        assert_eq!(human.sheets(), 1, "step two raises no sheet");
        let fills = sw.fills_at_least(1);
        match &fills[..] {
            [
                ExtResponse::Filled {
                    username: None,
                    password: Some(password),
                    ..
                },
            ] => assert_eq!(password.expose(), MARKER),
            other => panic!("page two gets the password and nothing else: {other:?}"),
        }
        let deliveries = sw.deliveries();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(
            fx.broker.pending_steps(),
            0,
            "the grant dies after step two"
        );

        let entries = fill_entries(&fx);
        let last = entries.last().expect("step two's entry");
        assert_eq!(last.outcome, Outcome::Allowed);
        assert_eq!(
            last.detail.as_deref(),
            Some(format!("AGENT_FILL_APPROVED (step 2 of 2, entry {})", first.seq).as_str()),
            "step two's entry names step one's"
        );
        assert_eq!(last.variables, ["password"]);
        assert_eq!(
            entries
                .iter()
                .filter(|e| e.outcome == Outcome::Allowed)
                .count(),
            2
        );

        // The grant is spent: a third call is a new request, with a sheet of its own.
        let _ = fx.request_fill(&fx.item, PAGE, &PASSWORD);
        assert_eq!(human.sheets(), 2);
    }
}

#[test]
fn each_step_is_delivered_under_its_own_probe_and_grant_ids() {
    let fx = fixture();
    let _human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::identifier_only(PAGE), OnDeliver::Redeem);
    let _ = fx.request_fill(&fx.item, PAGE, &both());
    let (probe_one, grant_one) = sw.deliveries().remove(0);
    sw.set(Tab::next_page(PAGE), OnDeliver::Redeem);
    let _ = fx.request_fill(&fx.item, PAGE, &PASSWORD);
    let (probe_two, grant_two) = sw.deliveries().remove(0);
    assert_ne!(probe_one, probe_two);
    assert_ne!(grant_one, grant_two);

    // Step one's grant id is spent: quoting it again gets nothing.
    let refused = sw.redeem(&grant_one, &Tab::next_page(PAGE));
    assert!(matches!(refused, ExtResponse::Error { .. }), "{refused:?}");
}

#[test]
fn the_second_step_refuses_another_item_agent_or_site() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::identifier_only(PAGE), OnDeliver::Redeem);
    let first = step_one(&fx, &sw);

    // Another item, same agent, same tab: a request of its own, with its own sheet.
    sw.set(Tab::next_page(PAGE), OnDeliver::Redeem);
    let other_item = fx.request_fill(&fx.with_code, PAGE, &PASSWORD);
    assert_eq!(written(&other_item).0, PASSWORD);
    assert_eq!(
        human.sheets(),
        2,
        "another item is never served by the pending step"
    );
    assert_eq!(
        fx.broker.pending_steps(),
        1,
        "and it leaves the pending step alone"
    );

    // Another agent — another sidecar process — asking for the same item's password: a sheet.
    sw.set(Tab::next_page(PAGE), OnDeliver::Redeem);
    let mut other_agent = SidecarChild::spawn(&fx.agent_endpoint, "example-agent");
    let reply = other_agent.request_fill_fields(&fx.item, PAGE, &["password"]);
    assert_eq!(reply["fields_written"], serde_json::json!(["password"]));
    assert_eq!(
        human.sheets(),
        3,
        "another agent is never served by the pending step"
    );
    assert_eq!(fx.broker.pending_steps(), 1);

    // Another site: the tab went to a sibling the item covers but which is not the same sign-in.
    // The pending step is spent, and nothing is asked or written.
    let sibling = "https://accounts.example.com";
    sw.set(Tab::next_page(sibling), OnDeliver::Redeem);
    let before = sw.deliveries().len();
    let refused = fx.request_fill(&fx.item, sibling, &PASSWORD);
    assert_eq!(code(&refused), Some("NO_MATCHING_TAB"));
    assert_eq!(human.sheets(), 3, "a refused step two raises no sheet");
    assert_eq!(sw.deliveries().len(), before, "and delivers nothing");
    assert_eq!(fx.broker.pending_steps(), 0, "it spent the pending step");
    let tail = details(&fx);
    assert_eq!(
        tail[tail.len() - 2..],
        [
            "AGENT_FILL_NO_TARGET".to_owned(),
            format!("AGENT_FILL_PENDING_REFUSED (entry {})", first.seq),
        ]
    );

    // A retry is a new request, with a sheet of its own.
    let retry = fx.request_fill(&fx.item, sibling, &PASSWORD);
    assert_eq!(written(&retry).0, PASSWORD);
    assert_eq!(human.sheets(), 4);
}

#[test]
fn a_password_request_in_a_new_tab_after_step_ones_tab_closed_is_a_new_request() {
    // The agent closed the tab that served step one and opened a fresh one at the same site. Step
    // two cannot come — its tab is gone — so the request is served as what it is: a new request
    // for the password, with a sheet of its own, not a refused continuation.
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::identifier_only(PAGE), OnDeliver::Redeem);
    let first = step_one(&fx, &sw);

    let mut new_tab = Tab::next_page(PAGE);
    new_tab.tab.tab_id += 100;
    new_tab.tab.document_id = Some("doc-new-tab".to_owned());
    sw.set(new_tab, OnDeliver::Redeem);
    let answer = fx.request_fill(&fx.item, PAGE, &PASSWORD);
    assert_eq!(written(&answer), (vec![AgentFillField::Password], vec![]));
    assert_eq!(
        human.sheets(),
        2,
        "a new tab is a new request, with its own sheet"
    );
    assert_eq!(
        fx.broker.pending_steps(),
        0,
        "the pending step ended with its tab"
    );
    let tail = details(&fx);
    assert!(
        tail.contains(&format!("AGENT_FILL_PENDING_REFUSED (entry {})", first.seq)),
        "step one's entry says its password never came there: {tail:?}"
    );
    assert!(
        !tail.iter().any(|d| d == "AGENT_FILL_NO_TARGET"),
        "nothing was refused: {tail:?}"
    );
}

#[test]
fn the_second_step_dies_with_the_flow_window() {
    let fx = fixture_with(AgentFillTimings {
        flow_window: Duration::from_millis(800),
        ..AgentFillTimings::default()
    });
    let sw = ServiceWorker::start(&fx, Tab::identifier_only(PAGE), OnDeliver::Redeem);
    // Step one needs a yes; everything after this is denied.
    let approving = Human::approving(&fx.queue);
    step_one(&fx, &sw);
    drop(approving);
    let human = Human::denying(&fx.queue);
    std::thread::sleep(Duration::from_millis(1_000));
    assert_eq!(fx.broker.pending_steps(), 0);

    sw.set(Tab::next_page(PAGE), OnDeliver::Redeem);
    let late = fx.request_fill(&fx.item, PAGE, &PASSWORD);
    assert_eq!(code(&late), Some("USER_DENIED"));
    assert_eq!(
        human.sheets(),
        1,
        "a late step two is a new request, with a sheet"
    );
    assert!(
        sw.fills().is_empty(),
        "and the password was never delivered: {:?}",
        sw.fills()
    );
}

#[test]
fn the_fill_result_reports_a_pending_password_when_step_two_never_comes() {
    let fx = fixture_with(AgentFillTimings {
        flow_window: Duration::from_millis(800),
        ..AgentFillTimings::default()
    });
    let _human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::identifier_only(PAGE), OnDeliver::Redeem);
    let first = step_one(&fx, &sw);

    // Nobody comes for the password. When the window closes, the log says so, as the follow-up
    // of step one's entry — and nothing else was released.
    let expired = format!("AGENT_FILL_PENDING_EXPIRED (entry {})", first.seq);
    assert!(eventually_recorded(&fx, &expired), "{:?}", details(&fx));
    assert_eq!(fx.broker.pending_steps(), 0);
    let entries = fill_entries(&fx);
    let follow_up = entries.last().expect("the follow-up");
    assert_eq!(follow_up.outcome, Outcome::Failed);
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.outcome == Outcome::Allowed)
            .count(),
        1
    );
}

#[test]
fn the_second_step_dies_with_a_lock() {
    let fx = fixture();
    let first = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::identifier_only(PAGE), OnDeliver::Redeem);
    step_one(&fx, &sw);
    drop(first);

    let (_handle, again) = fx.lock_and_unlock_again();
    assert_eq!(
        fx.broker.pending_steps(),
        0,
        "a lock takes the pending step"
    );

    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::connect(
        &again.extension_endpoint,
        Tab::next_page(PAGE),
        OnDeliver::Redeem,
    );
    let reply = request_fill_at(
        &again.agent_endpoint,
        "example-agent",
        &fx.item,
        PAGE,
        &PASSWORD,
    );
    assert_eq!(written(&reply).0, PASSWORD);
    assert_eq!(
        human.sheets(),
        1,
        "after a lock, the password needs a sheet of its own"
    );
    assert!(
        details(&fx).iter().all(|d| !d.contains("step 2 of 2")),
        "{:?}",
        details(&fx)
    );
    drop(sw);
}

#[test]
fn a_one_time_code_needs_its_own_sheet() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::code(PAGE), OnDeliver::Redeem);

    for round in 1..=2 {
        let reply = fx.request_fill(&fx.with_code, PAGE, &CODE);
        assert_eq!(written(&reply), (CODE.to_vec(), vec![]));
        assert_eq!(human.sheets(), round, "every code, its own sheet");
    }
    assert_eq!(
        sheets_seen(&human),
        [(CODE.to_vec(), false), (CODE.to_vec(), false)]
    );

    // The browser got the current code, in the reply the extension channel already uses for one.
    let generator = Field::totp("one-time password", Secret::from_string(code_uri()))
        .totp_generator()
        .expect("a generator");
    let now = kagisecure_core::unix_now();
    let fills = sw.fills_at_least(2);
    for fill in &fills {
        let ExtResponse::TotpCode { item_id, code, .. } = fill else {
            panic!("a code is answered with totp_code: {fill:?}");
        };
        assert_eq!(item_id, &fx.with_code);
        let current =
            [now.saturating_sub(30), now, now + 30].map(|t| generator.code_at(t).expect("a code"));
        assert!(
            current
                .iter()
                .any(|c| c.expose() == code.expose().as_bytes()),
            "the code released is the item's current one"
        );
    }

    // Audited like every one-time code, under `totp_code`, before it left.
    let allowed: Vec<AuditEntry> = fx
        .on_disk()
        .into_iter()
        .filter(|e| e.outcome == Outcome::Allowed)
        .collect();
    assert_eq!(allowed.len(), 2);
    for entry in allowed {
        assert_eq!(entry.tool, "totp_code");
        assert_eq!(entry.variables, ["one_time_code"]);
        assert_eq!(entry.detail.as_deref(), Some("AGENT_FILL_APPROVED"));
        assert_eq!(entry.target_path.as_deref(), Some(PAGE));
    }
}

#[test]
fn a_password_approval_never_implies_a_code() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);

    // A login filled a moment ago: the code still needs its own sheet.
    let login = fx.request_fill(&fx.with_code, PAGE, &both());
    assert_eq!(written(&login).0, both());
    sw.set(Tab::code(PAGE), OnDeliver::Redeem);
    let code_reply = fx.request_fill(&fx.with_code, PAGE, &CODE);
    assert_eq!(written(&code_reply).0, CODE);
    assert_eq!(human.sheets(), 2);

    // A pending identifier-first step does not pay for a code either, and is not spent by one.
    let fx = fixture();
    let sw = ServiceWorker::start(&fx, Tab::identifier_only(PAGE), OnDeliver::Redeem);
    let approving = Human::approving(&fx.queue);
    let _ = fx.request_fill(&fx.with_code, PAGE, &both());
    drop(approving);
    assert_eq!(fx.broker.pending_steps(), 1);
    let human = Human::denying(&fx.queue);
    sw.set(Tab::code(PAGE), OnDeliver::Redeem);
    let refused = fx.request_fill(&fx.with_code, PAGE, &CODE);
    assert_eq!(code(&refused), Some("USER_DENIED"));
    assert_eq!(human.sheets(), 1, "the code asked the human");
    assert!(
        !sw.fills()
            .iter()
            .any(|f| matches!(f, ExtResponse::TotpCode { .. })),
        "and no code was released without a yes"
    );
    assert_eq!(fx.broker.pending_steps(), 1);
}

#[test]
fn a_code_is_released_only_into_a_tab_with_a_code_field() {
    // A sign-in page with no code field: nothing to write it into, and no clipboard on this path.
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    let reply = fx.request_fill(&fx.with_code, PAGE, &CODE);
    assert_eq!(code(&reply), Some("NO_MATCHING_TAB"));
    assert_eq!(
        human.sheets(),
        0,
        "no sheet for a tab that cannot take a code"
    );
    assert!(sw.deliveries().is_empty());

    // The code field gone by the time the grant is redeemed: refused, and nothing released.
    sw.set(
        Tab::code(PAGE),
        OnDeliver::RedeemChanged(Box::new(|tab| tab.found.one_time_code = false)),
    );
    let reply = fx.request_fill(&fx.with_code, PAGE, &CODE);
    assert_eq!(code(&reply), Some("NO_MATCHING_TAB"));
    assert_eq!(human.sheets(), 1);
    assert!(
        sw.fills_at_least(1)
            .iter()
            .all(|f| matches!(f, ExtResponse::Error { .. })),
        "{:?}",
        sw.fills()
    );
    assert!(
        fx.on_disk().iter().all(|e| e.outcome != Outcome::Allowed),
        "nothing was released"
    );
}

#[test]
fn an_unmasked_report_is_audited_as_a_follow_up() {
    let fx = fixture();
    let _human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    let reply = fx.request_fill(&fx.item, PAGE, &both());
    assert_eq!(written(&reply).0, both());
    let (_, grant) = sw.deliveries().remove(0);
    let released = fill_entries(&fx)
        .into_iter()
        .find(|e| e.outcome == Outcome::Allowed)
        .expect("the release");
    let _ = fx.broker.take_notices();

    // The tripwire fires, and fires again: one follow-up, one notice, and no second fill.
    for _ in 0..2 {
        let noted = sw.report_outcome(
            &grant,
            vec![PageField::Password],
            Some(AgentFillFailure::Unmasked),
        );
        assert_eq!(noted, ExtResponse::Noted);
    }
    let unmasked = format!("AGENT_FILL_UNMASKED (entry {})", released.seq);
    assert!(eventually_recorded(&fx, &unmasked), "{:?}", details(&fx));
    assert_eq!(
        details(&fx).iter().filter(|d| **d == unmasked).count(),
        1,
        "once per fill"
    );
    let entry = fill_entries(&fx)
        .into_iter()
        .find(|e| e.detail.as_deref() == Some(unmasked.as_str()))
        .expect("the follow-up");
    assert_eq!(entry.outcome, Outcome::Failed);
    assert_eq!(entry.target_path.as_deref(), Some(PAGE));
    assert_eq!(sw.fills().len(), 1, "never a second fill");

    let notices = fx.broker.take_notices();
    assert!(
        matches!(
            &notices[..],
            [AgentFillNotice::Unmasked { item_title, origin, .. }]
                if item_title == "Example (work)" && origin.ascii() == PAGE
        ),
        "{notices:?}"
    );
}

#[test]
fn an_unmasked_report_without_a_password_write_is_ignored() {
    // Step one of a two-step grant wrote only the username; a code wrote only a code. Neither
    // put a password in the page, so the tripwire has nothing to say about either.
    let fx = fixture();
    let _human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::identifier_only(PAGE), OnDeliver::Redeem);
    let _ = step_one(&fx, &sw);
    let (_, step_one_grant) = sw.deliveries().remove(0);
    sw.set(Tab::code(PAGE), OnDeliver::Redeem);
    let _ = fx.request_fill(&fx.with_code, PAGE, &CODE);
    let (_, code_grant) = sw.deliveries().remove(0);
    let _ = fx.broker.take_notices();

    for grant in [&step_one_grant, &code_grant] {
        let noted = sw.report_outcome(
            grant,
            vec![PageField::Password],
            Some(AgentFillFailure::Unmasked),
        );
        assert_eq!(noted, ExtResponse::Noted);
    }
    // A grant nobody issued, too.
    let _ = sw.report_outcome(
        "grant-made-up",
        vec![PageField::Password],
        Some(AgentFillFailure::Unmasked),
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        details(&fx)
            .iter()
            .all(|d| !d.contains("AGENT_FILL_UNMASKED")),
        "{:?}",
        details(&fx)
    );
    assert!(fx.broker.take_notices().is_empty());
    assert_eq!(
        fx.broker.pending_steps(),
        1,
        "nor does it touch the pending step"
    );
}
