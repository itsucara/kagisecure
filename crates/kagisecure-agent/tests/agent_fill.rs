//! Agent-requested browser fills, end to end below the sheet (ADR-0036, Phase 1): a raw IPC client
//! on the agent socket plays the sidecar, a scripted duplex client on the extension socket plays
//! the extension's service worker, and a thread on the approval queue plays the human.
//!
//! What these assert is the shape of the feature: the gates answer in the documented order, a
//! hidden item is an absent one before any browser hears of it, exactly one tab in front is
//! filled or none is, a look-alike raises no sheet, and the agent hears field names — never a
//! value — while the value reaches the extension in the one reply that has always carried it.

mod agent_fill_support;

use std::time::Duration;

use agent_fill_support::{
    Fixture, Human, LOOK_ALIKE, MARKER, OnDeliver, PAGE, SAVED, Seen, ServiceWorker, Tab, both,
    carries_marker, code, fixture,
};
use kagisecure_agent::AgentFillNotice;
use kagisecure_agent::approval::{ApprovalKind, Decision};
use kagisecure_core::proto::Outcome;
use kagisecure_extension_ipc::protocol::{AgentFillFailure, Response as ExtResponse};
use kagisecure_ipc::protocol::{AgentFillField, Response};

/// An item id that names nothing, spelled like a real one.
const ABSENT: &str = "00000000-0000-4000-8000-000000000000";

fn fill(fx: &Fixture, item: &str) -> Response {
    fx.request_fill(item, PAGE, &both())
}

#[test]
fn gates_answer_in_the_documented_order() {
    let fx = fixture();

    // 1 before everything: off answers the same whatever else is wrong.
    fx.broker.set_enabled(false);
    assert_eq!(code(&fill(&fx, ABSENT)), Some("FILL_UNAVAILABLE"));
    assert_eq!(code(&fill(&fx, &fx.no_password)), Some("FILL_UNAVAILABLE"));
    fx.broker.set_enabled(true);

    // 3 before 5: an unknown item is NOT_FOUND although no browser is connected.
    assert_eq!(code(&fill(&fx, ABSENT)), Some("NOT_FOUND"));
    // 4 before 5: a missing password, and an archived item.
    assert_eq!(code(&fill(&fx, &fx.no_password)), Some("NOTHING_TO_FILL"));
    let archived = fill(&fx, &fx.archived);
    assert_eq!(code(&archived), Some("NOTHING_TO_FILL"));
    let Response::Error { message, .. } = &archived else {
        unreachable!()
    };
    assert!(message.contains("archived"), "{message}");
    // 5: nothing to ask.
    assert_eq!(code(&fill(&fx, &fx.item)), Some("FILL_UNAVAILABLE"));

    // 6: a browser, but nothing eligible in front.
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::nothing(), OnDeliver::Redeem);
    assert_eq!(code(&fill(&fx, &fx.item)), Some("NO_MATCHING_TAB"));
    assert_eq!(sw.locates(), 1, "gate 6 is the first that asks a browser");
    assert_eq!(human.sheets(), 0);
    drop(human);

    // 7 before 8, and before 5 and 6 (review finding M2): an audit backlog that cannot be
    // written raises no sheet and asks no browser.
    #[cfg(unix)]
    {
        let human = Human::approving(&fx.queue);
        sw.set(Tab::front(PAGE), OnDeliver::Redeem);
        let bytes = std::fs::read(fx.path()).expect("read");
        std::fs::remove_file(fx.path()).expect("remove");
        std::fs::create_dir(fx.path()).expect("a directory in its place");
        // A refusal is recorded best-effort; with the file broken it stays queued.
        assert_eq!(code(&fill(&fx, &fx.no_password)), Some("NOTHING_TO_FILL"));
        assert_eq!(code(&fill(&fx, &fx.item)), Some("AUDIT_UNAVAILABLE"));
        assert_eq!(human.sheets(), 0, "nobody is asked what cannot be recorded");
        assert_eq!(sw.locates(), 0, "and no tab is looked at first");
        std::fs::remove_dir(fx.path()).expect("remove the directory");
        std::fs::write(fx.path(), bytes).expect("put the file back");
        drop(human);
    }

    // 8: the human.
    let human = Human::denying(&fx.queue);
    sw.set(Tab::front(PAGE), OnDeliver::Redeem);
    assert_eq!(code(&fill(&fx, &fx.item)), Some("USER_DENIED"));
    assert_eq!(human.sheets(), 1);
    drop(human);

    // 9: delivery. A denial no longer sticks (amendment of 2026-10-03).
    let human = Human::approving(&fx.queue);
    sw.set(
        Tab::front(PAGE),
        OnDeliver::Undeliverable(AgentFillFailure::FormChanged),
    );
    assert_eq!(code(&fill(&fx, &fx.item)), Some("NO_MATCHING_TAB"));
    assert_eq!(human.sheets(), 1);

    // And 2, which needs a vault of its own to lock: after 1, before 3.
    let locked = fixture();
    drop(locked.handle.take());
    assert_eq!(code(&fill(&locked, ABSENT)), Some("VAULT_LOCKED"));
    locked.broker.set_enabled(false);
    assert_eq!(code(&fill(&locked, ABSENT)), Some("FILL_UNAVAILABLE"));
}

#[test]
fn hidden_and_absent_items_answer_identically_before_any_push() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);

    let absent = serde_json::to_string(&fill(&fx, ABSENT)).expect("json");
    assert!(absent.contains("NOT_FOUND"), "{absent}");
    for (what, id) in [
        ("hidden", &fx.hidden),
        ("in a hidden vault", &fx.in_hidden_vault),
        ("trashed", &fx.trashed),
    ] {
        for fields in [
            both(),
            vec![AgentFillField::Password],
            vec![AgentFillField::Username],
        ] {
            let reply = serde_json::to_string(&fx.request_fill(id, PAGE, &fields)).expect("json");
            assert_eq!(
                reply, absent,
                "a {what} item must answer like a missing one"
            );
        }
        // Whatever origin is claimed, even the look-alike.
        let reply = serde_json::to_string(&fx.request_fill(id, LOOK_ALIKE, &both())).expect("j");
        assert_eq!(
            reply, absent,
            "a {what} item must answer like a missing one"
        );
    }
    assert_eq!(sw.locates(), 0, "no browser is asked about a hidden item");
    assert_eq!(human.sheets(), 0);
    // The entries they leave are identical too, and name no item.
    let refusals: Vec<_> = fx
        .on_disk()
        .into_iter()
        .filter(|e| e.tool == "request_fill")
        .map(|e| (e.item_id, e.outcome, e.detail))
        .collect();
    assert!(!refusals.is_empty());
    assert!(
        refusals
            .iter()
            .all(|r| *r == (None, Outcome::Denied, Some("NOT_FOUND".to_owned()))),
        "{refusals:?}"
    );
}

#[test]
fn a_disabled_switch_answers_fill_unavailable_before_the_item_is_looked_up() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    fx.broker.set_enabled(false);
    let before = fx.on_disk().len();

    let mut answers = Vec::new();
    for id in [
        &fx.item,
        &fx.hidden,
        &fx.archived,
        &fx.no_password,
        &ABSENT.to_owned(),
    ] {
        for origin in [PAGE, LOOK_ALIKE, "not an origin"] {
            let reply = fx.request_fill(id, origin, &both());
            assert_eq!(code(&reply), Some("FILL_UNAVAILABLE"), "{reply:?}");
            answers.push(serde_json::to_string(&reply).expect("json"));
        }
    }
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "off must not vary with the item: {answers:?}"
    );
    assert_eq!(sw.locates(), 0);
    assert_eq!(human.sheets(), 0);
    assert_eq!(
        fx.on_disk().len(),
        before,
        "nothing about an item was even read"
    );
}

#[test]
fn an_approved_fill_types_the_value_into_the_page_and_tells_the_agent_only_field_names() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);

    let reply = fill(&fx, &fx.item);
    assert_eq!(
        reply,
        Response::FillResult {
            fields_written: both(),
            fields_pending: Vec::new(),
        }
    );

    // The value crossed exactly once, to the extension, in the reply that always carried it.
    let fills = sw.fills();
    assert_eq!(fills.len(), 1);
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
        other => panic!("expected a fill, got {other:?}"),
    }
    // Deliver named the probe whose report was approved.
    let seen = sw.seen();
    let located = seen.iter().find_map(|s| match s {
        Seen::Locate { probe_id } => Some(probe_id.clone()),
        _ => None,
    });
    let delivered = seen.iter().find_map(|s| match s {
        Seen::Deliver { probe_id, .. } => Some(probe_id.clone()),
        _ => None,
    });
    assert!(located.is_some());
    assert_eq!(delivered, located);

    // One full sheet, with the facts the ADR puts on it.
    let sheets = human.seen();
    assert_eq!(sheets.len(), 1);
    let sheet = &sheets[0];
    assert_eq!(sheet.kind, ApprovalKind::AgentFill);
    assert!(!sheet.presence_only);
    let facts = sheet.agent_fill.as_ref().expect("agent-fill facts");
    assert_eq!(facts.agent_name, "example-agent");
    assert_eq!(facts.sidecar_pid, std::process::id());
    assert_eq!(facts.page_origin.ascii(), PAGE);
    assert_eq!(facts.page_origin.emphasized, "example.com");
    assert_eq!(facts.saved_website, SAVED);
    assert!(facts.page_host_differs);
    assert_eq!(facts.item_title, "Example (work)");
    assert!(!carries_marker(&format!("{sheet:?}")));

    // Recorded as the agent's, before the release, with the browser-established origin.
    let entries = fx.on_disk();
    let approved = entries
        .iter()
        .find(|e| e.tool == "request_fill" && e.outcome == Outcome::Allowed)
        .expect("an Allowed entry");
    assert_eq!(approved.detail.as_deref(), Some("AGENT_FILL_APPROVED"));
    assert_eq!(approved.target_path.as_deref(), Some(PAGE));
    assert_eq!(approved.variables, vec!["username", "password"]);
    assert!(
        approved.actor.starts_with("mcp \"example-agent\""),
        "{}",
        approved.actor
    );
    assert!(approved.actor.contains(" via "), "{}", approved.actor);
    assert!(
        approved.actor.contains("(extension \""),
        "{}",
        approved.actor
    );
    assert_eq!(approved.client_pid, Some(std::process::id()));
    assert_eq!(fx.broker.live_grants(), 0, "a used grant is gone");
}

#[test]
fn the_sidecar_reply_never_contains_the_value() {
    let fx = fixture();
    let _human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);

    for fields in [
        both(),
        vec![AgentFillField::Password],
        vec![AgentFillField::Username],
    ] {
        let reply = fx.request_fill(&fx.item, PAGE, &fields);
        assert!(
            matches!(reply, Response::FillResult { .. }),
            "{fields:?}: {reply:?}"
        );
        assert!(!carries_marker(&reply), "the value reached the agent");
    }
    // It did cross — to the extension, which is where it belongs.
    assert!(sw.fills().iter().any(carries_marker));
    for entry in fx.on_disk() {
        assert!(!carries_marker(&entry), "{entry:?}");
    }
}

#[test]
fn two_eligible_tabs_are_no_matching_tab() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let first = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    let second = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);

    assert_eq!(code(&fill(&fx, &fx.item)), Some("NO_MATCHING_TAB"));
    assert_eq!(first.locates(), 1);
    assert_eq!(second.locates(), 1, "every connected browser is asked");
    assert_eq!(
        human.sheets(),
        0,
        "choosing would be guessing; nobody is asked"
    );
    assert!(first.fills().is_empty() && second.fills().is_empty());
    assert_eq!(
        fx.fill_entries(),
        vec![(Outcome::Denied, "AGENT_FILL_NO_TARGET".to_owned())]
    );

    // One of them on another page leaves exactly one eligible tab.
    second.set(Tab::nothing(), OnDeliver::Redeem);
    assert!(matches!(fill(&fx, &fx.item), Response::FillResult { .. }));
}

#[test]
fn a_look_alike_origin_raises_no_sheet_and_is_audited_as_a_mismatch() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(LOOK_ALIKE), OnDeliver::Redeem);

    // Whether the agent was fooled (claims the saved site) or honest (claims what it sees), the
    // tab in front is not a site saved for the item.
    let claims = [PAGE, LOOK_ALIKE];
    let mut answers = Vec::new();
    for claim in claims {
        let reply = fx.request_fill(&fx.item, claim, &both());
        assert_eq!(code(&reply), Some("NO_MATCHING_TAB"), "{claim}");
        answers.push(serde_json::to_string(&reply).expect("json"));
    }
    assert_eq!(answers[0], answers[1], "one code, one message");
    assert_eq!(human.sheets(), 0);
    assert!(sw.fills().is_empty());

    let entries: Vec<_> = fx
        .on_disk()
        .into_iter()
        .filter(|e| e.tool == "request_fill")
        .collect();
    assert_eq!(entries.len(), 2);
    for entry in &entries {
        assert_eq!(entry.outcome, Outcome::Denied);
        assert_eq!(entry.target_path.as_deref(), Some(LOOK_ALIKE));
    }
    // A mismatch no longer escalates to a block (amendment of 2026-10-03).
    for entry in &entries {
        assert_eq!(entry.detail.as_deref(), Some("AGENT_FILL_ORIGIN_MISMATCH"));
    }
    let notices = fx.broker.take_notices();
    let mismatches: Vec<_> = notices
        .iter()
        .filter_map(|n| match n {
            AgentFillNotice::OriginMismatch {
                item_title, origin, ..
            } => Some((item_title, origin)),
            _ => None,
        })
        .collect();
    assert_eq!(mismatches.len(), 2, "the human hears about each one");
    let (item_title, origin) = mismatches[0];
    assert_eq!(item_title, "Example (work)");
    assert_eq!(origin.ascii(), LOOK_ALIKE);
}

#[test]
fn a_claim_that_differs_on_a_saved_site_is_no_target_and_raises_no_notice() {
    let fx = fixture();
    let human = Human::approving(&fx.queue);
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);

    // The tab is on a saved site; the agent's bookkeeping is off by a subdomain.
    let reply = fx.request_fill(&fx.item, SAVED, &both());
    assert_eq!(code(&reply), Some("NO_MATCHING_TAB"));
    assert_eq!(human.sheets(), 0);
    assert_eq!(
        fx.fill_entries(),
        vec![(Outcome::Denied, "AGENT_FILL_NO_TARGET".to_owned())]
    );
    assert!(fx.broker.take_notices().is_empty());
}

#[test]
fn a_human_fill_lease_never_excuses_an_agent_fill() {
    let fx = fixture();
    // The human filled this item on this page a moment ago and chose "Allow for this session".
    let extension = fx.extension.lock().expect("listener");
    extension.grant_fill_lease_for_test(PAGE, &fx.item, "Example (work)");
    assert_eq!(extension.fill_leases().len(), 1);
    drop(extension);

    let human = Human::approving(&fx.queue);
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    let reply = fx.request_fill(&fx.item, PAGE, &[AgentFillField::Password]);
    assert!(matches!(reply, Response::FillResult { .. }), "{reply:?}");

    let sheets = human.seen();
    assert_eq!(sheets.len(), 1, "the agent still got a sheet");
    assert_eq!(sheets[0].kind, ApprovalKind::AgentFill);
    assert!(
        !sheets[0].presence_only,
        "the full sheet, not a presence prompt"
    );
}

#[test]
fn an_agent_approval_never_mints_a_fill_lease() {
    let fx = fixture();
    // A UI that answers "for this session" is clamped to once for an agent fill.
    let _human = Human::new(&fx.queue, |_| {
        Some(Decision::AllowSession {
            ttl_seconds: 900,
            uses: 10,
        })
    });
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    assert!(matches!(fill(&fx, &fx.item), Response::FillResult { .. }));
    assert!(
        fx.extension
            .lock()
            .expect("listener")
            .fill_leases()
            .is_empty(),
        "no fill lease"
    );
    assert!(fx.agent.leases().is_empty(), "no env lease");
}

#[test]
fn a_denied_sheet_is_user_denied_and_audited() {
    let fx = fixture();
    let _human = Human::denying(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    assert_eq!(code(&fill(&fx, &fx.item)), Some("USER_DENIED"));
    assert!(
        !sw.seen().iter().any(|s| matches!(s, Seen::Deliver { .. })),
        "nothing is delivered"
    );
    assert_eq!(
        fx.fill_entries(),
        vec![(Outcome::Denied, "AGENT_FILL_DENIED".to_owned())]
    );
}

#[test]
fn a_second_request_while_one_is_in_progress_is_refused_at_once() {
    let fx = fixture();
    // A human who takes their time over the first sheet.
    let human = Human::new(&fx.queue, |_| {
        std::thread::sleep(Duration::from_millis(800));
        Some(Decision::AllowOnce)
    });
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);

    std::thread::scope(|scope| {
        let first = scope.spawn(|| fill(&fx, &fx.item));
        // Until the first sheet is up.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while fx.queue.waiting() == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let started = std::time::Instant::now();
        let second = fill(&fx, &fx.item);
        assert_eq!(code(&second), Some("RATE_LIMITED"), "{second:?}");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "answered at once"
        );
        assert!(matches!(
            first.join().expect("first"),
            Response::FillResult { .. }
        ));
    });
    assert_eq!(
        human.sheets(),
        1,
        "one sheet at a time, and no queue of them"
    );
}

#[test]
fn a_fill_the_page_could_not_write_is_audited_as_not_written() {
    let fx = fixture();
    let _human = Human::approving(&fx.queue);
    let _sw = ServiceWorker::start(
        &fx,
        Tab::front(PAGE),
        OnDeliver::RedeemButFail(AgentFillFailure::WriteRejected),
    );
    assert_eq!(code(&fill(&fx, &fx.item)), Some("NO_MATCHING_TAB"));
    let entries = fx.on_disk();
    let allowed = entries
        .iter()
        .find(|e| e.tool == "request_fill" && e.outcome == Outcome::Allowed)
        .expect("the release was recorded");
    let last = entries.last().expect("an entry");
    assert_eq!(last.outcome, Outcome::Failed);
    assert_eq!(
        last.detail.as_deref(),
        Some(format!("AGENT_FILL_NOT_WRITTEN (entry {})", allowed.seq).as_str())
    );
}

#[test]
fn a_delivery_the_extension_could_not_make_is_not_delivered() {
    let fx = fixture();
    let _human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(
        &fx,
        Tab::front(PAGE),
        OnDeliver::Undeliverable(AgentFillFailure::NotVisible),
    );
    assert_eq!(code(&fill(&fx, &fx.item)), Some("NO_MATCHING_TAB"));
    assert!(sw.fills().is_empty());
    assert_eq!(fx.broker.live_grants(), 0);
    assert_eq!(
        fx.fill_entries(),
        vec![(Outcome::Failed, "AGENT_FILL_NOT_DELIVERED".to_owned())]
    );
}

#[test]
fn a_session_that_did_not_declare_agent_fill_is_never_pushed_to() {
    let fx = fixture();
    let mut client =
        kagisecure_extension_ipc::Client::connect(&fx.extension_endpoint).expect("connect");
    let welcome = client
        .call(
            "hello",
            &kagisecure_extension_ipc::protocol::Request::Hello {
                extension_id: kagisecure_extension_ipc::PINNED_EXTENSION_IDS[0].to_owned(),
                browser: "chrome".to_owned(),
                extension_version: "0.1.0".to_owned(),
                protocol_version: kagisecure_extension_ipc::PROTOCOL_VERSION,
                capabilities: vec![],
            },
        )
        .expect("hello");
    assert!(matches!(welcome, ExtResponse::Welcome { .. }));
    assert_eq!(fx.broker.connected_sessions(), 0);
    assert_eq!(code(&fill(&fx, &fx.item)), Some("FILL_UNAVAILABLE"));
    // And the agent-fill requests are not served on it.
    let refused = client
        .call(
            "report",
            &kagisecure_extension_ipc::protocol::Request::AgentFill {
                grant_id: "grant-x".to_owned(),
                page: kagisecure_extension_ipc::protocol::PageContext::top(PAGE),
                tab: Tab::front(PAGE).tab,
                found: Tab::front(PAGE).found,
            },
        )
        .expect("a reply");
    assert!(matches!(refused, ExtResponse::Error { .. }), "{refused:?}");
}

/// The origin of a page the item is not saved for, at which an agent claims to be.
const UNSAVED: &str = "https://unsaved.test";

/// What an agent learns from one `request_fill` when something target-independent goes wrong
/// after gate 5: the reply's bytes, and whether a sheet or a notice told the human about it.
fn probe_outcome(fx: &Fixture, human: &Human, tab_origin: &str) -> (String, usize, usize) {
    let reply = fx.request_fill(&fx.item, tab_origin, &both());
    (
        serde_json::to_string(&reply).expect("json"),
        human.sheets(),
        fx.broker.take_notices().len(),
    )
}

/// R-9's bit, asked while the audit log cannot be written (review finding M2, case A). Before,
/// a tab the item is saved for got `AUDIT_UNAVAILABLE` and one it is not saved for got
/// `NO_MATCHING_TAB` — the answer to "is this item saved for the site I am on", with no sheet and
/// no notice. The pre-flight now runs before any tab is looked at.
#[test]
#[cfg(unix)]
fn an_unwritable_audit_log_answers_the_same_whether_or_not_the_item_is_saved_for_the_tab() {
    let mut seen = Vec::new();
    for tab_origin in [PAGE, UNSAVED] {
        let fx = fixture();
        let human = Human::approving(&fx.queue);
        let sw = ServiceWorker::start(&fx, Tab::front(tab_origin), OnDeliver::Redeem);
        // Earlier entries that cannot be written: a refusal is recorded best-effort, and with a
        // directory where the vault file was it stays queued.
        std::fs::remove_file(fx.path()).expect("remove");
        std::fs::create_dir(fx.path()).expect("a directory in its place");
        assert_eq!(code(&fill(&fx, &fx.no_password)), Some("NOTHING_TO_FILL"));

        let outcome = probe_outcome(&fx, &human, tab_origin);
        assert_eq!(sw.locates(), 0, "no tab is looked at: {tab_origin}");
        seen.push(outcome);
        std::fs::remove_dir(fx.path()).expect("remove the directory");
    }
    assert!(seen[0].0.contains("AUDIT_UNAVAILABLE"), "{seen:?}");
    assert_eq!(
        seen[0], seen[1],
        "saved for the tab or not, the agent learns nothing"
    );
    assert_eq!(seen[0].1, 0, "no sheet");
}

/// R-9's bit, asked by locking the vault while the browsers are being asked (review finding M2,
/// case B). The `lock` tool closes the approval queue with the vault still in the handle; before,
/// a tab the item is saved for then got `VAULT_LOCKED` from the closed queue, with no sheet, and
/// one it is not saved for got `NO_MATCHING_TAB`. A lock since the flow began is now answered
/// right after the probe, before any report is read.
#[test]
fn a_lock_during_the_probe_answers_the_same_whether_or_not_the_item_is_saved_for_the_tab() {
    let mut seen = Vec::new();
    for tab_origin in [PAGE, UNSAVED] {
        let fx = agent_fill_support::fixture_with(kagisecure_agent::AgentFillTimings {
            probe_window: Duration::from_millis(800),
            ..kagisecure_agent::AgentFillTimings::default()
        });
        let human = Human::approving(&fx.queue);
        let _sw = ServiceWorker::start(&fx, Tab::front(tab_origin), OnDeliver::Redeem);
        // A second browser that never answers holds the probe open for its whole window.
        let mute = agent_fill_support::MuteSession::start(&fx);
        let outcome = std::thread::scope(|scope| {
            let pending = scope.spawn(|| probe_outcome(&fx, &human, tab_origin));
            assert!(mute.located(), "the probe has begun");
            let locked = agent_fill_support::agent_call(
                &fx.agent_endpoint,
                &kagisecure_ipc::protocol::Request::Lock,
            );
            assert_eq!(locked, Response::Locked);
            pending.join().expect("reply")
        });
        seen.push(outcome);
    }
    assert!(seen[0].0.contains("VAULT_LOCKED"), "{seen:?}");
    assert_eq!(
        seen[0], seen[1],
        "saved for the tab or not, the agent learns nothing"
    );
    assert_eq!(seen[0].1, 0, "no sheet");
}

/// Every agent-fill entry on disk — `request_fill`, and `totp_code` for a one-time code — as
/// (outcome, detail, whether it names an item).
fn entries(fx: &Fixture) -> Vec<(Outcome, String, bool)> {
    fx.on_disk()
        .into_iter()
        .filter(|e| e.tool == "request_fill" || e.tool == "totp_code")
        .map(|e| (e.outcome, e.detail.unwrap_or_default(), e.item_id.is_some()))
        .collect()
}

/// The one entry `run` left, however it ended: exactly one more `request_fill` entry than before.
fn one_entry(fx: &Fixture, run: impl FnOnce() -> Response) -> (Response, (Outcome, String, bool)) {
    let before = entries(fx).len();
    let reply = run();
    let after = entries(fx);
    assert_eq!(after.len(), before + 1, "{reply:?}: {after:?}");
    (reply, after[before].clone())
}

fn denied(detail: &str, names_item: bool) -> (Outcome, String, bool) {
    (Outcome::Denied, detail.to_owned(), names_item)
}

/// A request that holds the probe open with a browser that never answers, and does `meanwhile`
/// while the browsers are being asked.
fn during_the_probe(fx: &Fixture, meanwhile: impl FnOnce()) -> Response {
    let mute = agent_fill_support::MuteSession::start(fx);
    std::thread::scope(|scope| {
        let pending = scope.spawn(|| fill(fx, &fx.item));
        assert!(mute.located(), "the probe has begun");
        meanwhile();
        pending.join().expect("reply")
    })
}

fn quick_probe() -> Fixture {
    agent_fill_support::fixture_with(kagisecure_agent::AgentFillTimings {
        probe_window: Duration::from_millis(500),
        ..kagisecure_agent::AgentFillTimings::default()
    })
}

fn lock_through_the_agent_socket(fx: &Fixture) {
    let locked = agent_fill_support::agent_call(
        &fx.agent_endpoint,
        &kagisecure_ipc::protocol::Request::Lock,
    );
    assert_eq!(locked, Response::Locked);
}

/// ADR-0036 §10: every request leaves at least one entry — including every way out that used to
/// leave none (review finding L4). Each is driven here on its own, with the vault still in the
/// handle so there is somewhere to write to, and exactly one entry must appear. Entries written
/// before the item is looked up, and after it turned out hidden, name no item.
#[test]
fn every_way_out_of_request_fill_leaves_one_audit_entry() {
    use kagisecure_ipc::protocol::Request;

    // The arguments.
    let fx = fixture();
    let (reply, entry) = one_entry(&fx, || fx.request_fill(&fx.item, "not an origin", &both()));
    assert_eq!(code(&reply), Some("INVALID_ARGUMENT"));
    assert_eq!(entry, denied("INVALID_ARGUMENT", false));
    let (reply, entry) = one_entry(&fx, || fx.request_fill(&fx.item, PAGE, &[]));
    assert_eq!(code(&reply), Some("INVALID_ARGUMENT"));
    assert_eq!(entry, denied("INVALID_ARGUMENT", false));
    // A one-time code is served now (Phase 3): for an item with none, it is gate 4's answer,
    // recorded under the tool codes are audited as.
    let (reply, entry) = one_entry(&fx, || {
        fx.request_fill(&fx.item, PAGE, &[AgentFillField::OneTimeCode])
    });
    assert_eq!(code(&reply), Some("NOTHING_TO_FILL"));
    assert_eq!(entry, denied("NOTHING_TO_FILL", true));
    assert_eq!(
        fx.on_disk().last().map(|e| e.tool.clone()).as_deref(),
        Some("totp_code")
    );

    // Gate 2: locked, with the vault still in the handle (the `lock` tool).
    let fx = fixture();
    lock_through_the_agent_socket(&fx);
    let (reply, entry) = one_entry(&fx, || fill(&fx, &fx.item));
    assert_eq!(code(&reply), Some("VAULT_LOCKED"));
    assert_eq!(entry, denied("VAULT_LOCKED", false));

    // Gate 2: the file in dispute. Nothing can be written to it, so the entry waits in memory.
    let fx = fixture();
    let older = std::fs::read(fx.path()).expect("read the vault");
    let _ = agent_fill_support::agent_call(&fx.agent_endpoint, &Request::ListVaults);
    std::fs::write(fx.path(), &older).expect("restore an older copy");
    let unsaved = || {
        fx.handle
            .with(|v| v.unsaved_audit_entries())
            .expect("unlocked")
    };
    let before = unsaved();
    assert_eq!(code(&fill(&fx, &fx.item)), Some("VAULT_CONFLICT"));
    assert_eq!(unsaved(), before + 1, "one entry, queued");

    // After the probe: the item hidden, or left with nothing to fill, while the browsers were
    // being asked; or the vault locked meanwhile.
    for (what, change, answer, entry) in [
        (
            "hidden",
            (|item: &mut kagisecure_core::model::Item| item.agent_visible = false)
                as fn(&mut kagisecure_core::model::Item),
            "NOT_FOUND",
            denied("NOT_FOUND", false),
        ),
        (
            "archived",
            |item: &mut kagisecure_core::model::Item| item.archived = true,
            "NOTHING_TO_FILL",
            denied("NOTHING_TO_FILL", true),
        ),
    ] {
        let fx = quick_probe();
        let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
        let (reply, recorded) = one_entry(&fx, || {
            during_the_probe(&fx, || {
                fx.handle
                    .transact(Duration::from_secs(5), |tx| {
                        change(tx.find_item_mut(&fx.item)?);
                        Ok(())
                    })
                    .expect("unlocked")
                    .expect("saved");
            })
        });
        assert_eq!(code(&reply), Some(answer), "{what}");
        assert_eq!(recorded, entry, "{what}");
    }
    let fx = quick_probe();
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    let (reply, entry) = one_entry(&fx, || {
        during_the_probe(&fx, || lock_through_the_agent_socket(&fx))
    });
    assert_eq!(code(&reply), Some("VAULT_LOCKED"));
    assert_eq!(entry, denied("VAULT_LOCKED", true));

    // At the sheet: the vault locks instead of anybody answering.
    let fx = fixture();
    let endpoint = fx.agent_endpoint.clone();
    let _human = Human::new(&fx.queue, move |_| {
        let _ = agent_fill_support::agent_call(&endpoint, &Request::Lock);
        None
    });
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    let (reply, entry) = one_entry(&fx, || fill(&fx, &fx.item));
    assert_eq!(code(&reply), Some("VAULT_LOCKED"));
    assert_eq!(entry, denied("VAULT_LOCKED", true));

    // Approved, and a lock takes the approval before a grant is issued.
    let fx = fixture();
    let broker = std::sync::Arc::clone(&fx.broker);
    let _human = Human::new(&fx.queue, move |_| {
        broker.revoke_all();
        Some(Decision::AllowOnce)
    });
    let _sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    let (reply, entry) = one_entry(&fx, || fill(&fx, &fx.item));
    assert_eq!(code(&reply), Some("VAULT_LOCKED"));
    assert_eq!(
        entry,
        (Outcome::Failed, "AGENT_FILL_NOT_DELIVERED".to_owned(), true)
    );

    // Approved and issued, and a lock takes the waiting grant.
    let fx = fixture();
    let _human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Hold);
    let (reply, entry) = one_entry(&fx, || {
        std::thread::scope(|scope| {
            let pending = scope.spawn(|| fill(&fx, &fx.item));
            sw.delivered_grant().expect("a delivery");
            fx.broker.revoke_all();
            pending.join().expect("reply")
        })
    });
    assert_eq!(code(&reply), Some("VAULT_LOCKED"));
    assert_eq!(
        entry,
        (Outcome::Failed, "AGENT_FILL_NOT_DELIVERED".to_owned(), true)
    );
}
