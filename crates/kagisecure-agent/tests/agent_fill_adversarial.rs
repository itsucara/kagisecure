//! Agent-requested fills against somebody trying to get a value where the human did not send it
//! (ADR-0036 §4, §6).
//!
//! Each binding a grant carries is changed **alone** between the approval and the redemption —
//! the tab, the document, the origin, the extension session, the sidecar process — and each on
//! its own must refuse the fill, spend the grant and release nothing. So must time, a second use,
//! a lock and an audit log that cannot be written.

mod agent_fill_support;

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_fill_support::{
    Fixture, Human, OnDeliver, PAGE, ServiceWorker, Tab, both, carries_marker, code, fixture,
    fixture_with,
};
use kagisecure_agent::AgentFillTimings;
use kagisecure_agent::approval::Decision;
use kagisecure_core::proto::Outcome;
use kagisecure_extension_ipc::protocol::{ErrorCode as ExtCode, Response as ExtResponse};
use kagisecure_ipc::protocol::Response;

fn fill(fx: &Fixture) -> Response {
    fx.request_fill(&fx.item, PAGE, &both())
}

/// A redemption refused: nothing crossed, the grant is gone, nothing was recorded as released,
/// and the agent was told there was no tab.
fn assert_refused(fx: &Fixture, sw: &ServiceWorker, reply: &Response, what: &str) {
    assert_eq!(code(reply), Some("NO_MATCHING_TAB"), "{what}: {reply:?}");
    let fills = sw.fills_at_least(1);
    assert!(!fills.is_empty(), "{what}: the redemption was attempted");
    for fill in &fills {
        assert!(
            matches!(fill, ExtResponse::Error { .. }),
            "{what}: {fill:?}"
        );
        assert!(!carries_marker(fill), "{what}");
    }
    assert_eq!(fx.broker.live_grants(), 0, "{what}: the grant is spent");
    assert_eq!(
        fx.fill_entries(),
        vec![(Outcome::Failed, "AGENT_FILL_NOT_DELIVERED".to_owned())],
        "{what}: no Allowed entry, one NOT_DELIVERED"
    );
}

fn refused_when_only(what: &str, change: impl Fn(&mut Tab) + Send + Sync + 'static) {
    let fx = fixture();
    let _human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(
        &fx,
        Tab::front(PAGE),
        OnDeliver::RedeemChanged(Box::new(change)),
    );
    let reply = fill(&fx);
    assert_refused(&fx, &sw, &reply, what);
}

#[test]
fn a_grant_is_refused_when_only_the_tab_changes() {
    refused_when_only("another tab", |tab| tab.tab.tab_id += 1);
}

#[test]
fn a_grant_is_refused_when_only_the_document_changes() {
    refused_when_only("another document", |tab| {
        tab.tab.document_id = Some("doc-b".to_owned());
    });
    // Losing the document id is a change too, not a degradation the request may choose.
    refused_when_only("no document id", |tab| tab.tab.document_id = None);
}

#[test]
fn a_grant_is_refused_when_only_the_origin_changes() {
    // Another page on the same saved site, which the item covers: still not what was approved.
    refused_when_only("another origin on the same site", |tab| {
        tab.page = kagisecure_extension_ipc::protocol::PageContext::top("https://example.com");
    });
}

#[test]
fn a_grant_is_refused_when_only_the_frame_or_fields_change() {
    // Visibility and activity are no longer bindings (ADR-0036 amendment of 2026-10-03): an agent
    // may fill a background tab.
    refused_when_only("a frame", |tab| tab.page.top_origin_established = false);
    refused_when_only("identifier only now", |tab| tab.found.password = false);
}

#[test]
fn a_grant_is_refused_when_only_the_extension_session_changes() {
    let fx = fixture();
    let _human = Human::approving(&fx.queue);
    // The session that reports the tab, and holds the delivery for the test to redeem.
    let reporter = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Hold);
    // A second connected session, with nothing in front: it is asked, and not chosen.
    let other = ServiceWorker::start(&fx, Tab::nothing(), OnDeliver::Hold);

    std::thread::scope(|scope| {
        let pending = scope.spawn(|| fill(&fx));
        let grant = reporter.delivered_grant().expect("a delivery");
        // The same grant id, tab, document and origin — from the other session.
        let stolen = other.redeem(&grant, &Tab::front(PAGE));
        assert!(
            matches!(
                stolen,
                ExtResponse::Error {
                    code: ExtCode::NoMatch,
                    ..
                }
            ),
            "{stolen:?}"
        );
        assert!(!carries_marker(&stolen));
        // The failed attempt spent the grant: the rightful session gets nothing either.
        let late = reporter.redeem(&grant, &Tab::front(PAGE));
        assert!(matches!(late, ExtResponse::Error { .. }), "{late:?}");
        assert!(!carries_marker(&late));
        assert_eq!(
            code(&pending.join().expect("reply")),
            Some("NO_MATCHING_TAB")
        );
    });
    assert_eq!(fx.broker.live_grants(), 0);
    assert!(
        !fx.fill_entries()
            .iter()
            .any(|(outcome, _)| *outcome == Outcome::Allowed)
    );
}

/// The sidecar process that asked is gone by the time the extension redeems: the grant was bound
/// to it, so nothing is filled for whatever is left.
#[test]
fn a_grant_is_refused_when_only_the_agent_changes() {
    let fx = fixture();
    let sidecar_binary =
        kagisecure_test_support::binary("kagisecure-mcp", kagisecure_agent::bundle::SIDECAR);
    let mut child = Command::new(sidecar_binary)
        .env("KAGISECURE_SOCKET", fx.agent_endpoint.as_override())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn kagisecure-mcp");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let send = |stdin: &mut std::process::ChildStdin, value: serde_json::Value| {
        writeln!(stdin, "{value}").expect("write");
        stdin.flush().expect("flush");
    };
    send(
        &mut stdin,
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "example-agent", "version": "0"}}}),
    );
    let mut line = String::new();
    stdout.read_line(&mut line).expect("initialize reply");
    send(
        &mut stdin,
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    // The human approves only once the sidecar that asked is gone.
    let child = Arc::new(Mutex::new(child));
    let dying = Arc::clone(&child);
    let human = Human::new(&fx.queue, move |_| {
        let mut child = dying.lock().unwrap_or_else(|e| e.into_inner());
        let _ = child.kill();
        let _ = child.wait();
        Some(Decision::AllowOnce)
    });
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    send(
        &mut stdin,
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "request_fill",
            "arguments": {"item_id": fx.item, "origin": PAGE}}}),
    );

    // The flow finishes on its own: the redemption is refused and recorded.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while fx.fill_entries().is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(human.sheets(), 1);
    assert_refused(
        &fx,
        &sw,
        &code_only("NO_MATCHING_TAB"),
        "a sidecar that exited",
    );
}

/// A stand-in for a reply the test could not read (its sidecar is dead), so `assert_refused`
/// checks everything else.
fn code_only(code: &str) -> Response {
    Response::error(
        match code {
            "NO_MATCHING_TAB" => kagisecure_ipc::protocol::ErrorCode::NoMatchingTab,
            _ => kagisecure_ipc::protocol::ErrorCode::Internal,
        },
        "",
    )
}

#[test]
fn a_grant_expires_after_thirty_seconds() {
    // Thirty seconds in production (asserted in the broker's own unit tests); shortened here so
    // the test does not wait them out.
    let life = Duration::from_millis(300);
    let fx = fixture_with(AgentFillTimings {
        grant_life: life,
        ..AgentFillTimings::default()
    });
    let _human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(
        &fx,
        Tab::front(PAGE),
        OnDeliver::RedeemAfter(life + Duration::from_millis(200)),
    );
    let started = std::time::Instant::now();
    let reply = fill(&fx);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_refused(&fx, &sw, &reply, "an expired grant");
}

#[test]
fn a_grant_is_single_use() {
    let fx = fixture();
    let _human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Hold);

    std::thread::scope(|scope| {
        let pending = scope.spawn(|| fill(&fx));
        let grant = sw.delivered_grant().expect("a delivery");
        let first = sw.redeem(&grant, &Tab::front(PAGE));
        assert!(matches!(first, ExtResponse::Filled { .. }), "{first:?}");
        let second = sw.redeem(&grant, &Tab::front(PAGE));
        assert!(matches!(second, ExtResponse::Error { .. }), "{second:?}");
        assert!(!carries_marker(&second));
        sw.report_outcome(
            &grant,
            vec![
                kagisecure_extension_ipc::protocol::AgentFillField::Username,
                kagisecure_extension_ipc::protocol::AgentFillField::Password,
            ],
            None,
        );
        assert!(matches!(
            pending.join().expect("reply"),
            Response::FillResult { .. }
        ));
    });
    let allowed = fx
        .fill_entries()
        .into_iter()
        .filter(|(outcome, _)| *outcome == Outcome::Allowed)
        .count();
    assert_eq!(allowed, 1, "one approval, one release");
}

#[test]
fn a_lock_during_the_agent_fill_sheet_leaves_no_grant() {
    let fx = fixture();
    let handle = Arc::clone(&fx.handle);
    // The human locks the vault instead of answering.
    let _human = Human::new(&fx.queue, move |_| {
        drop(handle.take());
        None
    });
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    assert_eq!(code(&fill(&fx)), Some("VAULT_LOCKED"));
    assert_eq!(fx.broker.live_grants(), 0);
    assert!(
        !sw.seen()
            .iter()
            .any(|s| matches!(s, agent_fill_support::Seen::Deliver { .. })),
        "nothing to deliver"
    );
}

#[test]
fn a_lock_after_the_approval_revokes_the_waiting_grant() {
    let fx = fixture();
    let _human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Hold);
    std::thread::scope(|scope| {
        let pending = scope.spawn(|| fill(&fx));
        let grant = sw.delivered_grant().expect("a delivery");
        assert_eq!(fx.broker.live_grants(), 1);
        drop(fx.handle.take());
        assert_eq!(fx.broker.live_grants(), 0, "the lock took the grant");
        assert_eq!(code(&pending.join().expect("reply")), Some("VAULT_LOCKED"));
        let late = sw.redeem(&grant, &Tab::front(PAGE));
        assert!(matches!(late, ExtResponse::Error { .. }), "{late:?}");
        assert!(!carries_marker(&late));
    });
}

/// Unix-only: the save is broken by putting a directory where the vault file was.
#[test]
#[cfg(unix)]
fn a_release_that_cannot_be_audited_releases_nothing() {
    let fx = fixture();
    let path = fx.path();
    let saved = Arc::new(Mutex::new(Vec::new()));
    let stash = Arc::clone(&saved);
    // The pre-flight passes; the file breaks while the sheet is up.
    let _human = Human::new(&fx.queue, move |_| {
        *stash.lock().unwrap_or_else(|e| e.into_inner()) =
            std::fs::read(&path).expect("read the vault");
        std::fs::remove_file(&path).expect("remove");
        std::fs::create_dir(&path).expect("a directory in its place");
        Some(Decision::AllowOnce)
    });
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    let reply = fill(&fx);
    assert_eq!(code(&reply), Some("AUDIT_UNAVAILABLE"), "{reply:?}");
    let fills = sw.fills_at_least(1);
    assert_eq!(fills.len(), 1);
    assert!(
        matches!(
            fills[0],
            ExtResponse::Error {
                code: ExtCode::AuditUnavailable,
                ..
            }
        ),
        "{:?}",
        fills[0]
    );
    assert!(!carries_marker(&fills[0]), "nothing crossed");

    std::fs::remove_dir(fx.path()).expect("remove the directory");
    std::fs::write(fx.path(), &*saved.lock().unwrap_or_else(|e| e.into_inner()))
        .expect("put the file back");
    fx.handle
        .flush(Duration::from_secs(1))
        .expect("unlocked")
        .expect("flushed");
    let entries = fx.fill_entries();
    assert!(
        !entries
            .iter()
            .any(|(outcome, _)| *outcome == Outcome::Allowed),
        "{entries:?}"
    );
    assert_eq!(
        entries.last(),
        Some(&(Outcome::Failed, "AUDIT_UNAVAILABLE".to_owned()))
    );
}

#[test]
fn stopping_the_extension_listener_takes_the_waiting_grant_with_it() {
    let fx = fixture();
    let _human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Hold);
    std::thread::scope(|scope| {
        let pending = scope.spawn(|| fill(&fx));
        let _grant = sw.delivered_grant().expect("a delivery");
        // The app stops the extension listener on every lock; that ends every session.
        fx.extension.lock().expect("listener").stop();
        let reply = pending.join().expect("reply");
        assert!(
            matches!(code(&reply), Some("NO_MATCHING_TAB" | "VAULT_LOCKED")),
            "{reply:?}"
        );
    });
    assert_eq!(fx.broker.live_grants(), 0);
}

/// A redemption that outlives its deadline — here, one stuck behind another writer holding the
/// vault file — is given up on rather than waited for until it ends, and when it does end,
/// nothing is handed out: the agent has been told nothing was filled, and that stays true.
#[test]
fn a_redemption_past_its_deadline_frees_the_flow_and_hands_out_nothing() {
    let fx = fixture_with(AgentFillTimings {
        redeem_deadline: Duration::from_millis(300),
        ..AgentFillTimings::default()
    });
    let _human = Human::approving(&fx.queue);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Hold);
    std::thread::scope(|scope| {
        let pending = scope.spawn(|| fill(&fx));
        let grant = sw.delivered_grant().expect("a delivery");

        // Another process holds the vault file for a while.
        let (held, holding) = std::sync::mpsc::channel();
        let path = fx.path();
        let writer = scope.spawn(move || {
            let mut other = kagisecure_core::vault::Vault::open_with_password(path, b"pw")
                .expect("another writer opens the vault");
            other
                .transact(|_| {
                    held.send(()).expect("signal");
                    std::thread::sleep(Duration::from_millis(1500));
                    Ok(())
                })
                .expect("the other writer commits");
        });
        holding.recv().expect("the other writer holds the file");

        let sw = &sw;
        let redeeming = scope.spawn(move || sw.redeem(&grant, &Tab::front(PAGE)));
        // Without the deadline this redemption would release once the writer lets go, and the
        // agent would be told "filled".
        let reply = pending.join().expect("reply");
        assert_eq!(code(&reply), Some("NO_MATCHING_TAB"), "{reply:?}");
        let late = redeeming.join().expect("the redemption ends");
        assert!(matches!(late, ExtResponse::Error { .. }), "{late:?}");
        assert!(!carries_marker(&late), "nothing crossed");
        writer.join().expect("writer");
    });
    assert!(fx.broker.connected_sessions() > 0);
    assert_eq!(fx.broker.live_grants(), 0);
    let entries = fx.fill_entries();
    assert!(
        entries
            .iter()
            .any(|(outcome, detail)| *outcome == Outcome::Failed
                && detail.starts_with("AGENT_FILL_NOT_DELIVERED (entry ")),
        "the committed entry is followed up: {entries:?}"
    );
}
