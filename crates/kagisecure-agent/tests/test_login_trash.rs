//! `trash_test_logins` (ADR-0048 §12, Phase 3): the cleanup an agent runs when it rebuilds a test
//! environment.
//!
//! What these assert: a filter and a reason are required; the switch answers first; only sealed,
//! live logins in the test-login vault are touched — an unsealed item there and the person's own
//! logins are not; a match saved for a website outside the allowed origins refuses the whole
//! request with nothing trashed; everything matched goes in one transaction with one audit entry
//! naming the agent; and a trashed login vanishes from `list_test_logins` and from fills. The
//! unattended socket's `NO_GRANT` is in `unattended.rs`.

mod agent_fill_support;

use std::collections::BTreeMap;
use std::time::Duration;

use agent_fill_support::{
    Fixture, Human, OnDeliver, PAGE, ServiceWorker, Tab, agent_call, both, code, fixture,
};
use kagisecure_core::model::{Category, Item, TestLoginPolicy};
use kagisecure_core::proto::{ItemId, Outcome};
use kagisecure_core::vault::Vault;
use kagisecure_ipc::protocol::{Request, Response, TestLoginStatus};

const LOCAL: &str = "http://localhost:47800";
const PARTNER: &str = "https://staging.example-partner.com";
const WAIT: Duration = Duration::from_secs(5);

fn set_policy(fx: &Fixture, enabled: bool, domains: &[&str]) {
    fx.handle
        .transact(WAIT, |tx| {
            tx.ensure_agent_test_vault("test")?;
            tx.set_test_login_policy(
                TestLoginPolicy {
                    enabled,
                    auto_domains: domains.iter().map(|d| (*d).to_owned()).collect(),
                    unknown: BTreeMap::new(),
                },
                "test",
            )
        })
        .expect("unlocked")
        .expect("policy");
}

fn create(fx: &Fixture, app: &str, username: &str, website: &str) -> ItemId {
    match agent_call(
        &fx.agent_endpoint,
        &Request::CreateTestLogin {
            app: app.to_owned(),
            purpose: "buyer".to_owned(),
            username: username.to_owned(),
            websites: vec![website.to_owned()],
            generator: None,
            tags: Vec::new(),
            reason: None,
            bind: None,
        },
    ) {
        Response::TestLoginCreated {
            status: TestLoginStatus::Created,
            item_id,
            ..
        } => item_id,
        other => panic!("expected a created test login, got {other:?}"),
    }
}

fn trash(fx: &Fixture, website: Option<&str>, tag: Option<&str>, reason: &str) -> Response {
    agent_call(
        &fx.agent_endpoint,
        &Request::TrashTestLogins {
            website: website.map(str::to_owned),
            tag: tag.map(str::to_owned),
            reason: reason.to_owned(),
        },
    )
}

fn listed(fx: &Fixture) -> Vec<ItemId> {
    match agent_call(
        &fx.agent_endpoint,
        &Request::ListTestLogins {
            website: None,
            tag: None,
            query: None,
            limit: 50,
            cursor: None,
        },
    ) {
        Response::TestLogins { items, .. } => items.into_iter().map(|i| i.item_id).collect(),
        other => panic!("expected a listing, got {other:?}"),
    }
}

fn trashed_on_disk(fx: &Fixture, id: &ItemId) -> bool {
    let vault = Vault::open_with_password(fx.path(), b"pw").expect("open");
    vault.item_by_id(id).expect("still there").is_trashed()
}

fn trash_entries(fx: &Fixture) -> Vec<kagisecure_core::audit::AuditEntry> {
    fx.on_disk()
        .into_iter()
        .filter(|e| e.tool == "trash_test_logins")
        .collect()
}

#[test]
fn a_filter_and_a_reason_are_required_and_the_switch_answers_first() {
    let fx = fixture();
    // Arguments first, whatever the switch.
    assert_eq!(
        code(&trash(&fx, None, None, "rebuild")),
        Some("INVALID_ARGUMENT")
    );
    assert_eq!(
        code(&trash(&fx, None, Some("app:shop"), "")),
        Some("INVALID_ARGUMENT")
    );
    assert_eq!(
        code(&trash(&fx, Some("ftp://localhost"), None, "rebuild")),
        Some("INVALID_ARGUMENT")
    );
    assert_eq!(
        code(&trash(&fx, None, Some("app:shop"), "two\nlines")),
        Some("INVALID_ARGUMENT")
    );
    // No test-login vault, then the switch off.
    assert_eq!(
        code(&trash(&fx, None, Some("app:shop"), "rebuild")),
        Some("TEST_LOGINS_OFF")
    );
    set_policy(&fx, false, &[]);
    assert_eq!(
        code(&trash(&fx, Some(LOCAL), None, "rebuild")),
        Some("TEST_LOGINS_OFF")
    );
    assert!(trash_entries(&fx).is_empty());
}

#[test]
fn only_sealed_test_logins_that_match_are_trashed_in_one_audited_step() {
    let fx = fixture();
    set_policy(&fx, true, &[]);
    let human = Human::approving(&fx.queue);
    let a = create(&fx, "shop", "a@example.test", LOCAL);
    let b = create(&fx, "shop", "b@example.test", "http://127.0.0.1:47800");
    let other = create(&fx, "blog", "c@example.test", LOCAL);
    // An unsealed item in the test-login vault carrying the same tag: never touched.
    let unsealed = fx
        .handle
        .transact(WAIT, |tx| {
            let test_vault = tx.agent_test_vault().unwrap().id;
            let mut item = Item::from_template(test_vault, Category::Login, "typed by hand");
            item.tags = vec!["app:shop".to_owned()];
            item.urls = vec![LOCAL.to_owned()];
            item.set_agent_visible_all(true);
            let id = item.id;
            tx.add_item(item);
            Ok(id)
        })
        .expect("unlocked")
        .expect("written");

    let reply = trash(
        &fx,
        None,
        Some("app:shop"),
        "rebuilding the shop environment",
    );
    let Response::TestLoginsTrashed { trashed, item_ids } = &reply else {
        panic!("{reply:?}")
    };
    assert_eq!(*trashed, 2);
    assert_eq!(item_ids, &[a, b]);
    assert!(human.seen().is_empty(), "no sheet: every match is local");

    assert!(trashed_on_disk(&fx, &a) && trashed_on_disk(&fx, &b));
    assert!(!trashed_on_disk(&fx, &other), "a login with another tag");
    assert!(!trashed_on_disk(&fx, &unsealed), "an unsealed item");
    let own: ItemId = fx.item.parse().unwrap();
    assert!(!trashed_on_disk(&fx, &own), "the person's own login");
    assert_eq!(listed(&fx), [other]);

    // One entry for the whole change, naming the agent in full.
    let entries = trash_entries(&fx);
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0].outcome, Outcome::Allowed);
    assert_eq!(
        entries[0].detail.as_deref(),
        Some("TEST_LOGINS_TRASHED matched=2")
    );
    assert!(
        entries[0].actor.starts_with("mcp \"example-agent\""),
        "{}",
        entries[0].actor
    );

    // Trashed logins do not match again: the next call trashes nothing, and says so.
    let again = trash(&fx, None, Some("app:shop"), "again");
    assert!(
        matches!(again, Response::TestLoginsTrashed { trashed: 0, .. }),
        "{again:?}"
    );
    assert_eq!(
        trash_entries(&fx).last().unwrap().detail.as_deref(),
        Some("TEST_LOGINS_TRASHED matched=0")
    );
}

#[test]
fn a_match_outside_the_allowed_origins_refuses_the_whole_request() {
    let fx = fixture();
    set_policy(&fx, true, &[]);
    let human = Human::approving(&fx.queue);
    let local = create(&fx, "shop", "a@example.test", LOCAL);
    // Created at the sheet: a site outside §3.
    let partner = create(&fx, "shop", "b@example.test", PARTNER);
    let sheets = human.seen().len();

    let refused = trash(&fx, None, Some("app:shop"), "rebuild");
    assert_eq!(code(&refused), Some("INVALID_ARGUMENT"), "{refused:?}");
    let Response::Error { message, .. } = &refused else {
        unreachable!()
    };
    assert!(
        !message.contains("example-partner"),
        "names no login: {message}"
    );
    assert!(!trashed_on_disk(&fx, &local) && !trashed_on_disk(&fx, &partner));
    assert_eq!(human.seen().len(), sheets, "a refusal, not a sheet");
    let entries = trash_entries(&fx);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].outcome, Outcome::Denied);
    assert_eq!(
        entries[0].detail.as_deref(),
        Some("TEST_LOGINS_TRASH_REFUSED")
    );

    // Narrowed to the local site, it goes ahead.
    let reply = trash(&fx, Some(LOCAL), None, "rebuild");
    assert!(
        matches!(&reply, Response::TestLoginsTrashed { trashed: 1, item_ids } if item_ids == &[local]),
        "{reply:?}"
    );
    assert!(!trashed_on_disk(&fx, &partner));

    // Once the person allows the domain, the partner login can be trashed too.
    set_policy(&fx, true, &["example-partner.com"]);
    let reply = trash(&fx, Some(PARTNER), None, "rebuild");
    assert!(
        matches!(reply, Response::TestLoginsTrashed { trashed: 1, .. }),
        "{reply:?}"
    );
}

#[test]
fn a_trashed_test_login_no_longer_fills() {
    let fx = fixture();
    set_policy(&fx, true, &["example.com"]);
    let human = Human::approving(&fx.queue);
    let id = create(&fx, "shop", "alice@example.test", PAGE);
    let sw = ServiceWorker::start(&fx, Tab::front(PAGE), OnDeliver::Redeem);
    let reply = trash(&fx, Some(PAGE), None, "rebuild");
    assert!(
        matches!(reply, Response::TestLoginsTrashed { trashed: 1, .. }),
        "{reply:?}"
    );

    let fill = fx.request_fill(&id.to_string(), PAGE, &both());
    assert!(matches!(fill, Response::Error { .. }), "{fill:?}");
    assert!(sw.fills().is_empty(), "nothing crossed");
    assert_eq!(human.sheets(), 0, "and nobody was asked");
    assert!(listed(&fx).is_empty());
}
