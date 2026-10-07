//! The sign-up fill (ADR-0048 §7, Phase 1b): `request_fill ["username", "new_password"]` types a
//! sealed test login's generated password into every new-password box of a recognised sign-up
//! form, and nothing else.
//!
//! What these assert: an unsealed item answers `NOTHING_TO_FILL` with nothing asked; a sealed one
//! at an allowed origin is one grant with no sheet, audited `TEST_LOGIN_FILL (automatic,
//! sign-up)`; at any other origin it is the ordinary sheet; the reply that crosses carries
//! `new_password` and never `password`; and a login fill never takes a sign-up page, nor a
//! sign-up fill a login page — both are the one `NO_MATCHING_TAB`.

mod agent_fill_support;

use std::collections::BTreeMap;
use std::time::Duration;

use agent_fill_support::{
    Fixture, Human, MARKER, OnDeliver, PAGE, ServiceWorker, Tab, both, code, fixture,
};
use kagisecure_agent::approval::Decision;
use kagisecure_core::model::TestLoginPolicy;
use kagisecure_core::proto::{ItemId, Outcome};
use kagisecure_extension_ipc::protocol::{FillValue, Response as ExtResponse};
use kagisecure_ipc::protocol::{AgentFillField, Request, Response, TestLoginStatus};

const WAIT: Duration = Duration::from_secs(5);

fn sign_up() -> Vec<AgentFillField> {
    vec![AgentFillField::Username, AgentFillField::NewPassword]
}

fn set_policy(fx: &Fixture, domains: &[&str]) {
    fx.handle
        .transact(WAIT, |tx| {
            tx.ensure_agent_test_vault("test")?;
            tx.set_test_login_policy(
                TestLoginPolicy {
                    enabled: true,
                    auto_domains: domains.iter().map(|d| (*d).to_owned()).collect(),
                    unknown: BTreeMap::new(),
                },
                "test",
            )
        })
        .expect("unlocked")
        .expect("policy");
}

/// Create a sealed test login for `website` through the agent socket, approving any sheet.
fn create(fx: &Fixture, website: &str) -> ItemId {
    let reply = agent_fill_support::agent_call(
        &fx.agent_endpoint,
        &Request::CreateTestLogin {
            app: "shop".to_owned(),
            purpose: "buyer".to_owned(),
            username: "alice@example.test".to_owned(),
            websites: vec![website.to_owned()],
            generator: None,
            tags: Vec::new(),
            reason: None,
            bind: None,
        },
    );
    match reply {
        Response::TestLoginCreated {
            status: TestLoginStatus::Created,
            item_id,
            ..
        } => item_id,
        other => panic!("expected a created test login, got {other:?}"),
    }
}

fn written(reply: &Response) -> Vec<AgentFillField> {
    match reply {
        Response::FillResult { fields_written, .. } => fields_written.clone(),
        other => panic!("expected a fill result, got {other:?}"),
    }
}

#[test]
fn an_unsealed_item_answers_nothing_to_fill_and_asks_nobody() {
    let fx = fixture();
    set_policy(&fx, &["example.com"]);
    let human = Human::approving(&fx.queue);
    let _sw = ServiceWorker::start(&fx, Tab::sign_up(PAGE), OnDeliver::Redeem);
    for fields in [sign_up(), vec![AgentFillField::NewPassword]] {
        let reply = fx.request_fill(&fx.item, PAGE, &fields);
        assert_eq!(code(&reply), Some("NOTHING_TO_FILL"), "{reply:?}");
        let Response::Error { message, .. } = &reply else {
            unreachable!()
        };
        assert!(message.contains("create_test_login"), "{message}");
        assert!(!message.contains(MARKER));
    }
    assert_eq!(human.sheets(), 0);
}

#[test]
fn a_sealed_item_at_an_allowed_origin_is_one_grant_and_no_sheet() {
    let fx = fixture();
    set_policy(&fx, &["example.com"]);
    let human = Human::approving(&fx.queue);
    let id = create(&fx, PAGE);
    let sw = ServiceWorker::start(&fx, Tab::sign_up(PAGE), OnDeliver::Redeem);

    let reply = fx.request_fill(&id.to_string(), PAGE, &sign_up());
    assert_eq!(written(&reply), sign_up());
    assert_eq!(
        human.sheets(),
        0,
        "a sealed test login at an allowed origin"
    );

    let fills = sw.fills_at_least(1);
    assert_eq!(fills.len(), 1, "one grant, one crossing: {fills:?}");
    match &fills[0] {
        ExtResponse::Filled {
            username,
            password,
            new_password,
            ..
        } => {
            assert_eq!(username.as_deref(), Some("alice@example.test"));
            assert!(
                password.is_none(),
                "a sign-up reply never carries a password"
            );
            assert!(new_password.is_some());
        }
        other => panic!("expected a fill, got {other:?}"),
    }
    let json = serde_json::to_string(&fills[0]).unwrap();
    assert!(!json.contains("\"password\""), "{}", json.len());

    let allowed: Vec<_> = fx
        .on_disk()
        .into_iter()
        .filter(|e| e.tool == "request_fill" && e.outcome == Outcome::Allowed)
        .collect();
    assert_eq!(allowed.len(), 1);
    assert_eq!(
        allowed[0].detail.as_deref(),
        Some("TEST_LOGIN_FILL (automatic, sign-up)")
    );
    assert_eq!(allowed[0].variables, ["username", "new_password"]);
}

#[test]
fn a_sealed_item_at_loopback_needs_no_listed_domain_and_no_sheet() {
    const LOCAL: &str = "http://localhost:47800";
    let fx = fixture();
    set_policy(&fx, &[]);
    let human = Human::approving(&fx.queue);
    let id = create(&fx, LOCAL);
    let sw = ServiceWorker::start(&fx, Tab::sign_up(LOCAL), OnDeliver::Redeem);
    let reply = fx.request_fill(&id.to_string(), LOCAL, &sign_up());
    assert_eq!(written(&reply), sign_up());
    assert_eq!(human.sheets(), 0);
    assert_eq!(sw.fills_at_least(1).len(), 1);
}

#[test]
fn a_sealed_item_elsewhere_raises_the_sheet() {
    let fx = fixture();
    set_policy(&fx, &[]);
    let human = Human::new(&fx.queue, |_| Some(Decision::AllowOnce));
    let id = create(&fx, PAGE);
    let sheets_after_create = human.sheets();
    let sw = ServiceWorker::start(&fx, Tab::sign_up(PAGE), OnDeliver::Redeem);
    let reply = fx.request_fill(&id.to_string(), PAGE, &sign_up());
    assert_eq!(written(&reply), sign_up());
    assert_eq!(
        human.sheets(),
        sheets_after_create + 1,
        "the ADR-0036 sheet"
    );
    assert_eq!(sw.fills_at_least(1).len(), 1);
    let allowed = fx
        .on_disk()
        .into_iter()
        .find(|e| e.tool == "request_fill" && e.outcome == Outcome::Allowed)
        .expect("an Allowed entry");
    assert_eq!(
        allowed.detail.as_deref(),
        Some("AGENT_FILL_APPROVED (sign-up)")
    );
}

#[test]
fn a_login_fill_never_takes_a_sign_up_page_nor_a_sign_up_fill_a_login_page() {
    let fx = fixture();
    set_policy(&fx, &["example.com"]);
    let human = Human::approving(&fx.queue);
    let id = create(&fx, PAGE);
    let sw = ServiceWorker::start(&fx, Tab::sign_up(PAGE), OnDeliver::Redeem);
    let login = fx.request_fill(&id.to_string(), PAGE, &both());
    assert_eq!(code(&login), Some("NO_MATCHING_TAB"), "{login:?}");

    sw.set(Tab::front(PAGE), OnDeliver::Redeem);
    let sign_up_on_login = fx.request_fill(&id.to_string(), PAGE, &sign_up());
    assert_eq!(code(&sign_up_on_login), Some("NO_MATCHING_TAB"));
    // One code, one message, whatever the reason.
    let message = |r: &Response| match r {
        Response::Error { message, .. } => message.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(message(&login), message(&sign_up_on_login));
    assert_eq!(human.sheets(), 0);
}

#[test]
fn the_filled_sign_up_reply_is_the_serde_canary() {
    let reply =
        ExtResponse::filled_sign_up("i", true, Some("u".to_owned()), FillValue::new(MARKER));
    let json = serde_json::to_string(&reply).unwrap();
    assert!(json.contains("\"new_password\""));
    assert!(!json.contains("\"password\""));
    assert!(!reply.carries_only(&[]), "never on the human path");
}
