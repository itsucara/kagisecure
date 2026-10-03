//! A release re-checks every binding it is about to follow, and its errors never describe an item
//! the agent cannot see.
//!
//! `add_variables` refuses a binding to anything `describe_item` would not show. But a binding is
//! a standing route to a value, and the user can hide or trash the item afterwards; the release
//! re-checked only the *environment*, so the next `write_env_file` still followed the binding and
//! released the value of an item the user had just taken away from agents. And when resolution did
//! fail — the field deleted — the reply carried core's error text, which named the item by its
//! **title**: the one piece of an invisible item's metadata an agent must not learn.

mod common;

use common::{REAL_DOTENV, error_code, error_message, fixture, with_ui, write_env_file};
use kagisecure_agent::approval::Decision;
use kagisecure_agent::vault::REQUEST_LOCK_TIMEOUT;
use kagisecure_core::model::Item;

const HIDDEN_TITLE: &str = "Payroll-Admin-Root-7f3a";

fn change_item(fx: &common::Fixture, change: impl FnOnce(&mut Item)) {
    fx.handle
        .transact(REQUEST_LOCK_TIMEOUT, |tx| {
            let item = tx.find_item_mut(&fx.item_id)?;
            item.title = HIDDEN_TITLE.to_owned();
            change(item);
            Ok(())
        })
        .expect("unlocked")
        .expect("committed");
}

fn release(fx: &common::Fixture) -> kagisecure_ipc::protocol::Response {
    let dir = fx.canonical_project().display().to_string();
    let (reply, _) = with_ui(&fx.agent, Decision::AllowOnce, || {
        fx.client("release-visibility")
            .call(&write_env_file(fx, &dir, REAL_DOTENV, false, 900))
            .expect("call")
    });
    reply
}

fn assert_refused_without_a_trace(
    fx: &common::Fixture,
    reply: &kagisecure_ipc::protocol::Response,
) {
    assert_eq!(error_code(reply).as_deref(), Some("NOT_FOUND"), "{reply:?}");
    let message = error_message(reply).unwrap_or_default();
    assert!(
        !message.contains(HIDDEN_TITLE),
        "the reply names the hidden item: {message:?}"
    );
    assert!(
        !fx.canonical_project().join(REAL_DOTENV).exists(),
        "nothing may be released"
    );
}

#[test]
fn a_binding_to_an_item_hidden_since_is_not_followed() {
    let fx = fixture();
    change_item(&fx, |item| item.agent_visible = false);
    let reply = release(&fx);
    assert_refused_without_a_trace(&fx, &reply);
}

#[test]
fn a_binding_to_an_item_trashed_since_is_not_followed() {
    let fx = fixture();
    change_item(&fx, |item| item.trashed_at = Some(1));
    let reply = release(&fx);
    assert_refused_without_a_trace(&fx, &reply);
}

/// The per-field flag decides whether `describe_item` discloses a field, not whether a binding
/// the *user* made may inject it: "show the username, keep the password concealed — only via
/// injection" (ui-spec.md's per-field override) has to keep working. The item-level rule is what
/// a release re-checks.
#[test]
fn a_user_binding_to_a_field_kept_out_of_describe_item_is_still_injected() {
    let fx = fixture();
    change_item(&fx, |item| {
        for field in &mut item.fields {
            field.agent_visible = false;
        }
    });
    let reply = release(&fx);
    assert!(error_code(&reply).is_none(), "{reply:?}");
    assert!(fx.canonical_project().join(REAL_DOTENV).exists());
}

#[test]
fn a_binding_to_a_field_that_is_gone_does_not_name_the_item() {
    let fx = fixture();
    change_item(&fx, |item| item.fields.clear());
    let reply = release(&fx);
    assert_refused_without_a_trace(&fx, &reply);
}
