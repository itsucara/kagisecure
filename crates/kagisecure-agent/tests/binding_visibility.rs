//! `add_variables` may bind a variable only to a field the agent could have been shown.
//!
//! A binding is a standing route to a value: the next `write_env_file` or `run_with_env` on the
//! environment releases whatever the bound field holds. So a binding target is held to exactly the
//! rules `describe_item` applies — the item visible to agents, in a logical vault visible to
//! agents, not in the trash — plus the field's own agent flag. A target that fails any of them is
//! answered exactly as one that does not exist (threat-model M-8): the same code and the same
//! message, byte for byte, so a caller cannot learn by binding what it could not learn by listing.

mod common;

use common::{Fixture, allow_session, error_code, error_message, fixture, with_ui};
use kagisecure_agent::VaultHandle;
use kagisecure_agent::vault::REQUEST_LOCK_TIMEOUT;
use kagisecure_core::model::{Field, Item, Secret, VaultMeta};
use kagisecure_core::proto::{Category, FieldId, ItemId};
use kagisecure_ipc::protocol::{FieldRef, Request, Response, VariableRequest};

/// Add an item to the fixture's vault as the app would, and return its id and its one field's id.
fn add_item(
    handle: &VaultHandle,
    shape: impl FnOnce(&mut kagisecure_core::vault::Tx<'_>, &mut Item),
) -> (ItemId, FieldId) {
    handle
        .transact(REQUEST_LOCK_TIMEOUT, |tx| {
            let vault_id = tx.default_vault_id()?;
            let mut item = Item::new(vault_id, Category::ApiCredential, "Bound target");
            let mut field = Field::concealed("token", Secret::from_string("x".to_owned()));
            field.agent_visible = true;
            let field_id = field.id;
            item.fields.push(field);
            item.agent_visible = true;
            shape(tx, &mut item);
            let id = item.id;
            tx.add_item(item);
            Ok((id, field_id))
        })
        .expect("unlocked")
        .expect("committed")
}

fn bind(fx: &Fixture, name: &str, item_id: ItemId, field_id: FieldId) -> Response {
    let (reply, seen) = with_ui(&fx.agent, allow_session(900, 10), || {
        fx.client("binding")
            .call(&Request::AddVariables {
                environment_id: fx.env_id.parse().expect("env id"),
                variables: vec![VariableRequest {
                    name: name.to_owned(),
                    hint: None,
                    bind_to: Some(FieldRef { item_id, field_id }),
                }],
            })
            .expect("call")
    });
    assert_eq!(
        seen.len(),
        1,
        "every binding request is put to the human alike"
    );
    reply
}

fn bound(fx: &Fixture, name: &str) -> bool {
    fx.handle
        .with(|v| {
            v.find_environment(&fx.env_id)
                .expect("env")
                .var(name)
                .is_some()
        })
        .expect("unlocked")
}

#[test]
fn a_binding_reaches_only_what_describe_item_would_show() {
    let fx = fixture();

    let (in_hidden_vault, hidden_vault_field) = add_item(&fx.handle, |tx, item| {
        let hidden = tx.add_logical_vault(VaultMeta::new("Not for agents"));
        tx.set_vault_agent_visible(hidden, false);
        item.vault_id = hidden;
    });
    let (trashed, trashed_field) = add_item(&fx.handle, |_, item| {
        item.trashed_at = Some(kagisecure_core::unix_now());
    });
    let (field_hidden, hidden_field) = add_item(&fx.handle, |_, item| {
        item.fields[0].agent_visible = false;
    });
    let (archived, archived_field) = add_item(&fx.handle, |_, item| {
        item.archived = true;
    });

    let absent = bind(&fx, "ABSENT", ItemId::new(), FieldId::new());
    assert_eq!(
        error_code(&absent).as_deref(),
        Some("NOT_FOUND"),
        "{absent:?}"
    );
    let absent_message = error_message(&absent);

    for (name, item, field) in [
        ("IN_HIDDEN_VAULT", in_hidden_vault, hidden_vault_field),
        ("TRASHED", trashed, trashed_field),
        ("FIELD_HIDDEN", field_hidden, hidden_field),
    ] {
        let reply = bind(&fx, name, item, field);
        assert_eq!(
            error_code(&reply).as_deref(),
            Some("NOT_FOUND"),
            "{name}: {reply:?}"
        );
        assert_eq!(
            error_message(&reply),
            absent_message,
            "{name} is distinguishable from a target that does not exist"
        );
        assert!(!bound(&fx, name), "{name} was bound anyway");
    }

    // The same two items `describe_item` refuses to show.
    for item in [in_hidden_vault, trashed] {
        let described = fx
            .client("binding")
            .call(&Request::DescribeItem { item_id: item })
            .expect("call");
        assert_eq!(error_code(&described).as_deref(), Some("NOT_FOUND"));
    }

    // And what an agent may see stays bindable: archived items are listed and described.
    let reply = bind(&fx, "ARCHIVED", archived, archived_field);
    assert!(
        matches!(reply, Response::AddedVariables { .. }),
        "{reply:?}"
    );
    assert!(bound(&fx, "ARCHIVED"));
}
