//! "Show new items to agents" and bulk agent-visibility changes (ADR-0007 amendment 2026-10-04).

use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::model::{Category, Field, Item, Secret};
use kagisecure_core::vault::{
    AgentVisibilityScope, CreateOptions, TOOL_SET_AGENT_VISIBLE_BULK, Vault,
};
use std::path::{Path, PathBuf};

const PASSWORD: &[u8] = b"correct horse battery staple";
const SECRET_VALUE: &str = "bulk-visibility-canary-value";

fn new_vault(dir: &Path) -> (Vault, PathBuf) {
    let path = dir.join("v.kagivault");
    let options = CreateOptions {
        kdf: KdfParams::new(64, 1, 1).unwrap(),
        vault_name: "Test".to_owned(),
        kdf_hint: None,
    };
    let (vault, _code) = Vault::create(&path, PASSWORD, &options).unwrap();
    (vault, path)
}

fn login(vault: &Vault, title: &str, tag: Option<&str>) -> Item {
    let mut item = Item::new(vault.default_vault_id().unwrap(), Category::Login, title);
    item.fields.push(Field::public("username", "u"));
    item.fields.push(Field::concealed(
        "password",
        Secret::from_string(SECRET_VALUE.to_owned()),
    ));
    if let Some(tag) = tag {
        item.tags.push(tag.to_owned());
    }
    item
}

fn fully_visible(item: &Item) -> bool {
    item.agent_visible && item.fields.iter().all(|f| f.agent_visible)
}

fn fully_hidden(item: &Item) -> bool {
    !item.agent_visible && item.fields.iter().all(|f| !f.agent_visible)
}

#[test]
fn a_new_vault_shows_new_items_to_agents_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, path) = new_vault(dir.path());
    let vault_id = vault.default_vault_id().unwrap();
    assert!(vault.new_items_agent_visible(vault_id));

    let item = login(&vault, "A", None);
    vault
        .transact(|tx| {
            tx.add_new_item(item);
            Ok(())
        })
        .unwrap();
    assert!(fully_visible(&vault.items()[0]));

    drop(vault);
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert!(reopened.new_items_agent_visible(vault_id));
    assert!(fully_visible(&reopened.items()[0]));
}

#[test]
fn turning_the_setting_off_keeps_new_items_hidden_and_persists() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, path) = new_vault(dir.path());
    let vault_id = vault.default_vault_id().unwrap();
    vault
        .transact(|tx| {
            assert!(tx.set_new_items_agent_visible(vault_id, false));
            Ok(())
        })
        .unwrap();
    let item = login(&vault, "A", None);
    vault
        .transact(|tx| {
            tx.add_new_item(item);
            Ok(())
        })
        .unwrap();
    assert!(fully_hidden(&vault.items()[0]));

    drop(vault);
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert!(!reopened.new_items_agent_visible(vault_id));
}

#[test]
fn the_setting_does_not_touch_existing_items() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _path) = new_vault(dir.path());
    let vault_id = vault.default_vault_id().unwrap();
    let item = login(&vault, "Old", None);
    vault
        .transact(|tx| {
            tx.add_item(item);
            tx.set_new_items_agent_visible(vault_id, true);
            Ok(())
        })
        .unwrap();
    assert!(fully_hidden(&vault.items()[0]));
}

#[test]
fn a_bulk_change_by_tag_is_one_transaction_with_one_count_only_audit_entry() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _path) = new_vault(dir.path());
    let tagged: Vec<Item> = (0..5)
        .map(|n| login(&vault, &format!("T{n}"), Some("imported:chromium")))
        .collect();
    let other = login(&vault, "Other", Some("work"));
    let mut binned = login(&vault, "Binned", Some("imported:chromium"));
    binned.trashed_at = Some(1);
    vault
        .transact(|tx| {
            for item in tagged {
                tx.add_item(item);
            }
            tx.add_item(other);
            tx.add_item(binned);
            Ok(())
        })
        .unwrap();
    let before = vault.audit_entries().len();

    let result = vault
        .transact(|tx| {
            Ok(tx.set_agent_visible_bulk(
                &AgentVisibilityScope::Tag("imported:chromium".to_owned()),
                true,
                "app",
            ))
        })
        .unwrap();
    assert_eq!(result.matched, 5);
    assert_eq!(result.changed, 5);

    for item in vault.items() {
        let expected = item.tags.iter().any(|t| t == "imported:chromium") && !item.is_trashed();
        assert_eq!(fully_visible(item), expected, "{}", item.title);
    }

    let entries = &vault.audit_entries()[before..];
    assert_eq!(entries.len(), 1, "one audit entry for the whole change");
    let entry = &entries[0];
    assert_eq!(entry.tool, TOOL_SET_AGENT_VISIBLE_BULK);
    let detail = entry.detail.as_deref().unwrap();
    assert_eq!(detail, "scope=tag visible=on matched=5 changed=5");
    assert!(!detail.contains("chromium"), "the tag is not recorded");
    assert!(!detail.contains(SECRET_VALUE));
}

#[test]
fn bulk_hide_by_ids_clears_field_flags_and_reports_unchanged_items() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _path) = new_vault(dir.path());
    let a = login(&vault, "A", None);
    let b = login(&vault, "B", None);
    let (a_id, b_id) = (a.id, b.id);
    vault
        .transact(|tx| {
            tx.add_new_item(a);
            tx.add_item(b);
            Ok(())
        })
        .unwrap();
    let result = vault
        .transact(|tx| {
            Ok(tx.set_agent_visible_bulk(
                &AgentVisibilityScope::Items(vec![a_id, b_id]),
                false,
                "app",
            ))
        })
        .unwrap();
    assert_eq!(result.matched, 2);
    assert_eq!(result.changed, 1, "B was already hidden");
    assert!(vault.items().iter().all(fully_hidden));
}

#[test]
fn bulk_show_all_and_by_category() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _path) = new_vault(dir.path());
    let vault_id = vault.default_vault_id().unwrap();
    let a = login(&vault, "A", None);
    let note = Item::new(vault_id, Category::SecureNote, "N");
    vault
        .transact(|tx| {
            tx.add_item(a);
            tx.add_item(note);
            Ok(())
        })
        .unwrap();
    let by_category = vault
        .transact(|tx| {
            Ok(tx.set_agent_visible_bulk(
                &AgentVisibilityScope::Category(Category::SecureNote),
                true,
                "app",
            ))
        })
        .unwrap();
    assert_eq!(by_category.matched, 1);
    let all = vault
        .transact(|tx| Ok(tx.set_agent_visible_bulk(&AgentVisibilityScope::All, true, "app")))
        .unwrap();
    assert_eq!((all.matched, all.changed), (2, 1));
    assert!(vault.items().iter().all(fully_visible));
}
