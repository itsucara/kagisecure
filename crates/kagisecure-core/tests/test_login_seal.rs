//! The agent test-login seal and vault (ADR-0048 §2, §5): a seal is deterministic for the same
//! item and password, separated from every other key, broken by any change to what it covers, and
//! honoured only inside the test-login vault; `VaultMeta.purpose` round-trips and is absent from
//! an ordinary vault.

mod common;

use std::collections::BTreeMap;

use common::{PASSWORD, new_vault};
use kagisecure_core::Vault;
use kagisecure_core::model::{Category, Item, Secret, TestLoginPolicy, VaultMeta, VaultPurpose};
use kagisecure_core::proto::{FieldId, VaultId};
use kagisecure_core::vault::test_login::{
    AUDIT_TOOL_TEST_LOGIN_POLICY, AUDIT_TOOL_TEST_VAULT_CREATED, EXTRA_KEY, TEST_VAULT_NAME,
    TestLoginProvenance,
};

const ACTOR: &str = "test-login-seal-test";

/// A login in `vault_id` with `password`, built the way the agent builds one.
fn login(vault_id: VaultId, password: &str) -> Item {
    let mut item = Item::from_template(vault_id, Category::Login, "test: shop / buyer #1");
    let primary = item
        .primary_secret
        .expect("a login template designates one");
    let field = item.fields.iter_mut().find(|f| f.id == primary).unwrap();
    field.value =
        kagisecure_core::model::FieldValue::Secret(Secret::new(password.as_bytes().to_vec()));
    item
}

/// A sealed test login, written to the test vault, and its id.
fn sealed(vault: &mut Vault, password: &str) -> kagisecure_core::proto::ItemId {
    vault
        .transact(|tx| {
            let test_vault = tx.ensure_agent_test_vault(ACTOR)?;
            let mut item = login(test_vault, password);
            tx.attach_test_login_provenance(&mut item, "mcp \"Claude\"", "shop", "buyer")?;
            let id = item.id;
            tx.add_new_item(item);
            Ok(id)
        })
        .unwrap()
}

#[test]
fn the_test_vault_is_created_once_found_by_purpose_and_audited() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _, path) = new_vault(dir.path());
    assert!(vault.agent_test_vault().is_none());
    let first = vault
        .transact(|tx| tx.ensure_agent_test_vault(ACTOR))
        .unwrap();
    let again = vault
        .transact(|tx| tx.ensure_agent_test_vault(ACTOR))
        .unwrap();
    assert_eq!(first, again, "one test vault, however often it is ensured");

    let meta = vault.agent_test_vault().unwrap();
    assert_eq!(meta.name, TEST_VAULT_NAME);
    assert!(meta.agent_visible && meta.new_items_agent_visible);
    assert_eq!(meta.test_login_policy(), Some(&TestLoginPolicy::default()));
    let created = vault
        .audit_entries()
        .iter()
        .filter(|e| e.tool == AUDIT_TOOL_TEST_VAULT_CREATED)
        .count();
    assert_eq!(created, 1);

    // Renamed by the person: still found, by purpose.
    let reopened = {
        drop(vault);
        Vault::open_with_password(&path, PASSWORD).unwrap()
    };
    assert_eq!(reopened.agent_test_vault().map(|v| v.id), Some(first));
}

#[test]
fn a_policy_change_is_audited_with_counts_only() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _, _) = new_vault(dir.path());
    assert!(
        vault
            .transact(|tx| tx.set_test_login_policy(TestLoginPolicy::default(), ACTOR))
            .is_err(),
        "no test vault yet"
    );
    vault
        .transact(|tx| {
            tx.ensure_agent_test_vault(ACTOR)?;
            tx.set_test_login_policy(
                TestLoginPolicy {
                    enabled: true,
                    auto_domains: vec!["example-partner.com".to_owned()],
                    unknown: BTreeMap::new(),
                },
                ACTOR,
            )
        })
        .unwrap();
    let (_, policy) = vault.test_login_policy().unwrap();
    assert!(policy.enabled);
    let entry = vault
        .audit_entries()
        .iter()
        .rev()
        .find(|e| e.tool == AUDIT_TOOL_TEST_LOGIN_POLICY)
        .unwrap();
    assert_eq!(entry.detail.as_deref(), Some("enabled=on domains=1"));
}

#[test]
fn a_seal_is_deterministic_and_verifies_after_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _, path) = new_vault(dir.path());
    let id = sealed(&mut vault, "Gen3rated-Password-For-Test!");
    let item = vault.item_by_id(&id).unwrap();
    assert!(vault.test_login_sealed(item));
    let stored = TestLoginProvenance::of(item).unwrap();
    assert_eq!(stored.app, "shop");
    assert_eq!(stored.purpose, "buyer");
    assert_eq!(stored.v, 1);
    let again = vault
        .transact(|tx| tx.seal_test_login(tx.item_by_id(&id).unwrap()))
        .unwrap();
    assert_eq!(
        again, stored.seal,
        "the same item and password seal the same"
    );

    drop(vault);
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert!(reopened.test_login_sealed(reopened.item_by_id(&id).unwrap()));
}

#[test]
fn a_seal_is_domain_separated_by_item_field_password_and_vault_key() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _, _) = new_vault(dir.path());
    let other_dir = tempfile::tempdir().unwrap();
    let (mut other, _, _) = new_vault(other_dir.path());
    let pw = "Same-Password-In-Both-Places-42";
    let a = sealed(&mut vault, pw);
    let b = sealed(&mut vault, pw);
    let c = sealed(&mut other, pw);
    let seal = |v: &Vault, id| {
        TestLoginProvenance::of(v.item_by_id(&id).unwrap())
            .unwrap()
            .seal
    };
    assert_ne!(seal(&vault, a), seal(&vault, b), "another item id");
    assert_ne!(seal(&vault, a), seal(&other, c), "another vault key");

    // Another primary-secret field id over the same password and item: another seal.
    let moved = vault
        .transact(|tx| {
            let mut item = login(tx.agent_test_vault().unwrap().id, pw);
            item.id = a;
            let primary = item.primary_secret.unwrap();
            let field = item.fields.iter_mut().find(|f| f.id == primary).unwrap();
            field.id = FieldId::new();
            item.primary_secret = Some(field.id);
            tx.seal_test_login(&item)
        })
        .unwrap();
    assert_ne!(moved, seal(&vault, a), "another field id");
}

#[test]
fn editing_the_password_or_the_seal_breaks_it_in_either_byte() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _, _) = new_vault(dir.path());
    let id = sealed(&mut vault, "Original-Generated-Value-0001");

    // A person types a real password into the test item: the exemption is gone.
    vault
        .transact(|tx| {
            let item = tx.item_by_id_mut(&id).unwrap();
            let primary = item.primary_secret.unwrap();
            let field = item.fields.iter_mut().find(|f| f.id == primary).unwrap();
            field.value = kagisecure_core::model::FieldValue::Secret(Secret::new(
                b"my-real-password".to_vec(),
            ));
            Ok(())
        })
        .unwrap();
    assert!(!vault.test_login_sealed(vault.item_by_id(&id).unwrap()));

    // The seal itself tampered with, in its first and in its last byte: refused both ways, by
    // the comparison that looks at every byte.
    let id = sealed(&mut vault, "Second-Generated-Value-0002");
    for index in [0usize, 31] {
        let mut item = login(vault.agent_test_vault().unwrap().id, "x");
        let original = vault.item_by_id(&id).unwrap();
        item.id = original.id;
        let mut provenance = TestLoginProvenance::of(original).unwrap();
        provenance.seal[index] ^= 1;
        item.extra
            .insert(EXTRA_KEY.to_owned(), provenance.to_value());
        assert!(!vault.test_login_sealed(&item), "byte {index}");
    }
}

#[test]
fn a_seal_outside_the_test_vault_is_not_honoured() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _, _) = new_vault(dir.path());
    let id = sealed(&mut vault, "Generated-Then-Moved-Elsewhere-9");
    let personal = vault.default_vault_id().unwrap();
    vault
        .transact(|tx| {
            tx.item_by_id_mut(&id).unwrap().vault_id = personal;
            Ok(())
        })
        .unwrap();
    let item = vault.item_by_id(&id).unwrap();
    assert!(!vault.in_agent_test_vault(item));
    assert!(!vault.test_login_sealed(item), "moved out: ordinary");
}

#[test]
fn the_purpose_round_trips_and_an_ordinary_vault_has_none() {
    let mut meta = VaultMeta::new("Personal");
    let mut bytes = Vec::new();
    ciborium::into_writer(&meta, &mut bytes).unwrap();
    let map: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
    assert!(
        !map.as_map()
            .unwrap()
            .iter()
            .any(|(k, _)| k.as_text() == Some("purpose")),
        "an ordinary vault encodes exactly as before the key existed"
    );
    // A vault written before the key existed decodes with no purpose.
    let legacy: VaultMeta = ciborium::from_reader(bytes.as_slice()).unwrap();
    assert!(legacy.purpose.is_none());

    meta.purpose = Some(VaultPurpose::AgentTestLogins(TestLoginPolicy {
        enabled: true,
        auto_domains: vec!["example-partner.com".to_owned()],
        unknown: BTreeMap::new(),
    }));
    let mut bytes = Vec::new();
    ciborium::into_writer(&meta, &mut bytes).unwrap();
    let back: VaultMeta = ciborium::from_reader(bytes.as_slice()).unwrap();
    assert_eq!(back.purpose, meta.purpose);
    assert!(back.unknown.is_empty());
}

#[test]
fn a_purpose_from_a_newer_build_is_kept_verbatim_and_means_nothing_here() {
    use ciborium::Value;
    let mut meta = VaultMeta::new("Future");
    let future = Value::Map(vec![(
        Value::Text("SomethingNew".into()),
        Value::Map(vec![(Value::Text("x".into()), Value::Integer(1.into()))]),
    )]);
    meta.purpose = Some(VaultPurpose::Unknown(future.clone()));
    let mut bytes = Vec::new();
    ciborium::into_writer(&meta, &mut bytes).unwrap();
    let back: VaultMeta = ciborium::from_reader(bytes.as_slice()).unwrap();
    assert_eq!(back.purpose, Some(VaultPurpose::Unknown(future)));
    assert!(back.test_login_policy().is_none());
}
