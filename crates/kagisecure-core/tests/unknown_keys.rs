//! Vault-format §9 rule 1: a build must not destroy top-level or nested CBOR keys it does not
//! recognize. These tests build a vault file carrying fields this build's structs do not model at
//! every level the format doc names — `Body`, `Header`, `Item`, `Field`, `Environment`,
//! `VaultMeta`, a wrapped-key slot, and an `AuditEntry` — then prove they survive a
//! `Vault::transact` byte-for-byte, and that the audit hash chain still verifies with an entry
//! carrying a field this build does not recognize.
//!
//! §9 also says a schema bump (unlike an additive field) may not be safe to write back; a third
//! test checks that a vault whose `body.schema` or `header.v` is newer than this build writes
//! still opens, but refuses the write with a specific error.

use ciborium::Value;

use kagisecure_core::Error;
use kagisecure_core::audit::{self, AuditDraft};
use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::crypto::{aead, body_key};
use kagisecure_core::model::{Category, Environment, Field, Item};
use kagisecure_core::proto::Outcome;
use kagisecure_core::vault::{self, Body, CreateOptions, Vault, header};

const PASSWORD: &[u8] = b"unknown key regression test password";

fn cheap_options() -> CreateOptions {
    CreateOptions {
        kdf: KdfParams::new(64, 1, 1).unwrap(),
        vault_name: "Test".to_owned(),
        kdf_hint: None,
    }
}

/// Re-encrypt `body` under `header` with `vault_key` and overwrite the file at `path` — standing
/// in for "a build with more fields than this one wrote this file".
fn write_custom_vault(
    path: &std::path::Path,
    header: &header::Header,
    body: &Body,
    vault_key: &[u8],
) {
    let header_cbor = header.to_cbor().unwrap();
    let framed = header::framed(&header_cbor);
    let mut plaintext = Vec::new();
    ciborium::into_writer(body, &mut plaintext).unwrap();
    let vk: [u8; 32] = vault_key.try_into().unwrap();
    let key = body_key(&vk);
    let nonce = aead::nonce().unwrap();
    let ciphertext = aead::seal(&key, &nonce, &framed, &plaintext).unwrap();
    let mut out = framed;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    std::fs::write(path, out).unwrap();
}

/// Decrypt the file at `path` back into its typed header and body — used to make byte-exact
/// assertions the public `Vault` API has no accessor for (the whole `Body`, one `VaultMeta`).
fn read_custom_vault(path: &std::path::Path, vault_key: &[u8]) -> (header::Header, Body) {
    let bytes = std::fs::read(path).unwrap();
    let parts = header::split(&bytes).unwrap();
    let vk: [u8; 32] = vault_key.try_into().unwrap();
    let key = body_key(&vk);
    let plaintext = aead::open(&key, &parts.body_nonce, parts.aad, parts.body_ct).unwrap();
    let body: Body = ciborium::from_reader(plaintext.as_slice()).unwrap();
    (parts.header, body)
}

#[test]
fn unknown_keys_at_every_level_survive_transact_byte_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.kagivault");
    let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    let vault_key = vault.export_vault_key_for_platform_wrapping();

    let vault_id = vault.default_vault_id().unwrap();
    let mut item = Item::new(vault_id, Category::Login, "Acme");
    item.fields.push(Field::public("username", "deploy"));
    let item_id = item.id;
    let field_id = item.fields[0].id;

    let env = Environment::new(vault_id, "acme / staging");
    let env_id = env.id;

    vault
        .transact(|tx| {
            tx.add_item(item);
            tx.add_environment(env);
            Ok(())
        })
        .unwrap();

    // Splice in fields a hypothetical newer build wrote, at every level §9 rule 1 covers.
    let (mut header, mut body) = read_custom_vault(&path, &vault_key);
    header.unknown.insert(
        "device_keys".to_owned(),
        Value::Text("future-header".to_owned()),
    );
    header.wrapped_keys[0]
        .unknown
        .insert("share_id".to_owned(), Value::Text("future-slot".to_owned()));
    body.unknown.insert(
        "shared_vaults".to_owned(),
        Value::Text("future-body".to_owned()),
    );
    body.vaults[0].unknown.insert(
        "owner_device".to_owned(),
        Value::Text("future-vaultmeta".to_owned()),
    );
    {
        let item = body.items.iter_mut().find(|i| i.id == item_id).unwrap();
        item.unknown.insert(
            "shared_with".to_owned(),
            Value::Text("future-item".to_owned()),
        );
        let field = item.fields.iter_mut().find(|f| f.id == field_id).unwrap();
        field.unknown.insert("masked".to_owned(), Value::Bool(true));
    }
    {
        let env = body.envs.iter_mut().find(|e| e.id == env_id).unwrap();
        env.unknown
            .insert("policy".to_owned(), Value::Text("future-env".to_owned()));
    }

    // An audit entry carrying a field this build does not model, correctly chained from genesis.
    let mut entries = Vec::new();
    audit::append_at(
        &mut entries,
        &audit::genesis(),
        AuditDraft {
            actor: "cli".to_owned(),
            tool: "create_environment".to_owned(),
            outcome: Outcome::Allowed,
            ..AuditDraft::default()
        },
        1_700_000_000,
    );
    entries[0]
        .unknown
        .insert("client_version".to_owned(), Value::Text("9.9".to_owned()));
    // The digest must be recomputed after adding the field: it is part of what gets hashed.
    let audit_head = audit::digest(&entries[0]);
    let original_canonical = audit::canonical(&entries[0]);
    body.audit = entries;
    body.audit_head = audit_head;

    write_custom_vault(&path, &header, &body, &vault_key);

    // The vault opens, and every field this build does not model is still visible.
    let mut vault = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(
        vault.header().unknown.get("device_keys"),
        Some(&Value::Text("future-header".to_owned()))
    );
    assert_eq!(
        vault.header().wrapped_keys[0].unknown.get("share_id"),
        Some(&Value::Text("future-slot".to_owned()))
    );
    let opened_item = vault.find_item(&item_id.to_string()).unwrap();
    assert_eq!(
        opened_item.unknown.get("shared_with"),
        Some(&Value::Text("future-item".to_owned()))
    );
    assert_eq!(
        opened_item.field("username").unwrap().unknown.get("masked"),
        Some(&Value::Bool(true))
    );
    let opened_env = vault.find_environment(&env_id.to_string()).unwrap();
    assert_eq!(
        opened_env.unknown.get("policy"),
        Some(&Value::Text("future-env".to_owned()))
    );
    assert_eq!(vault.audit_entries().len(), 1);
    assert_eq!(
        vault.audit_entries()[0].unknown.get("client_version"),
        Some(&Value::Text("9.9".to_owned()))
    );
    assert_eq!(
        audit::canonical(&vault.audit_entries()[0]),
        original_canonical,
        "an entry with an unrecognized field must still hash byte-identically to how it was written"
    );
    assert_eq!(
        audit::verify(vault.audit_entries(), vault.audit_head()),
        Ok(())
    );

    // Body-level and VaultMeta-level extras have no accessor on the public `Vault` API; check
    // them at the byte level, same as the assertions above ultimately rest on.
    let (_, body_after_open) = read_custom_vault(&path, &vault_key);
    assert_eq!(
        body_after_open.unknown.get("shared_vaults"),
        Some(&Value::Text("future-body".to_owned()))
    );
    assert_eq!(
        body_after_open.vaults[0].unknown.get("owner_device"),
        Some(&Value::Text("future-vaultmeta".to_owned()))
    );

    // A transaction that changes something unrelated must not disturb any of the above.
    vault
        .transact(|tx| {
            tx.find_item_mut(&item_id.to_string()).unwrap().title = "Acme (renamed)".to_owned();
            Ok(())
        })
        .unwrap();

    let (header_after_tx, body_after_tx) = read_custom_vault(&path, &vault_key);
    assert_eq!(
        header_after_tx.unknown.get("device_keys"),
        Some(&Value::Text("future-header".to_owned()))
    );
    assert_eq!(
        header_after_tx.wrapped_keys[0].unknown.get("share_id"),
        Some(&Value::Text("future-slot".to_owned()))
    );
    assert_eq!(
        body_after_tx.unknown.get("shared_vaults"),
        Some(&Value::Text("future-body".to_owned()))
    );
    assert_eq!(
        body_after_tx.vaults[0].unknown.get("owner_device"),
        Some(&Value::Text("future-vaultmeta".to_owned()))
    );
    let item_after_tx = body_after_tx
        .items
        .iter()
        .find(|i| i.id == item_id)
        .unwrap();
    assert_eq!(item_after_tx.title, "Acme (renamed)");
    assert_eq!(
        item_after_tx.unknown.get("shared_with"),
        Some(&Value::Text("future-item".to_owned()))
    );
    assert_eq!(
        item_after_tx.fields[0].unknown.get("masked"),
        Some(&Value::Bool(true))
    );
    let env_after_tx = body_after_tx.envs.iter().find(|e| e.id == env_id).unwrap();
    assert_eq!(
        env_after_tx.unknown.get("policy"),
        Some(&Value::Text("future-env".to_owned()))
    );
    assert_eq!(body_after_tx.audit.len(), 1);
    assert_eq!(
        audit::canonical(&body_after_tx.audit[0]),
        original_canonical,
        "a transaction that never touches the audit log must not change its encoding"
    );
    assert_eq!(
        audit::verify(&body_after_tx.audit, &body_after_tx.audit_head),
        Ok(())
    );

    // And a second, unrelated transaction.
    vault
        .transact(|tx| {
            tx.find_item_mut(&item_id.to_string()).unwrap().notes =
                Some(kagisecure_core::model::SecretText::new("edited".to_owned()));
            Ok(())
        })
        .unwrap();

    let (header_after_save, body_after_save) = read_custom_vault(&path, &vault_key);
    assert_eq!(
        header_after_save.unknown.get("device_keys"),
        Some(&Value::Text("future-header".to_owned()))
    );
    assert_eq!(
        body_after_save.unknown.get("shared_vaults"),
        Some(&Value::Text("future-body".to_owned()))
    );
    assert_eq!(
        body_after_save.vaults[0].unknown.get("owner_device"),
        Some(&Value::Text("future-vaultmeta".to_owned()))
    );
    let item_after_save = body_after_save
        .items
        .iter()
        .find(|i| i.id == item_id)
        .unwrap();
    assert_eq!(
        item_after_save
            .notes
            .as_ref()
            .map(kagisecure_core::model::SecretText::expose),
        Some("edited")
    );
    assert_eq!(
        item_after_save.unknown.get("shared_with"),
        Some(&Value::Text("future-item".to_owned()))
    );
    assert_eq!(
        item_after_save.fields[0].unknown.get("masked"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        audit::canonical(&body_after_save.audit[0]),
        original_canonical,
        "a transaction that never touches the audit log must not change its encoding either"
    );
    assert_eq!(
        audit::verify(&body_after_save.audit, &body_after_save.audit_head),
        Ok(())
    );
}

#[test]
fn a_newer_body_schema_opens_but_refuses_to_be_written() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.kagivault");
    let (vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    let vault_key = vault.export_vault_key_for_platform_wrapping();
    drop(vault);

    let (header, mut body) = read_custom_vault(&path, &vault_key);
    let newer = vault::BODY_SCHEMA_VERSION + 1;
    body.schema = newer;
    write_custom_vault(&path, &header, &body, &vault_key);

    // Reading is unaffected — this is exactly the case vault-format §9 rule 1 says must not
    // destroy data.
    let mut vault = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(vault.items().len(), 0);

    let err = vault.transact(|_| Ok(())).unwrap_err();
    assert!(
        matches!(
            &err,
            Error::VaultSchemaTooNew {
                field: "body.schema",
                found,
                supported,
            } if *found == newer && *supported == vault::BODY_SCHEMA_VERSION
        ),
        "unexpected error: {err:?}"
    );

    // Nothing was written: the file on disk still declares the newer schema, not the erased one a
    // successful (but wrong) write would have produced.
    let (_, body_still_on_disk) = read_custom_vault(&path, &vault_key);
    assert_eq!(body_still_on_disk.schema, newer);
}

#[test]
fn a_newer_header_schema_opens_but_refuses_to_be_written() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.kagivault");
    let (vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    let vault_key = vault.export_vault_key_for_platform_wrapping();
    drop(vault);

    let (mut header, body) = read_custom_vault(&path, &vault_key);
    let newer = header::HEADER_SCHEMA_VERSION + 1;
    header.v = newer;
    write_custom_vault(&path, &header, &body, &vault_key);

    let mut vault = Vault::open_with_password(&path, PASSWORD).unwrap();

    let err = vault.transact(|_| Ok(())).unwrap_err();
    assert!(
        matches!(
            &err,
            Error::VaultSchemaTooNew {
                field: "header.v",
                found,
                supported,
            } if *found == newer && *supported == header::HEADER_SCHEMA_VERSION
        ),
        "unexpected error: {err:?}"
    );

    // Nor is any slot re-wrapped over it: a fresh wrap replaces a slot wholesale, which is only
    // safe because a slot key every writer must honour comes with a `header.v` bump.
    let prepared = vault.prepare_master_password(b"another").unwrap();
    let err = vault
        .transact(|tx| tx.install_master_password(prepared))
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::VaultSchemaTooNew {
                field: "header.v",
                ..
            }
        ),
        "unexpected error: {err:?}"
    );
    let (on_disk, _) = read_custom_vault(&path, &vault_key);
    assert_eq!(on_disk.v, newer);
    Vault::open_with_password(&path, PASSWORD).expect("the old password still opens it");
}

/// Two levels §9 rule 1 did not cover before: a KDF descriptor (the header's, and a slot's own)
/// and a retired value in an item's history. Both keep what a newer build added across an older
/// build's write. A descriptor with a parameter this build does not understand is never derived
/// with — that would read as a wrong password — and a fresh wrap by this build starts clean, so it
/// never claims a parameter it did not apply.
#[test]
fn unknown_kdf_and_history_keys_survive_and_a_fresh_wrap_starts_clean() {
    use kagisecure_core::model::{FieldRevision, Secret};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.kagivault");
    let (mut vault, code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    let vault_key = vault.export_vault_key_for_platform_wrapping();
    let vault_id = vault.default_vault_id().unwrap();
    let mut item = Item::new(vault_id, Category::Login, "Acme");
    item.history.push(FieldRevision::concealed(
        "password",
        Secret::new(b"old".to_vec()),
        1_700_000_000,
    ));
    let item_id = item.id;
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    // A newer build's additions: a parameter on the recovery slot's own KDF, and a note on a
    // retired value.
    let (mut header, mut body) = read_custom_vault(&path, &vault_key);
    header
        .wrapped_keys
        .iter_mut()
        .find(|s| s.kind == "recovery")
        .and_then(|s| s.kdf.as_mut())
        .expect("the recovery slot carries its own KDF")
        .unknown
        .insert("pepper_id".to_owned(), Value::Integer(7.into()));
    body.items
        .iter_mut()
        .find(|i| i.id == item_id)
        .unwrap()
        .history[0]
        .unknown
        .insert("retired_by".to_owned(), Value::Text("rotation".to_owned()));
    write_custom_vault(&path, &header, &body, &vault_key);

    // An older build opens with the password and writes: both survive.
    let mut vault = Vault::open_with_password(&path, PASSWORD).unwrap();
    vault
        .transact(|tx| {
            tx.item_by_id_mut(&item_id).unwrap().title = "Acme (renamed)".to_owned();
            Ok(())
        })
        .unwrap();
    drop(vault);
    let (header, body) = read_custom_vault(&path, &vault_key);
    let recovery_kdf = header
        .wrapped_keys
        .iter()
        .find(|s| s.kind == "recovery")
        .and_then(|s| s.kdf.as_ref())
        .unwrap();
    assert_eq!(
        recovery_kdf.unknown.get("pepper_id"),
        Some(&Value::Integer(7.into()))
    );
    let history = &body.items.iter().find(|i| i.id == item_id).unwrap().history[0];
    assert_eq!(
        history.unknown.get("retired_by"),
        Some(&Value::Text("rotation".to_owned()))
    );

    // This build will not derive with that descriptor: a clear refusal, not a "wrong code".
    let refused = Vault::open_with_recovery_code(&path, &code);
    assert!(
        matches!(
            refused,
            Err(Error::Unsupported {
                what: "KDF parameter",
                ..
            })
        ),
        "{:?}",
        refused.err()
    );

    // The header's own descriptor the same way: kept through a write it did not open by, and
    // dropped — on purpose — by a fresh wrap, which describes only what this build derived.
    let (mut header, body) = read_custom_vault(&path, &vault_key);
    for slot in &mut header.wrapped_keys {
        if let Some(kdf) = slot.kdf.as_mut() {
            kdf.unknown.clear();
        }
    }
    header
        .kdf
        .unknown
        .insert("pepper_id".to_owned(), Value::Integer(7.into()));
    write_custom_vault(&path, &header, &body, &vault_key);
    assert!(matches!(
        Vault::open_with_password(&path, PASSWORD),
        Err(Error::Unsupported {
            what: "KDF parameter",
            ..
        })
    ));
    let mut vault = Vault::open_with_recovery_code(&path, &code).unwrap();
    vault.transact(|_| Ok(())).unwrap();
    let (on_disk, _) = read_custom_vault(&path, &vault_key);
    assert_eq!(
        on_disk.kdf.unknown.get("pepper_id"),
        Some(&Value::Integer(7.into())),
        "a write that did not re-wrap the password slot keeps the parameter"
    );

    let prepared = vault.prepare_master_password(b"a new password").unwrap();
    vault
        .transact(|tx| tx.install_master_password(prepared))
        .unwrap();
    drop(vault);
    let (on_disk, _) = read_custom_vault(&path, &vault_key);
    assert!(on_disk.kdf.unknown.is_empty(), "a fresh wrap starts clean");
    Vault::open_with_password(&path, b"a new password").expect("and it opens");
}
