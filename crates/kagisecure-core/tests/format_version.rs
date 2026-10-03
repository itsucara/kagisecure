//! Every vault file keeps its own `format_ver` (vault-format §9, ADR-0035 §16).
//!
//! Version 2 is what a vault holding shared-vault device keys is written as, so that a build
//! predating the unknown-key passthrough refuses the file instead of dropping the keys on its next
//! save. That protection only lasts if nothing writes such a file back at version 1: these tests
//! pin that a version 2 file stays version 2 through every write path a session has, that a
//! version 1 file is not upgraded by an ordinary write, and that anything newer than this build
//! reads is refused before a key is derived.

use kagisecure_core::Error;
use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::crypto::{aead, body_key};
use kagisecure_core::model::{Category, Item};
use kagisecure_core::vault::{CreateOptions, FileConflict, Vault, header};

const PASSWORD: &[u8] = b"format version test password";

fn cheap_options() -> CreateOptions {
    CreateOptions {
        kdf: KdfParams::new(64, 1, 1).unwrap(),
        vault_name: "Format".to_owned(),
        kdf_hint: None,
    }
}

fn format_ver_on_disk(path: &std::path::Path) -> u16 {
    let bytes = std::fs::read(path).unwrap();
    u16::from_le_bytes([bytes[8], bytes[9]])
}

/// Re-seal the file at `path` unchanged except for its `format_ver`, the way a build that writes
/// that version would: the header bytes are kept exactly, and the body is encrypted again under
/// the new prefix, which is its associated data.
fn reseal_as_version(path: &std::path::Path, vault_key: &[u8], format_ver: u16) {
    let bytes = std::fs::read(path).unwrap();
    let parts = header::split(&bytes).unwrap();
    let vk: [u8; 32] = vault_key.try_into().unwrap();
    let key = body_key(&vk);
    let plaintext = aead::open(&key, &parts.body_nonce, parts.aad, parts.body_ct).unwrap();
    let framed = header::framed_with_version(&parts.aad[header::PREFIX_LEN..], format_ver);
    let nonce = aead::nonce().unwrap();
    let ciphertext = aead::seal(&key, &nonce, &framed, &plaintext).unwrap();
    let mut out = framed;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    std::fs::write(path, out).unwrap();
}

fn add_item(vault: &mut Vault, title: &str) {
    vault
        .transact(|tx| {
            let vault_id = tx.default_vault_id()?;
            tx.add_item(Item::new(vault_id, Category::Login, title));
            Ok(())
        })
        .unwrap();
}

fn titles(vault: &Vault) -> Vec<String> {
    vault.items().iter().map(|i| i.title.clone()).collect()
}

/// A vault created, then re-sealed as version 2, and the path it lives at.
fn version_2_vault(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("v2.kagivault");
    let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    add_item(&mut vault, "before");
    let vault_key = vault.export_vault_key_for_platform_wrapping();
    drop(vault);
    reseal_as_version(&path, &vault_key, 2);
    path
}

#[test]
fn a_new_vault_is_written_as_version_1() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.kagivault");
    let (vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    assert_eq!(header::FORMAT_VERSION, 1);
    assert_eq!(vault.format_ver(), 1);
    assert_eq!(format_ver_on_disk(&path), 1);
}

#[test]
fn a_version_1_vault_stays_version_1_after_a_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.kagivault");
    let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    add_item(&mut vault, "one");
    add_item(&mut vault, "two");
    assert_eq!(vault.format_ver(), 1);
    assert_eq!(format_ver_on_disk(&path), 1);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(reopened.format_ver(), 1);
    assert_eq!(titles(&reopened), ["one", "two"]);
}

#[test]
fn a_version_2_vault_opens_and_stays_version_2_after_a_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = version_2_vault(dir.path());

    let mut vault = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(vault.format_ver(), 2);
    assert_eq!(titles(&vault), ["before"]);

    add_item(&mut vault, "after");
    assert_eq!(vault.format_ver(), 2);
    assert_eq!(
        format_ver_on_disk(&path),
        2,
        "a transaction must not write a version 2 file back as version 1"
    );

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(reopened.format_ver(), 2);
    assert_eq!(titles(&reopened), ["before", "after"]);
}

#[test]
fn a_version_2_vault_stays_version_2_after_a_rollback_and_an_audit_flush() {
    let dir = tempfile::tempdir().unwrap();
    let path = version_2_vault(dir.path());
    let mut vault = Vault::open_with_password(&path, PASSWORD).unwrap();

    let failed: kagisecure_core::Result<()> = vault.transact(|tx| {
        let vault_id = tx.default_vault_id()?;
        tx.add_item(Item::new(vault_id, Category::Login, "never"));
        Err(Error::Malformed)
    });
    assert!(failed.is_err());
    assert_eq!(
        vault.format_ver(),
        2,
        "a rollback restores the file's version"
    );

    vault.queue_audit(kagisecure_core::audit::AuditDraft {
        actor: "format-test".to_owned(),
        tool: "flush".to_owned(),
        outcome: kagisecure_core::proto::Outcome::Allowed,
        ..Default::default()
    });
    vault.flush_audit().unwrap();
    assert_eq!(format_ver_on_disk(&path), 2);
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(titles(&reopened), ["before"]);
}

#[test]
fn a_session_follows_a_file_another_writer_wrote_as_version_2() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("followed.kagivault");
    let (mut first, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    add_item(&mut first, "first");
    assert_eq!(first.format_ver(), 1);

    // Another writer re-seals the same state as version 2: a continuation of what `first` saw.
    reseal_as_version(&path, &first.export_vault_key_for_platform_wrapping(), 2);

    assert!(first.refresh_if_changed().unwrap());
    assert_eq!(
        first.format_ver(),
        2,
        "the adopted file's version is the session's"
    );
    add_item(&mut first, "second");
    assert_eq!(format_ver_on_disk(&path), 2);
}

#[test]
fn a_transaction_adopting_a_version_2_file_writes_version_2() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("adopt.kagivault");
    let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    reseal_as_version(&path, &vault.export_vault_key_for_platform_wrapping(), 2);

    // No refresh first: the transaction itself finds the new generation and adopts it.
    add_item(&mut vault, "adopted");
    assert_eq!(vault.format_ver(), 2);
    assert_eq!(format_ver_on_disk(&path), 2);
}

#[test]
fn a_version_4_vault_is_refused_before_any_key_is_derived() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v4.kagivault");
    let (vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    let vault_key = vault.export_vault_key_for_platform_wrapping();
    drop(vault);
    reseal_as_version(&path, &vault_key, 4);
    let before = std::fs::read(&path).unwrap();

    for result in [
        Vault::open_with_password(&path, PASSWORD),
        // A wrong password is refused for the version, not the password: nothing was derived.
        Vault::open_with_password(&path, b"not the password"),
        Vault::open_with_vault_key(&path, &vault_key),
    ] {
        assert!(
            matches!(
                result,
                Err(Error::UnsupportedFormatVersion {
                    found: 4,
                    supported: 3
                })
            ),
            "{result:?}"
        );
    }
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing was written");
}

#[test]
fn a_session_refuses_to_build_on_a_file_rewritten_as_version_4() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("to-v4.kagivault");
    let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    reseal_as_version(&path, &vault.export_vault_key_for_platform_wrapping(), 4);
    let before = std::fs::read(&path).unwrap();

    let result = vault.transact(|_| Ok(()));
    assert!(
        matches!(
            result,
            Err(Error::UnsupportedFormatVersion {
                found: 4,
                supported: 3
            })
        ),
        "{result:?}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before, "nothing was written");
}

#[test]
fn a_newer_build_s_file_is_its_own_conflict_and_is_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("newer.kagivault");
    let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    add_item(&mut vault, "mine");
    reseal_as_version(&path, &vault.export_vault_key_for_platform_wrapping(), 4);
    let newer = std::fs::read(&path).unwrap();

    let conflict = vault.examine_conflict().unwrap().unwrap();
    assert!(
        matches!(conflict, FileConflict::TooNew { found: 4, .. }),
        "{conflict:?}"
    );
    assert_eq!(conflict.as_str(), "too_new");
    assert!(conflict.file_sha256().is_some());

    let result = vault.overwrite_with_this_session(&conflict, "format-test", "keep mine");
    assert!(
        matches!(
            result,
            Err(Error::UnsupportedFormatVersion {
                found: 4,
                supported: 3
            })
        ),
        "{result:?}"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        newer,
        "the newer file is untouched"
    );
}

#[test]
fn a_file_claiming_format_ver_0_is_damage_not_a_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zero.kagivault");
    let (vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    let vault_key = vault.export_vault_key_for_platform_wrapping();
    drop(vault);
    reseal_as_version(&path, &vault_key, 0);
    assert!(matches!(
        Vault::open_with_password(&path, PASSWORD),
        Err(Error::Malformed)
    ));
}
