//! Shared-vault device keys in the personal vault (ADR-0035 §5, §16).
//!
//! A device key is the only copy of this computer's key pair for every shared vault it belongs
//! to. These tests pin what keeps it from being lost or disclosed: it round-trips inside the
//! encrypted body and nowhere else; the first one raises the file to `format_ver` 2 after taking
//! a create-new backup of the version 1 file; the version never drops back; and "keep this app's
//! version" after a conflict keeps device keys that only the file holds.

mod common;

use common::{PASSWORD, contains, new_vault};
use kagisecure_core::Error;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::model::{Category, Item, Secret};
use kagisecure_core::proto::Outcome;
use kagisecure_core::vault::device::{
    DEVICE_KEY_ID_LEN, MAX_DEVICE_LABEL_CHARS, SUITE_X25519_ED25519_V1,
};
use kagisecure_core::vault::{
    AUDIT_TOOL_DEVICE_KEY_ADDED, AUDIT_TOOL_DEVICE_KEY_REMOVED, AUDIT_TOOL_OVERWRITE, DeviceKey,
    FileConflict, Vault, header,
};
use std::path::{Path, PathBuf};

/// The actor every device key change in these tests is recorded under.
const ACTOR: &str = "device-key-test";

/// Test-only key material with a distinctive marker, so a leak of any part of it is findable.
fn secret_keys(tag: u8) -> Vec<u8> {
    let mut bytes = b"device-secret-canary-7c1e9a:".to_vec();
    bytes.resize(64, tag);
    bytes
}

fn device_key(tag: u8, label: &str) -> DeviceKey {
    DeviceKey::new(
        [tag; DEVICE_KEY_ID_LEN],
        SUITE_X25519_ED25519_V1,
        label,
        1_790_000_000,
        Secret::new(secret_keys(tag)),
    )
    .unwrap()
}

fn add_device(vault: &mut Vault, tag: u8, label: &str) {
    vault
        .transact(|tx| tx.add_device_key(device_key(tag, label), ACTOR))
        .unwrap();
}

/// Add an item, audited: the audit log is what tells a session its file went backwards, so the
/// conflict tests below need every change to leave an entry.
fn add_item(vault: &mut Vault, title: &str) {
    vault
        .transact(|tx| {
            let vault_id = tx.default_vault_id()?;
            tx.add_item(Item::new(vault_id, Category::Login, title));
            tx.append_audit(AuditDraft {
                actor: "device-key-test".to_owned(),
                tool: title.to_owned(),
                outcome: Outcome::Allowed,
                ..AuditDraft::default()
            });
            Ok(())
        })
        .unwrap();
}

fn format_ver_on_disk(path: &Path) -> u16 {
    let bytes = std::fs::read(path).unwrap();
    u16::from_le_bytes([bytes[8], bytes[9]])
}

fn backups(path: &Path) -> Vec<String> {
    let prefix = format!("{}.bak-", path.file_name().unwrap().to_string_lossy());
    let mut names: Vec<String> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&prefix))
        .collect();
    names.sort();
    names
}

fn labels(vault: &Vault) -> Vec<String> {
    vault
        .device_keys()
        .iter()
        .map(|d| d.label().to_owned())
        .collect()
}

#[test]
fn a_device_key_round_trips_through_the_encrypted_body_only() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    add_device(&mut vault, 0x11, "Laptop");
    drop(vault);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    let keys = reopened.device_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].id(), &[0x11; 32]);
    assert_eq!(keys[0].suite(), SUITE_X25519_ED25519_V1);
    assert_eq!(keys[0].label(), "Laptop");
    assert_eq!(keys[0].created_at(), 1_790_000_000);
    assert_eq!(keys[0].secret_keys().expose(), secret_keys(0x11));

    // Neither on disk in the clear, nor in any Debug rendering the vault or the key has.
    let marker = b"device-secret-canary-7c1e9a";
    assert!(!contains(&std::fs::read(&path).unwrap(), marker));
    let rendered = format!("{reopened:?} {:?} {:#?}", keys[0], keys);
    assert!(!contains(rendered.as_bytes(), marker), "{rendered}");
    // Nor in anything an item listing produces: a device key is not an item.
    assert!(reopened.items().is_empty());
    assert!(reopened.item_summaries().is_empty());
}

#[test]
fn the_first_device_key_upgrades_a_version_1_file_after_backing_it_up() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    add_item(&mut vault, "before");
    assert_eq!(vault.format_ver(), 1);
    let version_1 = std::fs::read(&path).unwrap();

    add_device(&mut vault, 1, "Laptop");

    assert_eq!(vault.format_ver(), header::DEVICE_KEYS_FORMAT_VERSION);
    assert_eq!(format_ver_on_disk(&path), 2);
    let backup = vault
        .format_upgrade_backup()
        .expect("the upgrade took a backup")
        .to_owned();
    assert_eq!(
        backup.file_name().unwrap().to_string_lossy(),
        format!("{}.bak-1", path.file_name().unwrap().to_string_lossy())
    );
    assert_eq!(
        std::fs::read(&backup).unwrap(),
        version_1,
        "the backup is the version 1 file exactly as it was"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the backup is as private as the vault");
    }

    // The backup is a vault the older version opens as it was: no device key, the old item.
    let old = Vault::open_with_password(&backup, PASSWORD).unwrap();
    assert_eq!(old.format_ver(), 1);
    assert!(old.device_keys().is_empty());
    assert_eq!(old.items().len(), 1);
}

#[test]
fn a_write_that_raises_nothing_takes_no_backup() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    add_item(&mut vault, "one");
    assert!(backups(&path).is_empty());
    assert!(vault.format_upgrade_backup().is_none());

    add_device(&mut vault, 1, "Laptop");
    add_device(&mut vault, 2, "Desktop");
    add_item(&mut vault, "two");
    assert_eq!(backups(&path).len(), 1, "only the upgrade itself backed up");
}

#[test]
fn an_existing_backup_is_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let plain = PathBuf::from(format!("{}.bak-1", path.display()));
    std::fs::write(&plain, b"an older backup somebody kept").unwrap();

    add_device(&mut vault, 1, "Laptop");

    assert_eq!(
        std::fs::read(&plain).unwrap(),
        b"an older backup somebody kept"
    );
    let backup = vault.format_upgrade_backup().unwrap();
    let name = backup.file_name().unwrap().to_string_lossy().into_owned();
    let expected_prefix = format!("{}.bak-1-", path.file_name().unwrap().to_string_lossy());
    assert!(name.starts_with(&expected_prefix), "{name}");
    let suffix = &name[expected_prefix.len()..];
    assert_eq!(suffix.len(), 8, "{name}");
    assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()), "{name}");
    assert_eq!(backups(&path).len(), 2);
    assert_eq!(
        Vault::open_with_password(backup, PASSWORD)
            .unwrap()
            .format_ver(),
        1
    );
}

#[test]
fn removing_the_last_device_key_keeps_version_2() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    add_device(&mut vault, 1, "Laptop");
    let removed = vault
        .transact(|tx| Ok(tx.remove_device_key(&[1; 32], ACTOR)))
        .unwrap();
    assert_eq!(
        removed.map(|k| k.label().to_owned()).as_deref(),
        Some("Laptop")
    );
    assert!(vault.device_keys().is_empty());
    assert_eq!(format_ver_on_disk(&path), 2);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert!(reopened.device_keys().is_empty());
    assert_eq!(reopened.format_ver(), 2);
    assert_eq!(backups(&path).len(), 1);
}

#[test]
fn removing_a_device_key_that_is_not_there_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, _path) = new_vault(dir.path());
    add_device(&mut vault, 1, "Laptop");
    let removed = vault
        .transact(|tx| Ok(tx.remove_device_key(&[9; 32], ACTOR).is_some()))
        .unwrap();
    assert!(!removed);
    assert_eq!(labels(&vault), ["Laptop"]);
}

#[test]
fn a_second_device_key_with_the_same_id_is_refused_and_nothing_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    add_device(&mut vault, 1, "Laptop");
    let before = std::fs::read(&path).unwrap();

    let result = vault.transact(|tx| tx.add_device_key(device_key(1, "Laptop again"), ACTOR));
    assert!(matches!(result, Err(Error::DeviceKey(_))), "{result:?}");
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(labels(&vault), ["Laptop"]);
}

#[test]
fn a_device_key_this_build_cannot_use_is_refused_before_it_reaches_the_vault() {
    let secret = || Secret::new(vec![1; 64]);
    assert!(matches!(
        DeviceKey::new([1; 32], "x25519-ed25519-v2", "Laptop", 1, secret()),
        Err(Error::DeviceKey(_))
    ));
    assert!(matches!(
        DeviceKey::new(
            [1; 32],
            SUITE_X25519_ED25519_V1,
            "Laptop",
            1,
            Secret::new(vec![1; 63])
        ),
        Err(Error::DeviceKey(_))
    ));
    assert!(matches!(
        DeviceKey::new(
            [1; 32],
            SUITE_X25519_ED25519_V1,
            &"x".repeat(MAX_DEVICE_LABEL_CHARS + 1),
            1,
            secret()
        ),
        Err(Error::DeviceKey(_))
    ));
    // The refusal names no key material.
    let error = DeviceKey::new(
        [1; 32],
        SUITE_X25519_ED25519_V1,
        "Laptop",
        1,
        Secret::new(b"device-secret-canary-7c1e9a".to_vec()),
    )
    .unwrap_err();
    assert!(!format!("{error} {error:?}").contains("canary"));
}

#[test]
fn a_rolled_back_transaction_neither_adds_the_key_nor_upgrades_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let before = std::fs::read(&path).unwrap();
    let result: kagisecure_core::Result<()> = vault.transact(|tx| {
        tx.add_device_key(device_key(1, "Laptop"), ACTOR)?;
        Err(Error::Malformed)
    });
    assert!(result.is_err());
    assert!(vault.device_keys().is_empty());
    assert_eq!(vault.format_ver(), 1);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(backups(&path).is_empty(), "no upgrade, so no backup");
}

#[test]
fn another_session_adopting_the_upgraded_file_keeps_its_device_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (mut first, _code, path) = new_vault(dir.path());
    let mut second = Vault::open_with_password(&path, PASSWORD).unwrap();

    add_device(&mut first, 1, "Laptop");
    // `second` still descends from the version 1 file; its next write must adopt the upgrade,
    // not write the file back as version 1 without the key.
    add_item(&mut second, "from second");
    assert_eq!(second.format_ver(), 2);
    assert_eq!(labels(&second), ["Laptop"]);
    assert_eq!(format_ver_on_disk(&path), 2);
    assert!(
        second.format_upgrade_backup().is_none(),
        "only the upgrading write backs up"
    );

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(labels(&reopened), ["Laptop"]);
    assert_eq!(reopened.items().len(), 1);
}

/// A session and a file that went separate ways: the file is restored to an older copy, and a
/// second writer adds a device key to it that the session never sees.
fn diverged_with_a_device_key_only_in_the_file(dir: &Path) -> (Vault, PathBuf) {
    let (mut session, _code, path) = new_vault(dir);
    add_device(&mut session, 1, "Laptop");
    let older = std::fs::read(&path).unwrap();
    add_item(&mut session, "only in the session");

    std::fs::write(&path, &older).unwrap();
    let mut other = Vault::open_with_password(&path, PASSWORD).unwrap();
    add_device(&mut other, 2, "Desktop");
    let vault_key = other.export_vault_key_for_platform_wrapping();
    drop(other);

    // The same id, a different entry: the label was changed in the file's version (by a later
    // build, say — this one has no rename).
    let mut body = raw_body(&path, &vault_key);
    let ciborium::Value::Array(devices) = map_entry(&mut body, "devices") else {
        panic!("devices is not an array")
    };
    *map_entry(&mut devices[0], "label") =
        ciborium::Value::Text("Laptop (renamed in the file)".to_owned());
    write_raw_body(&path, &vault_key, &body);
    (session, path)
}

#[test]
fn keeping_this_session_s_version_keeps_device_keys_only_the_file_has() {
    let dir = tempfile::tempdir().unwrap();
    let (mut session, path) = diverged_with_a_device_key_only_in_the_file(dir.path());

    let conflict = session.examine_conflict().unwrap().unwrap();
    let FileConflict::Diverged { lost, .. } = &conflict else {
        panic!("expected a diverged file, got {conflict:?}");
    };
    assert_eq!(lost.device_keys.only_in_file, 1, "{lost:?}");
    assert_eq!(lost.device_keys.differing, 1, "{lost:?}");

    session
        .overwrite_with_this_session(&conflict, "device-key-test", "keep mine")
        .unwrap();

    // This session's entry for the key both hold, then the file's key it did not have.
    assert_eq!(labels(&session), ["Laptop", "Desktop"]);
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(labels(&reopened), ["Laptop", "Desktop"]);
    assert_eq!(
        reopened.device_keys()[1].secret_keys().expose(),
        secret_keys(2),
        "the kept key is the file's key material, unchanged"
    );
    assert_eq!(reopened.format_ver(), 2);
    let titles: Vec<&str> = reopened.items().iter().map(|i| i.title.as_str()).collect();
    assert_eq!(titles, ["only in the session"]);

    let last = reopened.audit_entries().last().unwrap();
    assert_eq!(last.tool, AUDIT_TOOL_OVERWRITE);
    let detail = last.detail.as_deref().unwrap();
    assert!(
        detail.contains(" device_keys_kept=1 device_keys_retired=0 reason=keep mine"),
        "{detail}"
    );
}

#[test]
fn an_overwrite_with_no_device_keys_to_keep_records_zero() {
    let dir = tempfile::tempdir().unwrap();
    let (mut session, _code, path) = new_vault(dir.path());
    add_item(&mut session, "first");
    let older = std::fs::read(&path).unwrap();
    add_item(&mut session, "second");
    std::fs::write(&path, &older).unwrap();
    let mut other = Vault::open_with_password(&path, PASSWORD).unwrap();
    add_item(&mut other, "only in the file");

    let conflict = session.examine_conflict().unwrap().unwrap();
    session
        .overwrite_with_this_session(&conflict, "device-key-test", "r")
        .unwrap();
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    let detail = reopened
        .audit_entries()
        .last()
        .unwrap()
        .detail
        .clone()
        .unwrap();
    assert!(
        detail.contains(" device_keys_kept=0 device_keys_retired=0 reason=r"),
        "{detail}"
    );
    assert!(reopened.device_keys().is_empty());
    assert_eq!(reopened.format_ver(), 1);
}

#[test]
fn an_overwrite_that_raises_the_version_backs_up_the_file_it_replaces() {
    let dir = tempfile::tempdir().unwrap();
    let (mut session, _code, path) = new_vault(dir.path());
    add_item(&mut session, "first");
    let older = std::fs::read(&path).unwrap();
    add_device(&mut session, 1, "Laptop");
    add_item(&mut session, "second");
    let upgrade_backup = session.format_upgrade_backup().unwrap().to_owned();

    // The file is restored to its version 1 copy and changed there; the session keeps its key.
    std::fs::write(&path, &older).unwrap();
    let mut other = Vault::open_with_password(&path, PASSWORD).unwrap();
    add_item(&mut other, "only in the file");
    let replaced = std::fs::read(&path).unwrap();

    let conflict = session.examine_conflict().unwrap().unwrap();
    session
        .overwrite_with_this_session(&conflict, "device-key-test", "keep mine")
        .unwrap();

    assert_eq!(format_ver_on_disk(&path), 2);
    let backup = session.format_upgrade_backup().unwrap();
    assert_ne!(
        backup, upgrade_backup,
        "the first backup is kept, not replaced"
    );
    assert_eq!(std::fs::read(backup).unwrap(), replaced);
    assert_eq!(backups(&path).len(), 2);
}

/// The body of the vault file at `path`, decrypted, as a plain CBOR value.
fn raw_body(path: &Path, vault_key: &[u8]) -> ciborium::Value {
    use kagisecure_core::crypto::{aead, body_key};
    let bytes = std::fs::read(path).unwrap();
    let parts = header::split(&bytes).unwrap();
    let key = body_key(&vault_key.try_into().unwrap());
    let plaintext = aead::open(&key, &parts.body_nonce, parts.aad, parts.body_ct).unwrap();
    ciborium::from_reader(plaintext.as_slice()).unwrap()
}

/// Replace the body of the vault file at `path`, keeping its prefix and header bytes exactly.
fn write_raw_body(path: &Path, vault_key: &[u8], body: &ciborium::Value) {
    use kagisecure_core::crypto::{aead, body_key};
    let bytes = std::fs::read(path).unwrap();
    let parts = header::split(&bytes).unwrap();
    let key = body_key(&vault_key.try_into().unwrap());
    let mut plaintext = Vec::new();
    ciborium::into_writer(body, &mut plaintext).unwrap();
    let nonce = aead::nonce().unwrap();
    let mut out = parts.aad.to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&aead::seal(&key, &nonce, parts.aad, &plaintext).unwrap());
    std::fs::write(path, out).unwrap();
}

fn map_entry<'a>(map: &'a mut ciborium::Value, key: &str) -> &'a mut ciborium::Value {
    let ciborium::Value::Map(entries) = map else {
        panic!("not a map")
    };
    &mut entries
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(key))
        .unwrap_or_else(|| panic!("no {key}"))
        .1
}

#[test]
fn a_device_key_entry_keeps_keys_this_build_does_not_know() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    add_device(&mut vault, 1, "Laptop");
    let vault_key = vault.export_vault_key_for_platform_wrapping();
    drop(vault);

    // A newer build's field on the entry, e.g. a binding to a hardware-held key.
    let mut body = raw_body(&path, &vault_key);
    let ciborium::Value::Array(devices) = map_entry(&mut body, "devices") else {
        panic!("devices is not an array")
    };
    let ciborium::Value::Map(entry) = &mut devices[0] else {
        panic!("a device key is not a map")
    };
    entry.push((
        ciborium::Value::Text("enclave_binding".to_owned()),
        ciborium::Value::Text("from a newer build".to_owned()),
    ));
    write_raw_body(&path, &vault_key, &body);

    let mut reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(
        reopened.device_keys()[0].unknown().get("enclave_binding"),
        Some(&ciborium::Value::Text("from a newer build".to_owned()))
    );
    add_item(&mut reopened, "a later write");
    drop(reopened);

    let mut body = raw_body(&path, &vault_key);
    let ciborium::Value::Array(devices) = map_entry(&mut body, "devices") else {
        panic!("devices is not an array")
    };
    assert!(
        map_entry(&mut devices[0], "enclave_binding")
            .as_text()
            .is_some_and(|t| t == "from a newer build"),
        "the unknown key did not survive a write"
    );
}

#[test]
fn a_body_without_device_keys_has_no_devices_key_at_all() {
    // So a version 1 body encodes exactly as it did before device keys existed.
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    add_item(&mut vault, "one");
    let vault_key = vault.export_vault_key_for_platform_wrapping();
    let ciborium::Value::Map(entries) = raw_body(&path, &vault_key) else {
        panic!("the body is not a map")
    };
    assert!(entries.iter().all(|(k, _)| k.as_text() != Some("devices")));
}

#[test]
fn keeping_this_session_s_version_over_a_version_2_file_does_not_lower_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut session, _code, path) = new_vault(dir.path());
    add_item(&mut session, "first");
    let older = std::fs::read(&path).unwrap();
    add_item(&mut session, "second");

    // The file is restored to the older copy, and another writer raises it to version 2 and
    // then removes the device key again: version 2, and nothing in it that needs version 2.
    std::fs::write(&path, &older).unwrap();
    let mut other = Vault::open_with_password(&path, PASSWORD).unwrap();
    add_device(&mut other, 1, "Laptop");
    other
        .transact(|tx| Ok(tx.remove_device_key(&[1; 32], ACTOR)))
        .unwrap();
    add_item(&mut other, "only in the file");
    assert_eq!(format_ver_on_disk(&path), 2);
    assert_eq!(session.format_ver(), 1);

    let conflict = session.examine_conflict().unwrap().unwrap();
    session
        .overwrite_with_this_session(&conflict, "device-key-test", "keep mine")
        .unwrap();
    assert_eq!(
        format_ver_on_disk(&path),
        2,
        "the overwrite kept the file's version"
    );
    assert_eq!(session.format_ver(), 2);
}

#[test]
fn adding_and_removing_a_device_key_is_audited_by_id_only() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    add_device(&mut vault, 0xab, "Laptop");
    vault
        .transact(|tx| Ok(tx.remove_device_key(&[0xab; 32], ACTOR)))
        .unwrap();
    // Removing a key that is not there records nothing.
    vault
        .transact(|tx| Ok(tx.remove_device_key(&[0xcd; 32], ACTOR)))
        .unwrap();

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    let entries: Vec<_> = reopened
        .audit_entries()
        .iter()
        .map(|e| (e.tool.as_str(), e.actor.as_str(), e.detail.as_deref()))
        .collect();
    let id = format!("id={}", "ab".repeat(32));
    assert_eq!(
        entries,
        [
            (AUDIT_TOOL_DEVICE_KEY_ADDED, ACTOR, Some(id.as_str())),
            (AUDIT_TOOL_DEVICE_KEY_REMOVED, ACTOR, Some(id.as_str())),
        ]
    );
    let rendered = format!("{:?}", reopened.audit_entries());
    assert!(!rendered.contains("canary"), "{rendered}");
    assert!(!rendered.contains("Laptop"), "{rendered}");
}

#[test]
fn an_older_copy_put_back_after_a_device_key_was_added_is_refused_not_adopted() {
    // A sync tool restoring its copy, or a build that predates version 2 and already had the
    // vault open saving over it: the file goes back to before the key existed.
    let dir = tempfile::tempdir().unwrap();
    let (mut session, _code, path) = new_vault(dir.path());
    add_item(&mut session, "one");
    let before_the_key = std::fs::read(&path).unwrap();
    add_device(&mut session, 7, "Laptop");

    std::fs::write(&path, &before_the_key).unwrap();
    let result = session.transact(|tx| {
        tx.append_audit(AuditDraft {
            actor: ACTOR.to_owned(),
            tool: "after".to_owned(),
            outcome: Outcome::Allowed,
            ..AuditDraft::default()
        });
        Ok(())
    });
    assert!(matches!(result, Err(Error::VaultDiverged(_))), "{result:?}");
    assert!(matches!(
        session.refresh_if_changed(),
        Err(Error::VaultDiverged(_))
    ));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before_the_key,
        "nothing was written"
    );
    assert_eq!(
        labels(&session),
        ["Laptop"],
        "the session still holds the key"
    );
    assert_eq!(session.format_ver(), 2);

    // A person can put the key back by keeping this session's version.
    let conflict = session.examine_conflict().unwrap().unwrap();
    assert!(
        matches!(conflict, FileConflict::Diverged { .. }),
        "{conflict:?}"
    );
    session
        .overwrite_with_this_session(&conflict, ACTOR, "restore the device key")
        .unwrap();
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(labels(&reopened), ["Laptop"]);
    assert_eq!(reopened.format_ver(), 2);
}

#[test]
fn a_file_at_a_lower_format_ver_does_not_continue_the_session_even_if_its_log_does() {
    let dir = tempfile::tempdir().unwrap();
    let (mut session, _code, path) = new_vault(dir.path());
    add_device(&mut session, 7, "Laptop");
    let vault_key = session.export_vault_key_for_platform_wrapping();

    // The same audit log, byte for byte, but no device keys and version 1: what a writer that
    // does not know device keys would produce from this very file.
    let mut body = raw_body(&path, &vault_key);
    let ciborium::Value::Map(entries) = &mut body else {
        panic!("the body is not a map")
    };
    entries.retain(|(k, _)| k.as_text() != Some("devices"));
    write_raw_body(&path, &vault_key, &body);
    reseal_as_version_1(&path, &vault_key);
    let lowered = std::fs::read(&path).unwrap();
    assert_eq!(format_ver_on_disk(&path), 1);

    assert!(matches!(
        session.transact(|_| Ok(())),
        Err(Error::VaultDiverged(_))
    ));
    assert!(matches!(
        session.refresh_if_changed(),
        Err(Error::VaultDiverged(_))
    ));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        lowered,
        "nothing was written"
    );
    assert_eq!(labels(&session), ["Laptop"]);
    assert!(matches!(
        session.examine_conflict().unwrap(),
        Some(FileConflict::Diverged { .. })
    ));
}

/// Re-frame the file at `path` as `format_ver` 1, re-sealing its body under the new prefix.
fn reseal_as_version_1(path: &Path, vault_key: &[u8]) {
    use kagisecure_core::crypto::{aead, body_key};
    let bytes = std::fs::read(path).unwrap();
    let parts = header::split(&bytes).unwrap();
    let key = body_key(&vault_key.try_into().unwrap());
    let plaintext = aead::open(&key, &parts.body_nonce, parts.aad, parts.body_ct).unwrap();
    let framed = header::framed_with_version(&parts.aad[header::PREFIX_LEN..], 1);
    let nonce = aead::nonce().unwrap();
    let ciphertext = aead::seal(&key, &nonce, &framed, &plaintext).unwrap();
    let mut out = framed;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    std::fs::write(path, out).unwrap();
}

#[test]
fn a_removed_device_key_is_retired_and_can_never_be_added_again() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    add_device(&mut vault, 1, "Laptop");
    vault
        .transact(|tx| Ok(tx.remove_device_key(&[1; 32], ACTOR)))
        .unwrap();
    assert_eq!(vault.retired_device_keys(), [[1; 32]]);

    let before = std::fs::read(&path).unwrap();
    let again = vault.transact(|tx| tx.add_device_key(device_key(1, "Laptop"), ACTOR));
    assert!(matches!(again, Err(Error::DeviceKey(_))), "{again:?}");
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(reopened.retired_device_keys(), [[1; 32]]);
    assert!(reopened.device_keys().is_empty());
    // Ids only: nothing of the key's material is kept for a retired key.
    let vault_key = reopened.export_vault_key_for_platform_wrapping();
    let mut body = raw_body(&path, &vault_key);
    assert_eq!(
        *map_entry(&mut body, "retired_devices"),
        ciborium::Value::Array(vec![ciborium::Value::Bytes(vec![1; 32])])
    );
}

#[test]
fn keeping_this_session_s_version_never_brings_back_a_key_this_session_removed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut session, _code, path) = new_vault(dir.path());
    add_device(&mut session, 1, "Old laptop");
    let with_the_key = std::fs::read(&path).unwrap();
    session
        .transact(|tx| Ok(tx.remove_device_key(&[1; 32], ACTOR)))
        .unwrap();

    // An older copy, still holding the key, is put back and changed there.
    std::fs::write(&path, &with_the_key).unwrap();
    let mut other = Vault::open_with_password(&path, PASSWORD).unwrap();
    add_item(&mut other, "only in the file");

    let conflict = session.examine_conflict().unwrap().unwrap();
    let FileConflict::Diverged { lost, .. } = &conflict else {
        panic!("expected a diverged file, got {conflict:?}");
    };
    assert_eq!(
        lost.device_keys.only_in_file, 0,
        "a key this session retired is not kept"
    );
    session
        .overwrite_with_this_session(&conflict, ACTOR, "keep mine")
        .unwrap();

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert!(
        reopened.device_keys().is_empty(),
        "the removed key stayed removed"
    );
    assert_eq!(reopened.retired_device_keys(), [[1; 32]]);
}

#[test]
fn keeping_this_session_s_version_honours_a_removal_made_only_in_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let (mut session, _code, path) = new_vault(dir.path());
    add_device(&mut session, 1, "Old laptop");
    add_device(&mut session, 2, "Work laptop");
    let older = std::fs::read(&path).unwrap();
    add_item(&mut session, "only in the session");

    // In the file's version, the old laptop was retired.
    std::fs::write(&path, &older).unwrap();
    let mut other = Vault::open_with_password(&path, PASSWORD).unwrap();
    other
        .transact(|tx| Ok(tx.remove_device_key(&[1; 32], ACTOR)))
        .unwrap();

    let conflict = session.examine_conflict().unwrap().unwrap();
    let FileConflict::Diverged { lost, .. } = &conflict else {
        panic!("expected a diverged file, got {conflict:?}");
    };
    assert_eq!(lost.device_keys_retired_in_file, 1, "{lost:?}");
    session
        .overwrite_with_this_session(&conflict, ACTOR, "keep mine")
        .unwrap();

    assert_eq!(labels(&session), ["Work laptop"]);
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(labels(&reopened), ["Work laptop"]);
    assert_eq!(reopened.retired_device_keys(), [[1; 32]]);
    let detail = reopened
        .audit_entries()
        .last()
        .unwrap()
        .detail
        .clone()
        .unwrap();
    assert!(
        detail.contains(" device_keys_kept=0 device_keys_retired=1 reason=keep mine"),
        "{detail}"
    );
}

#[test]
fn only_keys_that_are_not_retired_are_active() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    add_device(&mut vault, 1, "Old laptop");
    add_device(&mut vault, 2, "Work laptop");
    let vault_key = vault.export_vault_key_for_platform_wrapping();
    drop(vault);

    // Another writer's body listing a key that is also retired: this build never writes one.
    let mut body = raw_body(&path, &vault_key);
    let ciborium::Value::Map(entries) = &mut body else {
        panic!("the body is not a map")
    };
    entries.push((
        ciborium::Value::Text("retired_devices".to_owned()),
        ciborium::Value::Array(vec![ciborium::Value::Bytes(vec![1; 32])]),
    ));
    write_raw_body(&path, &vault_key, &body);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(reopened.device_keys().len(), 2);
    let active: Vec<&str> = reopened
        .active_device_keys()
        .map(DeviceKey::label)
        .collect();
    assert_eq!(active, ["Work laptop"]);
}
