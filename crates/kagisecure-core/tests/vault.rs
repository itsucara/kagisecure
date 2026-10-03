//! End-to-end tests for the vault file: round-trip, authentication, recovery and upgrades.

use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::model::{Category, Field, FieldValue, Item, Secret};
use kagisecure_core::vault::{CreateOptions, UnlockedBy, Vault, header};
use kagisecure_core::{Error, RecoveryCode};
use std::path::{Path, PathBuf};

const PASSWORD: &[u8] = b"correct horse battery staple";
const SECRET_VALUE: &str = "sk_live_kagisecure_canary_9f3a";

/// Argon2id parameters cheap enough for a test suite. The point of several of these tests is that
/// the *file* decides the cost, so using non-default values here is not a shortcut — it is half
/// the assertion.
fn cheap_options() -> CreateOptions {
    CreateOptions {
        kdf: KdfParams::new(64, 1, 1).unwrap(),
        vault_name: "Test".to_owned(),
        kdf_hint: Some("test-profile".to_owned()),
    }
}

fn sample_item(vault: &Vault) -> Item {
    let mut item = Item::new(
        vault.default_vault_id().unwrap(),
        Category::Login,
        "Acme staging",
    );
    item.fields.push(Field::public("username", "deploy"));
    item.fields.push(Field::concealed(
        "password",
        Secret::from_string(SECRET_VALUE.to_owned()),
    ));
    item.tags.push("staging".to_owned());
    item
}

fn new_vault(dir: &Path) -> (Vault, RecoveryCode, PathBuf) {
    let path = dir.join("test.kagivault");
    let (vault, code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    (vault, code, path)
}

#[test]
fn round_trips_items_through_a_save_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = sample_item(&vault);
    let id = item.id;
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(reopened.items().len(), 1);
    let item = reopened.find_item(&id.to_string()).unwrap();
    assert_eq!(item.title, "Acme staging");
    assert_eq!(item.tags, ["staging"]);
    assert_eq!(
        item.field("username").unwrap().value.as_public(),
        Some("deploy")
    );
    let secret = item.field("password").unwrap().value.as_secret().unwrap();
    assert_eq!(secret.expose(), SECRET_VALUE.as_bytes());
    assert_eq!(reopened.unlocked_by(), UnlockedBy::Password);
}

#[test]
fn items_resolve_by_id_prefix_and_by_title() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, _path) = new_vault(dir.path());
    let item = sample_item(&vault);
    let id = item.id.to_string();
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();

    assert!(vault.find_item(&id).is_ok());
    assert!(vault.find_item(&id[..8]).is_ok());
    assert!(vault.find_item("Acme staging").is_ok());
    assert!(matches!(
        vault.find_item("nope"),
        Err(Error::ItemNotFound(_))
    ));
}

/// The lookup every secret-release channel uses: the exact id, in its canonical spelling, and
/// nothing a person might type instead — so a title collision or a trashed namesake can neither
/// block it nor be told apart through it.
#[test]
fn item_by_id_accepts_the_canonical_id_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, _path) = new_vault(dir.path());
    let item = sample_item(&vault);
    let item_id = item.id;
    let id = item_id.to_string();
    let vid = vault.default_vault_id().unwrap();
    vault
        .transact(|tx| {
            tx.add_item(item);
            // A trashed namesake: `find_item` now calls the title ambiguous.
            let mut namesake = Item::new(vid, Category::Login, "Acme staging");
            namesake.trashed_at = Some(1);
            tx.add_item(namesake);
            Ok(())
        })
        .unwrap();

    assert_eq!(vault.item_by_id(&item_id).map(|i| i.id), Some(item_id));
    assert_eq!(vault.item_by_id_str(&id).map(|i| i.id), Some(item_id));
    for not_an_id in [
        "Acme staging".to_owned(),
        id[..8].to_owned(),
        id.to_uppercase(),
        id.replace('-', ""),
        format!("{{{id}}}"),
        format!("urn:uuid:{id}"),
        String::new(),
    ] {
        assert!(
            vault.item_by_id_str(&not_an_id).is_none(),
            "{not_an_id:?} is not an item id"
        );
    }
    assert!(matches!(
        vault.find_item("Acme staging"),
        Err(Error::AmbiguousItem(_))
    ));

    vault
        .transact(|tx| {
            tx.item_by_id_mut(&item_id).unwrap().title = "Renamed".to_owned();
            assert!(tx.remove_item_by_id(&item_id).is_some());
            assert!(tx.remove_item_by_id(&item_id).is_none());
            Ok(())
        })
        .unwrap();
    assert!(vault.item_by_id(&item_id).is_none());
}

#[test]
fn ambiguous_titles_are_refused_rather_than_guessed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, _path) = new_vault(dir.path());
    let vid = vault.default_vault_id().unwrap();
    vault
        .transact(|tx| {
            tx.add_item(Item::new(vid, Category::Login, "duplicate"));
            tx.add_item(Item::new(vid, Category::Login, "duplicate"));
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        vault.find_item("duplicate"),
        Err(Error::AmbiguousItem(_))
    ));
}

#[test]
fn removing_an_item_removes_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = sample_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            tx.remove_item("Acme staging").unwrap();
            Ok(())
        })
        .unwrap();
    assert!(
        Vault::open_with_password(&path, PASSWORD)
            .unwrap()
            .items()
            .is_empty()
    );
}

#[test]
fn a_wrong_password_fails_and_yields_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = sample_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    match Vault::open_with_password(&path, b"wrong password") {
        Err(Error::Decrypt) => {}
        other => panic!("expected Error::Decrypt, got {other:?}"),
    }
}

#[test]
fn the_error_for_a_wrong_password_says_nothing_about_the_contents() {
    let rendered = Error::Decrypt.to_string();
    assert!(!rendered.contains(SECRET_VALUE));
    // Wrong key and tampered bytes are deliberately the same error (threat-model M-8).
    assert!(rendered.contains("wrong password"));
    assert!(rendered.contains("tampered"));
}

/// Every byte of the header — magic, version, length prefix and CBOR map alike — is authenticated
/// as the body's AAD, so flipping any one of them must make the body fail to decrypt rather than
/// make an attack cheaper (vault-format §2, roadmap M1).
#[test]
fn tampering_with_any_header_byte_breaks_the_body() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = sample_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    let original = std::fs::read(&path).unwrap();
    let header_end = header::split(&original).unwrap().aad.len();

    let mut checked = 0;
    for i in 0..header_end {
        let mut corrupted = original.clone();
        corrupted[i] ^= 0x01;
        std::fs::write(&path, &corrupted).unwrap();
        // Some flips break parsing before decryption (magic, version, a CBOR type byte); the rest
        // must reach the AEAD and be rejected there. No flip may produce a readable vault.
        assert!(
            Vault::open_with_password(&path, PASSWORD).is_err(),
            "flipping header byte {i} produced a vault that still opened"
        );
        checked += 1;
    }
    assert!(checked > 100, "expected a header of meaningful size");
}

/// The specific claim from vault-format §2: downgrading the Argon2id memory cost in the header
/// does not make an attack cheaper, it makes the file undecryptable.
#[test]
fn downgrading_the_kdf_cost_in_the_header_breaks_the_body() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.kagivault");
    let mut options = cheap_options();
    options.kdf = KdfParams::new(1024, 2, 1).unwrap();
    let (vault, _code) = Vault::create(&path, PASSWORD, &options).unwrap();
    drop(vault);

    let original = std::fs::read(&path).unwrap();
    let parts = header::split(&original).unwrap();
    let mut header = parts.header;
    assert_eq!(header.kdf.m_kib, 1024);
    header.kdf.m_kib = 8;

    let rewritten = header.to_cbor().unwrap();
    let mut forged = header::framed(&rewritten);
    assert_ne!(forged.as_slice(), parts.aad, "the forgery should differ");
    forged.extend_from_slice(&parts.body_nonce);
    forged.extend_from_slice(parts.body_ct);
    std::fs::write(&path, &forged).unwrap();

    // The cheaper KDF now yields a different KEK, so the slot itself fails first; either way the
    // vault does not open.
    assert!(Vault::open_with_password(&path, PASSWORD).is_err());
}

#[test]
fn tampering_with_the_body_fails_the_aead() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = sample_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    let original = std::fs::read(&path).unwrap();
    // Flip a bit in the ciphertext, and separately a bit in the body nonce.
    for offset in [original.len() - 1, original.len() - 20] {
        let mut corrupted = original.clone();
        corrupted[offset] ^= 0x80;
        std::fs::write(&path, &corrupted).unwrap();
        assert!(matches!(
            Vault::open_with_password(&path, PASSWORD),
            Err(Error::Decrypt)
        ));
    }
}

#[test]
fn truncation_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _code, path) = new_vault(dir.path());
    drop(vault);

    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, &original[..original.len() / 2]).unwrap();
    assert!(Vault::open_with_password(&path, PASSWORD).is_err());
}

#[test]
fn the_recovery_code_unlocks_independently_of_the_password() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, code, path) = new_vault(dir.path());
    let item = sample_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    // The code survives a trip through its printable form, which is the only form the user has.
    let printed = code.display();
    let retyped = RecoveryCode::parse(&printed.to_lowercase().replace('-', " ")).unwrap();

    let mut recovered = Vault::open_with_recovery_code(&path, &retyped).unwrap();
    assert_eq!(recovered.unlocked_by(), UnlockedBy::RecoveryCode);
    assert_eq!(recovered.items().len(), 1);

    // ... and the user can then set a new master password.
    let prepared = recovered
        .prepare_master_password(b"a whole new password")
        .unwrap();
    recovered
        .transact(|tx| tx.install_master_password(prepared))
        .unwrap();
    drop(recovered);

    let reopened = Vault::open_with_password(&path, b"a whole new password").unwrap();
    assert_eq!(reopened.items().len(), 1);
    assert!(matches!(
        Vault::open_with_password(&path, PASSWORD),
        Err(Error::Decrypt)
    ));
}

/// A password change rerolls the password slot's salt. The recovery slot carries its own KDF
/// descriptor precisely so that this does not invalidate it (ADR-0006).
#[test]
fn a_password_change_does_not_invalidate_the_recovery_code() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, code, path) = new_vault(dir.path());
    let salt_before = vault.header().kdf.salt.clone();
    let prepared = vault.prepare_master_password(b"second password").unwrap();
    vault
        .transact(|tx| tx.install_master_password(prepared))
        .unwrap();
    assert_ne!(vault.header().kdf.salt, salt_before);
    drop(vault);

    assert!(Vault::open_with_recovery_code(&path, &code).is_ok());
    assert!(Vault::open_with_password(&path, b"second password").is_ok());
}

#[test]
fn a_wrong_recovery_code_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _code, path) = new_vault(dir.path());
    drop(vault);
    let other = RecoveryCode::generate().unwrap();
    assert!(matches!(
        Vault::open_with_recovery_code(&path, &other),
        Err(Error::Decrypt)
    ));
}

#[test]
fn reissuing_a_recovery_code_retires_the_old_one() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, old, path) = new_vault(dir.path());
    let (new, prepared) = vault.prepare_recovery_code().unwrap();
    vault
        .transact(|tx| tx.install_recovery_code(prepared))
        .unwrap();
    drop(vault);

    assert!(Vault::open_with_recovery_code(&path, &new).is_ok());
    assert!(matches!(
        Vault::open_with_recovery_code(&path, &old),
        Err(Error::Decrypt)
    ));
}

/// Roadmap M1: "Argon2id parameters are read from the header, not hardcoded in the open path; a
/// vault with non-default parameters opens correctly."
#[test]
fn non_default_kdf_parameters_are_read_from_the_header() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("odd.kagivault");
    let mut options = cheap_options();
    options.kdf = KdfParams::new(96, 2, 2).unwrap();
    let (vault, _code) = Vault::create(&path, PASSWORD, &options).unwrap();
    drop(vault);

    let opened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(opened.header().kdf.m_kib, 96);
    assert_eq!(opened.header().kdf.t, 2);
    assert_eq!(opened.header().kdf.p, 2);
    assert_ne!(
        opened.header().kdf.m_kib,
        kagisecure_core::crypto::kdf::DEFAULT_M_KIB
    );
}

/// Vault-format §9 rule 4: a KDF parameter upgrade is a re-wrap, not a re-encrypt.
#[test]
fn kdf_parameters_can_be_upgraded_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, code, path) = new_vault(dir.path());
    let item = sample_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();

    let stronger = KdfParams::new(256, 2, 1).unwrap();
    let prepared = vault.prepare_kdf_upgrade(PASSWORD, &stronger).unwrap();
    vault
        .transact(|tx| tx.install_master_password(prepared))
        .unwrap();
    drop(vault);

    let opened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(opened.header().kdf.m_kib, 256);
    assert_eq!(opened.header().kdf.t, 2);
    assert_eq!(opened.items().len(), 1, "items survived the re-wrap");
    assert_eq!(
        opened
            .find_item("Acme staging")
            .unwrap()
            .field("password")
            .unwrap()
            .value
            .as_secret()
            .unwrap()
            .expose(),
        SECRET_VALUE.as_bytes()
    );
    // The recovery slot is untouched by a password-slot upgrade.
    drop(opened);
    assert!(Vault::open_with_recovery_code(&path, &code).is_ok());
}

#[test]
fn upgrading_with_the_wrong_password_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _code, path) = new_vault(dir.path());
    let stronger = KdfParams::new(256, 2, 1).unwrap();
    assert!(matches!(
        vault.prepare_kdf_upgrade(b"not the password", &stronger),
        Err(Error::Decrypt)
    ));
    drop(vault);
    assert_eq!(
        Vault::open_with_password(&path, PASSWORD)
            .unwrap()
            .header()
            .kdf
            .m_kib,
        64
    );
}

#[test]
fn creating_over_an_existing_vault_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (_vault, _code, path) = new_vault(dir.path());
    assert!(matches!(
        Vault::create(&path, PASSWORD, &cheap_options()),
        Err(Error::VaultExists(_))
    ));
}

#[test]
fn opening_a_missing_vault_says_so() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        Vault::open_with_password(dir.path().join("nope.kagivault"), PASSWORD),
        Err(Error::VaultNotFound(_))
    ));
}

#[test]
fn the_file_starts_with_the_documented_layout() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _code, path) = new_vault(dir.path());
    drop(vault);
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[..8], b"KAGIVLT\x00");
    assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), 1);
    let header_len = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    // magic + version + length prefix + header + 24-byte nonce + at least a 16-byte tag.
    assert!(bytes.len() > 14 + header_len + 24 + 16);
    let parts = header::split(&bytes).unwrap();
    let header = &parts.header;
    assert_eq!(parts.aad.len(), 14 + header_len);
    assert_eq!(header.vault_id.len(), 16);
    assert_eq!(header.body_aead, "xchacha20poly1305");
    assert_eq!(header.compression, "none");
    assert_eq!(header.wrapped_keys.len(), 2);
    assert_eq!(header.wrapped_keys[0].kind, "password");
    assert_eq!(header.wrapped_keys[1].kind, "recovery");
    assert_eq!(header.kdf_hint.as_deref(), Some("test-profile"));
}

#[test]
#[cfg_attr(not(unix), allow(unused_variables))]
fn the_vault_file_is_owner_only_and_written_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = sample_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "vault file must be owner read/write only");
    }
    // Windows: the `0600` counterpart, read back from the file the rename left in place.
    #[cfg(windows)]
    {
        use kagisecure_core::windows_acl::{self, ObjectKind};
        let me = windows_acl::current_user_sid().unwrap();
        let security = windows_acl::path_security(&path).unwrap();
        assert!(
            windows_acl::is_owner_only(&security, &me, ObjectKind::File, true),
            "vault file must be owner-only with a protected DACL: {security:?}"
        );
    }

    // No temporary files are left behind by a successful save.
    let strays: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(strays.is_empty(), "left temporary files behind: {strays:?}");
}

/// Roadmap M1: a vault written by this version lives in `tests/vectors/` and a test opens it.
/// The file is never regenerated — if this test fails, the format changed.
#[test]
fn the_golden_vector_still_opens() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/v1-argon2id-64k.kagivault");
    assert!(
        path.exists(),
        "golden vector missing; regenerate deliberately, never automatically"
    );

    // Copy it out, because opening does not write but future changes might.
    let dir = tempfile::tempdir().unwrap();
    let working = dir.path().join("golden.kagivault");
    std::fs::copy(&path, &working).unwrap();

    let vault = Vault::open_with_password(&working, b"golden vector password").unwrap();
    assert_eq!(vault.header().kdf.m_kib, 64);
    assert_eq!(vault.header().kdf.t, 1);
    assert_eq!(vault.items().len(), 1);
    let item = vault.find_item("Golden vector").unwrap();
    assert_eq!(item.category, Category::ApiCredential);
    assert_eq!(
        item.field("username").unwrap().value.as_public(),
        Some("vector")
    );
    match &item.field("token").unwrap().value {
        FieldValue::Secret(s) => assert_eq!(s.expose(), b"vector-token-value"),
        FieldValue::Public(_) => panic!("token should be secret material"),
    }
}

// ---------------------------------------------------------------------------------------------
// The platform (Secure Enclave / TPM) slot — ADR-0004, ADR-0008
// ---------------------------------------------------------------------------------------------
//
// These tests stand in for the keystore with the identity function. That is deliberate: what the
// core crate is responsible for is storing an opaque blob, handing the vault key out exactly once
// for wrapping, and opening a vault from an already-unwrapped key. Whether the Enclave's
// ciphertext is any good is the Enclave's business and is tested on the Swift side.

#[test]
fn a_platform_slot_round_trips_through_an_unwrapped_vault_key() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = sample_item(&vault);
    let exported = vault.export_vault_key_for_platform_wrapping();
    assert_eq!(exported.len(), 32, "the vault key is 32 bytes");
    vault
        .transact(|tx| {
            tx.add_item(item);
            // A real keystore would encrypt these; the test keeps them as they are.
            tx.install_platform_slot("macos-se-test", "Touch ID", exported.to_vec());
            Ok(())
        })
        .unwrap();

    let reopened = Vault::open_with_vault_key(&path, &exported).unwrap();
    assert_eq!(reopened.unlocked_by(), UnlockedBy::PlatformKey);
    assert_eq!(reopened.items().len(), 1);
    assert!(reopened.platform_slot().is_some());
    assert_eq!(reopened.platform_slot().unwrap().id, "macos-se-test");
}

#[test]
fn a_wrong_vault_key_is_refused_the_same_way_a_wrong_password_is() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _code, path) = new_vault(dir.path());
    drop(vault);
    assert!(matches!(
        Vault::open_with_vault_key(&path, &[7u8; 32]),
        Err(Error::Decrypt)
    ));
    // A key of the wrong length never reaches the crypto at all.
    assert!(matches!(
        Vault::open_with_vault_key(&path, &[7u8; 16]),
        Err(Error::Malformed)
    ));
}

#[test]
fn enrolling_twice_replaces_the_slot_rather_than_accumulating() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, _path) = new_vault(dir.path());
    vault
        .transact(|tx| {
            tx.install_platform_slot("device-a", "Touch ID", vec![1, 2, 3]);
            tx.install_platform_slot("device-b", "Touch ID", vec![4, 5, 6]);
            Ok(())
        })
        .unwrap();
    let platform: Vec<_> = vault
        .header()
        .wrapped_keys
        .iter()
        .filter(|s| s.kind == "platform")
        .collect();
    assert_eq!(platform.len(), 1);
    assert_eq!(platform[0].id, "device-b");
}

#[test]
fn removing_the_platform_slot_leaves_the_password_and_recovery_slots_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, code, path) = new_vault(dir.path());
    vault
        .transact(|tx| {
            tx.install_platform_slot("device-a", "Touch ID", vec![1, 2, 3]);
            Ok(())
        })
        .unwrap();

    let (first, second) = vault
        .transact(|tx| Ok((tx.remove_platform_slot(), tx.remove_platform_slot())))
        .unwrap();
    assert!(first);
    assert!(!second, "removing twice is a no-op");
    drop(vault);

    assert!(Vault::open_with_password(&path, PASSWORD).is_ok());
    assert!(Vault::open_with_recovery_code(&path, &code).is_ok());
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert!(reopened.platform_slot().is_none());
}

#[test]
fn a_platform_slot_survives_a_master_password_change() {
    // The slot wraps the vault key, and a password change re-wraps only the password slot
    // (vault-format §3). Touch ID must keep working across one.
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let vk = vault.export_vault_key_for_platform_wrapping();
    let prepared = vault
        .prepare_master_password(b"a whole new password")
        .unwrap();
    vault
        .transact(|tx| {
            tx.install_platform_slot("device-a", "Touch ID", vk.to_vec());
            tx.install_master_password(prepared)
        })
        .unwrap();
    drop(vault);

    assert!(Vault::open_with_vault_key(&path, &vk).is_ok());
    assert!(Vault::open_with_password(&path, b"a whole new password").is_ok());
}

#[test]
fn categories_carry_their_own_new_item_templates() {
    use kagisecure_core::proto::Category as C;

    let dir = tempfile::tempdir().unwrap();
    let (vault, _code, _path) = new_vault(dir.path());
    let vault_id = vault.default_vault_id().unwrap();

    let login = Item::from_template(vault_id, C::Login, "Example");
    let labels: Vec<&str> = login.fields.iter().map(|f| f.label.as_str()).collect();
    assert_eq!(
        labels,
        ["username", "password", "one-time password"],
        "website lives only in Item::urls (ADR-0029), never as a template field"
    );
    assert!(login.fields[1].value.is_secret(), "password is concealed");
    assert!(!login.fields[0].value.is_secret(), "username is not");
    assert!(
        !login.agent_visible,
        "a new item is never visible to agents (threat-model M-9)"
    );

    // Every first-class category has an icon and a display name, and none of them is `Other`.
    for category in C::first_class() {
        assert!(!category.symbol_name().is_empty());
        assert!(!category.display_name().is_empty());
        assert!(!matches!(category, C::Other(_)));
    }
}

#[test]
fn a_legacy_website_field_is_folded_into_urls_on_open() {
    // Before ADR-0029, a Login item could carry a `website` field (`FieldKind::Url`) alongside
    // `Item::urls`. Reopening such a vault should fold that field's value into `urls` and drop
    // the field, so `Item::urls` stays the one source of truth going forward.
    use kagisecure_core::model::FieldKind;

    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let vault_id = vault.default_vault_id().unwrap();

    let mut item = Item::new(vault_id, Category::Login, "Legacy login");
    item.fields.push(Field::public("username", "deploy"));
    let mut website = Field::public("website", "https://legacy.example.com");
    website.kind = FieldKind::Url;
    item.fields.push(website);
    let item_id = item.id;
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    let migrated = reopened.find_item(&item_id.to_string()).unwrap();
    assert_eq!(migrated.urls, vec!["https://legacy.example.com".to_owned()]);
    assert!(
        migrated.fields.iter().all(|f| f.label != "website"),
        "the legacy field must be gone once its value has moved"
    );
    assert!(migrated.fields.iter().any(|f| f.label == "username"));
}

#[test]
fn a_legacy_website_field_does_not_duplicate_an_existing_url() {
    use kagisecure_core::model::FieldKind;

    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let vault_id = vault.default_vault_id().unwrap();

    let mut item = Item::new(vault_id, Category::Login, "Already migrated");
    item.urls.push("https://example.com".to_owned());
    let mut website = Field::public("website", "https://example.com");
    website.kind = FieldKind::Url;
    item.fields.push(website);
    let item_id = item.id;
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    let migrated = reopened.find_item(&item_id.to_string()).unwrap();
    assert_eq!(migrated.urls, vec!["https://example.com".to_owned()]);
}

#[test]
fn trashing_an_item_is_a_soft_delete_that_survives_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = sample_item(&vault);
    let now = kagisecure_core::unix_now();
    vault
        .transact(|tx| {
            tx.add_item(item);
            tx.find_item_mut("Acme staging").unwrap().trashed_at = Some(now);
            Ok(())
        })
        .unwrap();
    drop(vault);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    let item = reopened.find_item("Acme staging").unwrap();
    assert!(item.is_trashed());
    assert_eq!(item.trashed_at, Some(now));
    assert!(reopened.item_summaries()[0].trashed);
}

#[test]
fn a_logical_vault_can_be_added_and_survives_a_reopen() {
    use kagisecure_core::model::VaultMeta;

    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let default_id = vault.default_vault_id().unwrap();

    let id = vault
        .transact(|tx| {
            let id = tx.add_logical_vault(VaultMeta::new("Imported"));
            let mut item = Item::new(id, Category::Login, "In the new vault");
            item.fields.push(Field::public("username", "deploy"));
            tx.add_item(item);
            Ok(id)
        })
        .unwrap();
    assert_ne!(id, default_id);
    // The first logical vault stays the default; adding one never re-points existing items.
    assert_eq!(vault.default_vault_id().unwrap(), default_id);
    drop(vault);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    let summaries = reopened.vault_summaries();
    assert_eq!(summaries.len(), 2);
    let imported = summaries.iter().find(|v| v.id == id).unwrap();
    assert_eq!(imported.name, "Imported");
    assert_eq!(imported.item_count, 1);
    // Default-deny survives the round trip (threat-model M-9).
    assert!(!imported.agent_visible);
    assert_eq!(reopened.find_vault("Imported").unwrap(), id);
}

#[test]
fn field_extra_round_trips_and_is_absent_when_empty() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());

    let mut item = sample_item(&vault);
    let id = item.id;
    item.fields[0].extra.insert(
        "onepassword_designation".to_owned(),
        ciborium::Value::Text("username".to_owned()),
    );
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    let item = reopened.find_item(&id.to_string()).unwrap();
    assert_eq!(
        item.field("username")
            .unwrap()
            .extra
            .get("onepassword_designation"),
        Some(&ciborium::Value::Text("username".to_owned()))
    );
    // A field nobody wrote an extra on stays empty rather than gaining a key.
    assert!(item.field("password").unwrap().extra.is_empty());
}

/// A vault written before `Field.extra` existed still opens: the key is additive, defaulted and
/// skipped when empty, so `body.schema` did not move (vault-format.md §9).
#[test]
fn the_checked_in_v1_vector_still_opens_with_field_extra_present() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/v1-argon2id-64k.kagivault");
    let dir = tempfile::tempdir().unwrap();
    let working = dir.path().join("golden.kagivault");
    std::fs::copy(&path, &working).unwrap();

    let vault = Vault::open_with_password(&working, b"golden vector password").unwrap();
    assert_eq!(vault.items().len(), 1);
    for item in vault.items() {
        for field in &item.fields {
            assert!(field.extra.is_empty());
        }
    }
}

/// Password history is Secret-typed, survives a round trip, and is invisible to every
/// metadata-only view (ADR-0002 §3: the summary is what an agent can ever be shown).
#[test]
fn password_history_round_trips_and_stays_out_of_the_summary() {
    use kagisecure_core::model::FieldRevision;

    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());

    let mut item = sample_item(&vault);
    let id = item.id;
    item.agent_visible = true;
    item.history.push(FieldRevision::concealed(
        "password",
        Secret::from_string("retired-value-2019".to_owned()),
        1_560_000_000,
    ));
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    let item = reopened.find_item(&id.to_string()).unwrap();
    assert_eq!(item.history.len(), 1);
    assert_eq!(item.history[0].label, "password");
    assert_eq!(item.history[0].retired_at, 1_560_000_000);
    assert_eq!(
        item.history[0].value.as_secret().unwrap().expose(),
        b"retired-value-2019"
    );

    // A retired value is not a field: nothing can resolve it by label.
    assert_eq!(
        item.field("password")
            .unwrap()
            .value
            .as_secret()
            .unwrap()
            .expose(),
        SECRET_VALUE.as_bytes()
    );

    // The metadata view carries no trace of it, not even a count, on an agent-visible item.
    let summary = item.summary();
    assert!(summary.agent_visible);
    let rendered = serde_json::to_string(&summary).unwrap();
    assert!(!rendered.contains("history"), "{rendered}");
    assert!(!rendered.contains("retired"), "{rendered}");
    assert!(!format!("{item:?}").contains("retired-value-2019"));
}

/// The `format_ver` 2 golden vector: a vault holding one shared-vault device key (ADR-0035 §5,
/// §16). Its key material is public test data (RFC 7748 §6.1 Alice's X25519 key, RFC 8032 §7.1
/// TEST 1's Ed25519 seed); see `examples/make_golden_vector.rs`. Never regenerated.
#[test]
fn the_version_2_device_key_golden_vector_still_opens() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/v2-devices-argon2id-64k.kagivault");
    let dir = tempfile::tempdir().unwrap();
    let working = dir.path().join("golden-v2.kagivault");
    std::fs::copy(&path, &working).unwrap();

    let vault = Vault::open_with_password(&working, b"golden vector password").unwrap();
    assert_eq!(vault.format_ver(), 2);
    assert_eq!(vault.header().kdf.m_kib, 64);
    assert_eq!(vault.items().len(), 1);
    assert!(vault.find_item("Golden vector").is_ok());

    let keys = vault.device_keys();
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(key.id()),
        "1ccbda9a1b81bbf470d5ab39998783822db70612b841fca593e81d9222b05b8f"
    );
    assert_eq!(key.suite(), "x25519-ed25519-v1");
    assert_eq!(key.label(), "Golden vector device");
    assert_eq!(key.created_at(), 1_790_000_000);
    assert_eq!(
        hex(key.secret_keys().expose()),
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a\
         9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    );
    assert!(key.unknown().is_empty());
    vault.verify_audit().unwrap();
}

/// A transaction on the version 2 vector writes version 2 and keeps its device key.
#[test]
fn a_transaction_on_the_version_2_golden_vector_keeps_its_version_and_device_key() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/v2-devices-argon2id-64k.kagivault");
    let dir = tempfile::tempdir().unwrap();
    let working = dir.path().join("golden-v2.kagivault");
    std::fs::copy(&path, &working).unwrap();

    let mut vault = Vault::open_with_password(&working, b"golden vector password").unwrap();
    vault
        .transact(|tx| {
            let vault_id = tx.default_vault_id()?;
            tx.add_item(Item::new(vault_id, Category::Login, "added"));
            Ok(())
        })
        .unwrap();
    assert!(
        vault.format_upgrade_backup().is_none(),
        "nothing was raised"
    );
    drop(vault);

    let bytes = std::fs::read(&working).unwrap();
    assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), 2);
    let reopened = Vault::open_with_password(&working, b"golden vector password").unwrap();
    assert_eq!(reopened.device_keys().len(), 1);
    assert_eq!(reopened.items().len(), 2);
}

/// The `format_ver` 3 golden vectors (ADR-0042 §2): a personal vault holding a machine vault key,
/// and the machine vault it opens. The key is public test data; see
/// `examples/make_golden_vector.rs`. Never regenerated.
#[test]
fn the_version_3_machine_vault_golden_vectors_still_open() {
    use kagisecure_core::vault::machine::{ExecutablePin, LoginField, PresencePath, ScheduleTime};

    let vectors = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let dir = tempfile::tempdir().unwrap();
    let personal_path = dir.path().join("golden-v3.kagivault");
    let machine_path = dir.path().join("golden-v3.machine.kagivault");
    std::fs::copy(
        vectors.join("v3-machine-key-argon2id-64k.kagivault"),
        &personal_path,
    )
    .unwrap();
    std::fs::copy(vectors.join("v3-machine-vault.kagivault"), &machine_path).unwrap();

    let personal = Vault::open_with_password(&personal_path, b"golden vector password").unwrap();
    assert_eq!(personal.format_ver(), 3);
    assert!(!personal.is_machine());
    let key = personal.machine_vault_key().unwrap();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(&key.to_keychain_bytes()),
        "6d616368696e652d7661756c742d6964\
         000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    personal.verify_audit().unwrap();

    let machine = Vault::open_machine(&machine_path, key).unwrap();
    assert_eq!(machine.format_ver(), 3);
    assert!(machine.header().wrapped_keys.is_empty());
    let login = machine.find_item("Golden service bot").unwrap();
    assert_eq!(login.urls, ["https://service.example"]);
    assert!(login.totp_field().is_some());
    let injected = machine.resolve_environment("golden deploy", None).unwrap();
    assert_eq!(injected[0].value.expose(), b"golden-deploy-token");

    let section = machine.machine().unwrap();
    assert_eq!(section.jobs.len(), 2);
    assert_eq!(section.jobs[0].schedule.len(), 2);
    assert!(matches!(
        section.jobs[0].schedule[0],
        ScheduleTime::Daily {
            hour: 2,
            minute: 30
        }
    ));
    assert!(matches!(
        section.jobs[1].run_browser.as_ref().unwrap().pin,
        ExecutablePin::CodeSigning { .. }
    ));
    let command = &section.command_grants[0];
    assert_eq!(command.variables, ["DEPLOY_TOKEN"]);
    assert_eq!(command.uses, 4);
    assert_eq!(command.limits.expires_at, 1_790_000_000 + 30 * 24 * 60 * 60);
    let grant = &section.login_grants[0];
    assert_eq!(grant.origin, "https://service.example");
    assert!(grant.one_time_codes);
    assert!(grant.fields.contains(&LoginField::OneTimeCode));
    assert_eq!(grant.presence, PresencePath::ConfirmedMasterPassword);
    assert_eq!(section.arm.as_ref().unwrap().armed_at, 1_790_000_000);
    assert!(section.unknown.is_empty());
}

/// A transaction on each version 3 vector keeps its version and what makes it what it is.
#[test]
fn a_transaction_on_the_version_3_golden_vectors_keeps_their_version() {
    let vectors = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let dir = tempfile::tempdir().unwrap();
    let personal_path = dir.path().join("golden-v3.kagivault");
    let machine_path = dir.path().join("golden-v3.machine.kagivault");
    std::fs::copy(
        vectors.join("v3-machine-key-argon2id-64k.kagivault"),
        &personal_path,
    )
    .unwrap();
    std::fs::copy(vectors.join("v3-machine-vault.kagivault"), &machine_path).unwrap();

    let mut personal =
        Vault::open_with_password(&personal_path, b"golden vector password").unwrap();
    personal
        .transact(|tx| {
            let vault_id = tx.default_vault_id()?;
            tx.add_item(Item::new(vault_id, Category::Login, "added"));
            Ok(())
        })
        .unwrap();
    assert!(personal.format_upgrade_backup().is_none());
    let mut machine =
        Vault::open_machine(&machine_path, personal.machine_vault_key().unwrap()).unwrap();
    machine
        .transact(|tx| {
            tx.machine_mut()?.arm = None;
            Ok(())
        })
        .unwrap();
    drop(machine);

    for path in [&personal_path, &machine_path] {
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), 3);
    }
    let reopened =
        Vault::open_machine(&machine_path, personal.machine_vault_key().unwrap()).unwrap();
    assert!(reopened.machine().unwrap().arm.is_none());
    assert_eq!(reopened.machine().unwrap().login_grants.len(), 1);
}
