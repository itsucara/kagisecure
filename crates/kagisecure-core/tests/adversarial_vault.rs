//! Adversarial tests for the vault file format and its at-rest crypto
//! (`kagisecure_core::vault`, `kagisecure_core::crypto`).
//!
//! `tests/vault.rs` already establishes that the format round-trips and that a single flipped
//! header bit breaks the body. These tests go after the properties that only show up when you
//! push harder: a *semantically* forged header rather than a flipped bit, every bit of every
//! byte rather than bit 0, nonce uniqueness across thousands of real writes, what
//! happens when the process dies between the temporary file and the rename, what the vault key
//! leaves behind after the vault is dropped, and whether the unlock path has any floor under the
//! KDF cost a file is allowed to declare.
//!
//! Scenarios: C-01 (KDF cost floor), C-02 (header authentication), C-03 (nonce reuse), C-04
//! (golden vectors), C-05 (key residue after lock), C-09 (save atomicity under kill), C-10 (file
//! and directory modes).

mod common;

use common::{CANARY, PASSWORD, cheap_options, contains, new_vault};
use kagisecure_core::Error;
use kagisecure_core::crypto::kdf::{KdfParams, MIN_M_KIB, MIN_T};
use kagisecure_core::model::{Category, Field, FieldValue, Item, Secret};
use kagisecure_core::vault::{CreateOptions, Vault, header};
use std::collections::HashSet;
use std::path::Path;

/// The password the checked-in golden vectors were written with.
const GOLDEN_PASSWORD: &[u8] = b"golden vector password";

/// The environment variable that turns this test binary into the save-loop child used by C-09.
///
/// C-09 kills the child with `SIGKILL`, so both it and this constant are Unix-only.
#[cfg(unix)]
const SAVE_LOOP_VAR: &str = "KAGISECURE_LANE1_SAVE_LOOP";

/// What the save-loop child writes to stdout once it is past process start-up and inside the
/// loop, so the parent kills a running write rather than a process still in the linker.
#[cfg(unix)]
const READY: &str = "kagisecure-lane1-save-loop-ready\n";

fn canary_item(vault: &Vault) -> Item {
    let mut item = Item::new(
        vault.default_vault_id().unwrap(),
        Category::ApiCredential,
        "Adversarial canary",
    );
    item.fields.push(Field::public("username", "lane1"));
    item.fields.push(Field::concealed(
        "token",
        Secret::from_string(CANARY.to_owned()),
    ));
    item
}

// ---------------------------------------------------------------------------------------------
// C-01 — is there a floor under the declared KDF cost?
// ---------------------------------------------------------------------------------------------

/// `Vault::open` derives the KEK from whatever `slot.effective_kdf(&header.kdf)` says, and
/// `KdfParams::validate` used to bound the parameters only from *above* (`MAX_M_KIB`, `MAX_T`,
/// `MAX_P`) plus Argon2's own absolute minimums, so a file declaring m = 8 KiB, t = 1 — the
/// weakest parameter set Argon2 will accept — unlocked silently at essentially no work factor.
/// `MIN_M_KIB` / `MIN_T` are now a floor under both the create and the open path.
///
/// Note that this is *not* the header-downgrade attack: tampering with an existing header is
/// caught, because the header is the body AEAD's associated data (see
/// `a_semantically_forged_header_never_opens_a_vault` below). It is the absence of a policy
/// floor on a file that was genuinely written that way.
#[test]
fn unlocking_refuses_a_vault_whose_declared_kdf_cost_is_below_a_floor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("weak.kagivault");
    let options = CreateOptions {
        kdf: weakest_possible_kdf(),
        vault_name: "Weak".to_owned(),
        kdf_hint: None,
    };
    // The floor is enforced in `KdfParams::validate`, which the create path runs too, so such a
    // file cannot even be written by this build.
    let created = Vault::create(&path, PASSWORD, &options);
    assert!(
        created.is_err(),
        "a vault declaring m = 8 KiB, t = 1 was created; the floor should refuse it"
    );
    assert!(!path.exists(), "nothing should have been written");
}

/// The other half of the same policy, and the reason the floor is where it is: the v1 golden
/// vector was written at m = 64 KiB, t = 1 and golden vectors are never edited, so that cost has
/// to keep opening. The floor is therefore compatibility-bound rather than security-meaningful;
/// `KdfParams::meets_recommended_floor` carries the cost a *new* vault should be created at.
#[test]
fn the_floor_is_the_golden_vector_s_own_cost_and_no_higher() {
    let at_the_floor = KdfParams::new(MIN_M_KIB, MIN_T, 1).unwrap();
    assert!(at_the_floor.validate().is_ok());
    assert!(
        !at_the_floor.meets_recommended_floor(),
        "the floor that keeps v1 files opening is not a security-meaningful cost"
    );
    assert!(KdfParams::defaults().unwrap().meets_recommended_floor());

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("floor.kagivault");
    let options = CreateOptions {
        kdf: at_the_floor,
        vault_name: "Floor".to_owned(),
        kdf_hint: None,
    };
    let (vault, _code) = Vault::create(&path, PASSWORD, &options).unwrap();
    drop(vault);
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(reopened.header().kdf.m_kib, MIN_M_KIB);
}

/// Parameters below the floor, built by hand: `KdfParams::new` validates, so a file declaring
/// them can only come from another tool. This is what the open path has to refuse.
fn weakest_possible_kdf() -> KdfParams {
    let mut kdf = KdfParams::new(MIN_M_KIB, MIN_T, 1).unwrap();
    kdf.m_kib = 8; // Argon2's own absolute minimum
    kdf.t = 1;
    assert!(kdf.validate().is_err());
    kdf
}

// ---------------------------------------------------------------------------------------------
// C-02 — every header field is authenticated
// ---------------------------------------------------------------------------------------------

/// Flip **every bit of every byte** of the framed header, not just bit 0 as `tests/vault.rs`
/// does, and require that no flip ever yields an open vault. The dangerous failure mode is not
/// an error — it is a flip that opens *something*, so the test distinguishes the two by
/// asserting on the `Result` rather than on `is_err()` alone.
#[test]
fn no_single_bit_flip_anywhere_in_the_header_ever_opens_a_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = canary_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    let original = std::fs::read(&path).unwrap();
    let header_end = header::split(&original).unwrap().aad.len();

    let mut flips = 0;
    for byte_index in 0..header_end {
        for bit in 0..8u8 {
            let mut corrupted = original.clone();
            corrupted[byte_index] ^= 1 << bit;
            if corrupted == original {
                continue;
            }
            std::fs::write(&path, &corrupted).unwrap();
            if let Ok(opened) = Vault::open_with_password(&path, PASSWORD) {
                panic!(
                    "flipping bit {bit} of header byte {byte_index} opened a vault with {} items",
                    opened.items().len()
                );
            }
            flips += 1;
        }
    }
    assert!(flips > 800, "expected a header of meaningful size");
}

/// A bit flip is the easy case: a CBOR type byte often breaks parsing before any key material is
/// touched, which proves nothing about authentication. This test instead re-encodes a
/// *semantically valid* header with one field changed and splices it back in, so every case
/// reaches the AEAD. None of them may open the vault, and none may open a *different* vault.
#[test]
fn a_semantically_forged_header_never_opens_a_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = canary_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    let original = std::fs::read(&path).unwrap();
    let parts = header::split(&original).unwrap();
    let base = parts.header.clone();
    let nonce = parts.body_nonce;
    let body_ct = parts.body_ct.to_vec();

    let mut forgeries: Vec<(&str, header::Header)> = Vec::new();

    let mut h = base.clone();
    h.vault_id[0] ^= 0xff;
    forgeries.push(("vault_id changed", h));

    let mut h = base.clone();
    h.created_at = 0;
    forgeries.push(("created_at zeroed", h));

    let mut h = base.clone();
    h.kdf_hint = Some("attacker".to_owned());
    forgeries.push(("kdf_hint rewritten", h));

    let mut h = base.clone();
    h.kdf_hint = None;
    forgeries.push(("kdf_hint removed", h));

    let mut h = base.clone();
    h.kdf.salt[0] ^= 0xff;
    forgeries.push(("kdf salt changed", h));

    let mut h = base.clone();
    h.kdf.m_kib = 8;
    h.kdf.t = 1;
    forgeries.push(("kdf cost downgraded", h));

    let mut h = base.clone();
    h.wrapped_keys[0].label = "Not the master password".to_owned();
    forgeries.push(("slot label rewritten", h));

    let mut h = base.clone();
    h.wrapped_keys.swap(0, 1);
    forgeries.push(("slots reordered", h));

    let mut h = base.clone();
    h.wrapped_keys.truncate(1);
    forgeries.push(("recovery slot dropped", h));

    for (name, forged) in forgeries {
        let mut file = header::framed(&forged.to_cbor().unwrap());
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&body_ct);
        std::fs::write(&path, &file).unwrap();
        match Vault::open_with_password(&path, PASSWORD) {
            Err(_) => {}
            Ok(opened) => panic!("{name}: the forged header opened a vault: {opened:?}"),
        }
    }
}

/// The body ciphertext of one vault cannot be grafted onto another vault's header, even when
/// both files share a password: the AAD binds the body to its own header, and the wrapped key
/// binds the slot to its own `vault_id`.
#[test]
fn a_body_cannot_be_transplanted_between_two_vaults_with_the_same_password() {
    let dir = tempfile::tempdir().unwrap();
    let left = dir.path().join("left.kagivault");
    let right = dir.path().join("right.kagivault");
    for path in [&left, &right] {
        let (mut vault, _code) = Vault::create(path, PASSWORD, &cheap_options()).unwrap();
        let item = canary_item(&vault);
        vault
            .transact(|tx| {
                tx.add_item(item);
                Ok(())
            })
            .unwrap();
    }

    let left_bytes = std::fs::read(&left).unwrap();
    let right_bytes = std::fs::read(&right).unwrap();
    let left_parts = header::split(&left_bytes).unwrap();
    let right_parts = header::split(&right_bytes).unwrap();

    let mut hybrid = left_parts.aad.to_vec();
    hybrid.extend_from_slice(&right_parts.body_nonce);
    hybrid.extend_from_slice(right_parts.body_ct);
    let hybrid_path = dir.path().join("hybrid.kagivault");
    std::fs::write(&hybrid_path, &hybrid).unwrap();

    assert!(Vault::open_with_password(&hybrid_path, PASSWORD).is_err());
}

// ---------------------------------------------------------------------------------------------
// C-03 — nonce reuse across saves
// ---------------------------------------------------------------------------------------------

/// XChaCha20-Poly1305's 192-bit nonce makes random nonces safe, but only if a write really draws
/// a fresh one each time. A vault that is saved on every keystroke reaches thousands of writes
/// quickly, so this drives the real transactional write path rather than `aead::nonce()` directly.
#[test]
fn thousands_of_saves_never_reuse_a_body_nonce() {
    const SAVES: usize = 2_000;

    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = canary_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();

    let mut seen: HashSet<[u8; 24]> = HashSet::with_capacity(SAVES);
    for i in 0..SAVES {
        vault.transact(|_| Ok(())).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let nonce = header::split(&bytes).unwrap().body_nonce;
        assert!(
            seen.insert(nonce),
            "save {i} reused a body nonce: {nonce:02x?}"
        );
    }
    assert_eq!(seen.len(), SAVES);
}

/// Saving identical content twice must still produce different ciphertext — the fingerprint of a
/// deterministic nonce, and the thing an observer of a backup directory would notice first.
#[test]
fn saving_the_same_content_twice_produces_different_ciphertext() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = canary_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();

    vault.transact(|_| Ok(())).unwrap();
    let first = std::fs::read(&path).unwrap();
    vault.transact(|_| Ok(())).unwrap();
    let second = std::fs::read(&path).unwrap();

    assert_eq!(first.len(), second.len());
    assert_ne!(first, second);
    let a = header::split(&first).unwrap();
    let b = header::split(&second).unwrap();
    assert_eq!(a.aad, b.aad, "the header should not have changed");
    assert_ne!(a.body_nonce, b.body_nonce);
    assert_ne!(a.body_ct, b.body_ct);
}

// ---------------------------------------------------------------------------------------------
// C-04 — every checked-in golden vector still decrypts
// ---------------------------------------------------------------------------------------------

/// A golden vector opened the way it is meant to be: with the password — or, for a machine vault
/// (ADR-0042 §2), which has no password slot, with the machine vault key a personal vector holds.
fn open_golden(working: &Path, vectors: &Path) -> kagisecure_core::Result<Vault> {
    match Vault::open_with_password(working, GOLDEN_PASSWORD) {
        Err(Error::NoSuchSlot(_)) => {}
        other => return other,
    }
    for entry in std::fs::read_dir(vectors)? {
        let Ok(personal) = Vault::open_with_password(entry?.path(), GOLDEN_PASSWORD) else {
            continue;
        };
        if let Some(key) = personal.machine_vault_key()
            && let Ok(machine) = Vault::open_machine(working, key)
        {
            return Ok(machine);
        }
    }
    Err(Error::NoSuchSlot("password"))
}

/// `tests/vault.rs` opens one named vector. This walks the whole directory, so a vector added
/// for a future format version is covered the day it lands rather than the day someone
/// remembers to write a test for it.
#[test]
fn every_checked_in_golden_vector_still_decrypts() {
    let vectors = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let dir = tempfile::tempdir().unwrap();

    let mut opened = 0;
    for entry in std::fs::read_dir(&vectors).expect("the vectors directory must exist") {
        let entry = entry.unwrap();
        let source = entry.path();
        if source.extension().and_then(|e| e.to_str()) != Some("kagivault") {
            continue;
        }
        let working = dir.path().join(entry.file_name());
        std::fs::copy(&source, &working).unwrap();

        let vault = open_golden(&working, &vectors)
            .unwrap_or_else(|e| panic!("{} no longer decrypts: {e}", source.display()));
        assert!(
            !vault.items().is_empty(),
            "{} decrypted to an empty body",
            source.display()
        );
        for item in vault.items() {
            for field in &item.fields {
                if let FieldValue::Secret(secret) = &field.value {
                    assert!(
                        !secret.is_empty(),
                        "{} has an empty secret field",
                        source.display()
                    );
                }
            }
        }
        assert!(
            vault.verify_audit().is_ok(),
            "{} has a broken audit chain",
            source.display()
        );
        opened += 1;
    }
    assert!(opened >= 1, "no golden vectors were found in {vectors:?}");
}

/// A golden vector must not be silently rewritten by opening it: the file on disk is the
/// assertion, and a test that mutates it destroys the evidence.
#[test]
fn opening_a_golden_vector_does_not_modify_it() {
    let vectors = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let dir = tempfile::tempdir().unwrap();
    for entry in std::fs::read_dir(&vectors).unwrap() {
        let source = entry.unwrap().path();
        if source.extension().and_then(|e| e.to_str()) != Some("kagivault") {
            continue;
        }
        let working = dir.path().join(source.file_name().unwrap());
        std::fs::copy(&source, &working).unwrap();
        let before = std::fs::read(&working).unwrap();
        let vault = open_golden(&working, &vectors).unwrap();
        drop(vault);
        assert_eq!(before, std::fs::read(&working).unwrap());
    }
}

// ---------------------------------------------------------------------------------------------
// C-05 — what the vault key leaves behind when the vault is locked
// ---------------------------------------------------------------------------------------------

/// Dropping a `Vault` *is* the lock operation, and the key is a `Zeroizing<[u8; 32]>` so its own
/// storage is wiped. What is not wiped is every intermediate the open path made along the way —
/// the decrypted body's CBOR is `Zeroizing`, but the item `Secret`s decoded out of it are moved
/// into ordinary `Vec`s inside the `Body`, and the body itself is a plain struct.
///
/// This probe locks a vault and then allocates over the freed region looking for the canary
/// secret. It is best effort by nature: a miss does not prove the memory was wiped, only that
/// the allocator did not hand the same block back.
#[test]
fn no_decrypted_secret_survives_in_memory_after_the_vault_is_locked() {
    const PROBES: usize = 2_048;
    const PROBE_LEN: usize = 4096;

    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = canary_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert!(!reopened.items().is_empty());
    drop(reopened);

    let mut found = false;
    for _ in 0..PROBES {
        let probe: Vec<u8> = vec![0u8; PROBE_LEN];
        if contains(&probe, CANARY.as_bytes()) {
            found = true;
            break;
        }
    }
    assert!(
        !found,
        "the canary secret was still readable in memory freed by locking the vault"
    );
}

/// The part of C-05 that holds unconditionally and is worth pinning: nothing about a locked
/// vault is reachable through its own API, and the one sanctioned export is explicitly named.
#[test]
fn the_exported_vault_key_is_wrapped_in_a_zeroizing_buffer() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _code, _path) = new_vault(dir.path());
    let exported = vault.export_vault_key_for_platform_wrapping();
    assert_eq!(exported.len(), 32);
    assert_ne!(&exported[..], &[0u8; 32]);
    // The `Debug` of the vault itself never mentions key material.
    let rendered = format!("{vault:?}");
    assert!(!rendered.contains(CANARY));
    assert!(!rendered.to_lowercase().contains("key"));
}

// ---------------------------------------------------------------------------------------------
// C-09 — write atomicity when the process dies mid-write
// ---------------------------------------------------------------------------------------------

/// `write_atomically` writes to a randomly named temporary file in the same directory, fsyncs it
/// and renames it over the target. A process killed at any point must therefore leave the file
/// either wholly old or wholly new — never a half-written vault, and never a vault the password
/// no longer opens.
///
/// The kill has to be a real `SIGKILL` of a real process, so this test re-executes its own
/// binary as a child (see `save_loop_child_entry_point`) and kills it at a randomized delay.
#[test]
#[cfg(unix)]
fn a_save_killed_mid_write_always_leaves_a_file_that_still_opens() {
    use std::process::{Command, Stdio};

    const ROUNDS: usize = 24;

    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _code, path) = new_vault(dir.path());
    let item = canary_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();
    drop(vault);

    let exe = std::env::current_exe().unwrap();
    for round in 0..ROUNDS {
        let mut child = Command::new(&exe)
            .args([
                "save_loop_child_entry_point",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env(SAVE_LOOP_VAR, &path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the test binary should re-execute");

        // Wait for the child to say it is inside the save loop before killing it. Killing a
        // process that is still in the dynamic linker proves nothing about the write path, and on
        // macOS a `SIGKILL` delivered during image loading can wedge the loader for every other
        // process on the machine.
        // The child runs under libtest, which prints its own banner to the same stdout, so the
        // marker is found by reading lines rather than by reading `READY.len()` bytes.
        let stdout = child.stdout.take().expect("piped");
        let mut reader = std::io::BufReader::new(stdout);
        let mut ready = false;
        loop {
            let mut line = String::new();
            match std::io::BufRead::read_line(&mut reader, &mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if line == READY {
                        ready = true;
                        break;
                    }
                }
                Err(e) => panic!("round {round}: reading the child's stdout failed: {e}"),
            }
        }
        assert!(
            ready,
            "round {round}: the child never reached the save loop"
        );

        // Spread the kill across the whole save cycle: CBOR, AEAD, temporary file, rename.
        let delay = 1 + (round as u64 * 7) % 40;
        std::thread::sleep(std::time::Duration::from_millis(delay));
        let _ = child.kill();
        let _ = child.wait();
        drop(reader);

        let vault = Vault::open_with_password(&path, PASSWORD).unwrap_or_else(|e| {
            panic!("round {round}: the vault did not open after a killed save: {e}")
        });
        assert_eq!(vault.items().len(), 1, "round {round}: body was damaged");
        let token = vault.items()[0].field("token").unwrap();
        match &token.value {
            FieldValue::Secret(secret) => assert_eq!(secret.expose(), CANARY.as_bytes()),
            FieldValue::Public(_) => panic!("round {round}: the token stopped being secret"),
        }
        drop(vault);

        // A killed save may legitimately leave its temporary file behind — a crash cannot clean
        // up — but that file must never be mistaken for the vault, and must never be readable.
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".tmp") {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = entry.metadata().unwrap().permissions().mode() & 0o777;
                    assert_eq!(mode, 0o600, "a stray temporary vault file was not 0600");
                }
                std::fs::remove_file(entry.path()).unwrap();
            }
        }
    }
}

/// Not a test: the child half of `a_save_killed_mid_write_always_leaves_a_file_that_still_opens`.
///
/// It is `#[ignore]`d so a normal run skips it, and it returns immediately unless the parent set
/// the environment variable that names the vault to hammer.
#[test]
#[ignore = "child process entry point for the save-atomicity test, not a test of its own"]
#[cfg(unix)]
fn save_loop_child_entry_point() {
    let Ok(path) = std::env::var(SAVE_LOOP_VAR) else {
        return;
    };
    let Ok(mut vault) = Vault::open_with_password(&path, PASSWORD) else {
        return;
    };
    // The vault is open and the process is fully loaded: from here on, a kill lands inside the
    // write path rather than inside the dynamic linker.
    if vault.transact(|_| Ok(())).is_err() {
        return;
    }
    {
        use std::io::Write;
        let mut out = std::io::stdout();
        if out.write_all(READY.as_bytes()).is_err() || out.flush().is_err() {
            return;
        }
    }
    loop {
        // Keep the body changing so each write writes different bytes, without changing the
        // invariants the parent checks.
        let result = vault.transact(|tx| {
            if let Ok(item) = tx.find_item_mut("Adversarial canary") {
                item.updated_at = kagisecure_core::unix_now();
            }
            Ok(())
        });
        if result.is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// C-10 — file and directory modes
// ---------------------------------------------------------------------------------------------

/// Threat-model M-13: the vault file is `0600` and the directory holding it `0700` — and stays
/// that way after a save *over an existing file*, which is the case a naive `create(true)` would
/// get wrong by inheriting the old inode's mode or by widening it through the umask.
#[test]
#[cfg(unix)]
fn the_vault_and_its_directory_keep_their_owner_only_modes_across_repeated_saves() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let app_dir = dir.path().join("Application Support").join("kagisecure");
    let path = app_dir.join("adversarial.kagivault");

    let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    let item = canary_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();

    for round in 0..5 {
        vault.transact(|_| Ok(())).unwrap();
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "round {round}: vault file mode");
        let dir_mode = std::fs::metadata(&app_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "round {round}: vault directory mode");

        let strays: Vec<String> = std::fs::read_dir(&app_dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(
            strays.is_empty(),
            "round {round}: stray temporaries {strays:?}"
        );
    }
}

/// The same property on Windows, where `0600`/`0700` are a DACL instead: after every save — each
/// one a fresh temporary file renamed over the last — the vault and its sibling lock file carry
/// exactly one entry, for this user, in a protected DACL, and the directory the first write
/// created carries the inheritable
/// form of the same. The temp directory it sits in is *not* touched: an existing directory's ACL
/// is left alone on Windows by design (see `kagisecure_core::windows_acl`).
#[test]
#[cfg(windows)]
fn the_vault_and_the_directory_it_created_are_owner_only_across_repeated_saves() {
    use kagisecure_core::windows_acl::{self, ObjectKind};

    let dir = tempfile::tempdir().unwrap();
    let app_dir = dir.path().join("Application Support").join("kagisecure");
    let path = app_dir.join("adversarial.kagivault");
    let me = windows_acl::current_user_sid().unwrap();

    let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    let item = canary_item(&vault);
    vault
        .transact(|tx| {
            tx.add_item(item);
            Ok(())
        })
        .unwrap();

    for round in 0..5 {
        vault.transact(|_| Ok(())).unwrap();
        let file = windows_acl::path_security(&path).unwrap();
        assert!(
            windows_acl::is_owner_only(&file, &me, ObjectKind::File, true),
            "round {round}: vault file {file:?}"
        );
        // The sibling lock file every write takes (ADR-0039) is owner-only too.
        let lock =
            windows_acl::path_security(&kagisecure_core::vault::lock::lock_path(&path)).unwrap();
        assert!(
            windows_acl::is_owner_only(&lock, &me, ObjectKind::File, true),
            "round {round}: lock file {lock:?}"
        );
        for created in [&app_dir, &dir.path().join("Application Support")] {
            let security = windows_acl::path_security(created).unwrap();
            assert!(
                windows_acl::is_owner_only(&security, &me, ObjectKind::Directory, true),
                "round {round}: {} {security:?}",
                created.display()
            );
        }
    }
    let untouched = windows_acl::path_security(dir.path()).unwrap();
    assert!(
        !untouched.dacl_protected,
        "a directory that already existed must keep its own ACL: {untouched:?}"
    );
}

/// A pre-existing world-readable directory is a realistic starting state — a user who restored a
/// backup, or a `~/Library/Application Support` created by something else. Saving into it must
/// not leave the vault readable by anyone else.
#[test]
#[cfg(unix)]
fn saving_into_a_world_readable_directory_still_writes_an_owner_only_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let app_dir = dir.path().join("loose");
    std::fs::create_dir_all(&app_dir).unwrap();
    std::fs::set_permissions(&app_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    let path = app_dir.join("adversarial.kagivault");
    let (_vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();

    let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600);
    let dir_mode = std::fs::metadata(&app_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        dir_mode, 0o700,
        "the write should tighten the directory it writes into"
    );
}
