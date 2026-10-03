//! Several writers of one vault file: separate `Vault` values standing in for the app, the CLI
//! and the agent daemon, each holding the whole decrypted body in memory.
//!
//! Before transactions, each of them wrote its own copy back and the last writer silently erased
//! everyone else's changes — including audit entries, the one record of what agents asked for.
//! These tests pin the replacement: `Vault::transact` starts every write from the file as it is
//! now, a file that went backwards is refused rather than built on, and audit drafts survive a
//! failed write.

mod common;

use std::collections::HashSet;
use std::time::Duration;

use common::{PASSWORD, new_vault};
use kagisecure_core::Error;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::model::{Category, Item};
use kagisecure_core::proto::Outcome;
use kagisecure_core::vault::{Tx, Vault};

const NEW_PASSWORD: &[u8] = b"a completely different passphrase";

fn draft(tool: &str) -> AuditDraft {
    AuditDraft {
        actor: "concurrent-writers".to_owned(),
        tool: tool.to_owned(),
        outcome: Outcome::Allowed,
        ..AuditDraft::default()
    }
}

/// One realistic write: an item and the audit entry that records it, in one transaction.
fn add_item_audited(tx: &mut Tx<'_>, title: &str) {
    let vault_id = tx.default_vault_id().unwrap();
    tx.add_item(Item::new(vault_id, Category::Login, title));
    tx.append_audit(draft(title));
}

fn titles(vault: &Vault) -> Vec<String> {
    vault.items().iter().map(|i| i.title.clone()).collect()
}

fn tools(vault: &Vault) -> Vec<String> {
    vault
        .audit_entries()
        .iter()
        .map(|e| e.tool.clone())
        .collect()
}

/// The audit chain verifies and `seq` runs 0, 1, 2, … with no gap or repeat.
fn assert_log_intact(vault: &Vault) {
    vault.verify_audit().expect("the audit chain verifies");
    for (index, entry) in vault.audit_entries().iter().enumerate() {
        assert_eq!(entry.seq, index as u64, "seq is contiguous");
    }
}

#[test]
fn two_writers_that_opened_the_same_version_both_keep_their_changes() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _code, path) = new_vault(dir.path());
    let mut b = Vault::open_with_password(&path, PASSWORD).unwrap();

    a.transact(|tx| {
        add_item_audited(tx, "X");
        Ok(())
    })
    .unwrap();
    // B has not seen X — and does not need to: its transaction starts from the file.
    assert!(titles(&b).is_empty());
    b.transact(|tx| {
        assert_eq!(
            titles(tx),
            ["X"],
            "the closure sees the other writer's commit"
        );
        add_item_audited(tx, "Y");
        Ok(())
    })
    .unwrap();

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(titles(&reopened), ["X", "Y"]);
    assert_eq!(tools(&reopened), ["X", "Y"]);
    assert_log_intact(&reopened);

    // A long-lived reader catches up without writing.
    assert!(a.refresh_if_changed().unwrap());
    assert_eq!(titles(&a), ["X", "Y"]);
    assert!(!a.refresh_if_changed().unwrap(), "nothing changed since");
}

#[test]
fn eight_threads_with_two_handles_each_lose_not_one_of_eight_hundred_writes() {
    const THREADS: usize = 8;
    const HANDLES: usize = 2;
    const OPS: usize = 50;

    let dir = tempfile::tempdir().unwrap();
    let (vault, _code, path) = new_vault(dir.path());
    drop(vault);

    std::thread::scope(|scope| {
        for thread in 0..THREADS {
            let path = &path;
            scope.spawn(move || {
                let mut handles: Vec<Vault> = (0..HANDLES)
                    .map(|_| {
                        let mut v = Vault::open_with_password(path, PASSWORD).unwrap();
                        // Sixteen writers contend for one lock; nobody should give up here.
                        v.set_lock_timeout(Duration::from_secs(120));
                        v
                    })
                    .collect();
                for op in 0..OPS {
                    for (h, vault) in handles.iter_mut().enumerate() {
                        let title = format!("t{thread}-h{h}-op{op}");
                        vault
                            .transact(|tx| {
                                add_item_audited(tx, &title);
                                Ok(())
                            })
                            .unwrap_or_else(|e| panic!("{title}: {e}"));
                    }
                }
            });
        }
    });

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    let expected = THREADS * HANDLES * OPS;
    assert_eq!(reopened.items().len(), expected);
    assert_eq!(reopened.audit_entries().len(), expected);
    let unique: HashSet<String> = titles(&reopened).into_iter().collect();
    assert_eq!(unique.len(), expected, "every write landed exactly once");
    assert_log_intact(&reopened);
}

#[test]
fn a_password_changed_by_another_writer_does_not_break_this_session() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _code, path) = new_vault(dir.path());
    let mut b = Vault::open_with_password(&path, PASSWORD).unwrap();

    // The Argon2id half runs before the lock; only the cheap install runs inside it.
    let prepared = b.prepare_master_password(NEW_PASSWORD).unwrap();
    b.transact(|tx| {
        tx.install_master_password(prepared)?;
        tx.append_audit(draft("password changed"));
        Ok(())
    })
    .unwrap();

    // A still holds the vault key, which a password change does not touch, so it can adopt
    // B's header and keep writing — without undoing the change.
    a.transact(|tx| {
        add_item_audited(tx, "after the change");
        Ok(())
    })
    .unwrap();

    assert!(matches!(
        Vault::open_with_password(&path, PASSWORD),
        Err(Error::Decrypt)
    ));
    let reopened = Vault::open_with_password(&path, NEW_PASSWORD).unwrap();
    assert_eq!(titles(&reopened), ["after the change"]);
    assert_eq!(tools(&reopened), ["password changed", "after the change"]);
    assert_log_intact(&reopened);
}

#[test]
fn a_header_change_prepared_against_a_stale_header_is_refused_not_applied() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _code, path) = new_vault(dir.path());
    let mut b = Vault::open_with_password(&path, PASSWORD).unwrap();

    let stale_password = a.prepare_master_password(b"A's choice").unwrap();
    let (stale_code, stale_recovery) = a.prepare_recovery_code().unwrap();

    let (b_code, b_recovery) = b.prepare_recovery_code().unwrap();
    let b_password = b.prepare_master_password(NEW_PASSWORD).unwrap();
    b.transact(|tx| {
        tx.install_master_password(b_password)?;
        tx.install_recovery_code(b_recovery)
    })
    .unwrap();
    let after_b = std::fs::read(&path).unwrap();

    let refused = a.transact(|tx| tx.install_master_password(stale_password));
    assert!(
        matches!(refused, Err(Error::VaultConflict(_))),
        "{refused:?}"
    );
    let refused = a.transact(|tx| tx.install_recovery_code(stale_recovery));
    assert!(
        matches!(refused, Err(Error::VaultConflict(_))),
        "{refused:?}"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        after_b,
        "nothing was written"
    );

    // B's password and B's recovery code are the ones that work; A's never took effect.
    Vault::open_with_password(&path, NEW_PASSWORD).unwrap();
    assert!(Vault::open_with_password(&path, b"A's choice").is_err());
    Vault::open_with_recovery_code(&path, &b_code).unwrap();
    assert!(Vault::open_with_recovery_code(&path, &stale_code).is_err());

    // Each refused transaction started by adopting the file, so A already holds B's header;
    // prepared again from it, A's change goes through.
    assert!(!a.refresh_if_changed().unwrap());
    let fresh = a.prepare_master_password(b"A's choice").unwrap();
    a.transact(|tx| tx.install_master_password(fresh)).unwrap();
    Vault::open_with_password(&path, b"A's choice").unwrap();
}

#[test]
fn a_kdf_upgrade_checks_the_password_before_the_lock_and_the_slot_under_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _code, path) = new_vault(dir.path());
    let stronger = kagisecure_core::crypto::kdf::KdfParams::new(128, 1, 1).unwrap();

    assert!(matches!(
        a.prepare_kdf_upgrade(b"wrong password", &stronger),
        Err(Error::Decrypt)
    ));
    let prepared = a.prepare_kdf_upgrade(PASSWORD, &stronger).unwrap();
    a.transact(|tx| tx.install_master_password(prepared))
        .unwrap();
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(reopened.header().kdf.m_kib, 128);
}

#[test]
fn a_file_copied_back_from_earlier_in_the_session_is_refused_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _code, path) = new_vault(dir.path());

    a.transact(|tx| {
        tx.append_audit(draft("denied-exfiltration-1"));
        Ok(())
    })
    .unwrap();
    let old_copy = std::fs::read(&path).unwrap();
    a.transact(|tx| {
        tx.append_audit(draft("denied-exfiltration-2"));
        Ok(())
    })
    .unwrap();

    // Same-user malware restores the older, fully authentic file to erase entry 2.
    std::fs::write(&path, &old_copy).unwrap();

    let result = a.transact(|tx| {
        tx.append_audit(draft("next"));
        Ok(())
    });
    assert!(matches!(result, Err(Error::VaultDiverged(_))), "{result:?}");
    assert_eq!(std::fs::read(&path).unwrap(), old_copy, "not overwritten");
    assert!(a.last_save_error().unwrap().contains("audit log"));
    // This session still holds the evidence, unchanged.
    assert_eq!(
        tools(&a),
        ["denied-exfiltration-1", "denied-exfiltration-2"]
    );

    // The other read-only path agrees.
    assert!(matches!(
        a.refresh_if_changed(),
        Err(Error::VaultDiverged(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), old_copy);
}

#[test]
fn a_different_vault_at_the_path_is_refused_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _code, path) = new_vault(dir.path());
    let elsewhere = tempfile::tempdir().unwrap();
    let (_other, _other_code, other_path) = new_vault(elsewhere.path());
    std::fs::copy(&other_path, &path).unwrap();
    let foreign = std::fs::read(&path).unwrap();

    let result = a.transact(|_| Ok(()));
    assert!(matches!(result, Err(Error::VaultReplaced(_))), "{result:?}");
    assert!(matches!(
        a.refresh_if_changed(),
        Err(Error::VaultReplaced(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), foreign);
}

/// A pending draft outlives a transaction that cannot even read the file, and is written by the
/// first one that can.
#[test]
#[cfg(unix)]
fn a_pending_draft_survives_an_unreadable_vault_and_is_flushed_once_it_is_back() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _code, path) = new_vault(dir.path());
    let good = std::fs::read(&path).unwrap();

    a.queue_audit(draft("denied while the disk was bad"));
    // Same technique as `audit_durability.rs`: a directory where the vault should be.
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();

    let result = a.transact(|tx| {
        add_item_audited(tx, "never");
        Ok(())
    });
    assert!(result.is_err());
    assert!(a.items().is_empty());
    assert_eq!(a.unsaved_audit_entries(), 1);
    assert!(a.last_save_error().is_some());

    std::fs::remove_dir(&path).unwrap();
    std::fs::write(&path, &good).unwrap();
    a.flush_audit().unwrap();
    assert_eq!(a.unsaved_audit_entries(), 0);
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(tools(&reopened), ["denied while the disk was bad"]);
    assert!(reopened.items().is_empty());
}

/// The real thing: the file reads fine but the write at the end of the transaction fails, after
/// the closure already changed memory. macOS can make exactly that happen without privileges —
/// `rename(2)` cannot replace a file flagged immutable (`chflags uchg`) — so this runs there;
/// the same path is covered on every platform by the vault module's fault-injection unit tests.
#[test]
#[cfg(target_os = "macos")]
fn a_write_that_fails_after_the_closure_ran_takes_the_mutation_back_out_of_memory() {
    use std::process::Command;

    struct Immutable<'a>(&'a std::path::Path);
    impl Drop for Immutable<'_> {
        fn drop(&mut self) {
            let _ = Command::new("chflags").arg("nouchg").arg(self.0).status();
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let (mut a, _code, path) = new_vault(dir.path());
    a.transact(|tx| {
        add_item_audited(tx, "committed");
        Ok(())
    })
    .unwrap();
    let before = std::fs::read(&path).unwrap();
    a.queue_audit(draft("pending"));

    assert!(
        Command::new("chflags")
            .arg("uchg")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let guard = Immutable(&path);

    let result = a.transact(|tx| {
        add_item_audited(tx, "rolled back");
        Ok(())
    });
    assert!(matches!(result, Err(Error::Io(_))), "{result:?}");
    assert_eq!(
        titles(&a),
        ["committed"],
        "the mutation is gone from memory"
    );
    assert_eq!(tools(&a), ["committed"]);
    assert_eq!(a.unsaved_audit_entries(), 1, "the pending draft is not");
    assert_eq!(std::fs::read(&path).unwrap(), before);

    drop(guard);
    a.flush_audit().unwrap();
    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(titles(&reopened), ["committed"]);
    assert_eq!(tools(&reopened), ["committed", "pending"]);
    assert_log_intact(&reopened);
}
