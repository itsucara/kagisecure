//! "Keep this app's version": `Vault::overwrite_with_this_session`, the explicit answer to a vault
//! file that transactions refuse to build on (ADR-0039, user decision 3).
//!
//! Every other write starts from the file and refuses one that went backwards, turned into a
//! different vault, or vanished. These tests pin the one deliberate exception: it only runs
//! against exactly the conflict a person was shown, it writes this session's header and body
//! together, it records what it replaced inside the file it writes, it never drops a pending
//! audit draft, and ordinary transactions work again afterwards.

mod common;

use std::sync::mpsc;
use std::time::Duration;

use common::{PASSWORD, new_vault};
use kagisecure_core::Error;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::model::{Category, Item};
use kagisecure_core::proto::Outcome;
use kagisecure_core::vault::{AUDIT_TOOL_OVERWRITE, FileConflict, Tx, Vault};

const OTHER_PASSWORD: &[u8] = b"a password set only in the restored copy";

fn draft(tool: &str) -> AuditDraft {
    AuditDraft {
        actor: "overwrite-test".to_owned(),
        tool: tool.to_owned(),
        outcome: Outcome::Allowed,
        ..AuditDraft::default()
    }
}

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

fn on_disk(path: &std::path::Path) -> Vault {
    Vault::open_with_password(path, PASSWORD).unwrap()
}

/// `a` writes "kept" and "also kept"; the file is then restored to the copy taken after "kept",
/// and a second writer `b` — which opened that restored copy — adds "only in the file". `a` is
/// left unlocked with a longer history than the file, the file with an item `a` never saw.
fn diverged(dir: &std::path::Path) -> (Vault, Vault, std::path::PathBuf) {
    let (mut a, _code, path) = new_vault(dir);
    a.transact(|tx| {
        add_item_audited(tx, "kept");
        Ok(())
    })
    .unwrap();
    let older = std::fs::read(&path).unwrap();
    a.transact(|tx| {
        add_item_audited(tx, "also kept");
        Ok(())
    })
    .unwrap();

    std::fs::write(&path, &older).unwrap();
    let mut b = Vault::open_with_password(&path, PASSWORD).unwrap();
    b.transact(|tx| {
        add_item_audited(tx, "only in the file");
        Ok(())
    })
    .unwrap();
    (a, b, path)
}

#[test]
fn a_diverged_file_is_overwritten_with_this_sessions_version_and_the_override_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, path) = diverged(dir.path());
    assert!(matches!(
        a.transact(|_| Ok(())),
        Err(Error::VaultDiverged(_))
    ));

    let conflict = a
        .examine_conflict()
        .unwrap()
        .expect("the file is in conflict");
    let FileConflict::Diverged { file_sha256, lost } = &conflict else {
        panic!("expected a diverged file, got {conflict:?}");
    };
    assert_eq!(lost.audit_len, 2, "kept, only in the file");
    assert_eq!(lost.shared_audit_len, 1, "both logs start with `kept`");
    assert_eq!(lost.audit_entries_only_in_file(), 1);
    assert_eq!(lost.items.only_in_file, 1);
    assert_eq!(lost.items.differing, 0);
    assert!(!lost.master_password_differs);
    assert!(!lost.recovery_code_differs);
    assert!(!lost.platform_slot_differs);
    // Examining changes nothing.
    assert_eq!(titles(&a), ["kept", "also kept"]);

    a.overwrite_with_this_session(&conflict, "app", "user chose keep")
        .unwrap();
    assert!(a.last_save_error().is_none());
    assert_eq!(a.unsaved_audit_entries(), 0);
    assert_eq!(a.examine_conflict().unwrap(), None, "no conflict any more");

    // The session's content is what is on disk, and the file's own log says what replaced what.
    let disk = on_disk(&path);
    assert_eq!(titles(&disk), ["kept", "also kept"]);
    assert_eq!(tools(&disk), ["kept", "also kept", AUDIT_TOOL_OVERWRITE]);
    disk.verify_audit().unwrap();
    let entry = disk.audit_entries().last().unwrap();
    assert_eq!(entry.actor, "app");
    assert_eq!(entry.outcome, Outcome::Allowed);
    let detail = entry.detail.as_deref().unwrap();
    let sha_prefix: String = file_sha256[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        detail,
        format!(
            "found=diverged file_sha256={sha_prefix} file_audit_len=2 shared_audit_len=1 \
             session_audit_len=2 device_keys_kept=0 device_keys_retired=0 reason=user chose keep"
        )
    );

    // Later transactions build on it as usual …
    a.transact(|tx| {
        add_item_audited(tx, "after the override");
        Ok(())
    })
    .unwrap();
    let disk = on_disk(&path);
    assert_eq!(titles(&disk), ["kept", "also kept", "after the override"]);
    disk.verify_audit().unwrap();

    // … and to the writer whose version was discarded, the override is itself a file that no
    // longer continues what it saw: it is refused, not silently merged into.
    assert!(matches!(
        b.transact(|_| Ok(())),
        Err(Error::VaultDiverged(_))
    ));
}

#[test]
fn the_sessions_header_is_written_so_a_password_changed_only_in_the_file_stops_working() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, path) = diverged(dir.path());
    let prepared = b.prepare_master_password(OTHER_PASSWORD).unwrap();
    b.transact(|tx| tx.install_master_password(prepared))
        .unwrap();
    assert!(Vault::open_with_password(&path, PASSWORD).is_err());

    let conflict = a.examine_conflict().unwrap().unwrap();
    let FileConflict::Diverged { lost, .. } = &conflict else {
        panic!("expected a diverged file, got {conflict:?}");
    };
    assert!(lost.master_password_differs);
    assert!(!lost.recovery_code_differs);

    a.overwrite_with_this_session(&conflict, "app", "test")
        .unwrap();
    // The password this session knows opens the file again; the one set only in the discarded
    // version does not.
    assert_eq!(titles(&on_disk(&path)), ["kept", "also kept"]);
    assert!(matches!(
        Vault::open_with_password(&path, OTHER_PASSWORD),
        Err(Error::Decrypt)
    ));
}

#[test]
fn a_file_that_became_consistent_again_is_refused_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _code, path) = new_vault(dir.path());
    a.transact(|tx| {
        add_item_audited(tx, "first");
        Ok(())
    })
    .unwrap();
    let older = std::fs::read(&path).unwrap();
    a.transact(|tx| {
        add_item_audited(tx, "second");
        Ok(())
    })
    .unwrap();
    let newest = std::fs::read(&path).unwrap();
    std::fs::write(&path, &older).unwrap();
    let conflict = a.examine_conflict().unwrap().unwrap();

    // Someone puts the newer file back before the person confirms.
    std::fs::write(&path, &newest).unwrap();
    assert_eq!(a.examine_conflict().unwrap(), None);
    assert!(matches!(
        a.overwrite_with_this_session(&conflict, "app", "test"),
        Err(Error::VaultNotInConflict(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), newest, "not rewritten");

    // A forward continuation written by another process is not a conflict either: it merges.
    let mut other = Vault::open_with_password(&path, PASSWORD).unwrap();
    other
        .transact(|tx| {
            add_item_audited(tx, "from elsewhere");
            Ok(())
        })
        .unwrap();
    let continued = std::fs::read(&path).unwrap();
    assert!(matches!(
        a.overwrite_with_this_session(&conflict, "app", "test"),
        Err(Error::VaultNotInConflict(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), continued);
    a.transact(|_| Ok(())).unwrap();
    assert_eq!(titles(&a), ["first", "second", "from elsewhere"]);
}

#[test]
fn a_file_that_changed_again_after_it_was_examined_is_refused_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, path) = diverged(dir.path());
    let shown = a.examine_conflict().unwrap().unwrap();

    // The diverged file moves on after the person was shown what it held.
    b.transact(|tx| {
        add_item_audited(tx, "added after the confirmation");
        Ok(())
    })
    .unwrap();
    let current = std::fs::read(&path).unwrap();

    assert!(matches!(
        a.overwrite_with_this_session(&shown, "app", "test"),
        Err(Error::VaultConflict(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), current, "not rewritten");

    // Asking again, with what the file holds now, goes through.
    let now = a.examine_conflict().unwrap().unwrap();
    assert_ne!(now, shown);
    a.overwrite_with_this_session(&now, "app", "test").unwrap();
    assert_eq!(titles(&on_disk(&path)), ["kept", "also kept"]);
}

#[test]
fn a_concurrent_writer_holding_the_lock_makes_the_overwrite_busy() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _b, path) = diverged(dir.path());
    a.queue_audit(draft("pending"));
    let conflict = a.examine_conflict().unwrap().unwrap();
    a.set_lock_timeout(Duration::from_millis(150));
    let holder = Vault::open_with_password(&path, PASSWORD).unwrap();

    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    std::thread::scope(|scope| {
        let holding = scope.spawn(move || {
            let mut holder = holder;
            holder.transact(|_| {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
        });
        held_rx.recv().unwrap();
        let before = std::fs::read(&path).unwrap();

        let busy = a.overwrite_with_this_session(&conflict, "app", "test");
        assert!(matches!(busy, Err(Error::VaultBusy { .. })), "{busy:?}");
        assert_eq!(std::fs::read(&path).unwrap(), before, "nothing was written");
        assert!(a.last_save_error().unwrap().contains("gave up waiting"));
        assert_eq!(a.unsaved_audit_entries(), 1, "the draft is still pending");
        assert_eq!(tools(&a), ["kept", "also kept"]);

        release_tx.send(()).unwrap();
        holding.join().unwrap().unwrap();
    });

    // The holder's commit changed the file, so the conflict must be looked at again first.
    assert!(matches!(
        a.overwrite_with_this_session(&conflict, "app", "test"),
        Err(Error::VaultConflict(_))
    ));
    let now = a.examine_conflict().unwrap().unwrap();
    a.overwrite_with_this_session(&now, "app", "test").unwrap();
    assert_eq!(
        tools(&on_disk(&path)),
        ["kept", "also kept", "pending", AUDIT_TOOL_OVERWRITE]
    );
}

#[test]
fn pending_drafts_are_written_by_the_overwrite_never_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _b, path) = diverged(dir.path());
    // Queued before and after a transaction the conflict refuses — which runs no closure, and
    // keeps what was pending exactly as it was.
    a.queue_audit(draft("queued"));
    let refused = a.transact(|tx| {
        tx.queue_audit(draft("never queued: the closure does not run"));
        Ok(())
    });
    assert!(matches!(refused, Err(Error::VaultDiverged(_))));
    assert_eq!(a.unsaved_audit_entries(), 1);
    a.queue_audit(draft("queued later"));
    assert_eq!(a.unsaved_audit_entries(), 2);

    let conflict = a.examine_conflict().unwrap().unwrap();
    a.overwrite_with_this_session(&conflict, "app", "test")
        .unwrap();

    assert_eq!(a.unsaved_audit_entries(), 0);
    let disk = on_disk(&path);
    assert_eq!(
        tools(&disk),
        [
            "kept",
            "also kept",
            "queued",
            "queued later",
            AUDIT_TOOL_OVERWRITE
        ],
        "every pending draft is in the file, in order, before the override's own entry"
    );
    disk.verify_audit().unwrap();
    assert!(
        disk.audit_entries()
            .last()
            .unwrap()
            .detail
            .as_deref()
            .unwrap()
            .contains("session_audit_len=4")
    );
}

#[test]
fn a_vanished_file_is_recreated_only_by_the_explicit_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _code, path) = new_vault(dir.path());
    a.transact(|tx| {
        add_item_audited(tx, "survivor");
        Ok(())
    })
    .unwrap();
    std::fs::remove_file(&path).unwrap();

    assert!(matches!(
        a.transact(|_| Ok(())),
        Err(Error::VaultNotFound(_))
    ));
    assert!(!path.exists(), "an ordinary write never recreates it");

    let conflict = a.examine_conflict().unwrap().unwrap();
    assert_eq!(conflict, FileConflict::Missing);
    a.overwrite_with_this_session(&conflict, "app", "test")
        .unwrap();

    let disk = on_disk(&path);
    assert_eq!(titles(&disk), ["survivor"]);
    let detail = disk.audit_entries().last().unwrap().detail.clone().unwrap();
    assert!(detail.starts_with("found=missing file_sha256=none file_audit_len=0"));
    a.transact(|_| Ok(())).unwrap();
}

#[test]
fn a_different_vault_or_an_unreadable_file_is_overwritten_only_as_examined() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, _code, path) = new_vault(dir.path());
    a.transact(|tx| {
        add_item_audited(tx, "mine");
        Ok(())
    })
    .unwrap();

    let elsewhere = tempfile::tempdir().unwrap();
    let (_other, _other_code, other_path) = new_vault(elsewhere.path());
    std::fs::copy(&other_path, &path).unwrap();
    let replaced = a.examine_conflict().unwrap().unwrap();
    assert!(
        matches!(replaced, FileConflict::Replaced { .. }),
        "{replaced:?}"
    );

    std::fs::write(&path, b"not a vault at all").unwrap();
    let unreadable = a.examine_conflict().unwrap().unwrap();
    assert!(
        matches!(unreadable, FileConflict::Unreadable { .. }),
        "{unreadable:?}"
    );
    // What the person was shown was the other vault, not this: refused.
    assert!(matches!(
        a.overwrite_with_this_session(&replaced, "app", "test"),
        Err(Error::VaultConflict(_))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"not a vault at all");

    a.overwrite_with_this_session(&unreadable, "app", "test")
        .unwrap();
    let disk = on_disk(&path);
    assert_eq!(titles(&disk), ["mine"]);
    assert!(
        disk.audit_entries()
            .last()
            .unwrap()
            .detail
            .as_deref()
            .unwrap()
            .starts_with("found=unreadable")
    );
}

// There used to be a test here (`the_overwrite_is_refused_from_inside_a_transaction`) proving that
// `overwrite_with_this_session`, called through `Tx` from inside a running transaction, refuses
// with `Error::NestedTransaction` at runtime. `Tx` no longer has a `DerefMut`, so
// `overwrite_with_this_session` — a `&mut Vault` method — is not reachable through `tx` at all any
// more: `tx.overwrite_with_this_session(...)` is `error[E0599]: no method named
// 'overwrite_with_this_session' found for mutable reference '&mut Tx<'_>'`. What was a runtime
// check this test exercised is now a compile error nothing can write in the first place; see the
// `compile_fail` doctest on `kagisecure_core::vault::Tx`'s own documentation.
