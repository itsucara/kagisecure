//! `Vault`'s tracking of whether its audit log has actually made it to disk.
//!
//! A denial is the evidence of a prompt-injection exfiltration attempt (vault-format §8's stated
//! purpose for the audit log), and it is queued in memory before a transaction writes it. If every
//! write keeps failing — the data directory goes read-only, the disk fills — that evidence stays
//! only in memory and is gone the moment the vault locks, and every caller that flushes
//! best-effort (see `kagisecure-agent`) swallows the error. `Vault::unsaved_audit_entries` and
//! `Vault::last_save_error` are how a human can still find out.

use kagisecure_core::audit::AuditDraft;
use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::proto::Outcome;
use kagisecure_core::vault::{CreateOptions, Vault};

const PASSWORD: &[u8] = b"correct horse battery staple";

fn cheap_options() -> CreateOptions {
    CreateOptions {
        kdf: KdfParams::new(64, 1, 1).unwrap(),
        vault_name: "Test".to_owned(),
        kdf_hint: Some("test-profile".to_owned()),
    }
}

fn denial_draft() -> AuditDraft {
    AuditDraft {
        actor: "mcp".to_owned(),
        tool: "fill_credential".to_owned(),
        outcome: Outcome::Denied,
        detail: Some("USER_DECLINED".to_owned()),
        ..AuditDraft::default()
    }
}

#[test]
fn opening_a_vault_starts_with_nothing_unsaved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.kagivault");
    let (vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    assert_eq!(vault.unsaved_audit_entries(), 0);
    assert!(vault.last_save_error().is_none());
    drop(vault);

    let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
    assert_eq!(reopened.unsaved_audit_entries(), 0);
    assert!(reopened.last_save_error().is_none());
}

#[test]
fn appending_without_saving_is_visible_as_unsaved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.kagivault");
    let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    assert_eq!(vault.unsaved_audit_entries(), 0);

    vault.queue_audit(denial_draft());
    assert_eq!(vault.unsaved_audit_entries(), 1);

    vault.flush_audit().unwrap();
    assert_eq!(vault.unsaved_audit_entries(), 0);
}

/// The portable, reliable way to make a write fail without root: replace the vault file with a
/// directory of the same name, so the atomic rename at the end of `write_atomically` fails.
///
/// Stripping the containing directory's write bit was the first thing tried here, but
/// `write_atomically` best-effort restores that directory to mode `0700` before it writes a
/// single byte ("an existing directory keeps whatever mode it has" is the comment, but it sets it
/// anyway when the `chmod` itself succeeds), so a permissions trick against a directory this
/// process owns silently heals itself. Renaming a regular file onto an existing directory, by
/// contrast, is refused by every unix `rename(2)` and needs no elevated privilege to set up.
#[test]
#[cfg(unix)]
fn a_write_failure_leaves_the_gap_visible_until_a_write_succeeds() {
    use std::fs;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.kagivault");
    let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap_options()).unwrap();
    let good = fs::read(&path).unwrap();

    vault.queue_audit(denial_draft());
    assert_eq!(vault.unsaved_audit_entries(), 1);
    assert!(vault.last_save_error().is_none());

    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();

    let result = vault.flush_audit();
    assert!(
        result.is_err(),
        "the flush should have failed to rename its temp file onto a directory"
    );
    assert_eq!(
        vault.unsaved_audit_entries(),
        1,
        "the failed write must not be mistaken for a successful one"
    );
    let message = vault
        .last_save_error()
        .expect("a failed write records an error");
    assert!(!message.is_empty());
    // The error is a plain I/O message; it must never carry the denial's own content.
    assert!(!message.contains("USER_DECLINED"));

    // Put the vault file back exactly as it was — a transaction refuses a missing file outright
    // (unlike the old `save`, which recreated one; ADR-0039 §"When the file can no longer be built
    // on") — then prove a successful write clears both.
    fs::remove_dir(&path).unwrap();
    fs::write(&path, &good).unwrap();
    vault.queue_audit(denial_draft());
    assert_eq!(vault.unsaved_audit_entries(), 2);
    vault.flush_audit().unwrap();
    assert_eq!(vault.unsaved_audit_entries(), 0);
    assert!(vault.last_save_error().is_none());
}
