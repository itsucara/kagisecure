//! A denial must still be answered as a denial even when the audit entry for it cannot be saved.
//!
//! `Service::denied` (service.rs) writes the audit entry *before* it answers the caller, and the
//! save is best-effort: a disk failure must never turn a refusal into something else, or silently
//! swallow the one piece of evidence a human would ever see of a prompt-injection exfiltration
//! attempt (docs/mcp-server.md §6). This proves both halves of that: the wire response is
//! unaffected by a save failure, and the failure itself is not lost — it surfaces on the `Vault`
//! (`unsaved_audit_entries`, `last_save_error`) for the app to show later.
//!
//! Unix-only, like `kagisecure-core`'s own `audit_durability` tests: the way this file breaks a
//! save (see `break_vault_save`) needs a unix `rename(2)`.
#![cfg(unix)]

mod common;

use common::{REAL_DOTENV, error_code, fixture, with_ui, write_env_file};
use kagisecure_agent::approval::Decision;

/// Replace the vault file with a directory of the same name, so the write path's atomic rename
/// fails. Same technique as `kagisecure-core`'s own `audit_durability` tests, and for the same
/// reason: stripping the containing directory's write bit does not work here, because
/// `write_atomically` best-effort restores that directory to mode `0700` before it writes.
fn break_vault_save(path: &std::path::Path) {
    std::fs::remove_file(path).expect("remove the vault file");
    std::fs::create_dir(path).expect("put a directory in its place");
}

#[test]
fn a_denial_whose_save_fails_is_still_a_denial_and_the_vault_reports_it() {
    let fx = fixture();
    let dir = fx.canonical_project().display().to_string();
    let vault_path = fx.dir.path().join("test.kagivault");

    let unsaved_before = fx
        .handle
        .with(kagisecure_core::Vault::unsaved_audit_entries)
        .expect("vault unlocked");
    assert_eq!(unsaved_before, 0, "fixture starts with nothing unsaved");

    break_vault_save(&vault_path);

    let (reply, seen) = with_ui(&fx.agent, Decision::Deny, || {
        let mut client = fx.client("adversarial-audit-durability");
        client
            .call(&write_env_file(&fx, &dir, REAL_DOTENV, true, 900))
            .expect("call")
    });

    assert!(!seen.is_empty(), "the tool did ask");
    assert_eq!(
        error_code(&reply).as_deref(),
        Some("USER_DENIED"),
        "reply was {reply:?}"
    );

    // The failure did not vanish: it is visible on the vault the app already holds a reference
    // to, for exactly as long as it takes a later save to succeed.
    let (unsaved_after, last_error) = fx
        .handle
        .with(|vault| {
            (
                kagisecure_core::Vault::unsaved_audit_entries(vault),
                kagisecure_core::Vault::last_save_error(vault),
            )
        })
        .expect("vault still unlocked");
    assert!(
        unsaved_after > 0,
        "the denial's audit entry should still be waiting to be saved"
    );
    let message = last_error.expect("a failed save records an error");
    assert!(!message.is_empty());
    assert!(
        !message.contains("USER_DENIED"),
        "the save error must never carry the denial's own detail: {message}"
    );
}
