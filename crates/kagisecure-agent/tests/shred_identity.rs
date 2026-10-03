//! Shredding destroys only the file kagisecure wrote, never whatever the path names now.
//!
//! `revoke_env_file` needs no approval and a vault lock shreds every file in the written ledger,
//! so the ledger is the whole authorization for destroying bytes. It used to be a list of *paths*:
//! swap the approved `.env` for a symlink to something valuable after the write, and the next
//! revoke — or the user pressing Lock — zeroed and unlinked through the symlink. The ledger now
//! records the identity of the file that was written, and the shredder opens the path without
//! following a final symlink and refuses anything that is not that same regular file.
//!
//! Unix-only: creating a symlink needs no privilege there, which is what makes the swap cheap
//! enough to be the attack.
#![cfg(unix)]

mod common;

use common::{REAL_DOTENV, fixture, with_ui, write_env_file};
use kagisecure_agent::approval::Decision;
use kagisecure_core::vault::Vault;
use kagisecure_ipc::protocol::{Request, Response};

const VICTIM: &[u8] = b"ssh-ed25519 AAAA the user's own key, not kagisecure's\n";

/// Write `.env` with an "Allow once" approval, then replace it with a symlink to a victim file in
/// the same project. Returns (the `.env` path, the victim path).
fn written_then_swapped(fx: &common::Fixture) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = fx.canonical_project();
    let target = dir.join(REAL_DOTENV);
    let victim = fx.dir.path().join("victim_key");
    std::fs::write(&victim, VICTIM).expect("victim");

    let (reply, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        fx.client("shred-identity")
            .call(&write_env_file(
                fx,
                &dir.display().to_string(),
                REAL_DOTENV,
                false,
                900,
            ))
            .expect("call")
    });
    assert_eq!(seen.len(), 1);
    assert!(
        matches!(reply, Response::WroteEnvFile { .. }),
        "precondition: {reply:?}"
    );

    std::fs::remove_file(&target).expect("remove the written file");
    std::os::unix::fs::symlink(&victim, &target).expect("plant the symlink");
    (target, victim)
}

fn audit_details(fx: &common::Fixture) -> Vec<(String, Option<String>)> {
    let path = fx.dir.path().join("test.kagivault");
    Vault::open_with_password(&path, b"pw")
        .expect("open")
        .audit_entries()
        .iter()
        .map(|e| (e.tool.clone(), e.detail.clone()))
        .collect()
}

#[test]
fn revoking_by_path_does_not_shred_through_a_symlink_planted_after_the_write() {
    let fx = fixture();
    let (target, victim) = written_then_swapped(&fx);

    let reply = fx
        .client("shred-identity")
        .call(&Request::RevokeEnvFile {
            lease_id: None,
            path: Some(target.display().to_string()),
        })
        .expect("call");
    match reply {
        Response::Revoked { shredded } => assert!(
            shredded.is_empty(),
            "nothing kagisecure wrote is at that path any more: {shredded:?}"
        ),
        other => panic!("revoking is cleanup and must not fail: {other:?}"),
    }
    assert_eq!(
        std::fs::read(&victim).expect("the victim must still be there"),
        VICTIM,
        "the victim's bytes must be untouched"
    );
    assert!(
        audit_details(&fx).iter().any(|(tool, detail)| {
            tool == "revoke_env_file" && detail.as_deref() == Some("NOT_SHREDDED_FILE_REPLACED")
        }),
        "the skipped shred is recorded: {:?}",
        audit_details(&fx)
    );
}

#[test]
fn locking_does_not_shred_through_a_symlink_planted_after_the_write() {
    let fx = fixture();
    let (_target, victim) = written_then_swapped(&fx);

    drop(fx.handle.take());

    assert_eq!(
        std::fs::read(&victim).expect("the victim must still be there"),
        VICTIM,
        "a lock must not zero the victim"
    );
    assert!(
        audit_details(&fx).iter().any(|(tool, detail)| {
            tool == "lock" && detail.as_deref() == Some("NOT_SHREDDED_FILE_REPLACED")
        }),
        "the skipped shred is recorded on the vault before it is gone: {:?}",
        audit_details(&fx)
    );
}

#[test]
fn a_file_replaced_in_place_by_a_different_regular_file_is_not_shredded_either() {
    let fx = fixture();
    let dir = fx.canonical_project();
    let target = dir.join(REAL_DOTENV);
    let (_, seen) = with_ui(&fx.agent, Decision::AllowOnce, || {
        fx.client("shred-identity")
            .call(&write_env_file(
                &fx,
                &dir.display().to_string(),
                REAL_DOTENV,
                false,
                900,
            ))
            .expect("call")
    });
    assert_eq!(seen.len(), 1);

    // A different file renamed over the one kagisecure wrote: both exist at once before the
    // rename, so they are guaranteed distinct inodes.
    let replacement = dir.join("user-owned.tmp");
    std::fs::write(&replacement, VICTIM).expect("replacement");
    std::fs::rename(&replacement, &target).expect("rename over");

    drop(fx.handle.take());

    assert_eq!(
        std::fs::read(&target).expect("the user's file must still be there"),
        VICTIM
    );
}
