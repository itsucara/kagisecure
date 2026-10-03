//! Audit before release: the one path by which a value leaves the vault for an agent.
//!
//! # The rule
//!
//! A *release* — a `.env` file written, a child process started with an environment in it — is
//! the moment a secret stops being under the vault's control. Such a moment is recorded **before**
//! it happens: an `Allowed` audit entry describing it is written to the vault file, and only once
//! that write has succeeded does anything leave. An `Allowed` entry therefore means "authorized,
//! and committed to be released"; there is never a release the log does not show, whatever
//! happens afterwards — a crash, a full disk, a lock.
//!
//! When the entry cannot be written — the disk is full, the file is broken or in conflict with
//! this session, another process holds the write lock past the wait — the release does not happen
//! at all (*fail closed*): the caller answers `AUDIT_UNAVAILABLE`, and a `Failed` entry with
//! detail `AUDIT_UNAVAILABLE` is queued for the next write that succeeds, so the refusal itself is
//! not lost either.
//!
//! When the release was committed but then failed or ended abnormally — the file could not be
//! written, the program could not be started, the child was killed at its timeout — a second
//! entry follows: outcome `Failed`, the same tool, lease, target and variable names, and detail
//! `"<CODE> (entry <seq>)"` naming the `Allowed` entry it completes. That one is best-effort
//! ([`VaultHandle::record_best_effort`]): the release has already happened or already failed, and
//! a write problem must not change what the caller is told about it.
//!
//! # How the order is enforced
//!
//! Not by convention: [`audited_release`] is the only function here, and it runs its two closures
//! in two phases the caller cannot interleave.
//!
//! 1. `prepare` runs inside one transaction ([`VaultHandle::transact`], so on the file as it is on
//!    disk at that moment, under the file lock). It re-checks everything that decides the release
//!    — the target still exists and is still visible to agents — and resolves what is to be
//!    released into zeroize-on-drop buffers. The `Allowed` entry is appended in the same
//!    transaction, and the transaction's commit is the write that makes it durable.
//! 2. `act` is called with what `prepare` returned, plus the `seq` of the `Allowed` entry that was
//!    just committed, only if that transaction committed, and only after
//!    [`VaultHandle::transact`] has returned — by which point this handle's mutex and the vault's
//!    file lock have both been released. A command that runs for an hour holds up neither another
//!    request nor another process's write. The `seq` lets `act` register whatever it started
//!    (concretely: a spawned child) against that same number, so that something outside this call
//!    entirely — a vault lock racing the child's own run — can later record a `Failed` follow-up
//!    that names the right `Allowed` entry without needing this call still on the stack to ask.
//!
//! The types close the remaining ways round:
//!
//! * `act` receives the payload `R` and nothing else, and `R: 'static`. A [`Tx`], a `&Vault` and a
//!   [`MutexGuard`](std::sync::MutexGuard) on the handle all borrow something that lives shorter
//!   than `'static`, so the payload can be none of them and contain none of them.
//! * `act` is `'static` too, so it cannot have captured such a borrow from the caller either.
//! * No payload reaches `act` except through a committed transaction: the payload exists only as
//!   `prepare`'s return value, which this module holds until the commit has succeeded.
//!
//! ```compile_fail
//! # use std::time::Duration;
//! # use kagisecure_agent::release::{Acted, audited_release};
//! # use kagisecure_core::audit::AuditDraft;
//! // A payload that borrows the vault the transaction holds: refused, because `R: 'static`.
//! fn borrow_the_vault(handle: &kagisecure_agent::VaultHandle) {
//!     let _ = audited_release(
//!         handle,
//!         Duration::from_secs(1),
//!         AuditDraft::default(),
//!         |tx| Ok::<_, ()>(tx.path()),
//!         |path, _seq| Acted::done(path.to_path_buf()),
//!     );
//! }
//! ```
//!
//! ```compile_fail
//! # use std::time::Duration;
//! # use kagisecure_agent::release::{Acted, audited_release};
//! # use kagisecure_core::audit::AuditDraft;
//! // An act that holds the handle's guard: refused, because `act: 'static`.
//! fn hold_the_guard(handle: &kagisecure_agent::VaultHandle) {
//!     let guard = handle.guard();
//!     let _ = audited_release(
//!         handle,
//!         Duration::from_secs(1),
//!         AuditDraft::default(),
//!         |_tx| Ok::<_, ()>(()),
//!         move |(), _seq| Acted::done(guard.is_some()),
//!     );
//! }
//! ```
//!
//! The same call with owned data compiles — which is what keeps the two blocks above honest about
//! *why* they fail:
//!
//! ```no_run
//! # use std::time::Duration;
//! # use kagisecure_agent::release::{Acted, audited_release};
//! # use kagisecure_core::audit::AuditDraft;
//! fn owned(handle: &kagisecure_agent::VaultHandle) {
//!     let _ = audited_release(
//!         handle,
//!         Duration::from_secs(1),
//!         AuditDraft::default(),
//!         |tx| Ok::<_, ()>(tx.path().to_path_buf()),
//!         |path, _seq| Acted::done(path),
//!     );
//! }
//! ```

use std::time::Duration;

use kagisecure_core::audit::AuditDraft;
use kagisecure_core::proto::Outcome;
use kagisecure_core::vault::Tx;

use crate::vault::VaultHandle;

/// The detail of the `Failed` entry queued when a release is refused because its `Allowed` entry
/// could not be written — the same spelling as the error code the caller answers with, on both
/// the MCP and the browser-extension protocol.
pub const AUDIT_UNAVAILABLE: &str = "AUDIT_UNAVAILABLE";

/// What `act` reports back to [`audited_release`]: the caller's value, and whether the release
/// failed or ended abnormally.
#[derive(Debug)]
pub struct Acted<T> {
    value: T,
    abnormal: Option<&'static str>,
}

impl<T> Acted<T> {
    /// The release happened as authorized.
    pub fn done(value: T) -> Self {
        Self {
            value,
            abnormal: None,
        }
    }

    /// The release failed, or ended abnormally, for the reason `code` — a short machine-readable
    /// spelling such as `WRITE_FAILED`, `SPAWN_FAILED` or `TIMED_OUT`. A `Failed` entry with detail
    /// `"<code> (entry <seq>)"` is recorded after it.
    pub fn abnormal(code: &'static str, value: T) -> Self {
        Self {
            value,
            abnormal: Some(code),
        }
    }
}

/// A release that was committed to the audit log and then acted on.
#[derive(Debug)]
pub struct Released<T> {
    /// What `act` returned.
    pub value: T,
    /// The `seq` of the `Allowed` entry that authorized it.
    pub entry_seq: u64,
}

/// Why nothing was released. In every case nothing left the vault and `act` never ran.
#[derive(Debug)]
pub enum NotReleased<E> {
    /// The vault was locked.
    Locked,
    /// `prepare` refused, for the caller's own reason. The transaction was rolled back and
    /// nothing was recorded here; recording the refusal is the caller's business.
    Refused(E),
    /// The `Allowed` entry could not be written. A `Failed` entry with detail
    /// [`AUDIT_UNAVAILABLE`] has been queued for the next write that succeeds.
    AuditUnavailable(kagisecure_core::Error),
}

/// Release something only once the audit entry describing it is on disk.
///
/// * `entry` describes the release — tool, actor, client pid, environment or item, variable
///   names, target, lease — and, optionally, a `detail` saying how the release was authorized
///   (a browser fill's `FILL_APPROVED`, `FILL_CONFIRMED` or `FILL_USERNAME_ONLY`; the MCP tools
///   pass none). Its `outcome` is ignored: the entry is written as `Allowed`, and any follow-up
///   as `Failed`, whose `detail` replaces this one.
/// * `prepare` runs inside one transaction on the file as it is now. It re-checks whatever
///   decides the release and returns what `act` needs (the resolved values, in
///   zeroize-on-drop buffers). An `Err` rolls the transaction back and is returned as
///   [`NotReleased::Refused`]. It must be quick and must not wait on anything: the vault's file
///   lock is held while it runs.
/// * `act` performs the release, after the commit and with no lock held (see the module
///   documentation for why it cannot do otherwise), and is also handed the `seq` of the `Allowed`
///   entry that authorized it — the same number [`Released::entry_seq`] carries back to the
///   caller, just available before `act` returns rather than only after.
///
/// `wait` bounds how long the transaction and a follow-up entry wait for another writer.
///
/// # Errors
///
/// [`NotReleased`]: in each case `act` did not run.
pub fn audited_release<R, T, E>(
    handle: &VaultHandle,
    wait: Duration,
    entry: AuditDraft,
    prepare: impl FnOnce(&mut Tx<'_>) -> Result<R, E>,
    act: impl FnOnce(R, u64) -> Acted<T> + 'static,
) -> Result<Released<T>, NotReleased<E>>
where
    R: 'static,
{
    let Authorized { payload, entry_seq } = authorize(handle, wait, &entry, prepare)?;
    let Acted { value, abnormal } = act(payload, entry_seq);
    if let Some(code) = abnormal {
        let _ = handle.record_best_effort(wait, follow_up(&entry, code, entry_seq));
    }
    Ok(Released { value, entry_seq })
}

/// The `Failed` entry that records a release refused for want of an audit write: `entry`, with
/// detail [`AUDIT_UNAVAILABLE`]. Queue it ([`VaultHandle::queue_audit`]) rather than write it —
/// a write just failed.
#[must_use]
pub fn unavailable_entry(entry: &AuditDraft) -> AuditDraft {
    AuditDraft {
        outcome: Outcome::Failed,
        detail: Some(AUDIT_UNAVAILABLE.to_owned()),
        ..entry.clone()
    }
}

/// `prepare`'s payload, and the `Allowed` entry it was committed under. Only [`authorize`] makes
/// one, and only from a committed transaction.
struct Authorized<R> {
    payload: R,
    entry_seq: u64,
}

/// Phase one: `prepare` and the `Allowed` entry, as one transaction.
///
/// Returns only after [`VaultHandle::transact`] has — so, on `Ok`, with the entry durable, the
/// handle's mutex released and the file lock released.
fn authorize<R, E>(
    handle: &VaultHandle,
    wait: Duration,
    entry: &AuditDraft,
    prepare: impl FnOnce(&mut Tx<'_>) -> Result<R, E>,
) -> Result<Authorized<R>, NotReleased<E>> {
    let mut refused = None;
    let committed = handle.transact(wait, |tx| {
        let payload = match prepare(tx) {
            Ok(payload) => payload,
            Err(reason) => {
                refused = Some(reason);
                return Err(kagisecure_core::Error::TransactionAborted);
            }
        };
        tx.append_audit(AuditDraft {
            outcome: Outcome::Allowed,
            ..entry.clone()
        });
        // The closure's own entry keeps its position at commit: drafts pending from earlier were
        // chained before the closure ran, and anything queued meanwhile is chained after it.
        let entry_seq = tx
            .audit_entries()
            .last()
            .map(|e| e.seq)
            .ok_or(kagisecure_core::Error::TransactionAborted)?;
        Ok(Authorized { payload, entry_seq })
    });
    match committed {
        None => Err(NotReleased::Locked),
        Some(Ok(authorized)) => Ok(authorized),
        Some(Err(error)) => match refused {
            Some(reason) => Err(NotReleased::Refused(reason)),
            None => {
                eprintln!(
                    "kagisecure: a release was refused because its audit entry could not be \
                     written: {error}"
                );
                let _ = handle.queue_audit(unavailable_entry(entry));
                Err(NotReleased::AuditUnavailable(error))
            }
        },
    }
}

/// The entry that completes `entry_seq` when its release failed or ended abnormally: `entry`,
/// outcome `Failed`, detail `"<code> (entry <seq>)"`.
///
/// [`audited_release`] records it itself when `act` reports [`Acted::abnormal`]. It is public for
/// the one release whose last step cannot be inside `act`: a browser fill, whose value leaves in
/// the reply frame the connection loop writes after the request has been answered — the
/// connection is borrowed by that loop, and `act` must be `'static`. That caller records this
/// entry, best-effort, when the frame cannot be written.
#[must_use]
pub fn follow_up(entry: &AuditDraft, code: &str, entry_seq: u64) -> AuditDraft {
    AuditDraft {
        outcome: Outcome::Failed,
        detail: Some(format!("{code} (entry {entry_seq})")),
        ..entry.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use kagisecure_core::Vault;
    use kagisecure_core::proto::LeaseId;

    use super::*;

    fn scratch() -> (tempfile::TempDir, Arc<VaultHandle>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.kagivault");
        let mut options = kagisecure_core::vault::CreateOptions::new().expect("options");
        options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(
            kagisecure_core::crypto::kdf::MIN_M_KIB,
            kagisecure_core::crypto::kdf::MIN_T,
            1,
        )
        .expect("kdf");
        let (vault, _code) = Vault::create(&path, b"pw", &options).expect("create");
        (dir, VaultHandle::new(vault))
    }

    fn entry() -> AuditDraft {
        AuditDraft {
            actor: "mcp".to_owned(),
            tool: "run_with_env".to_owned(),
            lease_id: Some(LeaseId::new()),
            variables: vec!["TOKEN".to_owned()],
            target_path: Some("/tmp/project".to_owned()),
            ..AuditDraft::default()
        }
    }

    fn on_disk(handle: &VaultHandle) -> Vec<kagisecure_core::audit::AuditEntry> {
        let path = handle.with(|v| v.path().to_path_buf()).expect("unlocked");
        Vault::open_with_password(&path, b"pw")
            .expect("reopen")
            .audit_entries()
            .to_vec()
    }

    #[test]
    fn act_sees_the_allowed_entry_already_on_disk_and_no_lock_held() {
        let (_dir, handle) = scratch();
        let observer = Arc::clone(&handle);
        let released = audited_release(
            &handle,
            Duration::from_secs(1),
            entry(),
            |_tx| Ok::<_, ()>(()),
            move |(), _seq| {
                // The handle's mutex is free: this would deadlock if act ran inside the
                // transaction.
                let unlocked = observer.is_unlocked();
                Acted::done((unlocked, on_disk(&observer)))
            },
        )
        .expect("released");
        let (unlocked, seen) = released.value;
        assert!(unlocked);
        let last = seen.last().expect("an entry");
        assert_eq!(last.seq, released.entry_seq);
        assert_eq!(last.outcome, Outcome::Allowed);
        assert_eq!(last.tool, "run_with_env");
    }

    #[test]
    fn an_abnormal_end_is_completed_by_a_failed_entry_naming_the_allowed_one() {
        let (_dir, handle) = scratch();
        let described = entry();
        let released = audited_release(
            &handle,
            Duration::from_secs(1),
            described.clone(),
            |_tx| Ok::<_, ()>(()),
            |(), _seq| Acted::abnormal("SPAWN_FAILED", ()),
        )
        .expect("released");
        let entries = on_disk(&handle);
        let last = entries.last().expect("an entry");
        assert_eq!(last.outcome, Outcome::Failed);
        assert_eq!(
            last.detail.as_deref(),
            Some(format!("SPAWN_FAILED (entry {})", released.entry_seq).as_str())
        );
        assert_eq!(last.lease_id, described.lease_id);
        assert_eq!(last.variables, described.variables);
        assert_eq!(last.target_path, described.target_path);
        let allowed = &entries[usize::try_from(released.entry_seq).expect("seq")];
        assert_eq!(allowed.outcome, Outcome::Allowed);
        assert_eq!(allowed.lease_id, described.lease_id);
    }

    #[test]
    fn a_refusal_rolls_back_writes_nothing_and_never_acts() {
        let (_dir, handle) = scratch();
        let before = on_disk(&handle).len();
        let acted = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&acted);
        let refused = audited_release(
            &handle,
            Duration::from_secs(1),
            entry(),
            |tx| {
                tx.append_audit(AuditDraft {
                    tool: "inside".to_owned(),
                    ..AuditDraft::default()
                });
                Err::<(), _>("hidden")
            },
            move |(), _seq| {
                flag.store(true, Ordering::SeqCst);
                Acted::done(())
            },
        );
        assert!(matches!(refused, Err(NotReleased::Refused("hidden"))));
        assert!(!acted.load(Ordering::SeqCst));
        assert_eq!(on_disk(&handle).len(), before);
        assert_eq!(handle.with(Vault::unsaved_audit_entries), Some(0));
    }

    /// Unix-only: the save is broken by putting a directory where the vault file was, which needs
    /// a unix `rename(2)` to fail the way a full disk would.
    #[test]
    #[cfg(unix)]
    fn an_entry_that_cannot_be_written_releases_nothing_and_queues_the_refusal() {
        let (_dir, handle) = scratch();
        let path = handle.with(|v| v.path().to_path_buf()).expect("unlocked");
        let original = std::fs::read(&path).expect("read");
        std::fs::remove_file(&path).expect("remove");
        std::fs::create_dir(&path).expect("a directory in its place");

        let acted = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&acted);
        let outcome = audited_release(
            &handle,
            Duration::from_secs(1),
            entry(),
            |_tx| Ok::<_, ()>(()),
            move |(), _seq| {
                flag.store(true, Ordering::SeqCst);
                Acted::done(())
            },
        );
        assert!(matches!(outcome, Err(NotReleased::AuditUnavailable(_))));
        assert!(!acted.load(Ordering::SeqCst), "nothing may be released");
        assert_eq!(handle.with(Vault::unsaved_audit_entries), Some(1));

        std::fs::remove_dir(&path).expect("remove the directory");
        std::fs::write(&path, original).expect("put the file back");
        handle
            .flush(Duration::from_secs(1))
            .expect("unlocked")
            .expect("flushed");
        let last = on_disk(&handle).pop().expect("an entry");
        assert_eq!(last.outcome, Outcome::Failed);
        assert_eq!(last.detail.as_deref(), Some(AUDIT_UNAVAILABLE));
        assert_eq!(last.tool, "run_with_env");
        assert!(
            !on_disk(&handle)
                .iter()
                .any(|e| e.outcome == Outcome::Allowed && e.tool == "run_with_env"),
            "the Allowed entry was never committed"
        );
    }

    #[test]
    fn a_locked_vault_releases_nothing() {
        let (_dir, handle) = scratch();
        drop(handle.take());
        let outcome = audited_release(
            &handle,
            Duration::from_secs(1),
            entry(),
            |_tx| Ok::<_, ()>(()),
            |(), _seq| Acted::done(()),
        );
        assert!(matches!(outcome, Err(NotReleased::Locked)));
    }
}
