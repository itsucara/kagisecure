//! The shared, lockable owner of an unlocked vault.
//!
//! Two things need the vault at once: the UI (item CRUD, through `kagisecure-ffi`) and the agent
//! service (metadata queries and injections, driven by the IPC listener). They are in the same
//! process and the same trust domain, so they share one [`kagisecure_core::Vault`] behind one
//! mutex rather than opening the file twice.
//!
//! # Lock is `take`, not a flag
//!
//! [`VaultHandle::take`] moves the [`Vault`] out and hands it to the caller, who drops it. The
//! core zeroizes the vault key on drop, so "locked" is the absence of the key rather than a
//! boolean somebody could forget to check: every accessor here goes through an `Option`, and a
//! `None` is a `VAULT_LOCKED` for the agent and a locked root view for the app.
//!
//! # The lock hook
//!
//! An agent that is mid-approval when the user hits ⌘\ must not be able to complete. `take` runs
//! a hook — registered by [`crate::Agent`] when it starts — *after* the vault is gone, and that
//! hook revokes every lease, shreds every file written under one, and denies every pending
//! approval. The hook is a plain `Fn` held by the handle and holds only a `Weak` back to the
//! agent, so the two do not keep each other alive.
//!
//! More than one subsystem registers one — the MCP agent and the browser-extension listener both
//! need their own leases emptied on a lock, and neither is the other's business. Registering
//! returns a [`LockHookGuard`]: dropping it deregisters exactly that hook, by an id nobody else's
//! guard carries, and nothing else. There is deliberately no way to reach *in* and clear another
//! caller's hook — only its own guard can retire a hook, which is what keeps `Agent::stop()`
//! retiring its own hook from also silencing the extension's.
//!
//! # Other processes write the same file
//!
//! The CLI and a second app instance write the vault file too (core's `vault` module documents
//! how). So this handle's [`Vault`] is only as current as its last read, and every write it makes
//! goes through a transaction that starts from the file as it is on disk:
//!
//! * [`VaultHandle::sync`] brings memory up to date with the file. The agent and the extension
//!   call it at the start of every request, so a change another process made — an
//!   `agent-access --deny`, a deleted item — takes effect on the very next request.
//! * [`VaultHandle::transact`] runs a mutation as one transaction; every read that decides the
//!   mutation belongs inside its closure.
//! * [`VaultHandle::record_best_effort`] records an audit entry that must never change the
//!   caller's reply and must never be lost: it is queued first and then written, and a write that
//!   fails leaves it queued for the next successful write.
//!
//! **Lock order** is always this handle's mutex first, then the vault's file lock (taken inside
//! [`Vault::transact`]). The file lock is held only for the closure plus one write — never across
//! an approval sheet, a prompt, an Argon2id derivation or a child process. A release acts (writes
//! the `.env`, runs the child) only after both this mutex and the file lock are released
//! ([`crate::release`]), so a long-running command blocks neither this process's other requests
//! nor another writer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use kagisecure_core::Vault;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::vault::Tx;

/// How long an agent or browser-extension request waits for another process's write before it
/// gives up with [`kagisecure_core::Error::VaultBusy`].
///
/// A request is answered to a program, not to a person watching a spinner, so it can afford to
/// wait out a slow writer; beyond this, the holder is stuck rather than slow.
pub const REQUEST_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// What runs when the vault is taken out of the handle.
pub type LockHook = Box<dyn Fn() + Send + Sync>;

/// What runs when the vault is taken out of the handle, with mutable access to the vault itself,
/// a moment before it is returned to the caller and dropped.
///
/// [`LockHook`] runs after the vault is gone from the handle — deliberately, so nothing it does
/// can be mistaken for still being served — which is exactly why it cannot record anything durable
/// on that vault, since by the time it runs there is no vault left to reach through the handle.
/// A hook that needs to *write* something as part of locking (queue an audit entry describing
/// something the lock itself just did, not something a request in flight did) needs the vault
/// while it still exists: this is that hook, and [`VaultHandle::take`] runs it with the vault
/// still there, immediately before its own final [`Vault::flush_audit`] — so whatever this queues
/// rides out on that same last write, best-effort, like everything else queued and never lost
/// enough to be worth failing a lock over.
pub type VaultLockHook = Box<dyn Fn(&mut Vault) + Send + Sync>;

/// Identifies one registered hook within whichever slot holds it, so that slot can drop *that*
/// entry and no other. Never exposed on its own — only inside a [`LockHookGuard`].
type HookId = u64;

/// Which of [`VaultHandle`]'s two hook lists a [`LockHookGuard`] belongs to.
#[derive(Clone, Copy)]
enum HookSlot {
    /// [`VaultHandle::add_lock_hook`]'s list.
    Extra,
    /// [`VaultHandle::add_vault_lock_hook`]'s list.
    Vault,
}

/// A token for one hook registered with [`VaultHandle::add_lock_hook`] or
/// [`VaultHandle::add_vault_lock_hook`].
///
/// Dropping it deregisters exactly the hook it was returned for — by an id no other guard
/// carries — and nothing else, however many other subsystems have hooks of their own registered
/// at the time. There is no method on [`VaultHandle`] that removes a hook by any means other than
/// dropping the guard that registration handed back, which is what makes it impossible for one
/// caller to clear another's: nobody but the guard's owner has the id it carries.
///
/// Holds only a [`Weak`] reference back to the handle — the same discipline the hook closures
/// themselves already follow (see the module doc comment) — so holding a guard never keeps the
/// vault handle itself alive, and a handle already dropped simply makes deregistering a no-op.
///
/// A caller that wants its hook to keep running keeps this guard alive alongside whatever else it
/// owns, exactly as [`crate::Agent`] and [`crate::ExtensionAgent`] do; dropping it early — on an
/// explicit `stop()`, say — retires the hook immediately without disturbing anyone else's.
#[must_use = "the hook is deregistered as soon as this is dropped; keep it alive for as long as \
              the hook should run"]
pub struct LockHookGuard {
    handle: Weak<VaultHandle>,
    id: HookId,
    slot: HookSlot,
}

impl std::fmt::Debug for LockHookGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockHookGuard").finish_non_exhaustive()
    }
}

impl Drop for LockHookGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.upgrade() {
            handle.deregister(self.id, self.slot);
        }
    }
}

/// A vault that may or may not currently be unlocked, shared by the UI and the agent.
pub struct VaultHandle {
    vault: Mutex<Option<Vault>>,
    /// Hooks appended by [`VaultHandle::add_lock_hook`]: one entry per registration, each
    /// removable only by dropping its own [`LockHookGuard`].
    ///
    /// There used to be a single-slot `set_lock_hook` beside this list, which *replaced* whatever
    /// was registered there — so a second agent on the same handle (a second endpoint, or a restart
    /// overlapping the old instance) silently unregistered the first's hook, and the first's leases
    /// survived the next lock. Every registration is additive now; replacing was the one way left
    /// for one owner to retire another's hook without holding its guard.
    extra_locks: Mutex<Vec<(HookId, LockHook)>>,
    /// Hooks that need the vault itself, not just the fact that it is gone — see
    /// [`VaultLockHook`]. Additive for the same reason `extra_locks` is, and removed the same way.
    vault_locks: Mutex<Vec<(HookId, VaultLockHook)>>,
    /// Source of [`HookId`]s handed out by every registration method, so two hooks registered at
    /// the same instant — even in different slots — never share one.
    next_hook_id: AtomicU64,
    /// The shared vaults served to agents beside this vault ([`crate::shared`]). Emptied the
    /// moment the vault is taken, before any hook runs.
    shared: crate::shared::SharedSet,
}

impl std::fmt::Debug for VaultHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultHandle")
            .field("unlocked", &self.is_unlocked())
            .finish()
    }
}

impl VaultHandle {
    /// Wrap a freshly opened vault.
    #[must_use]
    pub fn new(vault: Vault) -> Arc<Self> {
        Arc::new(Self {
            vault: Mutex::new(Some(vault)),
            extra_locks: Mutex::new(Vec::new()),
            vault_locks: Mutex::new(Vec::new()),
            next_hook_id: AtomicU64::new(0),
            shared: crate::shared::SharedSet::default(),
        })
    }

    /// The shared vaults attached to this handle.
    pub(crate) const fn shared_set(&self) -> &crate::shared::SharedSet {
        &self.shared
    }

    /// The raw guard, for callers that need `&mut Vault` across several statements.
    ///
    /// A poisoned lock is recovered rather than propagated, for the reason `kagisecure-ffi`'s
    /// `VaultSession` gives: the vault's invariants are upheld by `&mut self` methods that cannot
    /// leave it half-written, and stranding a user's data behind an error they cannot act on is
    /// the worse failure.
    pub fn guard(&self) -> MutexGuard<'_, Option<Vault>> {
        self.vault.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether there is still a key in here.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.guard().is_some()
    }

    /// Run `f` against the vault, or return `None` if it is locked.
    pub fn with<T>(&self, f: impl FnOnce(&Vault) -> T) -> Option<T> {
        self.guard().as_ref().map(f)
    }

    /// Run `f` against the vault mutably, or return `None` if it is locked.
    pub fn with_mut<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> Option<T> {
        self.guard().as_mut().map(f)
    }

    /// Bring the vault up to date with its file, if another process changed it
    /// ([`Vault::refresh_if_changed`]). `None` if the vault is locked.
    ///
    /// On an error the in-memory state is left exactly as it was. Which errors must stop a
    /// request is the caller's decision: see `service::Service::sync`.
    pub fn sync(&self) -> Option<kagisecure_core::Result<bool>> {
        self.guard().as_mut().map(Vault::refresh_if_changed)
    }

    /// Run `f` as one transaction on the vault file ([`Vault::transact`]), waiting at most `wait`
    /// for another writer. `None` if the vault is locked.
    ///
    /// `wait` applies to this call only; the vault's own [`Vault::lock_timeout`], which the app
    /// chooses for its own writes, is restored afterwards.
    pub fn transact<T>(
        &self,
        wait: Duration,
        f: impl FnOnce(&mut Tx<'_>) -> kagisecure_core::Result<T>,
    ) -> Option<kagisecure_core::Result<T>> {
        let mut guard = self.guard();
        let vault = guard.as_mut()?;
        Some(waiting_at_most(vault, wait, |vault| vault.transact(f)))
    }

    /// Queue an audit entry to be written by the next successful write, without attempting one
    /// now ([`Vault::queue_audit`]). `false` if the vault is locked.
    ///
    /// For an entry recorded just after a write failed because another process holds the lock:
    /// trying again at once would only wait out the same holder a second time before answering.
    pub fn queue_audit(&self, draft: AuditDraft) -> bool {
        self.guard()
            .as_mut()
            .map(|vault| vault.queue_audit(draft))
            .is_some()
    }

    /// Record an audit entry that must neither change what the caller answers nor be lost.
    ///
    /// The draft is queued ([`Vault::queue_audit`]) and then written in a transaction of its own
    /// ([`Vault::flush_audit`]), which also writes anything queued earlier. If that write fails —
    /// another writer holds the lock past `wait`, the disk is full, the file conflicts with this
    /// session — the draft stays queued, keeping the time it was recorded, and is written by the
    /// next transaction that succeeds; the failure stays visible on the vault
    /// ([`Vault::unsaved_audit_entries`], [`Vault::last_save_error`]) for the app to show, and is
    /// echoed to stderr here (never the entry's own content).
    ///
    /// Returns `false` only when the vault is locked: there is then nowhere to record anything,
    /// and nothing to lose that the lock did not already take.
    pub fn record_best_effort(&self, wait: Duration, draft: AuditDraft) -> bool {
        let mut guard = self.guard();
        let Some(vault) = guard.as_mut() else {
            return false;
        };
        vault.queue_audit(draft);
        flush_logging(vault, wait);
        true
    }

    /// Write every audit entry still waiting to be saved, now, and report whether that worked
    /// ([`Vault::flush_audit`]), waiting at most `wait` for another writer. `None` if the vault is
    /// locked.
    ///
    /// Takes no file lock and succeeds at once when nothing is waiting. For the check a release
    /// makes before it puts a question to the human (see [`crate::release`]): entries that could
    /// not be written a moment ago mean the release's own entry probably cannot be either, and
    /// the human should not be asked to approve something that will then be refused.
    pub fn flush(&self, wait: Duration) -> Option<kagisecure_core::Result<()>> {
        let mut guard = self.guard();
        let vault = guard.as_mut()?;
        Some(waiting_at_most(vault, wait, Vault::flush_audit))
    }

    /// Write every audit entry still waiting to be saved, best-effort: as
    /// [`VaultHandle::record_best_effort`] without a new entry. Does nothing, and takes no file
    /// lock, when nothing is waiting or the vault is locked.
    pub fn flush_best_effort(&self, wait: Duration) {
        if let Some(vault) = self.guard().as_mut() {
            flush_logging(vault, wait);
        }
    }

    /// Register what should happen the moment the vault is taken away, beside every hook already
    /// registered.
    ///
    /// Additive by design: no registration displaces another, so neither the browser-extension
    /// listener nor a second MCP agent can unregister anyone's hook by existing, and nobody's
    /// stopping silences anyone else. Dropping the returned [`LockHookGuard`] removes just this one
    /// entry from the list, by an id no other guard carries.
    pub fn add_lock_hook(self: &Arc<Self>, hook: LockHook) -> LockHookGuard {
        let id = self.next_hook_id();
        self.extra_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((id, hook));
        self.guard_for(id, HookSlot::Extra)
    }

    /// Register a hook that needs the vault itself while locking — see [`VaultLockHook`]. Additive
    /// for the same reason [`VaultHandle::add_lock_hook`] is, and removed the same way: dropping
    /// the returned [`LockHookGuard`] takes only this one entry back out.
    pub fn add_vault_lock_hook(self: &Arc<Self>, hook: VaultLockHook) -> LockHookGuard {
        let id = self.next_hook_id();
        self.vault_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((id, hook));
        self.guard_for(id, HookSlot::Vault)
    }

    /// Hand out the next [`HookId`], unique for the life of this handle.
    fn next_hook_id(&self) -> HookId {
        self.next_hook_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Build the guard a registration method hands back: a [`Weak`] reference plus enough to find
    /// this one entry again, and nothing that would let it find any other.
    fn guard_for(self: &Arc<Self>, id: HookId, slot: HookSlot) -> LockHookGuard {
        LockHookGuard {
            handle: Arc::downgrade(self),
            id,
            slot,
        }
    }

    /// Remove one hook by id, from the one slot it was registered in. The only caller is a
    /// [`LockHookGuard`]'s `Drop` implementation, so the only way to reach this is by dropping the
    /// very guard a registration returned — never by naming another caller's hook.
    fn deregister(&self, id: HookId, slot: HookSlot) {
        match slot {
            HookSlot::Extra => {
                self.extra_locks
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|(hid, _)| *hid != id);
            }
            HookSlot::Vault => {
                self.vault_locks
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|(hid, _)| *hid != id);
            }
        }
    }

    /// Lock: move the vault out, run the hooks, and make a last attempt to write any audit entries
    /// still waiting to be saved.
    ///
    /// [`LockHook`]s run *after* the mutex is released and after the vault is gone, so anything
    /// they do — killing leases, denying approvals — happens in a world where no injection can
    /// still succeed. [`VaultLockHook`]s run next, still with the vault in hand but no longer
    /// reachable through this handle, so something that must *record* what locking itself just did
    /// (killing a running child, concretely) can still queue an entry to ride out on the final
    /// [`Vault::flush_audit`] just below — the one place left where that entry has anywhere to go.
    /// Dropping the returned value is what zeroizes the key, and with it any entry that final
    /// attempt could not write: those were recorded best-effort because a failed write must not
    /// block anything, and locking is the one moment there is no later write to carry them.
    ///
    /// The final flush waits the vault's own lock timeout for another writer; a caller answering
    /// to a person — the app, locking on its main thread — uses
    /// [`VaultHandle::take_flushing_within`] instead.
    pub fn take(&self) -> Option<Vault> {
        let wait = self.with(Vault::lock_timeout);
        self.take_flushing_within(wait.unwrap_or_default())
    }

    /// [`VaultHandle::take`], with its final audit flush waiting at most `wait` for another
    /// writer's lock. Everything else is identical, and the vault is taken — locked — whether or
    /// not the flush then succeeds.
    pub fn take_flushing_within(&self, wait: Duration) -> Option<Vault> {
        let mut taken = self.guard().take();
        // The shared vaults' device keys live in the vault just taken: nothing is served from
        // one of them from here on (`crate::shared`).
        self.shared.clear();
        if taken.is_some() {
            for (_, hook) in self
                .extra_locks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
            {
                hook();
            }
            if let Some(vault) = taken.as_mut() {
                for (_, hook) in self
                    .vault_locks
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                {
                    hook(vault);
                }
            }
        }
        if let Some(vault) = taken.as_mut()
            && let Err(e) = waiting_at_most(vault, wait, Vault::flush_audit)
        {
            eprintln!(
                "kagisecure: {} audit entries could not be written before the vault locked: {e}",
                vault.unsaved_audit_entries()
            );
        }
        taken
    }
}

/// What a failed [`VaultHandle::transact`] means for the request that attempted it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriteFailure {
    /// Another writer held the file lock past the wait, or the lock file was moved while held.
    /// Nothing was written; retrying shortly is safe.
    Busy,
    /// The file is no longer one this session will build on: an older copy restored over it
    /// ([`kagisecure_core::Error::VaultDiverged`]), a different file or a different vault at the
    /// path, or nothing there at all. Nothing was written, and nothing will be until the user
    /// decides which version is the vault — retrying cannot help.
    Conflict,
    /// Anything else: an I/O error, a result over the size limit.
    Other,
}

impl WriteFailure {
    /// Sort a write error into the three cases a caller answers differently.
    pub(crate) fn of(error: &kagisecure_core::Error) -> Self {
        use kagisecure_core::Error as E;
        match error {
            E::VaultBusy { .. } | E::LockLost(_) => Self::Busy,
            E::VaultDiverged(_)
            | E::VaultReplaced(_)
            | E::VaultNotFound(_)
            | E::BadMagic
            | E::Malformed
            | E::UnsupportedFormatVersion { .. }
            | E::HeaderDecode(_)
            | E::BodyDecode(_) => Self::Conflict,
            _ => Self::Other,
        }
    }
}

/// Whether an error from [`VaultHandle::sync`] means the file could not even be *checked* — an
/// I/O error reading it — as opposed to having been checked and found not to continue this
/// session (every other error).
///
/// The difference decides whether a request may still be served from memory. A file that was
/// read and is a different, older or unreadable vault is positive evidence that memory is not
/// what is on disk, and nothing may be decided from it. A read that failed says nothing about the
/// file's contents; and since every other writer only ever replaces the file with one that reads
/// back, a newer version this session cannot see is not the likely explanation. Serving from
/// memory then is what the vault did before other processes' writes were read at all, and every
/// write still goes through a transaction, which reads the file again and fails on its own.
pub(crate) fn sync_could_not_read(error: &kagisecure_core::Error) -> bool {
    matches!(error, kagisecure_core::Error::Io(_))
}

/// Flush the pending audit queue, echoing a failure to stderr (never an entry's content).
fn flush_logging(vault: &mut Vault, wait: Duration) {
    if let Err(e) = waiting_at_most(vault, wait, Vault::flush_audit) {
        eprintln!(
            "kagisecure: could not write the audit log yet ({} entries waiting): {e}",
            vault.unsaved_audit_entries()
        );
    }
}

/// Run `f` with the vault's lock timeout set to `wait`, then put the vault's own back.
fn waiting_at_most<T>(vault: &mut Vault, wait: Duration, f: impl FnOnce(&mut Vault) -> T) -> T {
    let own = vault.lock_timeout();
    vault.set_lock_timeout(wait);
    let out = f(vault);
    vault.set_lock_timeout(own);
    out
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn scratch_vault() -> (tempfile::TempDir, Vault) {
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
        (dir, vault)
    }

    #[test]
    fn taking_the_vault_locks_the_handle_and_runs_the_hook() {
        let (_dir, vault) = scratch_vault();
        let handle = VaultHandle::new(vault);
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&fired);
        let _guard = handle.add_lock_hook(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        assert!(handle.is_unlocked());
        assert!(handle.with(|v| v.path().to_path_buf()).is_some());

        drop(handle.take());
        assert!(!handle.is_unlocked());
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        assert!(handle.with(|v| v.path().to_path_buf()).is_none());
    }

    #[test]
    fn a_second_take_does_not_fire_the_hook_again() {
        let (_dir, vault) = scratch_vault();
        let handle = VaultHandle::new(vault);
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&fired);
        let _guard = handle.add_lock_hook(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        drop(handle.take());
        drop(handle.take());
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    fn draft(tool: &str) -> AuditDraft {
        AuditDraft {
            tool: tool.to_owned(),
            outcome: kagisecure_core::proto::Outcome::Allowed,
            ..AuditDraft::default()
        }
    }

    fn tools_on_disk(path: &std::path::Path) -> Vec<String> {
        Vault::open_with_password(path, b"pw")
            .expect("reopen")
            .audit_entries()
            .iter()
            .map(|e| e.tool.clone())
            .collect()
    }

    #[test]
    fn taking_the_vault_writes_the_entries_still_waiting() {
        let (_dir, vault) = scratch_vault();
        let path = vault.path().to_path_buf();
        let handle = VaultHandle::new(vault);
        assert!(handle.queue_audit(draft("queued")));
        assert!(!tools_on_disk(&path).contains(&"queued".to_owned()));

        let taken = handle.take().expect("unlocked");
        assert_eq!(taken.unsaved_audit_entries(), 0);
        assert!(tools_on_disk(&path).contains(&"queued".to_owned()));
    }

    #[test]
    fn a_request_wait_applies_to_that_call_only() {
        let (_dir, mut vault) = scratch_vault();
        vault.set_lock_timeout(Duration::from_millis(1500));
        let handle = VaultHandle::new(vault);
        let seen = handle
            .transact(Duration::from_secs(7), |tx| Ok(tx.lock_timeout()))
            .expect("unlocked")
            .expect("commit");
        assert_eq!(seen, Duration::from_secs(7));
        assert!(handle.record_best_effort(Duration::from_secs(3), draft("recorded")));
        assert_eq!(
            handle.with(Vault::lock_timeout),
            Some(Duration::from_millis(1500)),
            "the vault's own timeout, chosen by the app, is back"
        );
    }

    #[test]
    fn a_locked_handle_records_and_writes_nothing() {
        let (_dir, vault) = scratch_vault();
        let handle = VaultHandle::new(vault);
        drop(handle.take());
        assert!(!handle.queue_audit(draft("x")));
        assert!(!handle.record_best_effort(REQUEST_LOCK_TIMEOUT, draft("x")));
        assert!(handle.sync().is_none());
        assert!(handle.transact(REQUEST_LOCK_TIMEOUT, |_| Ok(())).is_none());
    }

    #[test]
    fn dropping_a_hooks_guard_retires_it_before_the_next_lock() {
        let (_dir, vault) = scratch_vault();
        let handle = VaultHandle::new(vault);
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&fired);
        let guard = handle.add_lock_hook(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        drop(guard);
        drop(handle.take());
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }

    /// The regression this module exists to prevent: one subsystem retiring its own hook — the
    /// MCP agent stopping, concretely — must never silence another's. Two `add_lock_hook`
    /// registrations and one `add_vault_lock_hook` stand in for an older MCP agent's primary hook,
    /// the browser extension's, and the MCP agent's vault-needing one — the hooks `Agent::stop`
    /// used to wipe in one call via the old `clear_lock_hook`.
    #[test]
    fn dropping_one_subsystems_guard_never_clears_anothers_hook() {
        let (_dir, vault) = scratch_vault();
        let handle = VaultHandle::new(vault);

        let agent_primary_fired = Arc::new(AtomicUsize::new(0));
        let agent_vault_fired = Arc::new(AtomicUsize::new(0));
        let extension_fired = Arc::new(AtomicUsize::new(0));

        let counter = Arc::clone(&agent_primary_fired);
        let agent_primary_guard = handle.add_lock_hook(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        let counter = Arc::clone(&agent_vault_fired);
        let agent_vault_guard = handle.add_vault_lock_hook(Box::new(move |_vault| {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        let counter = Arc::clone(&extension_fired);
        let extension_guard = handle.add_lock_hook(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        // "Stop the agent": drop only the two hooks it owns, exactly as `Agent::stop` now does.
        drop(agent_primary_guard);
        drop(agent_vault_guard);

        // "Lock": the extension's hook must still fire even though the agent already retired its
        // own.
        drop(handle.take());
        assert_eq!(agent_primary_fired.load(Ordering::SeqCst), 0);
        assert_eq!(agent_vault_fired.load(Ordering::SeqCst), 0);
        assert_eq!(
            extension_fired.load(Ordering::SeqCst),
            1,
            "the agent stopping must not silence the extension's own lock hook"
        );

        drop(extension_guard);
    }

    /// Two agents on one handle (two endpoints, or a restart that overlaps the old instance's
    /// drop): registering the second must not silence the first — the same owner-scoped rule
    /// the guards follow, applied to registration.
    #[test]
    fn a_second_registration_never_displaces_the_first() {
        let (_dir, vault) = scratch_vault();
        let handle = VaultHandle::new(vault);
        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&first);
        let _first_guard = handle.add_lock_hook(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        let counter = Arc::clone(&second);
        let _second_guard = handle.add_lock_hook(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        drop(handle.take());
        assert_eq!(first.load(Ordering::SeqCst), 1, "the first agent's hook");
        assert_eq!(second.load(Ordering::SeqCst), 1, "the second agent's hook");
    }

    #[test]
    fn dropping_one_registrations_guard_retires_only_that_hook() {
        let (_dir, vault) = scratch_vault();
        let handle = VaultHandle::new(vault);

        let first_fired = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&first_fired);
        let first_guard = handle.add_lock_hook(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        let second_fired = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&second_fired);
        let _second_guard = handle.add_lock_hook(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        // Dropping the first registration's guard must not reach the second hook.
        drop(first_guard);
        drop(handle.take());
        assert_eq!(first_fired.load(Ordering::SeqCst), 0);
        assert_eq!(second_fired.load(Ordering::SeqCst), 1);
    }
}
