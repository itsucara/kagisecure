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

use std::sync::{Arc, Mutex, MutexGuard};

use kagisecure_core::Vault;

/// What runs when the vault is taken out of the handle.
pub type LockHook = Box<dyn Fn() + Send + Sync>;

/// A vault that may or may not currently be unlocked, shared by the UI and the agent.
pub struct VaultHandle {
    vault: Mutex<Option<Vault>>,
    /// The MCP agent's hook. Exactly one, replaced by [`VaultHandle::set_lock_hook`].
    on_lock: Mutex<Option<LockHook>>,
    /// Additional hooks, appended by [`VaultHandle::add_lock_hook`].
    ///
    /// M6 gave the handle a second listener — the browser-extension one — and a second thing that
    /// must be emptied on lock. `set_lock_hook` replaces, so two callers of it would silently
    /// leave one of them unregistered and one set of leases alive past a lock. Rather than change
    /// `set_lock_hook`'s meaning under its existing caller, the additive form is a second list.
    extra_locks: Mutex<Vec<LockHook>>,
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
            on_lock: Mutex::new(None),
            extra_locks: Mutex::new(Vec::new()),
        })
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

    /// Register what should happen the moment the vault is taken away.
    ///
    /// Replaces any previous hook: there is one agent per handle.
    pub fn set_lock_hook(&self, hook: LockHook) {
        *self.on_lock.lock().unwrap_or_else(|e| e.into_inner()) = Some(hook);
    }

    /// Register an *additional* hook, without disturbing [`VaultHandle::set_lock_hook`]'s.
    ///
    /// Used by the browser-extension listener, which needs its fill leases emptied on a lock and
    /// must not be able to unregister the MCP agent's hook by existing.
    ///
    /// Hooks are never removed individually: each holds only a `Weak` back to its owner, so a
    /// stopped listener's hook upgrades to `None` and does nothing. What that costs is a `Vec`
    /// that grows by one entry per start/stop cycle of a listener; what it buys is that there is
    /// no way to unregister somebody else's hook by mistake. `clear_lock_hook` empties both.
    pub fn add_lock_hook(&self, hook: LockHook) {
        self.extra_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(hook);
    }

    /// Forget every lock hook, so a stopped agent is not woken by a later lock.
    pub fn clear_lock_hook(&self) {
        *self.on_lock.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.extra_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Lock: move the vault out and run the hook.
    ///
    /// The hook runs *after* the mutex is released and after the vault is gone, so anything it
    /// does — killing leases, denying approvals — happens in a world where no injection can still
    /// succeed. Dropping the returned value is what zeroizes the key.
    pub fn take(&self) -> Option<Vault> {
        let taken = self.guard().take();
        if taken.is_some() {
            {
                let hook = self.on_lock.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(hook) = hook.as_ref() {
                    hook();
                }
            }
            for hook in self
                .extra_locks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
            {
                hook();
            }
        }
        taken
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn scratch_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.kagivault");
        let mut options = kagisecure_core::vault::CreateOptions::new().expect("options");
        options.kdf = kagisecure_core::crypto::kdf::KdfParams::new(8, 1, 1).expect("kdf");
        let (vault, _code) = Vault::create(&path, b"pw", &options).expect("create");
        (dir, vault)
    }

    #[test]
    fn taking_the_vault_locks_the_handle_and_runs_the_hook() {
        let (_dir, vault) = scratch_vault();
        let handle = VaultHandle::new(vault);
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&fired);
        handle.set_lock_hook(Box::new(move || {
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
        handle.set_lock_hook(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        drop(handle.take());
        drop(handle.take());
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_cleared_hook_does_not_run() {
        let (_dir, vault) = scratch_vault();
        let handle = VaultHandle::new(vault);
        let fired = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&fired);
        handle.set_lock_hook(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        handle.clear_lock_hook();
        drop(handle.take());
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }
}
