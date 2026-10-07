//! The one object the app holds: an unlocked vault, behind a lock.
//!
//! Every mutating method writes the file before it returns. That is the same "append, then save"
//! discipline the M2 daemon follows (architecture.md §2.6) and it means the app never has a
//! window where the UI shows a change the disk does not have. It costs a whole-body re-encrypt
//! per call; batching is deferred, exactly as it is for the daemon.
//!
//! Locking is [`VaultSession::lock`], an explicit call (ADR-0038 §4): it takes the vault out of
//! the handle, which zeroizes the key and runs the lock hooks. Dropping this object does the same
//! thing as a backstop, but a pending presence prompt keeps the object alive (its release future
//! holds it), so the app locks by calling `lock()` first rather than relying on the last reference
//! going away.
//!
//! # A locked session
//!
//! After `lock()` the object may still be reachable — a SwiftUI view that has not been torn down
//! yet, a timer that fires once more, a release future finishing its await. Nothing on it panics:
//! a call that returns a `Result` answers [`FfiError::VaultLocked`], and one that cannot fail
//! answers what an empty vault would (no items, no counts, no slot).

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kagisecure_agent::VaultHandle;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::model::{Environment, Field, Item, VarSource, VaultId};
use kagisecure_core::proto::{Category, Outcome, VarName};

use kagisecure_core::vault::{
    AgentVisibilityScope, CreateOptions, FileConflict, Tx, UnlockedBy, Vault,
};
use kagisecure_core::{RecoveryCode, unix_now};
use zeroize::Zeroizing;

use crate::agent::{AuditDurabilityView, AuditRowView};
use crate::import::{
    DuplicatePolicyView, ImportFormat, ImportOutcomeView, ImportPlanHandle, ImportReportView,
};
use crate::presence::Presence;
use crate::types::{
    AgentTestLoginSettingsView, AgentVisibilityScopeView, BulkVisibilityView, EnvironmentView,
    FieldView, ItemDraft, ItemFilter, ItemSort, ItemView, KeepAppVersionOutcome, SidebarCounts,
    TagCount, UnlockKind, VaultConflictDetailsView, VaultConflictKindView, VaultView, field_value,
};
use crate::{FfiError, FfiResult};
use kagisecure_core::model::SecretText;

/// How long the app UI waits for another writer before giving up with [`FfiError::Busy`].
///
/// Also the wait a best-effort audit write from the app gets (`VaultHandle::record_best_effort`,
/// `VaultHandle::flush_best_effort`) before it gives up and leaves its entry queued.
///
/// Short on purpose: the app is answering to a person watching a spinner, not a program that can
/// afford to sit out a slow writer (design note "App UI lock timeout ≈ 2s"; compare
/// [`kagisecure_agent::vault::REQUEST_LOCK_TIMEOUT`]'s 5s for the agent and extension).
pub(crate) const APP_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a lock's final audit flush waits for another writer's file lock
/// (`VaultSession::lock_now`): short enough that locking — on the app's main thread — stays inside
/// [`APP_LOCK_TIMEOUT`] including the write itself.
pub(crate) const LOCK_FLUSH_WAIT: Duration = Duration::from_secs(1);

/// The `reason` [`VaultSession::keep_app_version_over_conflict`] records in the override's audit
/// entry (`kagisecure_core::vault::Vault::overwrite_with_this_session`).
const KEEP_APP_VERSION_REASON: &str =
    "user chose \"Keep this app's version\" in the conflict alert";

/// A fingerprint of everything [`VaultSession::save_item`] can change about an item, computed the
/// same way from the item as loaded (into [`ItemView::revision`]) and from the freshest copy
/// inside the write transaction, so a stale edit can be told apart from a fresh one.
///
/// # Why a digest of the content, and why not `updated_at`
///
/// `Item::updated_at` (Unix *seconds*) is tempting — it already changes on every save — but two
/// edits inside the same second are indistinguishable by it, which is exactly the race this check
/// exists to close: the second `save_item` would read the same `updated_at` the sheet was given
/// and sail through over the first save. Digesting the content itself has no such window, and it
/// also catches a change made by another process or an older build, which would not bump any
/// counter this build introduced. A per-item revision counter or random token stored in the item
/// would need a new key in the vault format for no gain over this.
///
/// # Why a digest, and not the content itself
///
/// [`ItemView::revision`] has to round-trip out to Swift and back unchanged (`ItemDraft::revision`)
/// so the check can run *inside* the write transaction against the freshest state (see the
/// module-level rule that every read deciding a mutation belongs in the transaction's closure).
/// Sending the edit sheet's own idea of the item back out a second time, in full, would mean a
/// second copy of every field's value — secrets included — leaving the process for no reason
/// beyond bookkeeping; ADR-0008 counts every such crossing.
///
/// # Why keyed (HMAC-SHA-256 under a random per-session key)
///
/// The digest covers every secret value and the notes, and it is handed to Swift for every item in
/// every list, with no presence check. An unkeyed hash of that would be an offline guessing
/// oracle: anything that can read the app's views — an automation agent driving the UI, a memory
/// or log scrape of the Swift side — could test candidate passwords, PINs or notes against it,
/// one guess at a time, without ever passing the presence gate (ADR-0038). Keyed with 32 random
/// bytes that are generated when the session unlocks and never leave this crate, the value says
/// "this item changed" and nothing else: without the key no guess can be checked, and the same
/// item gives unrelated revisions in two sessions. The key lives exactly as long as the only thing
/// a revision is compared against — an edit sheet opened in this session — and is zeroized with
/// the session.
///
/// Every editable part of the item feeds the MAC — not just what `save_item` currently touches —
/// so a future field the edit sheet learns to carry is covered without this function changing.
/// Fields are fed with explicit `0`-byte separators between parts and an `0xff` terminator after
/// each field, which is what stops `("a", "bc")` and `("ab", "c")` authenticating the same.
pub(crate) fn item_revision(item: &Item, key: &RevisionKey) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    /// Feed `bytes` into `mac` followed by a `0` separator, so `("a", "bc")` and `("ab", "c")`
    /// cannot authenticate the same.
    fn push(mac: &mut Hmac<Sha256>, bytes: &[u8]) {
        mac.update(bytes);
        mac.update(&[0u8]);
    }

    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.0.as_slice())
        .expect("HMAC accepts a key of any length");
    push(&mut mac, item.title.as_bytes());
    push(&mut mac, item.category.as_str().as_bytes());
    push(&mut mac, &[u8::from(item.favorite)]);
    push(&mut mac, &[u8::from(item.archived)]);
    push(&mut mac, &item.trashed_at.unwrap_or_default().to_le_bytes());
    push(&mut mac, &[u8::from(item.agent_visible)]);
    for tag in &item.tags {
        push(&mut mac, tag.as_bytes());
    }
    mac.update(&[0xffu8]);
    for url in &item.urls {
        push(&mut mac, url.as_bytes());
    }
    mac.update(&[0xffu8]);
    push(
        &mut mac,
        item.notes
            .as_ref()
            .map_or(&[][..], |n| n.as_secret().expose()),
    );
    for field in &item.fields {
        push(&mut mac, field.id.to_string().as_bytes());
        push(&mut mac, field.label.as_bytes());
        push(&mut mac, field.kind.as_str().as_bytes());
        push(&mut mac, field.section.as_deref().unwrap_or("").as_bytes());
        push(&mut mac, &[u8::from(field.agent_visible)]);
        match &field.value {
            kagisecure_core::model::FieldValue::Public(s) => {
                push(&mut mac, &[0u8]);
                push(&mut mac, s.as_bytes());
            }
            kagisecure_core::model::FieldValue::Secret(secret) => {
                push(&mut mac, &[1u8]);
                push(&mut mac, secret.expose());
            }
        }
        mac.update(&[0xffu8]);
    }
    // The primary-secret designation is part of what an edit can be stale against.
    push(
        &mut mac,
        item.primary_secret
            .map(|id| id.to_string())
            .unwrap_or_default()
            .as_bytes(),
    );
    let tag = mac.finalize().into_bytes();
    tag.iter().map(|b| format!("{b:02x}")).collect()
}

/// The key [`item_revision`] is computed under: 32 random bytes per session, zeroized on drop,
/// never handed out.
pub(crate) struct RevisionKey(kagisecure_core::crypto::Key);

impl RevisionKey {
    pub(crate) fn generate() -> FfiResult<Self> {
        Ok(Self(kagisecure_core::crypto::random::key()?))
    }
}

/// What [`VaultSession::save_item`]'s transaction decided, communicated through the closure's own
/// `Ok(T)` rather than an error: a conflict is not a failure `Vault::transact` should roll back
/// noisily over (it already rolls back cleanly — nothing was mutated before this is returned —
/// and the harmless re-seal a no-op transaction performs elsewhere in this crate, e.g.
/// `VaultSession::save`, is exactly what happens here too). `kagisecure_core::Error` is
/// `#[non_exhaustive]` and not this crate's to extend, so the FFI-specific
/// `FfiError::ItemChangedElsewhere` is produced by the caller from this, once the transaction has
/// already committed (or not needed to).
/// `Some("")` collapses to `None` — "keep the stored value" — exactly when the field already has
/// one on record (`had_old`) and the incoming draft would store it concealed. An empty string is
/// never a meaningful *new* secret while there is an old one to keep: the product already treats
/// an empty [`kagisecure_core::model::FieldValue`] as no value at all (its own `has_value`), so
/// nothing of substance is lost by refusing to tell "typed nothing" and "typed something, then
/// deleted it all" apart here — and a great deal is gained. This is the FFI boundary's own last
/// line of defense against the exact shape of bug that motivated it: whatever put an empty string
/// in a concealed field's slot — a failed reveal (the original bug this ADR closed), a Swift-side
/// state mix-up between two draft rows, a person who pressed "Change" and then Save without
/// typing — none of it can replace a real secret with an empty one, because Rust never sees the
/// difference between "empty" and "untouched" for this shape of field at all.
///
/// Scoped tightly on purpose:
/// * only when `had_old` — a brand-new field's empty starting value
///   (`ItemEditView.addField`/`FieldDraft::value` doc) still means exactly what it says, because
///   there is nothing stored yet to "keep";
/// * only when `concealed` — a *public* field's empty value is an ordinary, deliberate "cleared
///   this back to nothing" (a phone number, a username), and stays exactly that.
fn effective_value(concealed: bool, value: Option<String>, had_old: bool) -> Option<String> {
    match value {
        Some(v) if concealed && had_old && v.is_empty() => None,
        other => other,
    }
}

enum SaveItemOutcome {
    Saved(Box<ItemView>),
    Conflict,
    /// The draft itself was invalid — a new field with no value, or a concealed field asked to
    /// become public with no new value (ADR-0038 step 3). Communicated the same way `Conflict`
    /// is: nothing was mutated before this was returned, so the closure's `Ok(_)` still commits
    /// cleanly (a no-op) rather than needing `Vault::transact` to roll anything back.
    Invalid(String),
}

/// An unlocked vault, owned by the app for as long as it stays unlocked.
///
/// # Why the vault lives behind a [`VaultHandle`]
///
/// Since M4 the app is not the only thing that needs the unlocked vault: the agent library serves
/// MCP requests from its own threads at the same time. Both hold the one
/// [`kagisecure_agent::VaultHandle`], so there is one vault, one mutex, and one definition of
/// "locked" — the handle holding nothing.
///
/// Locking ([`VaultSession::lock`], and `Drop` as a backstop) does two things rather than one: it
/// takes the vault out of the handle (which zeroizes the key) **and** runs the handle's lock hook,
/// which is what kills every lease and denies every approval the agent still has in flight. There
/// is no window in which a locked vault serves an agent.
#[derive(uniffi::Object)]
pub struct VaultSession {
    handle: Arc<VaultHandle>,
    /// The one-time recovery code from [`VaultSession::create`], handed out exactly once.
    recovery_code: Mutex<Option<String>>,
    /// Set when [`VaultSession::sync`] or a write hits a conflict — the vault file changed,
    /// underneath this session, in a way writes cannot safely build on (step 4, user decision 3).
    /// Cleared the moment a read of the file proves it unchanged or continues cleanly again.
    conflict: Mutex<Option<VaultConflictKindView>>,
    /// The conflict [`VaultSession::conflict_details`] last described to the person — kept here,
    /// in full, so [`VaultSession::keep_app_version_over_conflict`] can hand the core exactly
    /// what was confirmed (`Vault::overwrite_with_this_session` refuses anything else).
    examined_conflict: Mutex<Option<FileConflict>>,
    /// The vault's path, kept so it can still be named after a lock.
    path: String,
    /// The header's `vault_id`, hex — [`VaultSession::vault_file_id`], kept for the same reason.
    vault_file_id: String,
    /// The same `vault_id`, raw — [`VaultSession::vault_file_id_bytes`].
    vault_file_id_bytes: Vec<u8>,
    /// How the session unlocked, as last read — [`VaultSession::unlocked_by`] after a lock.
    unlocked_by: Mutex<UnlockKind>,
    /// The presence gate, the release in flight, and the master-password back-off (ADR-0038).
    presence: Arc<Presence>,
    /// What [`ItemView::revision`] is keyed with for this session (`item_revision`).
    revision_key: RevisionKey,
}

/// A borrow of the unlocked vault inside the handle.
///
/// Built only by [`VaultRef::new`], and only over a guard that holds a vault, which is what makes
/// the `expect`s below unreachable: the handle cannot be emptied while this guard is held.
///
/// # Never across an `await`
///
/// This wraps a `std::sync::MutexGuard`, which is not `Send`, and every exported `async fn` must
/// return a `Send` future. So holding a `VaultRef` across the presence gate's `.await` is a
/// compile error, not a review rule — which is exactly the property ADR-0038 §3 needs: a prompt a
/// person may ignore for a minute must never hold the vault mutex that the agent, the list and
/// every other window wait on. `crate::release` reads what it needs, drops the borrow, awaits,
/// and borrows again.
pub(crate) struct VaultRef<'a>(std::sync::MutexGuard<'a, Option<Vault>>);

impl<'a> VaultRef<'a> {
    pub(crate) fn new(guard: std::sync::MutexGuard<'a, Option<Vault>>) -> Option<Self> {
        guard.is_some().then_some(Self(guard))
    }
}

impl std::ops::Deref for VaultRef<'_> {
    type Target = Vault;
    fn deref(&self) -> &Vault {
        self.0
            .as_ref()
            .expect("a VaultRef is only built over a guard that holds a vault")
    }
}

impl std::ops::DerefMut for VaultRef<'_> {
    fn deref_mut(&mut self) -> &mut Vault {
        self.0
            .as_mut()
            .expect("a VaultRef is only built over a guard that holds a vault")
    }
}

impl VaultSession {
    fn wrap(vault: Vault, code: Option<RecoveryCode>) -> FfiResult<Arc<Self>> {
        let revision_key = RevisionKey::generate()?;
        let path = vault.path().display().to_string();
        let vault_file_id_bytes = vault.header().vault_id.clone();
        let vault_file_id = vault_file_id_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let unlocked_by = unlock_kind(vault.unlocked_by());
        Ok(Arc::new(Self {
            handle: VaultHandle::new(vault),
            recovery_code: Mutex::new(code.map(|c| c.display().to_string())),
            conflict: Mutex::new(None),
            examined_conflict: Mutex::new(None),
            path,
            vault_file_id,
            vault_file_id_bytes,
            unlocked_by: Mutex::new(unlocked_by),
            presence: Presence::new(),
            revision_key,
        }))
    }

    /// An item as the app sees it, with its revision keyed for this session.
    pub(crate) fn view(&self, vault: &Vault, item: &Item) -> ItemView {
        ItemView {
            in_agent_test_vault: vault.in_agent_test_vault(item),
            ..ItemView::from_core(item, &self.revision_key)
        }
    }

    /// Borrow the unlocked vault, or [`FfiError::VaultLocked`].
    ///
    /// A poisoned lock means another thread panicked while holding the vault. Recovering the
    /// guard is right here: the vault's own invariants are upheld by `&mut self` methods that
    /// cannot leave it half-written, and refusing to unlock would strand the user's data behind
    /// an error they cannot act on.
    pub(crate) fn vault(&self) -> FfiResult<VaultRef<'_>> {
        VaultRef::new(self.handle.guard()).ok_or(FfiError::VaultLocked)
    }

    /// Run `f` on the unlocked vault, or answer [`FfiError::VaultLocked`].
    pub(crate) fn with_vault<T>(&self, f: impl FnOnce(&Vault) -> T) -> FfiResult<T> {
        self.handle.with(f).ok_or(FfiError::VaultLocked)
    }

    /// Run `f` on the unlocked vault, or answer `locked` — for the calls that cannot fail.
    fn read_or<T>(&self, locked: T, f: impl FnOnce(&Vault) -> T) -> T {
        self.handle.with(f).unwrap_or(locked)
    }

    /// This session's presence state (`crate::presence`).
    pub(crate) fn presence(&self) -> Arc<Presence> {
        Arc::clone(&self.presence)
    }

    /// Lock: record the release still waiting on its prompt, if any, as `VAULT_LOCKED`, then take
    /// the vault out of the handle — which zeroizes the key, runs the lock hooks and makes one
    /// last attempt to write the audit log.
    ///
    /// The handle's mutex is taken first and the presence registry second, the one lock order
    /// every release follows too (`Presence::register`), and the registry is closed before the
    /// mutex is let go: a release whose prompt answers after this point finds itself gone from
    /// the registry and hands nothing out, whatever the prompt said.
    ///
    /// # The final flush is bounded, and stays on the calling thread
    ///
    /// The app calls this on its main thread, so the flush of anything still queued waits at most
    /// [`LOCK_FLUSH_WAIT`] for another writer's lock (not the vault's default five seconds),
    /// keeping a lock inside the app's two-second budget. If that is not enough the entries are
    /// lost with the key: they exist only in memory, encrypted under nothing yet, and a locked
    /// session has nowhere to keep them (stderr says how many). Moving the flush to a background
    /// thread instead was rejected: it would keep the vault key alive in memory after `lock()`
    /// returned — the one thing a lock promises not to do — and entries would still be lost if
    /// the app quit before it finished. The window is narrow in practice: every write the app
    /// makes flushes the queue first, so what is left at a lock is only what could not be written
    /// in the last moments, and that failure was already on screen (`audit_durability`).
    fn lock_now(&self) {
        {
            let mut guard = self.handle.guard();
            self.presence.close_for_lock(guard.as_mut());
        }
        drop(self.handle.take_flushing_within(LOCK_FLUSH_WAIT));
    }

    /// [`VaultSession::change_master_password`], with `derive_starts` called between step 1 and
    /// the Argon2id derivation — with no lock held — so a test can prove other calls proceed
    /// while it runs.
    fn change_master_password_with(
        &self,
        new_password: String,
        derive_starts: impl FnOnce(),
    ) -> FfiResult<()> {
        let new_password = zeroize::Zeroizing::new(new_password);
        // 1. Under the handle's mutex, briefly: public header facts only.
        let plan = self.with_vault(Vault::plan_master_password)??;
        derive_starts();
        // 2. Nothing held: the deliberately slow part. The agent, the extension and the UI keep
        //    working on this handle meanwhile.
        let derived = plan.derive(new_password.as_bytes())?;
        drop(new_password);
        // 3. Under the mutex again, briefly: one AEAD wrap of the vault key.
        let prepared = self.with_vault(|v| v.wrap_master_password(derived))??;
        self.transact(|tx| {
            tx.install_master_password(prepared)?;
            // Recorded inside the transaction that makes the change (ADR-0040 step 10): the new
            // password and its audit entry reach the file together or not at all.
            tx.append_audit(app_draft(AUDIT_TOOL_CHANGE_MASTER_PASSWORD, None));
            Ok(())
        })
    }

    /// The handle to share with the agent library. Not exported: Swift never sees a vault.
    pub(crate) fn handle(&self) -> Arc<VaultHandle> {
        Arc::clone(&self.handle)
    }

    /// Run `f` as one transaction ([`Vault::transact`], via [`VaultHandle::transact`]), at the
    /// app's lock wait ([`APP_LOCK_TIMEOUT`]).
    ///
    /// This is the one path every mutator in this file goes through, which is what makes the
    /// module doc's rule ("every read that decides a change belongs inside the closure") a
    /// property of the code rather than a convention: `f` only ever sees state read *after* the
    /// lock was taken.
    pub(crate) fn transact<T>(
        &self,
        f: impl FnOnce(&mut Tx<'_>) -> kagisecure_core::Result<T>,
    ) -> FfiResult<T> {
        self.handle
            .transact(APP_LOCK_TIMEOUT, f)
            .ok_or(FfiError::VaultLocked)?
            .map_err(|e| self.map_write_error(e))
    }

    /// Queue `draft` on a vault already borrowed, let the borrow go, then write it best-effort
    /// (ADR-0040 §4: a failed write leaves it queued for the next one, and is never an error for
    /// the caller) — for a caller that decided what to record while holding the vault.
    pub(crate) fn record_after(&self, mut vault: VaultRef<'_>, draft: AuditDraft) {
        vault.queue_audit(draft);
        drop(vault);
        self.handle.flush_best_effort(APP_LOCK_TIMEOUT);
    }

    /// Sort an error from `VaultSession::transact` or [`VaultSession::sync`], recording a
    /// conflict ([`VaultSession::conflict`]) when the file is no longer one this session can
    /// safely write to.
    ///
    /// [`kagisecure_core::Error::VaultNotFound`] means something different here than it does in
    /// the blanket `From` conversion this delegates to for everything else: by the time a
    /// `transact` or `sync` call can even run, the vault was already open, so the file vanishing
    /// now is the file being pulled out from under an unlocked session — one more shape of
    /// "changed underneath us", not "no vault yet" (see `impl From<kagisecure_core::Error>`'s own
    /// doc comment for the other half of this split).
    ///
    /// A parse-shaped error (`BadMagic`, `HeaderDecode`, …) is ambiguous here: the closure may
    /// have produced it, or the file may have stopped being a vault this build can read. The core
    /// is asked which ([`Vault::examine_conflict`]) rather than guessed from the variant; only a
    /// file actually found in conflict turns it into one.
    fn map_write_error(&self, e: kagisecure_core::Error) -> FfiError {
        use kagisecure_core::Error as E;
        match &e {
            E::VaultDiverged(_) => self.set_conflict(VaultConflictKindView::Diverged),
            E::VaultReplaced(_) => self.set_conflict(VaultConflictKindView::Replaced),
            E::VaultNotFound(_) => self.set_conflict(VaultConflictKindView::Removed),
            E::BadMagic
            | E::Malformed
            | E::UnsupportedFormatVersion { .. }
            | E::HeaderDecode(_)
            | E::BodyDecode(_)
            | E::Unsupported { .. } => {
                // `examine` records the conflict it finds.
                if let Ok(Some(_)) = self.examine() {
                    return FfiError::Diverged {
                        message: format!(
                            "the file at {} is no longer a vault this app can read ({e}); \
                             nothing was written",
                            self.path
                        ),
                    };
                }
            }
            _ => {}
        }
        match e {
            E::VaultNotFound(p) => FfiError::Diverged {
                message: format!(
                    "the vault file at {} is no longer there; it may have been moved or deleted \
                     while unlocked",
                    p.display()
                ),
            },
            other => other.into(),
        }
    }

    fn set_conflict(&self, kind: VaultConflictKindView) {
        *self.conflict.lock().unwrap_or_else(PoisonError::into_inner) = Some(kind);
    }

    fn clear_conflict(&self) {
        *self.conflict.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

impl Drop for VaultSession {
    fn drop(&mut self) {
        // Taking is what zeroizes, and taking is what runs the lock hook. Both matter: the key
        // goes, and so does every lease the agent minted while it existed. A no-op after `lock`.
        self.lock_now();
    }
}

#[uniffi::export]
impl VaultSession {
    /// Create a vault file and unlock it.
    ///
    /// `kdf_m_kib` and `kdf_t` override the Argon2id cost; pass `None` for the v1 desktop profile.
    /// They exist so the test suite can create vaults that protect nothing in milliseconds, the
    /// same escape hatch the CLI's `--kdf-m-kib` flag is.
    ///
    /// The one-time recovery code is available from [`VaultSession::take_recovery_code`] and from
    /// nowhere else; the app must show it before the user gets any further (vault-format.md §3.2).
    ///
    /// # Errors
    ///
    /// [`FfiError::AlreadyExists`], plus I/O and KDF failures.
    #[uniffi::constructor]
    pub fn create(
        path: String,
        master_password: String,
        vault_name: String,
        kdf_m_kib: Option<u32>,
        kdf_t: Option<u32>,
    ) -> FfiResult<Arc<Self>> {
        // Owned, so it is ours to wipe: whatever buffer the binding allocated for the password is
        // zeroized when this returns (ADR-0008 crossing 1).
        let master_password = Zeroizing::new(master_password);
        let mut options = CreateOptions::new()?;
        options.vault_name = vault_name;
        if kdf_m_kib.is_some() || kdf_t.is_some() {
            let base = &options.kdf;
            options.kdf = KdfParams::new(
                kdf_m_kib.unwrap_or(base.m_kib),
                kdf_t.unwrap_or(base.t),
                base.p,
            )?;
        }
        let (vault, code) = Vault::create(&path, master_password.as_bytes(), &options)?;
        Self::wrap(vault, Some(code))
    }

    /// Unlock with the master password (ui-spec.md §6.1).
    ///
    /// # Errors
    ///
    /// [`FfiError::NotFound`] or [`FfiError::WrongCredential`].
    #[uniffi::constructor]
    pub fn unlock_with_password(path: String, master_password: String) -> FfiResult<Arc<Self>> {
        let master_password = Zeroizing::new(master_password);
        let vault = Vault::open_with_password(&path, master_password.as_bytes())?;
        Self::wrap(vault, None)
    }

    /// Unlock with the printable recovery code.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] if the code does not parse or its checksum fails,
    /// [`FfiError::WrongCredential`] if it parses but does not open this vault.
    #[uniffi::constructor]
    pub fn unlock_with_recovery_code(path: String, code: String) -> FfiResult<Arc<Self>> {
        let code = Zeroizing::new(code);
        let code = RecoveryCode::parse(&code)?;
        let vault = Vault::open_with_recovery_code(&path, &code)?;
        Self::wrap(vault, None)
    }

    /// Unlock with a vault key the platform keystore has already unwrapped.
    ///
    /// [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md) crossing 4. Swift obtains
    /// these 32 bytes from `SecKeyCreateDecryptedData` after a successful Touch ID, and should
    /// clear its own buffer once this returns.
    ///
    /// # Errors
    ///
    /// [`FfiError::WrongCredential`] if the key does not open this vault — including when it is
    /// not 32 bytes, which is not distinguished, for the same reason a wrong password is not.
    #[uniffi::constructor]
    pub fn unlock_with_vault_key(path: String, vault_key: Vec<u8>) -> FfiResult<Arc<Self>> {
        // The binding's copy of the key (UniFFI's lowered Vec, or the C ABI's `to_vec`) is moved
        // in here and wiped on the way out, success or failure (ADR-0008 crossing 4).
        let vault_key = Zeroizing::new(vault_key);
        let vault = Vault::open_with_vault_key(&path, &vault_key)?;
        Self::wrap(vault, None)
    }

    /// Lock the vault now (ADR-0038 §4).
    ///
    /// Takes the vault out of the shared handle: the vault key is zeroized, the agent's and the
    /// browser extension's lock hooks revoke every lease and deny every pending approval, and any
    /// audit entry still waiting is given one last chance to be written. A release still waiting
    /// on its presence prompt is recorded `VAULT_LOCKED` first and can no longer hand anything
    /// out, whatever the prompt answers. Every release object already handed out stops working.
    ///
    /// The app calls this before it lets go of the session, rather than relying on the last
    /// reference going away: a pending prompt's future holds a reference, so dropping would not
    /// lock until the prompt answered. Idempotent; afterwards every call on this object answers
    /// [`FfiError::VaultLocked`] or an empty result.
    pub fn lock(&self) {
        self.lock_now();
    }

    /// Whether the vault is still unlocked — `false` once [`VaultSession::lock`] has run.
    pub fn is_unlocked(&self) -> bool {
        self.handle.is_unlocked()
    }

    /// The one-time recovery code, if this session created the vault. Returns it once and then
    /// forgets it, so a second caller cannot re-read something the user was told is one-time.
    pub fn take_recovery_code(&self) -> Option<String> {
        self.recovery_code
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    /// Where this vault lives.
    pub fn path(&self) -> String {
        self.path.clone()
    }

    /// A stable identifier for this vault *file* — not a logical vault inside it
    /// ([`crate::types::ItemView::vault_id`], which is a different id with a different lifetime.
    /// This one is the header's own `vault_id` (vault-format §2.1), 16 random bytes minted once
    /// when [`VaultSession::create`] made the file and unchanged for the file's life, hex-encoded.
    ///
    /// Metadata, not secret material: it decides nothing about access and is safe to compare, log
    /// or persist. It exists so the app can tell "the same vault, reopened" apart from "a
    /// different vault that now happens to sit at the same path" — the same distinction
    /// [`kagisecure_core::Error::VaultReplaced`] already makes inside the core, exposed here so
    /// `AppModel`'s "lock and reopen from the file" flow can make it too (a file removed and
    /// replaced by a freshly created vault at the same path must not be recorded as a reopen of
    /// the vault that conflicted).
    pub fn vault_file_id(&self) -> String {
        self.vault_file_id.clone()
    }

    /// How this session unlocked — as last seen, once the vault is locked. (It can change while
    /// unlocked: setting a new master password after a recovery-code unlock makes it `Password`.)
    pub fn unlocked_by(&self) -> UnlockKind {
        let mut last = self
            .unlocked_by
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(now) = self.handle.with(|v| unlock_kind(v.unlocked_by())) {
            *last = now;
        }
        *last
    }

    /// The logical vaults inside the file, for the sidebar's vault switcher.
    pub fn vaults(&self) -> Vec<VaultView> {
        self.read_or(Vec::new(), |vault| {
            vault
                .vault_summaries()
                .iter()
                .map(|s| VaultView {
                    id: s.id.to_string(),
                    name: s.name.clone(),
                    item_count: u32::try_from(s.item_count).unwrap_or(u32::MAX),
                    agent_visible: s.agent_visible,
                    new_items_agent_visible: vault.new_items_agent_visible(s.id),
                })
                .collect()
        })
    }

    /// Share a logical vault with agents, or stop (threat-model M-9, default-deny).
    ///
    /// This is the outermost of the three gates an agent has to get through — vault, then
    /// environment or item, then an approval. With it off, an agent cannot see that the vault
    /// exists, and no environment inside it is reachable however it is flagged.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] if there is no such logical vault; I/O failures.
    pub fn set_vault_agent_visible(&self, vault_id: String, visible: bool) -> FfiResult<bool> {
        self.transact(|tx| {
            let id = tx.find_vault(&vault_id)?;
            Ok(tx.set_vault_agent_visible(id, visible))
        })
    }

    /// Set a logical vault's "Show new items to agents" setting (ADR-0007 amendment
    /// 2026-10-04). Existing items keep their visibility; [`VaultSession::set_agent_visible_bulk`]
    /// changes those. Returns whether the vault was found.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] if there is no such logical vault; I/O failures.
    pub fn set_new_items_agent_visible(&self, vault_id: String, visible: bool) -> FfiResult<bool> {
        self.transact(|tx| {
            let id = tx.find_vault(&vault_id)?;
            let found = tx.set_new_items_agent_visible(id, visible);
            tx.append_audit(AuditDraft {
                actor: "app".to_owned(),
                tool: "set_new_items_agent_visible".to_owned(),
                vault_id: Some(id),
                outcome: Outcome::Allowed,
                detail: Some(format!(
                    "new_items_agent_visible={}",
                    if visible { "on" } else { "off" }
                )),
                ..AuditDraft::default()
            });
            Ok(found)
        })
    }

    /// The agent test-login settings (ADR-0048 §1, §3): off, with no allowed domains, until the
    /// switch is turned on.
    pub fn agent_test_login_settings(&self) -> AgentTestLoginSettingsView {
        self.read_or(
            AgentTestLoginSettingsView {
                enabled: false,
                auto_domains: Vec::new(),
                vault_id: None,
            },
            |vault| match vault.test_login_policy() {
                Some((id, policy)) => AgentTestLoginSettingsView {
                    enabled: policy.enabled,
                    auto_domains: policy.auto_domains.clone(),
                    vault_id: Some(id.to_string()),
                },
                None => AgentTestLoginSettingsView {
                    enabled: false,
                    auto_domains: Vec::new(),
                    vault_id: None,
                },
            },
        )
    }

    /// Turn agent test logins on or off (ADR-0048 §1). Turning them on creates the test-login
    /// vault if there is none. One transaction, audited. The app asks for presence before it calls
    /// this to turn them on (`PresenceOwner.featureSwitch`); Rust cannot see that.
    ///
    /// # Errors
    ///
    /// I/O failures; nothing changes on any error.
    pub fn set_agent_test_logins(&self, enabled: bool) -> FfiResult<()> {
        self.transact(|tx| {
            if !enabled && tx.agent_test_vault().is_none() {
                return Ok(());
            }
            tx.ensure_agent_test_vault("app")?;
            let mut policy = tx
                .test_login_policy()
                .map(|(_, p)| p.clone())
                .unwrap_or_default();
            policy.enabled = enabled;
            tx.set_test_login_policy(policy, "app")
        })
    }

    /// Allow agent test logins without a sheet at `domain` and its subdomains (ADR-0048 §3).
    /// What the person typed is reduced to its registrable domain, which is returned. The app
    /// asks for presence before it calls this.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`]-style refusal for an IP address, a single label such as `localhost`
    /// or a public suffix itself; I/O failures.
    pub fn add_agent_test_login_domain(&self, domain: String) -> FfiResult<String> {
        let Some(domain) = kagisecure_agent::test_login::allowed_domain(&domain) else {
            return Err(FfiError::invalid(
                "Enter a registrable domain such as example.com — not an IP address, a single \
                 name such as localhost, or a public suffix.",
            ));
        };
        self.transact(|tx| {
            tx.ensure_agent_test_vault("app")?;
            let mut policy = tx
                .test_login_policy()
                .map(|(_, p)| p.clone())
                .unwrap_or_default();
            if !policy.auto_domains.contains(&domain) {
                policy.auto_domains.push(domain.clone());
            }
            tx.set_test_login_policy(policy, "app")?;
            Ok(domain)
        })
    }

    /// Stop allowing `domain` (ADR-0048 §3). Returns whether it was on the list.
    ///
    /// # Errors
    ///
    /// I/O failures.
    pub fn remove_agent_test_login_domain(&self, domain: String) -> FfiResult<bool> {
        let wanted = domain.trim().to_ascii_lowercase();
        self.transact(|tx| {
            let Some(mut policy) = tx.test_login_policy().map(|(_, p)| p.clone()) else {
                return Ok(false);
            };
            let before = policy.auto_domains.len();
            policy
                .auto_domains
                .retain(|d| !d.eq_ignore_ascii_case(&wanted));
            if policy.auto_domains.len() == before {
                return Ok(false);
            }
            tx.set_test_login_policy(policy, "app")?;
            Ok(true)
        })
    }

    /// Show every item in `scope` to agents with all its fields, or hide each one and all its
    /// fields — a multi-selection, a tag, a category, or everything — in **one** transaction with
    /// **one** audit entry recording the scope kind and counts, never a tag, a title or a value.
    ///
    /// An item id in [`AgentVisibilityScopeView::Items`] that is not canonical or names no item
    /// is ignored, so a selection that went stale while the list was open changes what is left.
    ///
    /// # Errors
    ///
    /// I/O failures; nothing changes on any error.
    pub fn set_agent_visible_bulk(
        &self,
        scope: AgentVisibilityScopeView,
        visible: bool,
    ) -> FfiResult<BulkVisibilityView> {
        let scope = match scope {
            AgentVisibilityScopeView::Items { item_ids } => AgentVisibilityScope::Items(
                item_ids
                    .iter()
                    .filter_map(|id| kagisecure_core::model::ItemId::parse_canonical(id))
                    .collect(),
            ),
            AgentVisibilityScopeView::Tag { tag } => AgentVisibilityScope::Tag(tag),
            AgentVisibilityScopeView::Category { category } => {
                let Ok(category) = category.parse::<Category>();
                AgentVisibilityScope::Category(category)
            }
            AgentVisibilityScopeView::All => AgentVisibilityScope::All,
        };
        let result = self.transact(|tx| Ok(tx.set_agent_visible_bulk(&scope, visible, "app")))?;
        Ok(BulkVisibilityView {
            matched: u32::try_from(result.matched).unwrap_or(u32::MAX),
            changed: u32::try_from(result.changed).unwrap_or(u32::MAX),
        })
    }

    /// The logical vault new items go into.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] if the file somehow contains no logical vault.
    pub fn default_vault_id(&self) -> FfiResult<String> {
        Ok(self.vault()?.default_vault_id()?.to_string())
    }

    /// The item list for one sidebar section, optionally filtered by the search field.
    ///
    /// `query` matches title, tags and URLs, case-insensitively, and **never** field values
    /// (ui-spec.md §3): a concealed value is not indexed in plaintext, and a public one is not
    /// searched either, so that turning a field from public to concealed cannot change what a
    /// search reveals.
    ///
    /// **Nor notes** (ADR-0038 user decision 3). A note is secret now, and a search that matched
    /// its text would be an oracle: anything that can type into the search field could learn a
    /// note one guess at a time — "does any item's note contain `1234`?" — by watching which rows
    /// stay, with no presence prompt ever shown. That is the same reason field values are not
    /// searched, applied to the one secret that used to be.
    ///
    /// Empty once the vault is locked.
    pub fn list_items(
        &self,
        filter: ItemFilter,
        query: Option<String>,
        sort: ItemSort,
    ) -> Vec<ItemView> {
        let Ok(vault) = self.vault() else {
            return Vec::new();
        };
        select_items(vault.items(), &filter, query, sort)
            .into_iter()
            .map(|item| self.view(&vault, item))
            .collect()
    }

    /// One item by id.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`].
    pub fn item(&self, item_id: String) -> FfiResult<ItemView> {
        let vault = self.vault()?;
        Ok(self.view(&vault, vault.find_item(&item_id)?))
    }

    /// The counts the sidebar shows (ui-spec.md §2.2).
    pub fn sidebar_counts(&self) -> SidebarCounts {
        let Ok(vault) = self.vault() else {
            return SidebarCounts {
                all: 0,
                favorites: 0,
                archive: 0,
                trash: 0,
                categories: Vec::new(),
                tags: Vec::new(),
            };
        };
        let items = vault.items();
        let live = || items.iter().filter(|i| !i.archived && !i.is_trashed());

        let mut categories: Vec<TagCount> = Category::first_class()
            .into_iter()
            .map(|c| TagCount {
                count: count(live().filter(|i| i.category == c)),
                name: c.as_str().to_owned(),
            })
            .collect();
        // Anything a foreign version wrote keeps its own row rather than vanishing.
        let mut extra: Vec<String> = live()
            .filter_map(|i| match &i.category {
                Category::Other(s) => Some(s.clone()),
                _ => None,
            })
            .collect();
        extra.sort_unstable();
        extra.dedup();
        for name in extra {
            let count = count(live().filter(|i| i.category.as_str() == name));
            categories.push(TagCount { name, count });
        }

        let mut tag_names: Vec<String> = live().flat_map(|i| i.tags.iter().cloned()).collect();
        tag_names.sort_unstable();
        tag_names.dedup();
        let tags = tag_names
            .into_iter()
            .map(|name| {
                let count = count(live().filter(|i| i.tags.contains(&name)));
                TagCount { name, count }
            })
            .collect();

        SidebarCounts {
            all: count(live()),
            favorites: count(live().filter(|i| i.favorite)),
            archive: count(items.iter().filter(|i| i.archived && !i.is_trashed())),
            trash: count(items.iter().filter(|i| i.is_trashed())),
            categories,
            tags,
        }
    }

    /// Create an item pre-populated with its category's default fields (vault-format.md §5.4).
    ///
    /// The item is saved immediately, so the list can select it and the detail pane can open it
    /// in edit mode. It is visible to agents, with every field, exactly when its logical vault's
    /// "Show new items to agents" setting is on ([`Tx::add_new_item`]).
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] for an unknown logical vault, plus I/O failures.
    pub fn create_item(
        &self,
        vault_id: Option<String>,
        category: String,
        title: String,
    ) -> FfiResult<ItemView> {
        self.transact(|tx| {
            let target: VaultId = match vault_id {
                Some(v) => tx.find_vault(&v)?,
                None => tx.default_vault_id()?,
            };
            let category: Category = category.parse().unwrap_or(Category::Login);
            let item = Item::from_template(target, category, title);
            let id = item.id.to_string();
            tx.add_new_item(item);
            Ok(self.view(tx, tx.find_item(&id)?))
        })
    }

    /// Replace an item's editable content with what the edit sheet produced (ui-spec.md §4.3).
    ///
    /// Fields carrying an existing id keep it, so a per-field agent-visibility toggle and any
    /// future per-field state survive an edit; a field with no id is new. Fields the draft omits
    /// are deleted. `agent_visible` — item-level and field-level — is *not* taken from the draft:
    /// it has its own toggles and its own methods, so an edit sheet cannot turn agent access on
    /// as a side effect of a rename.
    ///
    /// # `FieldDraft.value: None` (ADR-0038 step 3)
    ///
    /// Edit mode never prefills a concealed value, so most saves carry `None` for fields the user
    /// never touched: this keeps that field's stored [`kagisecure_core::model::FieldValue`]
    /// exactly as it was — moved, not re-derived from a plaintext the app never held — so an edit
    /// that only changes the title cannot, on a failed reveal or any other bug, replace a secret
    /// with an empty string. Two shapes of `None` are refused outright, before anything is
    /// written: a field with no `id` (nothing stored to keep), and a field going from concealed
    /// to public with no new value (which would otherwise turn "untick Concealed, then save" into
    /// a free release of the secret's plaintext).
    ///
    /// `Some("")` on an already-stored field that is staying (or becoming) concealed is treated
    /// exactly like `None` — see `effective_value` — so an empty string arriving through this
    /// call for any reason (a UI bug that puts the wrong row's state on this field, a person who
    /// pressed "Change" and then Save without typing) still cannot overwrite a real secret with
    /// nothing. Only this crate's own boundary can promise that; nothing about the app's UI is
    /// trusted to get an empty-versus-untouched distinction right on secret material.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] for an unknown item; [`FfiError::ItemChangedElsewhere`] (user
    /// decision 4) if the item on disk is no longer the one the edit sheet started from — another
    /// window, the CLI, or another process saved it first. The app should reload the item (its
    /// fresh [`ItemView::revision`] is not returned here, precisely because nothing was written)
    /// and let the user redo their edit; [`FfiError::Invalid`] for either shape of `None` above,
    /// with nothing written; plus I/O failures.
    pub fn save_item(&self, draft: ItemDraft) -> FfiResult<ItemView> {
        let outcome = self.transact(|tx| {
            let current = tx.find_item(&draft.id)?;
            // Checked against the freshest copy this transaction has, not one read before the
            // lock was taken (module doc: every read that decides a mutation belongs in the
            // closure) — otherwise this check could pass against state another writer has
            // already replaced, which is precisely the lost update it exists to catch.
            if item_revision(current, &self.revision_key) != draft.revision {
                return Ok(SaveItemOutcome::Conflict);
            }

            // Validate the whole draft against the freshest copy *before* mutating anything.
            // `Vault::transact` commits whatever this closure returns `Ok(_)` with — including
            // `SaveItemOutcome::Invalid` — so an invalid field must be caught here, with only
            // borrows taken so far, rather than partway through building the replacement fields
            // (`apply_draft`), which would otherwise commit a half-applied edit.
            if let Some(message) = draft_problem(current, &draft) {
                return Ok(SaveItemOutcome::Invalid(message));
            }
            let item = tx.find_item_mut(&draft.id)?;
            apply_draft(item, draft);
            let id = item.id.to_string();
            Ok(SaveItemOutcome::Saved(Box::new(
                self.view(tx, tx.find_item(&id)?),
            )))
        })?;
        match outcome {
            SaveItemOutcome::Saved(view) => Ok(*view),
            SaveItemOutcome::Conflict => Err(FfiError::ItemChangedElsewhere {
                message: "this item was changed elsewhere — reload".to_owned(),
            }),
            SaveItemOutcome::Invalid(message) => Err(FfiError::Invalid { message }),
        }
    }

    /// Toggle the favourite star.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn set_favorite(&self, item_id: String, favorite: bool) -> FfiResult<ItemView> {
        self.mutate(&item_id, |item| {
            item.favorite = favorite;
        })
    }

    /// Move an item to the archive, or bring it back.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn set_archived(&self, item_id: String, archived: bool) -> FfiResult<ItemView> {
        self.mutate(&item_id, |item| {
            item.archived = archived;
        })
    }

    /// Move an item to the trash, or restore it. A soft delete: nothing is destroyed.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn set_trashed(&self, item_id: String, trashed: bool) -> FfiResult<ItemView> {
        self.mutate(&item_id, |item| {
            item.trashed_at = trashed.then(unix_now);
        })
    }

    /// Set the item-level "Visible to agents" toggle (ui-spec.md §4.4).
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn set_agent_visible(&self, item_id: String, visible: bool) -> FfiResult<ItemView> {
        self.mutate(&item_id, |item| {
            item.agent_visible = visible;
            if !visible {
                // Turning the item off turns every field off with it, so an item that is later
                // re-exposed does not silently bring back per-field grants the user forgot about.
                for field in &mut item.fields {
                    field.agent_visible = false;
                }
            }
        })
    }

    /// Set one field's agent-visibility override (ui-spec.md §4.4).
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn set_field_agent_visible(
        &self,
        item_id: String,
        field_id: String,
        visible: bool,
    ) -> FfiResult<ItemView> {
        self.transact(|tx| {
            let item = tx.find_item_mut(&item_id)?;
            let field = item
                .fields
                .iter_mut()
                .find(|f| f.id.to_string() == field_id)
                .ok_or_else(|| kagisecure_core::Error::FieldNotFound {
                    item: item_id.clone(),
                    field: field_id.clone(),
                })?;
            field.agent_visible = visible;
            item.updated_at = unix_now();
            let id = item.id.to_string();
            Ok(self.view(tx, tx.find_item(&id)?))
        })
    }

    /// Delete an item for good. Only reachable from the Trash (ui-spec.md §2.2), and only for
    /// the item as the person saw it there.
    ///
    /// `revision` is the [`ItemView::revision`] of the Trash row the person chose to delete. Both
    /// checks run against the file as it is inside the transaction, not against this session's
    /// memory — the same rule [`VaultSession::save_item`], the other edit that destroys data,
    /// follows:
    ///
    /// * the item must still be **in the Trash**: another window, the CLI or another process may
    ///   have restored it since the row was drawn, and a restored item is one the person wants
    ///   back, not one to destroy;
    /// * it must still be **the item that was shown** (`revision`): if it was changed since —
    ///   restored and binned again, edited, anything — the confirmation was about something else,
    ///   and nothing is deleted.
    ///
    /// By id only (`Tx::remove_item_by_id`): a title or an id prefix never names an item here.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] for no such item; [`FfiError::ItemChangedElsewhere`] if it changed
    /// since `revision` was read (reload the Trash and ask again); [`FfiError::Invalid`] if it is
    /// not in the Trash; plus I/O failures. Nothing is deleted on any error.
    pub fn delete_item(&self, item_id: String, revision: String) -> FfiResult<()> {
        enum Deletion {
            Deleted,
            Stale,
            NotTrashed,
        }
        let outcome = self.transact(|tx| {
            let missing = || kagisecure_core::Error::ItemNotFound(item_id.clone());
            let id =
                kagisecure_core::model::ItemId::parse_canonical(&item_id).ok_or_else(missing)?;
            let current = tx.item_by_id(&id).ok_or_else(missing)?;
            if item_revision(current, &self.revision_key) != revision {
                return Ok(Deletion::Stale);
            }
            if !current.is_trashed() {
                return Ok(Deletion::NotTrashed);
            }
            tx.remove_item_by_id(&id).ok_or_else(missing)?;
            Ok(Deletion::Deleted)
        })?;
        match outcome {
            Deletion::Deleted => Ok(()),
            Deletion::Stale => Err(FfiError::ItemChangedElsewhere {
                message: "this item was changed elsewhere — reload".to_owned(),
            }),
            Deletion::NotTrashed => Err(FfiError::invalid(
                "only an item in the Trash can be deleted for good",
            )),
        }
    }

    /// One field of one item, freshly read. Used after a reveal so the UI can refresh a row.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`].
    pub fn field(&self, item_id: String, field_id: String) -> FfiResult<FieldView> {
        let vault = self.vault()?;
        let item = vault.find_item(&item_id)?;
        item.field(&field_id)
            .map(FieldView::from_core)
            .ok_or_else(|| FfiError::missing("field", field_id))
    }

    /// Every environment, names only (ui-spec.md §10.4). Read-only in M3.
    pub fn environments(&self) -> Vec<EnvironmentView> {
        self.read_or(Vec::new(), |vault| {
            vault
                .environments()
                .iter()
                .map(EnvironmentView::from_core)
                .collect()
        })
    }

    /// One environment.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] if there is no environment with that id or name.
    pub fn environment(&self, environment_id: String) -> FfiResult<EnvironmentView> {
        Ok(EnvironmentView::from_core(
            self.vault()?.find_environment(&environment_id)?,
        ))
    }

    /// Create an empty environment from the app (ui-spec.md §10.4).
    ///
    /// Created **invisible to agents**, unlike one an agent asked for through
    /// `create_environment`: the user has not said anything about sharing it yet, and
    /// default-deny is the rule (threat-model M-9, ADR-0007 §6).
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] on an empty name; I/O failures.
    pub fn create_environment(
        &self,
        name: String,
        description: Option<String>,
    ) -> FfiResult<EnvironmentView> {
        if name.trim().is_empty() {
            return Err(FfiError::invalid("an environment needs a name"));
        }
        self.transact(|tx| {
            let vault_id = tx.default_vault_id()?;
            let mut env = Environment::new(vault_id, name.trim());
            env.description = description.filter(|d| !d.trim().is_empty());
            let id = env.id.to_string();
            tx.add_environment(env);
            tx.append_audit(AuditDraft {
                actor: "app".to_owned(),
                tool: "create_environment".to_owned(),
                vault_id: Some(vault_id),
                outcome: Outcome::Allowed,
                ..AuditDraft::default()
            });
            Ok(EnvironmentView::from_core(tx.find_environment(&id)?))
        })
    }

    /// Share an environment with agents, or stop sharing it.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn set_environment_agent_visible(
        &self,
        environment_id: String,
        visible: bool,
    ) -> FfiResult<EnvironmentView> {
        self.transact(|tx| {
            let env = tx.find_environment_mut(&environment_id)?;
            env.agent_visible = visible;
            env.updated_at = unix_now();
            let id = env.id.to_string();
            Ok(EnvironmentView::from_core(tx.find_environment(&id)?))
        })
    }

    /// Supply the value for a variable, in the app, with the keyboard.
    ///
    /// This is the second half of `add_variables`' pending flow (mcp-server.md §2.6): the agent
    /// named the variable and could not supply a value, and this is where the human does. It is
    /// [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md) crossing 2 — a single
    /// field value going in — applied to an environment's inline binding rather than an item's
    /// field, and it is the only way a value enters an environment from Swift.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] if the environment does not exist; I/O failures.
    pub fn set_variable_value(
        &self,
        environment_id: String,
        name: String,
        value: String,
    ) -> FfiResult<EnvironmentView> {
        if name.trim().is_empty() {
            return Err(FfiError::invalid("a variable needs a name"));
        }
        let name = valid_var_name(&name)?;
        self.transact(|tx| {
            let env = tx.find_environment_mut(&environment_id)?;
            env.set_var(
                name.clone(),
                VarSource::Literal(kagisecure_core::Secret::from_string(value)),
            );
            env.updated_at = unix_now();
            let id = env.id.to_string();
            // `env.id` printed and re-parsed: `EnvId`'s `Display`/`FromStr` round-trip by
            // construction (both are the same UUID formatting), so this cannot fail.
            let parsed_id = id
                .parse()
                .expect("an EnvId's own Display round-trips through FromStr");
            tx.append_audit(AuditDraft {
                actor: "app".to_owned(),
                tool: "set_variable".to_owned(),
                environment_id: Some(parsed_id),
                variables: vec![name.to_string()],
                outcome: Outcome::Allowed,
                ..AuditDraft::default()
            });
            Ok(EnvironmentView::from_core(tx.find_environment(&id)?))
        })
    }

    /// Bind a variable to an item's field instead of a literal — the preferred shape, because
    /// rotating the credential once updates every environment that references it.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] if the environment, item or field does not exist.
    pub fn bind_variable(
        &self,
        environment_id: String,
        name: String,
        item_id: String,
        field_id: String,
    ) -> FfiResult<EnvironmentView> {
        let name = valid_var_name(&name)?;
        self.transact(|tx| {
            let item = tx.find_item(&item_id)?;
            let item_ref = item.id;
            let field = item
                .fields
                .iter()
                .find(|f| f.id.to_string() == field_id)
                .ok_or_else(|| kagisecure_core::Error::FieldNotFound {
                    item: item_id.clone(),
                    field: field_id.clone(),
                })?
                .id;
            let env = tx.find_environment_mut(&environment_id)?;
            env.set_var(
                name.clone(),
                VarSource::ItemField {
                    item: item_ref,
                    field,
                },
            );

            env.updated_at = unix_now();
            let id = env.id.to_string();
            Ok(EnvironmentView::from_core(tx.find_environment(&id)?))
        })
    }

    /// Remove one variable from an environment.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn remove_variable(
        &self,
        environment_id: String,
        name: String,
    ) -> FfiResult<EnvironmentView> {
        self.transact(|tx| {
            let env = tx.find_environment_mut(&environment_id)?;
            env.vars.retain(|v| v.name != name);
            env.updated_at = unix_now();
            let id = env.id.to_string();
            Ok(EnvironmentView::from_core(tx.find_environment(&id)?))
        })
    }

    /// Delete an environment.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], plus I/O failures.
    pub fn delete_environment(&self, environment_id: String) -> FfiResult<()> {
        self.transact(|tx| {
            tx.remove_environment(&environment_id)?;
            Ok(())
        })
    }

    /// A page of the audit log, newest first (ui-spec.md §10.4's audit viewer).
    ///
    /// The log lives in the vault, not in the agent, so this is readable whether or not the
    /// listener is running — which is what a user wants after a lock, when the question is
    /// "what did that thing just do?".
    pub fn audit_page(&self, limit: u32, offset: u32) -> Vec<AuditRowView> {
        let Ok(vault) = self.vault() else {
            return Vec::new();
        };
        let entries = vault.audit_entries();
        entries
            .iter()
            .rev()
            .skip(offset as usize)
            .take(limit as usize)
            .map(|e| AuditRowView {
                seq: e.seq,
                timestamp: e.timestamp,
                actor: e.actor.clone(),
                tool: e.tool.clone(),
                outcome: match e.outcome {
                    Outcome::Allowed => "allowed".to_owned(),
                    Outcome::Denied => "denied".to_owned(),
                    Outcome::Failed => "failed".to_owned(),
                },
                environment_id: e.environment_id.map(|i| i.to_string()),
                item_id: e.item_id.map(|i| i.to_string()),
                variables: e.variables.clone(),
                target_path: e.target_path.clone(),
                detail: e.detail.clone(),
            })
            .collect()
    }

    /// How many entries the audit log has, for the viewer's paging.
    pub fn audit_count(&self) -> u32 {
        self.read_or(0, |v| {
            u32::try_from(v.audit_entries().len()).unwrap_or(u32::MAX)
        })
    }

    /// Replace the master password (ui-spec.md §6, and required after a recovery-code unlock).
    ///
    /// Argon2id runs with **no lock held** — neither the vault file's lock nor the handle's mutex,
    /// which the agent's request loop, the browser extension and every other call on this session
    /// take too. A password change used to derive under that mutex, which stalled all of them for
    /// the whole derivation (hundreds of milliseconds at the desktop profile, seconds on a slow
    /// Mac). It now runs in three short steps around the slow one:
    ///
    /// 1. under the mutex, briefly: copy out the public header facts
    ///    ([`Vault::plan_master_password`]);
    /// 2. with nothing held: Argon2id ([`kagisecure_core::vault::MasterPasswordPlan::derive`]);
    /// 3. under the mutex, briefly: wrap the vault key under the derived key
    ///    ([`Vault::wrap_master_password`], one AEAD, no KDF);
    ///
    /// and then the transaction installs the slot ([`Tx::install_master_password`]) with its
    /// audit entry. The plan remembers the slot and KDF descriptor it was taken against, so a
    /// password change or KDF upgrade another process made meanwhile is refused at install, not
    /// silently undone. A lock while the derivation runs makes step 3 answer
    /// [`FfiError::VaultLocked`] and nothing is installed.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] (`kagisecure_core::Error::VaultConflict`) if another process changed
    /// the master password or the KDF cost first, so the prepared slot no longer replaces what is
    /// actually in the header — call this again to prepare against the fresh one;
    /// [`FfiError::VaultLocked`]; plus KDF, RNG and I/O failures.
    pub fn change_master_password(&self, new_password: String) -> FfiResult<()> {
        self.change_master_password_with(new_password, || {})
    }

    /// [`VaultSession::vault_file_id`] as the header's raw bytes — what a platform keystore binds
    /// its wrapped key to (ADR-0033: part of the Windows Hello blob's associated data), so a blob
    /// cannot be moved to another vault file. Not secret: it is in the plaintext header, and
    /// [`crate::platform_slot_info`] reads it without unlocking. Taken from the header this
    /// session unlocked, and unchanged for its life: a transaction refuses a file whose id differs
    /// ([`kagisecure_core::Error::VaultReplaced`]), so this is never a replaced file's id.
    pub fn vault_file_id_bytes(&self) -> Vec<u8> {
        self.vault_file_id_bytes.clone()
    }

    /// Whether this vault has a platform (Touch ID) slot.
    pub fn has_platform_slot(&self) -> bool {
        self.read_or(false, |v| v.platform_slot().is_some())
    }

    /// The platform slot's identifier, if there is one.
    pub fn platform_slot_id(&self) -> Option<String> {
        self.read_or(None, |v| v.platform_slot().map(|s| s.id.clone()))
    }

    /// Hand the raw vault key out for the Secure Enclave to encrypt.
    ///
    /// [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md) crossing 3, and the
    /// narrowest one: it is called once, during enrolment, and the caller is expected to pass the
    /// result to `SecKeyCreateEncryptedData` and then to
    /// [`VaultSession::install_platform_slot`] without holding on to it.
    ///
    /// Audited best-effort (ADR-0040 step 10), as `vault_key_export`: the key leaves the vault
    /// whether or not that entry can be written right now, and a failed write stays queued.
    ///
    /// Empty once the vault is locked — which [`VaultSession::install_platform_slot`] refuses, so
    /// an enrolment racing a lock cannot install a slot that opens nothing.
    pub fn export_vault_key_for_platform_wrapping(&self) -> Vec<u8> {
        let Ok(vault) = self.vault() else {
            return Vec::new();
        };
        let key = vault.export_vault_key_for_platform_wrapping().to_vec();
        self.record_after(vault, app_draft(AUDIT_TOOL_VAULT_KEY_EXPORT, None));
        key
    }

    /// Store the keystore's wrapped copy of the vault key, replacing any existing platform slot.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] for an empty blob — which would mean the keystore returned nothing
    /// and enrolling it would produce a slot that can never unlock — plus I/O failures.
    pub fn install_platform_slot(
        &self,
        slot_id: String,
        label: String,
        wrapped_key: Vec<u8>,
    ) -> FfiResult<()> {
        if wrapped_key.is_empty() {
            return Err(FfiError::invalid("the keystore returned no wrapped key"));
        }
        self.transact(|tx| {
            tx.install_platform_slot(&slot_id, &label, wrapped_key);
            tx.append_audit(app_draft(AUDIT_TOOL_TOUCH_ID_ENROL, None));
            Ok(())
        })
    }

    /// Forget the platform slot — the user turned Touch ID off, or the Enclave key is gone.
    ///
    /// # Errors
    ///
    /// I/O failures.
    pub fn remove_platform_slot(&self) -> FfiResult<bool> {
        self.transact(|tx| {
            let removed = tx.remove_platform_slot();
            if removed {
                tx.append_audit(app_draft(AUDIT_TOOL_TOUCH_ID_REMOVE, None));
            }
            Ok(removed)
        })
    }

    // MARK: - Import (import.md §8)

    /// Parse an export into a plan and hand back a handle to it.
    ///
    /// A method on the session rather than a free function, because importing into a vault
    /// requires one to be open — the app's File ▸ Import… is disabled while locked, and this is
    /// what makes that a property of the API rather than only of the menu.
    ///
    /// Nothing is written. The parse finishes here, so a malformed archive fails with the vault
    /// untouched; the values it produced stay inside the returned object. See `crate::import` for
    /// why that object is the only thing that crosses.
    ///
    /// `format` overrides detection the way `--format` does; `None` lets the parser be chosen
    /// from the file.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotFound`] if there is no file there, [`FfiError::Invalid`] if it cannot be
    /// parsed — a format that could not be told apart, a missing column, a parser limit.
    pub fn import_preview(
        &self,
        path: String,
        format: Option<ImportFormat>,
    ) -> FfiResult<Arc<ImportPlanHandle>> {
        crate::import::preview(&path, format)
    }

    /// The same plan, previewed against *this* vault under `policy`.
    ///
    /// [`ImportPlanHandle::report`] cannot know about duplicates, because a plan knows nothing
    /// about any vault. This is the report the sheet actually shows: same counts, plus a
    /// per-item action and the number of items the vault already has.
    ///
    /// Reads the vault. Writes nothing, to it or to the disk.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] if the plan has already been committed.
    pub fn import_preview_against(
        &self,
        plan: Arc<ImportPlanHandle>,
        policy: DuplicatePolicyView,
    ) -> FfiResult<ImportReportView> {
        plan.report_against(&*self.vault()?, policy)
    }

    /// Apply the plan and save.
    ///
    /// `target_vault` names one logical vault to put everything in, the way `--logical-vault`
    /// does; with `None` each item goes where the source said. A named vault the file does not
    /// have is created, and the outcome says which names those were.
    ///
    /// The plan is spent only by a commit that reached the disk: the handle then refuses a second
    /// call rather than importing twice. A commit that did not — another writer held the lock
    /// past the app's wait ([`FfiError::Busy`]), the file diverged, the write failed — leaves the
    /// handle exactly as it was, so the sheet can say what happened and offer Import again
    /// without making the person choose the file a second time. The save is the same atomic
    /// `0600` write every other mutating method on this object performs, so the file is either
    /// the old one or the new one.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] if the plan is spent or a commit of it is already running, or I/O
    /// failures from the save.
    pub fn import_commit(
        &self,
        plan: Arc<ImportPlanHandle>,
        policy: DuplicatePolicyView,
        target_vault: Option<String>,
    ) -> FfiResult<ImportOutcomeView> {
        // Checking the handle out touches only its own mutex, never the vault, so it happens
        // before any lock is taken — same rule as `prepare_master_password`.
        let checked_out = plan.begin_commit(target_vault)?;
        let result = self.transact(|tx| ImportPlanHandle::apply(tx, checked_out.plan(), policy));
        match result {
            Ok(outcome) => {
                checked_out.spend();
                Ok(outcome)
            }
            // Dropping the checkout puts the plan back, as it was before this call.
            Err(e) => Err(e),
        }
    }

    /// Write the vault to disk. Every mutating method already does through its own transaction;
    /// this is for a "save now" affordance and for tests. A transaction of its own — rather than
    /// the old direct, non-transactional `Vault::save` (crate-private since ADR-0039 step 6) — so
    /// it also picks up another writer's changes and flushes anything still in the pending audit
    /// queue, instead of merely risking [`kagisecure_core::Error::VaultConflict`] against stale
    /// in-memory state.
    ///
    /// # Errors
    ///
    /// I/O failures.
    pub fn save(&self) -> FfiResult<()> {
        self.transact(|_| Ok(()))
    }

    /// Whether the audit hash chain verifies (vault-format.md §8).
    ///
    /// `true` once the vault is locked: there is no log in memory to find broken, and `false`
    /// would raise the "audit log damaged" warning over a vault that is merely locked.
    pub fn audit_intact(&self) -> bool {
        self.read_or(true, |v| v.verify_audit().is_ok())
    }

    /// Whether every appended audit entry has actually made it to disk.
    ///
    /// Every mutating call in this file already saves before it returns, so in the common case
    /// this is `{ unsaved_entries: 0, last_error: None }`. It stops being that the moment a save
    /// starts failing somewhere the caller could not afford to fail loudly (agent-side denials in
    /// `kagisecure-agent::service`, extension refusals in `kagisecure-agent::extension`) — this is
    /// how the app notices and tells the human, even though this process was not the one whose
    /// save failed.
    pub fn audit_durability(&self) -> AuditDurabilityView {
        self.read_or(
            AuditDurabilityView {
                unsaved_entries: 0,
                last_error: None,
            },
            |vault| AuditDurabilityView {
                unsaved_entries: u32::try_from(vault.unsaved_audit_entries()).unwrap_or(u32::MAX),
                last_error: vault.last_save_error(),
            },
        )
    }

    // MARK: - Other writers (step 4, user decisions 3 and 4)

    /// Bring this session up to date with the file, if another writer changed it since the last
    /// call ([`Vault::refresh_if_changed`], via [`VaultHandle::sync`]).
    ///
    /// The app calls this on `NSApplicationDidBecomeActive`, on a timer (~2s) while it is
    /// frontmost, and right before the Audit view re-reads the log — never on every read, because
    /// a read needs no lock and this crate's writers already start every write from the file as it
    /// is (`Vault::transact`). `true` means either the in-memory state changed (re-read the lists)
    /// or a conflict was just detected or resolved (re-read [`VaultSession::conflict`]); `false`
    /// means nothing to do, including "could not even check right now" (a transient I/O error,
    /// where the safest thing is to keep showing what is in memory and try again next tick).
    pub fn sync(&self) -> bool {
        use kagisecure_core::Error as E;
        match self.handle.sync() {
            None => false,
            Some(Ok(changed)) => {
                self.clear_conflict();
                changed
            }
            Some(Err(E::VaultDiverged(_))) => {
                self.set_conflict(VaultConflictKindView::Diverged);
                true
            }
            Some(Err(E::VaultReplaced(_))) => {
                self.set_conflict(VaultConflictKindView::Replaced);
                true
            }
            Some(Err(E::VaultNotFound(_))) => {
                self.set_conflict(VaultConflictKindView::Removed);
                true
            }
            // Could not read the file: say nothing, keep showing memory, try again next tick.
            Some(Err(E::Io(_))) => false,
            // Read, and not decodable as this vault — a parse or format-version failure. Ask the
            // core what the file is rather than guessing from the variant.
            Some(Err(_)) => matches!(self.examine(), Ok(Some(_))),
        }
    }

    /// Why writes have stopped, if they have (step 4, user decision 3). `None` the rest of the
    /// time, including while merely locked-out-briefly ([`FfiError::Busy`] is not a conflict: it
    /// clears itself the moment the other writer lets go).
    pub fn conflict(&self) -> Option<VaultConflictKindView> {
        *self.conflict.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What choosing "Keep this app's version (overwrite the file)" would discard, for the
    /// confirmation shown before it runs; `None` if there is no conflict (any more).
    ///
    /// Reads the file ([`Vault::examine_conflict`]) and changes nothing on disk. It does update
    /// [`VaultSession::conflict`] to match what it found — including clearing it when the file
    /// turns out to continue this session again — and remembers the full answer, so that
    /// [`VaultSession::keep_app_version_over_conflict`] acts on exactly what the person read.
    ///
    /// # Errors
    ///
    /// [`FfiError::Io`] if the file could not be read at all (which is not the same as it being
    /// missing: that is [`VaultConflictKindView::Removed`]).
    pub fn conflict_details(&self) -> FfiResult<Option<VaultConflictDetailsView>> {
        self.examine()
    }

    /// "Keep this app's version (overwrite the file)" — one of the two choices the conflict alert
    /// offers, run only after the person confirmed `confirmed` (from
    /// [`VaultSession::conflict_details`]).
    ///
    /// Replaces the vault file with this session's header and body
    /// ([`Vault::overwrite_with_this_session`]), writing every audit entry still waiting in this
    /// session first and then one recording what was overwritten. Because the *header* is this
    /// session's, a master password, recovery code or Touch ID enrolment that exists only in the
    /// file's version is discarded with it, and this session's ones work again — which is why
    /// [`VaultConflictDetailsView`] reports them and the confirmation must say so. A missing file
    /// is recreated.
    ///
    /// Refuses to act on anything but what was confirmed: if the file changed after
    /// `confirmed` was built, nothing is written and the outcome is
    /// [`KeepAppVersionOutcome::FileChangedAgain`] with the new details, to confirm again. If the
    /// file continues this session again, nothing needs overwriting: the session catches up with
    /// it by an ordinary transaction and the outcome is
    /// [`KeepAppVersionOutcome::NoLongerInConflict`].
    ///
    /// # Errors
    ///
    /// [`FfiError::Busy`] if another writer held the lock past the app's wait (nothing was
    /// written; the conflict stays), and I/O failures. The conflict stays set on every error.
    pub fn keep_app_version_over_conflict(
        &self,
        confirmed: VaultConflictDetailsView,
    ) -> FfiResult<KeepAppVersionOutcome> {
        use kagisecure_core::Error as E;

        let examined = self
            .examined_conflict
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(examined) = examined.filter(|c| describes(c, &confirmed)) else {
            // Not what this session last showed: the person has to see the current answer.
            return self.reexamined();
        };

        let result = {
            let mut vault = self.vault()?;
            let own = vault.lock_timeout();
            vault.set_lock_timeout(APP_LOCK_TIMEOUT);
            let result =
                vault.overwrite_with_this_session(&examined, "app", KEEP_APP_VERSION_REASON);
            vault.set_lock_timeout(own);
            result
        };
        match result {
            Ok(()) => {
                self.forget_examined();
                self.clear_conflict();
                Ok(KeepAppVersionOutcome::Overwritten)
            }
            Err(E::VaultNotInConflict(_)) => self.catch_up_with_file(),
            // The file is not what was confirmed any more (or, unreachably, this session holds
            // nothing to write): never act on a stale confirmation.
            Err(E::VaultConflict(_)) => self.reexamined(),
            Err(e) => Err(self.map_write_error(e)),
        }
    }

    /// Best-effort audit note that a *new* session was opened to recover from a conflict
    /// (`VaultConflictKindView`) the *previous* session detected — call once, right after a fresh
    /// `unlock_with_*`/`create` succeeds in response to "Lock and reopen from the file".
    ///
    /// Never fails outward, the same way a reveal or a copy never blocks on the audit log (user
    /// decision 1): losing this note must not stand between the human and getting back into their
    /// vault. Uses [`VaultHandle::record_best_effort`] directly rather than going through
    /// `VaultSession::transact`, because a freshly opened session has nothing to be in conflict
    /// with yet — this is a plain best-effort append, not a write that needs to itself detect one.
    pub fn note_reopened_after_conflict(&self) {
        self.handle.record_best_effort(
            APP_LOCK_TIMEOUT,
            AuditDraft {
                actor: "app".to_owned(),
                tool: "vault_reopened_after_conflict".to_owned(),
                outcome: Outcome::Allowed,
                ..AuditDraft::default()
            },
        );
    }
}

impl VaultSession {
    /// Examine the file ([`Vault::examine_conflict`]), record what was found — the conflict kind
    /// for [`VaultSession::conflict`], the full answer for
    /// [`VaultSession::keep_app_version_over_conflict`] — and describe it.
    fn examine(&self) -> FfiResult<Option<VaultConflictDetailsView>> {
        let (found, session_audit_entries) = {
            let vault = self.vault()?;
            (vault.examine_conflict()?, vault.audit_entries().len())
        };
        let details = found
            .as_ref()
            .map(|c| VaultConflictDetailsView::from_core(c, session_audit_entries));
        match &details {
            Some(d) => self.set_conflict(d.kind),
            None => self.clear_conflict(),
        }
        *self
            .examined_conflict
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = found;
        Ok(details)
    }

    /// The answer when a confirmation turned out stale: what the file is now.
    fn reexamined(&self) -> FfiResult<KeepAppVersionOutcome> {
        match self.examine()? {
            Some(details) => Ok(KeepAppVersionOutcome::FileChangedAgain { details }),
            None => self.catch_up_with_file(),
        }
    }

    /// The file continues this session again: adopt it the ordinary way (a transaction, which
    /// also writes anything still waiting in the audit queue) instead of overwriting it.
    fn catch_up_with_file(&self) -> FfiResult<KeepAppVersionOutcome> {
        self.transact(|_| Ok(()))?;
        self.forget_examined();
        self.clear_conflict();
        Ok(KeepAppVersionOutcome::NoLongerInConflict)
    }

    fn forget_examined(&self) {
        *self
            .examined_conflict
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// A single-field toggle on one item: favourite, archive, trash, agent-visible. Reads the item
    /// fresh inside the transaction and applies `change` to it — last-writer-wins (user decision
    /// 4), unlike [`VaultSession::save_item`], which refuses over a stale base. A toggle has
    /// nothing to lose a race over: two toggles of the same flag converge on whichever ran last,
    /// exactly as if they had happened one after the other.
    fn mutate(&self, item_id: &str, change: impl FnOnce(&mut Item)) -> FfiResult<ItemView> {
        self.transact(|tx| {
            let item = tx.find_item_mut(item_id)?;
            change(item);
            item.updated_at = unix_now();
            let id = item.id.to_string();
            Ok(self.view(tx, tx.find_item(&id)?))
        })
    }
}

/// Whether `details` — what the person confirmed — describes `conflict`. The session's own audit
/// length is left out: it does not change what the file would lose.
fn describes(conflict: &FileConflict, details: &VaultConflictDetailsView) -> bool {
    let current = VaultConflictDetailsView::from_core(conflict, 0);
    current.kind == details.kind
        && current.file_fingerprint == details.file_fingerprint
        && current.diverged == details.diverged
}

/// Audit `tool` for a master-password change.
pub(crate) const AUDIT_TOOL_CHANGE_MASTER_PASSWORD: &str = "change_master_password";
/// Audit `tool` for installing a Touch ID (platform) slot.
pub(crate) const AUDIT_TOOL_TOUCH_ID_ENROL: &str = "touch_id_enrol";
/// Audit `tool` for removing the Touch ID (platform) slot.
pub(crate) const AUDIT_TOOL_TOUCH_ID_REMOVE: &str = "touch_id_remove";
/// Audit `tool` for handing the vault key out for the Secure Enclave to wrap.
pub(crate) const AUDIT_TOOL_VAULT_KEY_EXPORT: &str = "vault_key_export";

/// What is wrong with `draft` as an edit of `current`, if anything — checked before anything is
/// mutated (`VaultSession::save_item`, and a shared vault's `save_item`). `None` when the draft
/// may be applied with [`apply_draft`].
pub(crate) fn draft_problem(current: &Item, draft: &ItemDraft) -> Option<String> {
    let by_id: std::collections::HashMap<String, &Field> = current
        .fields
        .iter()
        .map(|f| (f.id.to_string(), f))
        .collect();
    for f in &draft.fields {
        let old = f.id.as_deref().and_then(|id| by_id.get(id));
        let value = effective_value(f.concealed, f.value.clone(), old.is_some());
        match (value, old) {
            (None, None) => {
                return Some(format!("field \"{}\" is new and needs a value", f.label));
            }
            (None, Some(old)) if !f.concealed && old.value.is_secret() => {
                return Some(format!(
                    "field \"{}\" cannot be made public without a new value",
                    f.label
                ));
            }
            // A stored secret keeps its kind unless its value comes with the change —
            // shown under presence (`EditReveal`) or typed anew. A kind is what the list's
            // card digits, the presence prompt's noun and the primary secret's candidacy
            // are read from, precisely because a label is not trustworthy; letting "PIN,
            // kind Concealed" become "PIN, kind CreditCardNumber" for free would print the
            // PIN's digits under the title without anyone touching the sensor.
            (None, Some(old)) if old.value.is_secret() && f.kind.to_core() != old.kind => {
                return Some(format!(
                    "field \"{}\" cannot change kind without its value: show it or enter \
                     a new one first",
                    f.label
                ));
            }
            _ => {}
        }
    }
    None
}

/// Apply `draft` to `item`, which [`draft_problem`] has already accepted it for: the rules
/// [`VaultSession::save_item`] documents.
pub(crate) fn apply_draft(item: &mut Item, draft: ItemDraft) {
    // Per-field state the draft does not carry and an edit must not destroy: the agent
    // visibility toggle, `Field::extra` — the metadata an importer wrote (vault-format §9
    // rule 1 says a round trip does not drop what this build did not put in the sheet) —
    // and, for a field the draft asks to keep, the stored value itself. `Secret` has no
    // `Clone` (model/secret.rs) by design, so "keep the stored value" means moving the
    // same field forward out of the item, never reconstructing it from a plaintext this
    // process was never handed.
    //
    // An item written before the primary-secret designation existed gets it now, from its
    // fields as they were *before* this edit: whatever the edit relabels, reorders or
    // retypes, it cannot choose which field is "the password" (`Item::primary_secret`).
    item.pin_primary_secret();
    let mut old_fields: std::collections::HashMap<String, Field> = std::mem::take(&mut item.fields)
        .into_iter()
        .map(|f| (f.id.to_string(), f))
        .collect();

    item.title = draft.title;
    item.category = draft.category.parse().unwrap_or(Category::Login);
    item.tags = draft.tags;
    item.urls = draft.urls;
    // `None` keeps the stored note, exactly as `FieldDraft.value: None` keeps a field's
    // value: the edit sheet no longer receives a note to send back (it is secret, and
    // `ItemView` carries only `has_notes`), so "not sent" must never mean "delete".
    // An empty string is how the sheet says "the person cleared it".
    match draft.notes {
        None => {}
        Some(n) if n.is_empty() => item.notes = None,
        Some(n) => item.notes = Some(SecretText::new(n)),
    }

    let mut fields = Vec::with_capacity(draft.fields.len());
    // Fields whose value this save supplied rather than kept: the only ones that may take
    // up a primary-secret role nobody holds any more (below).
    let mut supplied = Vec::new();
    for f in draft.fields {
        let old = f.id.as_ref().and_then(|id| old_fields.remove(id));
        let value = effective_value(f.concealed, f.value, old.is_some());
        let supplies_value = value.is_some();
        let (value, agent_visible, extra, unknown) = match (value, old) {
            (Some(v), Some(old)) => (
                field_value(f.concealed, v),
                old.agent_visible,
                old.extra,
                old.unknown,
            ),
            (Some(v), None) => (
                field_value(f.concealed, v),
                f.agent_visible,
                std::collections::BTreeMap::new(),
                std::collections::BTreeMap::new(),
            ),
            (None, Some(old)) => {
                // `draft_problem` already refused a `None` here unless `old` is
                // present and (staying concealed or already public), so moving `old.value`
                // forward untouched can never smuggle a secret into a public field.
                (old.value, old.agent_visible, old.extra, old.unknown)
            }
            (None, None) => unreachable!(
                "save_item: `draft_problem` already refused field \"{}\" (new, with no value)",
                f.label
            ),
        };
        let mut field = Field {
            id: f
                .id
                .and_then(|id| id.parse().ok())
                .unwrap_or_else(kagisecure_core::model::FieldId::new),
            label: f.label,
            kind: f.kind.to_core(),
            value,
            section: f.section.filter(|s| !s.is_empty()),
            agent_visible,
            extra,
            unknown,
        };
        // Keep the tag and the value in step: a field the user made concealed is a
        // `Concealed` field, whatever kind it started as.
        if field.value.is_secret() && field.kind == kagisecure_core::proto::FieldKind::Text {
            field.kind = kagisecure_core::proto::FieldKind::Concealed;
        }
        if supplies_value && field.is_primary_secret_candidate() {
            supplied.push(field.id);
        }
        fields.push(field);
    }
    item.fields = fields;
    // The designated field was deleted, or the item never had a secret: the first secret
    // this very save wrote — a value the editor typed or saw under presence — takes the
    // role. Never a kept one: handing the role to a field nobody chose for it is what the
    // designation exists to stop.
    if item.primary_secret_field().is_none()
        && let Some(first) = supplied.first()
    {
        item.primary_secret = Some(*first);
    }
    item.updated_at = unix_now();
}

/// An `Allowed` entry by the app.
pub(crate) fn app_draft(tool: &str, detail: Option<&str>) -> AuditDraft {
    AuditDraft {
        actor: "app".to_owned(),
        tool: tool.to_owned(),
        outcome: Outcome::Allowed,
        detail: detail.map(str::to_owned),
        ..AuditDraft::default()
    }
}

/// A variable name the app's editor typed, trimmed and validated: an identifier, or a refusal
/// the editor can show as it is (`VarName`'s own documentation has why a name must be one).
///
/// `pub(crate)`: a shared vault's environment editor (`crate::shared`) validates a variable name
/// the same way.
pub(crate) fn valid_var_name(name: &str) -> FfiResult<VarName> {
    VarName::new(name.trim()).map_err(|e| FfiError::invalid(e.to_string()))
}

fn unlock_kind(by: UnlockedBy) -> UnlockKind {
    match by {
        UnlockedBy::Password => UnlockKind::Password,
        UnlockedBy::RecoveryCode => UnlockKind::RecoveryCode,
        UnlockedBy::PlatformKey => UnlockKind::PlatformKey,
    }
}

/// The items of one sidebar section, filtered by the search field and sorted — the rules
/// [`VaultSession::list_items`] documents, shared with a shared vault's list.
pub(crate) fn select_items<'a>(
    items: impl IntoIterator<Item = &'a Item>,
    filter: &ItemFilter,
    query: Option<String>,
    sort: ItemSort,
) -> Vec<&'a Item> {
    let needle = query
        .map(|q| q.trim().to_lowercase())
        .filter(|q| !q.is_empty());

    let mut hits: Vec<&Item> = items
        .into_iter()
        .filter(|i| matches_filter(i, filter))
        .filter(|i| match &needle {
            None => true,
            Some(n) => {
                i.title.to_lowercase().contains(n)
                    || i.tags.iter().any(|t| t.to_lowercase().contains(n))
                    || i.urls.iter().any(|u| u.to_lowercase().contains(n))
            }
        })
        .collect();

    match sort {
        ItemSort::Title => hits.sort_by_key(|i| i.title.to_lowercase()),
        ItemSort::DateModified => hits.sort_by_key(|i| std::cmp::Reverse(i.updated_at)),
        ItemSort::DateCreated => hits.sort_by_key(|i| std::cmp::Reverse(i.created_at)),
        ItemSort::Category => {
            hits.sort_by_key(|i| (i.category.as_str().to_owned(), i.title.to_lowercase()))
        }
    }
    hits
}

fn count<'a>(iter: impl Iterator<Item = &'a Item>) -> u32 {
    u32::try_from(iter.count()).unwrap_or(u32::MAX)
}

pub(crate) fn matches_filter(item: &Item, filter: &ItemFilter) -> bool {
    let live = !item.archived && !item.is_trashed();
    match filter {
        ItemFilter::All => live,
        ItemFilter::Favorites => live && item.favorite,
        ItemFilter::Category { category } => live && item.category.as_str() == category,
        ItemFilter::Tag { tag } => live && item.tags.iter().any(|t| t == tag),
        ItemFilter::Archive => item.archived && !item.is_trashed(),
        ItemFilter::Trash => item.is_trashed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate::{TotpAlgorithm, TotpCodeView, totp_uri_from_parts};
    use crate::types::{FieldDraft, FieldKind};

    const URI: &str = "otpauth://totp/ACME:ada@example.com\
        ?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30";

    /// A vault with one Login item carrying a TOTP field, at KDF parameters that protect nothing.
    fn fixture() -> (tempfile::TempDir, Arc<VaultSession>, String, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("t.kagivault").display().to_string();
        let session = VaultSession::create(
            path,
            "pw".to_owned(),
            "Personal".to_owned(),
            Some(64),
            Some(1),
        )
        .expect("create");
        let item = session
            .create_item(None, "login".to_owned(), "GitHub".to_owned())
            .expect("item");
        let fields = item
            .fields
            .iter()
            .map(|f| FieldDraft {
                id: Some(f.id.clone()),
                label: f.label.clone(),
                kind: f.kind,
                concealed: f.concealed,
                value: Some(if f.kind == FieldKind::Totp {
                    URI.to_owned()
                } else {
                    String::new()
                }),
                section: f.section.clone(),
                agent_visible: f.agent_visible,
            })
            .collect();
        let saved = session
            .save_item(ItemDraft {
                id: item.id.clone(),
                category: item.category.clone(),
                title: item.title.clone(),
                fields,
                tags: Vec::new(),
                urls: Vec::new(),
                notes: None,
                revision: item.revision.clone(),
            })
            .expect("save");
        let field_id = saved
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .expect("a totp field")
            .id
            .clone();
        (dir, session, saved.id, field_id)
    }

    /// A presence gate that always says yes — these tests are about what a release carries, not
    /// about the gate (`tests/release_presence_adversarial.rs` is).
    struct YesGate;

    #[async_trait::async_trait]
    impl crate::presence::PresenceGate for YesGate {
        async fn confirm(&self, _reason: String) -> crate::presence::PresenceOutcome {
            crate::presence::PresenceOutcome::Confirmed
        }
    }

    fn with_yes_gate(session: &VaultSession) {
        // A second install is refused, and the first `YesGate` stays: either way, yes.
        let _ = session.set_presence_gate(Arc::new(YesGate));
    }

    /// One field's value, through a confirmed release.
    fn reveal(session: &VaultSession, item: String, field: String) -> FfiResult<String> {
        with_yes_gate(session);
        futures::executor::block_on(session.release_field(
            item,
            field,
            crate::presence::ReleasePurpose::Reveal,
        ))?
        .value()
    }

    /// A one-time code at `at`, through a confirmed release.
    fn code(
        session: &VaultSession,
        item: String,
        field: Option<String>,
        at: u64,
    ) -> FfiResult<TotpCodeView> {
        with_yes_gate(session);
        futures::executor::block_on(session.release_totp(
            item,
            field,
            crate::presence::ReleasePurpose::Reveal,
        ))?
        .code_at(at)
    }

    #[test]
    fn a_stored_totp_field_produces_a_code_and_a_countdown() {
        let (_dir, session, item, field) = fixture();
        let view = code(&session, item.clone(), Some(field), 1_699_999_980).expect("a code");
        assert_eq!(view.code.len(), 6);
        assert_eq!(view.seconds_remaining, 30);
        assert_eq!(view.params.issuer.as_deref(), Some("ACME"));

        // The item-level lookup finds the same field without being told which one it is.
        let by_item = code(&session, item, None, 1_699_999_980).expect("the item has one");
        assert_eq!(by_item.code, view.code);
    }

    #[test]
    fn the_stored_field_stays_concealed_in_every_list_view() {
        let (_dir, session, item, field) = fixture();
        let view = session.item(item.clone()).expect("the item");
        let totp = view
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .expect("the field");
        assert!(totp.concealed, "a TOTP seed is secret material");
        assert!(totp.has_value);
        assert!(
            totp.value.is_none(),
            "the seed must not ride along on a rendered field list"
        );
        // Released deliberately, it is the URI, which is what the edit sheet's "Show current
        // setup" needs.
        let revealed = reveal(&session, item, field).expect("reveal");
        assert!(revealed.starts_with("otpauth://"));
    }

    #[test]
    fn a_field_that_is_not_a_one_time_password_is_refused() {
        let (_dir, session, item, _) = fixture();
        let view = session.item(item.clone()).expect("the item");
        let password = view
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Concealed)
            .expect("the password field")
            .id
            .clone();
        let error = code(&session, item.clone(), Some(password), 0).expect_err("not a TOTP field");
        assert!(error.to_string().contains("not a one-time password"));
        assert!(code(&session, item, Some("nope".to_owned()), 0).is_err());
    }

    #[test]
    fn an_item_with_no_totp_field_is_refused_before_any_prompt() {
        let (_dir, session, _, _) = fixture();
        let bare = session
            .create_item(None, "secure-note".to_owned(), "Notes".to_owned())
            .expect("item");
        assert!(matches!(
            code(&session, bare.id, None, 0),
            Err(FfiError::NotPresent { .. })
        ));
    }

    #[test]
    fn a_hand_built_uri_can_be_saved_and_read_back() {
        let (_dir, session, item, field) = fixture();
        let uri = totp_uri_from_parts(
            "JBSWY3DPEHPK3PXP".to_owned(),
            crate::generate::TotpParamsView {
                algorithm: TotpAlgorithm::Sha256,
                digits: 8,
                period: 60,
                issuer: Some("Manual".to_owned()),
                account: None,
                caption: None,
            },
        )
        .expect("a uri");
        let view = session.item(item.clone()).expect("the item");
        let fields = view
            .fields
            .iter()
            .map(|f| FieldDraft {
                id: Some(f.id.clone()),
                label: f.label.clone(),
                kind: f.kind,
                concealed: f.concealed,
                // `None` for every field but the one being changed — exercising the same "keep
                // the stored value" path edit mode now uses instead of round-tripping a value
                // this process never held.
                value: if f.id == field {
                    Some(uri.clone())
                } else {
                    None
                },
                section: f.section.clone(),
                agent_visible: f.agent_visible,
            })
            .collect();
        session
            .save_item(ItemDraft {
                id: view.id.clone(),
                category: view.category.clone(),
                title: view.title.clone(),
                fields,
                tags: Vec::new(),
                urls: Vec::new(),
                notes: None,
                revision: view.revision.clone(),
            })
            .expect("save");
        let view = code(&session, item, Some(field), 59).expect("a code");
        assert_eq!(view.code.len(), 8);
        assert_eq!(view.params.period, 60);
        assert_eq!(view.params.issuer.as_deref(), Some("Manual"));
    }

    // MARK: - Step 4: transactional writes through the FFI

    /// A second `VaultSession` on the same file, unlocked with the fixture's password.
    fn second_handle(session: &VaultSession) -> Arc<VaultSession> {
        VaultSession::unlock_with_password(session.path(), "pw".to_owned())
            .expect("a second handle on the same vault")
    }

    /// A toggle from one handle must not undo an item another handle just added — each
    /// `transact` re-reads the file first, so the second writer's transaction starts from the
    /// first writer's committed state rather than from stale memory.
    #[test]
    fn a_toggle_survives_alongside_another_handles_new_item() {
        let (_dir, session, item_id, _field) = fixture();
        let other = second_handle(&session);

        // `other` writes first, from its own — currently identical — view of the file.
        let added = other
            .create_item(None, "secure-note".to_owned(), "Added elsewhere".to_owned())
            .expect("create on the second handle");

        // `session` still thinks the file is the version it last saw; its own transaction must
        // catch up before writing, not clobber `other`'s item.
        let toggled = session
            .set_favorite(item_id.clone(), true)
            .expect("toggle on the first handle");
        assert!(toggled.favorite);

        // A third, fresh open sees both.
        let verifier = second_handle(&session);
        assert!(verifier.item(item_id).expect("original item").favorite);
        assert!(
            verifier.item(added.id).is_ok(),
            "the second handle's item must still exist"
        );
    }

    /// `save_item` after another handle edited the very item the sheet is about to overwrite is
    /// refused (user decision 4) rather than silently discarding that edit.
    #[test]
    fn save_item_after_a_concurrent_edit_is_refused_as_changed_elsewhere() {
        let (_dir, session, item_id, _field) = fixture();
        let stale_view = session.item(item_id.clone()).expect("read before the race");
        let other = second_handle(&session);

        // The other handle changes the very item the stale draft describes — any change is
        // enough; a toggle is the simplest one that does not itself go through `save_item`.
        other
            .set_favorite(item_id.clone(), true)
            .expect("the other handle's edit");

        let stale_draft = ItemDraft {
            id: stale_view.id.clone(),
            category: stale_view.category.clone(),
            title: "A title the stale sheet typed".to_owned(),
            fields: Vec::new(),
            tags: stale_view.tags.clone(),
            urls: stale_view.urls.clone(),
            notes: None,
            revision: stale_view.revision.clone(),
        };
        match session.save_item(stale_draft) {
            Err(FfiError::ItemChangedElsewhere { .. }) => {}
            other => panic!("expected ItemChangedElsewhere, got {other:?}"),
        }

        // Nothing from the stale draft landed: the title is still whatever `other` last wrote it
        // as coming from `fixture()` ("GitHub"), not the stale sheet's title.
        let after = session.item(item_id).expect("read after the refusal");
        assert_eq!(after.title, "GitHub");
        assert!(
            after.favorite,
            "the other handle's real edit is still there"
        );
    }

    /// A file restored from an older copy — the shape a backup or a sync conflict takes — is
    /// refused as [`FfiError::Diverged`], and the write leaves the file exactly as found.
    #[test]
    fn a_diverged_file_is_refused_and_left_untouched() {
        let (_dir, session, _item_id, _field) = fixture();
        let path = session.path();

        // The pristine file, before anything is appended to the audit log.
        let older = std::fs::read(&path).expect("read the fresh vault file");

        // An operation that appends an audit entry and saves, so this session's memory knows an
        // audit log the "older" bytes above do not contain.
        session
            .create_environment("prod".to_owned(), None)
            .expect("an audited write");

        // Simulate an older copy being restored over the file — a backup, a sync conflict, a
        // `cp` from yesterday — while `session` is still unlocked and remembers the newer log.
        std::fs::write(&path, &older).expect("restore the older bytes");
        let before_attempt = std::fs::read(&path).expect("re-read before the refused write");

        match session.set_vault_agent_visible(
            session
                .vaults()
                .first()
                .expect("a logical vault")
                .id
                .clone(),
            true,
        ) {
            Err(FfiError::Diverged { .. }) => {}
            other => panic!("expected Diverged, got {other:?}"),
        }

        let after_attempt = std::fs::read(&path).expect("re-read after the refused write");
        assert_eq!(
            before_attempt, after_attempt,
            "a refused transaction must not touch the file"
        );
        assert_eq!(session.conflict(), Some(VaultConflictKindView::Diverged));
    }

    /// `sync()` reports the same conflict without any write being attempted first, so the app can
    /// show the alert on its timer rather than waiting for the next mutation to fail.
    #[test]
    fn sync_alone_detects_a_diverged_file() {
        let (_dir, session, _item_id, _field) = fixture();
        let path = session.path();
        let older = std::fs::read(&path).expect("read the fresh vault file");
        session
            .create_environment("prod".to_owned(), None)
            .expect("an audited write");
        std::fs::write(&path, &older).expect("restore the older bytes");

        assert!(
            session.sync(),
            "sync reports a change (the conflict) worth showing"
        );
        assert_eq!(session.conflict(), Some(VaultConflictKindView::Diverged));
    }

    /// Diverge `session`'s file the way `a_diverged_file_is_refused_and_left_untouched` does:
    /// the pristine bytes restored after an audited write. Returns the newer bytes too.
    fn diverge(session: &VaultSession) -> (Vec<u8>, Vec<u8>) {
        let path = session.path();
        let older = std::fs::read(&path).expect("read the fresh vault file");
        session
            .create_environment("prod".to_owned(), None)
            .expect("an audited write");
        let newer = std::fs::read(&path).expect("read the newer file");
        std::fs::write(&path, &older).expect("restore the older bytes");
        assert!(session.sync());
        (older, newer)
    }

    fn some_vault_id(session: &VaultSession) -> String {
        session
            .vaults()
            .first()
            .expect("a logical vault")
            .id
            .clone()
    }

    /// "Keep this app's version": the confirmed details are acted on, the file gets this
    /// session's contents plus an audit entry saying so, and writes work again.
    #[test]
    fn keeping_the_apps_version_overwrites_the_file_and_writes_work_again() {
        let (_dir, session, _item_id, _field) = fixture();
        diverge(&session);
        assert_eq!(session.conflict(), Some(VaultConflictKindView::Diverged));

        let details = session
            .conflict_details()
            .expect("examine")
            .expect("in conflict");
        assert_eq!(details.kind, VaultConflictKindView::Diverged);
        assert!(details.file_fingerprint.is_some());
        let lost = details.diverged.clone().expect("diverged details");
        // The restored copy is simply older: it holds nothing this session lacks.
        assert_eq!(lost.audit_entries_only_in_file, 0);
        assert_eq!(lost.items_only_in_file, 0);
        assert!(!lost.master_password_differs);

        assert_eq!(
            session
                .keep_app_version_over_conflict(details)
                .expect("keep"),
            KeepAppVersionOutcome::Overwritten
        );
        assert_eq!(session.conflict(), None);
        assert!(!session.sync(), "the file is exactly this session's now");

        let reopened =
            VaultSession::unlock_with_password(session.path(), "pw".to_owned()).expect("reopen");
        assert_eq!(
            reopened.environments().len(),
            1,
            "the session's content is on disk"
        );
        let newest = reopened.audit_page(1, 0);
        assert_eq!(newest[0].tool, kagisecure_core::vault::AUDIT_TOOL_OVERWRITE);
        assert_eq!(newest[0].actor, "app");
        assert!(
            newest[0]
                .detail
                .as_deref()
                .expect("a detail")
                .starts_with("found=diverged")
        );
        drop(reopened);

        session
            .set_vault_agent_visible(some_vault_id(&session), true)
            .expect("an ordinary write works again");
    }

    /// A confirmation built for one file is never used on another: the file moving on after it
    /// was shown gets the new details back, and nothing written.
    #[test]
    fn a_stale_confirmation_is_answered_with_the_files_new_details() {
        let (_dir, session, _item_id, _field) = fixture();
        diverge(&session);
        let shown = session
            .conflict_details()
            .expect("examine")
            .expect("conflict");

        let path = session.path();
        std::fs::write(&path, b"something else entirely").expect("replace the file");
        let KeepAppVersionOutcome::FileChangedAgain { details } = session
            .keep_app_version_over_conflict(shown)
            .expect("an answer")
        else {
            panic!("expected FileChangedAgain");
        };
        assert_eq!(details.kind, VaultConflictKindView::Unreadable);
        assert_eq!(
            std::fs::read(&path).expect("read"),
            b"something else entirely",
            "nothing was written"
        );
        assert_eq!(session.conflict(), Some(VaultConflictKindView::Unreadable));

        assert_eq!(
            session
                .keep_app_version_over_conflict(details)
                .expect("keep"),
            KeepAppVersionOutcome::Overwritten
        );
        assert_eq!(session.conflict(), None);
    }

    /// If the newer file comes back before the person confirms, nothing is overwritten: the
    /// session catches up with it, and the conflict clears.
    #[test]
    fn a_file_that_is_consistent_again_is_caught_up_with_not_overwritten() {
        let (_dir, session, _item_id, _field) = fixture();
        let (_older, newer) = diverge(&session);
        let details = session
            .conflict_details()
            .expect("examine")
            .expect("conflict");

        std::fs::write(session.path(), &newer).expect("put the newer file back");
        assert_eq!(
            session
                .keep_app_version_over_conflict(details)
                .expect("answer"),
            KeepAppVersionOutcome::NoLongerInConflict
        );
        assert_eq!(session.conflict(), None);
        let reopened =
            VaultSession::unlock_with_password(session.path(), "pw".to_owned()).expect("reopen");
        assert!(
            reopened
                .audit_page(50, 0)
                .iter()
                .all(|row| row.tool != kagisecure_core::vault::AUDIT_TOOL_OVERWRITE),
            "no overwrite happened"
        );
    }

    /// A vault file deleted while unlocked is only recreated by the explicit choice.
    #[test]
    fn a_removed_file_is_recreated_by_keeping_the_apps_version() {
        let (_dir, session, _item_id, _field) = fixture();
        std::fs::remove_file(session.path()).expect("remove");
        assert!(session.sync());
        assert_eq!(session.conflict(), Some(VaultConflictKindView::Removed));

        let details = session
            .conflict_details()
            .expect("examine")
            .expect("conflict");
        assert_eq!(details.kind, VaultConflictKindView::Removed);
        assert_eq!(details.file_fingerprint, None);
        assert_eq!(
            session
                .keep_app_version_over_conflict(details)
                .expect("keep"),
            KeepAppVersionOutcome::Overwritten
        );
        assert!(std::path::Path::new(&session.path()).is_file());
    }

    /// Something that is not a vault at the path is a conflict too — found by `sync` and by a
    /// write, not reported as a wrong credential.
    #[test]
    fn an_unreadable_file_is_a_conflict_not_a_wrong_credential() {
        let (_dir, session, _item_id, _field) = fixture();
        std::fs::write(session.path(), b"not a vault").expect("clobber");
        assert!(session.sync());
        assert_eq!(session.conflict(), Some(VaultConflictKindView::Unreadable));

        let (_dir2, other, _i, _f) = fixture();
        std::fs::write(other.path(), b"not a vault").expect("clobber");
        match other.set_vault_agent_visible(some_vault_id(&other), true) {
            Err(FfiError::Diverged { .. }) => {}
            result => panic!("expected Diverged, got {result:?}"),
        }
        assert_eq!(other.conflict(), Some(VaultConflictKindView::Unreadable));
    }

    // MARK: - ADR-0038 step 3: `FieldDraft.value: Option<String>`

    /// A draft that keeps every field's stored value (`value: None` throughout), changing only
    /// whatever the caller layers on top — the shape `beginEditing` now sends for a field the
    /// user never touched.
    fn keep_every_field(view: &ItemView) -> Vec<FieldDraft> {
        view.fields
            .iter()
            .map(|f| FieldDraft {
                id: Some(f.id.clone()),
                label: f.label.clone(),
                kind: f.kind,
                concealed: f.concealed,
                value: None,
                section: f.section.clone(),
                agent_visible: f.agent_visible,
            })
            .collect()
    }

    /// An [`ItemDraft`] built from `view`, with `title` and `fields` as given and everything else
    /// carried over unchanged.
    fn draft(view: &ItemView, title: &str, fields: Vec<FieldDraft>) -> ItemDraft {
        ItemDraft {
            id: view.id.clone(),
            category: view.category.clone(),
            title: title.to_owned(),
            fields,
            tags: view.tags.clone(),
            urls: view.urls.clone(),
            notes: None,
            revision: view.revision.clone(),
        }
    }

    /// `fixture()` plus a real value on the Login's password field, set the same way a first
    /// setup would: a new value supplied for an existing (already-concealed) field.
    fn fixture_with_password(
        value: &str,
    ) -> (tempfile::TempDir, Arc<VaultSession>, String, String) {
        let (dir, session, item_id, _totp_field) = fixture();
        let view = session.item(item_id.clone()).expect("the item");
        let password_id = view
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Concealed)
            .expect("the password field")
            .id
            .clone();
        let fields = view
            .fields
            .iter()
            .map(|f| FieldDraft {
                id: Some(f.id.clone()),
                label: f.label.clone(),
                kind: f.kind,
                concealed: f.concealed,
                value: if f.id == password_id {
                    Some(value.to_owned())
                } else {
                    None
                },
                section: f.section.clone(),
                agent_visible: f.agent_visible,
            })
            .collect();
        session
            .save_item(draft(&view, &view.title.clone(), fields))
            .expect("set the password");
        (dir, session, item_id, password_id)
    }

    /// Deleting for good needs the item to be in the Trash *now*, and to be the item the Trash
    /// row showed: a restore (or any change) by another writer since then refuses the delete.
    #[test]
    fn delete_for_good_needs_the_trashed_item_that_was_shown() {
        let (dir, session, item_id, _totp) = fixture();
        let path = dir.path().join("t.kagivault").display().to_string();

        // Not in the Trash: refused, and still there.
        let live = session.item(item_id.clone()).expect("item");
        let refused = session.delete_item(item_id.clone(), live.revision.clone());
        assert!(
            matches!(refused, Err(FfiError::Invalid { .. })),
            "{refused:?}"
        );
        assert!(session.item(item_id.clone()).is_ok());

        // Binned here; restored by another writer while the Trash row still shows it.
        let binned = session.set_trashed(item_id.clone(), true).expect("trash");
        let other = VaultSession::unlock_with_password(path, "pw".to_owned()).expect("unlock");
        other
            .set_trashed(item_id.clone(), false)
            .expect("restored elsewhere");
        let stale = session.delete_item(item_id.clone(), binned.revision.clone());
        assert!(
            matches!(stale, Err(FfiError::ItemChangedElsewhere { .. })),
            "{stale:?}"
        );
        assert!(!session.item(item_id.clone()).expect("still there").trashed);

        // A title or a prefix names nothing.
        let rebinned = session.set_trashed(item_id.clone(), true).expect("trash");
        for reference in ["GitHub".to_owned(), item_id[..8].to_owned()] {
            let e = session.delete_item(reference, rebinned.revision.clone());
            assert!(matches!(e, Err(FfiError::NotPresent { .. })), "{e:?}");
        }

        // In the Trash, as shown: deleted.
        session
            .delete_item(item_id.clone(), rebinned.revision)
            .expect("deleted for good");
        assert!(matches!(
            session.item(item_id),
            Err(FfiError::NotPresent { .. })
        ));
    }

    /// The app locks on the main thread. Another process holding the vault's file lock must not
    /// stall that for the vault's default five seconds: the lock-time flush waits at most
    /// `LOCK_FLUSH_WAIT`, so the whole lock stays inside the app's two-second budget — and the
    /// vault is locked either way.
    #[test]
    fn a_lock_does_not_wait_out_another_writer_past_the_apps_budget() {
        let (dir, session, _item, _totp) = fixture();
        let path = dir.path().join("t.kagivault");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let mut other = Vault::open_with_password(&path, b"pw").expect("another writer");
            other
                .transact(|_| {
                    ready_tx.send(()).unwrap();
                    std::thread::sleep(Duration::from_secs(7));
                    Ok(())
                })
                .expect("held");
        });
        ready_rx.recv().unwrap();
        // Something is waiting to be written, so the lock's final flush has work to try.
        assert!(
            session
                .handle()
                .queue_audit(app_draft("test_pending", None))
        );

        let started = std::time::Instant::now();
        session.lock();
        let took = started.elapsed();
        assert!(!session.is_unlocked());
        assert!(
            took < APP_LOCK_TIMEOUT,
            "locking took {took:?} while another writer held the file"
        );
        holder.join().unwrap();
    }

    /// `ItemView::revision` is keyed per session: the same item — same secrets, same everything —
    /// gets unrelated revisions in two sessions, and neither is anything computable from its
    /// content without the session's key — which is what an offline guess would need. Within a
    /// session it is stable across reads, changes with any edit, and still refuses a stale save.
    #[test]
    fn a_revision_is_keyed_per_session_and_still_catches_a_stale_save() {
        let (dir, first, item_id, _totp) = fixture_with_password("hunter2");
        let path = dir.path().join("t.kagivault").display().to_string();
        let second = VaultSession::unlock_with_password(path, "pw".to_owned()).expect("unlock");

        let a = first.item(item_id.clone()).expect("item");
        let b = second.item(item_id.clone()).expect("item");
        assert_eq!(a.updated_at, b.updated_at, "the very same stored item");
        assert_ne!(a.revision, b.revision, "equal secrets, different sessions");
        assert_eq!(a.revision.len(), 64);
        assert_eq!(
            first.item(item_id.clone()).expect("item").revision,
            a.revision,
            "stable within a session"
        );

        // The same digest under a key anyone knows (all zeroes) — a stand-in for whatever a caller
        // without this session's key could compute from a guessed value — matches neither.
        let unkeyed = first
            .with_vault(|vault| {
                let item = vault.item_by_id_str(&item_id).expect("item");
                let zero = RevisionKey(zeroize::Zeroizing::new([0u8; 32]));
                item_revision(item, &zero)
            })
            .expect("unlocked");
        assert_ne!(unkeyed, a.revision);
        assert_ne!(unkeyed, b.revision);

        // The conflict check still works: the second session saves, the first's sheet is stale.
        second
            .save_item(draft(
                &b,
                "Changed in the other window",
                keep_every_field(&b),
            ))
            .expect("the other window saves");
        let stale = first.save_item(draft(&a, "Stale sheet", keep_every_field(&a)));
        assert!(
            matches!(stale, Err(FfiError::ItemChangedElsewhere { .. })),
            "{stale:?}"
        );
        let fresh = first.item(item_id).expect("item");
        assert_ne!(fresh.revision, a.revision, "an edit changes the revision");
        first
            .save_item(draft(&fresh, "Fresh sheet", keep_every_field(&fresh)))
            .expect("a fresh sheet saves");
    }

    /// `None` keeps a concealed value byte for byte, including bytes an ASCII-only fixture would
    /// never exercise (multi-byte UTF-8) — this is the fix for the live data-loss bug: a failed
    /// reveal used to prefill `""`, and saving that replaced the real secret with an empty string.
    #[test]
    fn none_keeps_a_concealed_value_byte_for_byte() {
        let secret = "Correct-Horse-Báttery-🔑-09";
        let (_dir, session, item_id, password_id) = fixture_with_password(secret);
        assert_eq!(
            reveal(&session, item_id.clone(), password_id.clone())
                .expect("reveal before the no-op edit"),
            secret
        );

        let view = session.item(item_id.clone()).expect("re-read");
        let fields = keep_every_field(&view);
        session
            .save_item(draft(&view, "GitHub", fields))
            .expect("save with every value kept");

        assert_eq!(
            reveal(&session, item_id, password_id).expect("reveal after the no-op edit"),
            secret,
            "a `None` value must not have replaced the stored secret"
        );
    }

    /// A new field — one with no `id`, because the core has never minted one for it — always
    /// needs a value: there is no stored value for `None` to mean "keep".
    #[test]
    fn a_new_field_with_no_value_is_refused() {
        let (_dir, session, item_id, _field) = fixture();
        let view = session.item(item_id.clone()).expect("the item");

        let mut fields = keep_every_field(&view);
        fields.push(FieldDraft {
            id: None,
            label: "New field".to_owned(),
            kind: FieldKind::Text,
            concealed: false,
            value: None,
            section: None,
            agent_visible: false,
        });

        match session.save_item(draft(&view, &view.title.clone(), fields)) {
            Err(FfiError::Invalid { .. }) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }

        // `save_item`'s commit is a harmless re-seal even on a no-op (`SaveItemOutcome`'s own doc
        // comment: the same thing `Conflict` already does), so the file's ciphertext bytes are not
        // the right thing to compare — the content-only fingerprint is. It must be exactly what it
        // was: no field, secret or otherwise, was added, changed or dropped.
        let after = session.item(item_id).expect("read after the refused save");
        assert_eq!(
            after.revision, view.revision,
            "a refused save must leave the item's content exactly as it was"
        );
    }

    /// "Untick Concealed, then save" with no new value must not be a way to release a secret's
    /// plaintext into the public, agent-visible slot — the degenerate case ADR-0038 step 3 closes
    /// ahead of the presence gate it is a prerequisite for.
    #[test]
    fn unconcealing_a_field_with_no_new_value_is_refused() {
        let secret = "do-not-leak-me";
        let (_dir, session, item_id, password_id) = fixture_with_password(secret);
        let view = session.item(item_id.clone()).expect("re-read");
        let fields = view
            .fields
            .iter()
            .map(|f| FieldDraft {
                id: Some(f.id.clone()),
                label: f.label.clone(),
                kind: f.kind,
                // The one change: ask to make the password field public, with no new value.
                concealed: if f.id == password_id {
                    false
                } else {
                    f.concealed
                },
                value: None,
                section: f.section.clone(),
                agent_visible: f.agent_visible,
            })
            .collect();

        match session.save_item(draft(&view, &view.title.clone(), fields)) {
            Err(FfiError::Invalid { .. }) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }

        // As above: the commit behind a refusal is a harmless re-seal, so compare content, not
        // ciphertext bytes. The field must still be concealed and its value the one already
        // stored — refusing the edit must not have half-applied it.
        let after = session
            .item(item_id.clone())
            .expect("read after the refused save");
        assert_eq!(
            after.revision, view.revision,
            "a refused save must leave the item's content exactly as it was"
        );
        assert_eq!(
            reveal(&session, item_id, password_id).expect("still concealed"),
            secret,
            "the value must still be reachable only through reveal, not laundered into public"
        );
    }

    /// An edit that changes only the title must leave every secret — the password and the TOTP
    /// seed alike — byte for byte untouched. This is the exact shape `ItemEditView`'s title field
    /// produces: one field changed, every `FieldDraft.value` for every other field `None`.
    #[test]
    fn an_edit_that_changes_only_the_title_leaves_every_secret_untouched() {
        let secret = "s3cr3t-password-value";
        let (_dir, session, item_id, password_id) = fixture_with_password(secret);
        let view = session.item(item_id.clone()).expect("re-read");
        let totp_id = view
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .expect("the totp field")
            .id
            .clone();
        let totp_before = reveal(&session, item_id.clone(), totp_id.clone())
            .expect("reveal the seed before the edit");

        let fields = keep_every_field(&view);
        let saved = session
            .save_item(draft(&view, "A renamed title", fields))
            .expect("save the title-only edit");
        assert_eq!(saved.title, "A renamed title");

        assert_eq!(
            reveal(&session, item_id.clone(), password_id)
                .expect("reveal the password after the edit"),
            secret
        );
        assert_eq!(
            reveal(&session, item_id, totp_id).expect("reveal the seed after the edit"),
            totp_before,
            "the totp seed must be untouched by an edit that only renamed the item"
        );
    }

    /// `Some("")` for an already-stored, still-concealed field is treated exactly like `None`:
    /// whatever put an empty string there — a UI bug that misattributes one row's "entering a new
    /// value" state to another, a person who pressed "Change" and then Save without typing — it
    /// must not be able to replace a real secret with nothing. This is the FFI boundary's own
    /// guard, independent of anything the Swift UI does or fails to do correctly.
    #[test]
    fn an_empty_new_value_for_a_kept_concealed_field_does_not_overwrite_the_secret() {
        let secret = "do-not-erase-me";
        let (_dir, session, item_id, password_id) = fixture_with_password(secret);
        let view = session.item(item_id.clone()).expect("re-read");

        let fields = view
            .fields
            .iter()
            .map(|f| FieldDraft {
                id: Some(f.id.clone()),
                label: f.label.clone(),
                kind: f.kind,
                concealed: f.concealed,
                // The one field gets an explicit *empty* value rather than `None` — exactly the
                // shape a stray "" from a UI bug or an unfinished "Change" would take.
                value: if f.id == password_id {
                    Some(String::new())
                } else {
                    None
                },
                section: f.section.clone(),
                agent_visible: f.agent_visible,
            })
            .collect();

        session
            .save_item(draft(&view, &view.title.clone(), fields))
            .expect("an empty value for a kept concealed field must not be refused outright");

        assert_eq!(
            reveal(&session, item_id, password_id).expect("reveal after the empty-value save"),
            secret,
            "an empty string must never overwrite a stored secret with nothing"
        );
    }

    /// The empty-collapses-to-keep rule above is scoped to a field that already has something
    /// stored: a brand-new concealed field's empty starting value (`ItemEditView.addField`) still
    /// means exactly what it says, because there is nothing yet to keep, and it must still be
    /// possible to add a field and save before typing a value into it.
    #[test]
    fn a_brand_new_concealed_field_with_an_empty_value_still_saves() {
        let (_dir, session, item_id, _totp_field) = fixture();
        let view = session.item(item_id.clone()).expect("the item");

        let mut fields = keep_every_field(&view);
        fields.push(FieldDraft {
            id: None,
            label: "New secret".to_owned(),
            kind: FieldKind::Concealed,
            concealed: true,
            value: Some(String::new()),
            section: None,
            agent_visible: false,
        });

        let saved = session
            .save_item(draft(&view, &view.title.clone(), fields))
            .expect("a new field's empty starting value must not be refused");
        let new_field = saved
            .fields
            .iter()
            .find(|f| f.label == "New secret")
            .expect("the new field");
        assert!(new_field.concealed);
        assert_eq!(
            reveal(&session, saved.id, new_field.id.clone())
                .expect("reveal the new, still-empty field"),
            "",
            "an unfilled new field is empty, not silently populated from nowhere"
        );
    }

    /// The empty-collapses-to-keep rule is scoped to a *concealed* field. A public field cleared
    /// back to an empty string is an ordinary, deliberate edit (clearing a username, say) and
    /// must still take effect — it must not be silently reinterpreted as "keep the old value".
    #[test]
    fn a_public_field_cleared_to_empty_still_becomes_empty() {
        let (_dir, session, item_id, _totp_field) = fixture();
        let view = session.item(item_id.clone()).expect("the item");
        let username_id = view
            .fields
            .iter()
            .find(|f| f.label == "username")
            .expect("the username field")
            .id
            .clone();

        // First give it a real value, the same way any other public-field edit would.
        let fields = view
            .fields
            .iter()
            .map(|f| FieldDraft {
                id: Some(f.id.clone()),
                label: f.label.clone(),
                kind: f.kind,
                concealed: f.concealed,
                value: if f.id == username_id {
                    Some("alice".to_owned())
                } else {
                    None
                },
                section: f.section.clone(),
                agent_visible: f.agent_visible,
            })
            .collect();
        let saved = session
            .save_item(draft(&view, &view.title.clone(), fields))
            .expect("set the username");
        assert_eq!(
            saved
                .fields
                .iter()
                .find(|f| f.id == username_id)
                .and_then(|f| f.value.clone()),
            Some("alice".to_owned())
        );

        // Now clear it back to empty.
        let view2 = session.item(item_id.clone()).expect("re-read");
        let fields2 = view2
            .fields
            .iter()
            .map(|f| FieldDraft {
                id: Some(f.id.clone()),
                label: f.label.clone(),
                kind: f.kind,
                concealed: f.concealed,
                value: if f.id == username_id {
                    Some(String::new())
                } else {
                    None
                },
                section: f.section.clone(),
                agent_visible: f.agent_visible,
            })
            .collect();
        let cleared = session
            .save_item(draft(&view2, &view2.title.clone(), fields2))
            .expect("clear the username");
        assert_eq!(
            cleared
                .fields
                .iter()
                .find(|f| f.id == username_id)
                .and_then(|f| f.value.clone()),
            Some(String::new()),
            "clearing a public field to empty must take effect, not be treated as \"keep\""
        );
    }

    // MARK: - A password change does not stall the handle

    /// Run `f` on another thread; `None` if it has not finished within `limit` — which, for a
    /// call that only needs the handle's mutex, means something is holding it.
    fn finishes_within<T: Send + 'static>(
        limit: Duration,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(limit).ok()
    }

    #[test]
    fn the_handle_serves_other_calls_while_a_password_change_derives() {
        let (_dir, session, item, _) = fixture();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();

        // The change runs on its own thread and parks at the start of its Argon2id phase until
        // the test lets it go — standing in for a derivation that takes as long as it likes.
        let changer = {
            let session = Arc::clone(&session);
            std::thread::spawn(move || {
                session.change_master_password_with("a new password".to_owned(), move || {
                    entered_tx.send(()).expect("test alive");
                    resume_rx.recv().expect("test alive");
                })
            })
        };
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the change reached its derivation");

        // While it derives: an app read, an app write, and the agent's own view of the handle
        // all go through. Before the fix the derivation ran inside `with_vault`, so every one of
        // these waited on the mutex for as long as Argon2id took — here, forever.
        let reader = Arc::clone(&session);
        let item_id = item.clone();
        let read = finishes_within(Duration::from_secs(5), move || {
            reader.item(item_id).map(|view| view.title)
        });
        assert_eq!(
            read.expect("a read proceeds during the derivation")
                .expect("read"),
            "GitHub"
        );

        let writer = Arc::clone(&session);
        let item_id = item.clone();
        let wrote = finishes_within(Duration::from_secs(5), move || {
            writer.set_favorite(item_id, true).map(|view| view.favorite)
        });
        assert!(
            wrote
                .expect("a write proceeds during the derivation")
                .expect("write"),
            "the write took effect"
        );

        let handle = session.handle();
        let agent_view = finishes_within(Duration::from_secs(5), move || {
            handle.with(|vault| vault.items().len())
        });
        assert_eq!(
            agent_view.expect("the agent's handle is not blocked"),
            Some(1)
        );

        // Let the derivation finish: the change still lands, over the write made meanwhile.
        resume_tx.send(()).expect("changer alive");
        changer
            .join()
            .expect("no panic")
            .expect("the password change succeeds");
        assert_eq!(
            session
                .verify_master_password("a new password".to_owned())
                .expect("checked"),
            crate::presence::MasterPasswordCheck::Verified
        );
        assert!(session.item(item).expect("item").favorite);
    }

    #[test]
    fn a_lock_during_the_derivation_installs_nothing() {
        let (dir, session, _, _) = fixture();
        let path = dir.path().join("t.kagivault").display().to_string();
        let locker = Arc::clone(&session);
        let result = session.change_master_password_with("never installed".to_owned(), move || {
            locker.lock();
        });
        assert!(matches!(result, Err(FfiError::VaultLocked)), "{result:?}");
        assert!(
            VaultSession::unlock_with_password(path.clone(), "pw".to_owned()).is_ok(),
            "the old password still opens the vault"
        );
        assert!(matches!(
            VaultSession::unlock_with_password(path, "never installed".to_owned()),
            Err(FfiError::WrongCredential)
        ));
    }

    fn tiny_vault(
        dir: &tempfile::TempDir,
        name: &str,
        password: &str,
    ) -> (String, Arc<VaultSession>) {
        let path = dir.path().join(name).display().to_string();
        let session = VaultSession::create(
            path.clone(),
            password.to_owned(),
            "Personal".to_owned(),
            Some(64),
            Some(1),
        )
        .expect("create");
        (path, past_every_backoff(session))
    }

    /// A clock that jumps well past the master-password back-off every time it is read, so a
    /// test can check one password after another without the rate limit answering instead.
    struct PastEveryBackoff(std::sync::Mutex<std::time::Instant>);

    impl crate::presence::Clock for PastEveryBackoff {
        fn now(&self) -> std::time::Instant {
            let mut now = self.0.lock().unwrap();
            *now += crate::presence::MAX_PASSWORD_BACKOFF * 2;
            *now
        }
    }

    /// Give `session` a clock that jumps past every back-off, so [`verifies`] can check one
    /// password after another without the rate limit answering instead.
    fn past_every_backoff(session: Arc<VaultSession>) -> Arc<VaultSession> {
        session.set_clock_for_testing(Arc::new(PastEveryBackoff(std::sync::Mutex::new(
            std::time::Instant::now(),
        ))));
        session
    }

    /// Whether `password` verifies against `session` (see [`past_every_backoff`]).
    fn verifies(session: &VaultSession, password: &str) -> bool {
        match session
            .verify_master_password(password.to_owned())
            .expect("checked")
        {
            crate::presence::MasterPasswordCheck::Verified => true,
            crate::presence::MasterPasswordCheck::Wrong { .. } => false,
            crate::presence::MasterPasswordCheck::Throttled { .. } => {
                panic!("the clock steps past every back-off")
            }
        }
    }

    #[test]
    fn verify_master_password_accepts_the_password_and_nothing_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_path, session) = tiny_vault(&dir, "v.kagivault", "correct horse");
        assert!(verifies(&session, "correct horse"));
        assert!(!verifies(&session, "correct hors"));
        assert!(!verifies(&session, ""));
    }

    #[test]
    fn verify_master_password_checks_the_session_in_memory_not_the_file_on_disk() {
        // T-3: a same-user process swaps the vault file for one whose password it knows. The
        // check must not follow it: it answers for the vault this session unlocked.
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, session) = tiny_vault(&dir, "v.kagivault", "the real one");
        let (other_path, other) = tiny_vault(&dir, "other.kagivault", "attacker knows this");
        drop(other);
        std::fs::copy(&other_path, &path).expect("swap the file");

        assert!(verifies(&session, "the real one"));
        assert!(!verifies(&session, "attacker knows this"));

        // Removing the file altogether changes nothing either: nothing is read.
        std::fs::remove_file(&path).expect("remove");
        assert!(verifies(&session, "the real one"));
    }

    #[test]
    fn verify_master_password_follows_a_password_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_path, session) = tiny_vault(&dir, "v.kagivault", "old");
        session.change_master_password("new".to_owned()).unwrap();
        assert!(verifies(&session, "new"));
        assert!(!verifies(&session, "old"));
    }

    #[test]
    fn platform_slot_info_reads_the_vault_id_and_the_slot_together() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, session) = tiny_vault(&dir, "v.kagivault", "pw");

        let before = crate::platform_slot_info(path.clone()).unwrap();
        assert_eq!(before.vault_id, session.vault_file_id_bytes());
        assert_eq!(before.vault_id.len(), 16);
        assert_eq!(before.slot_id, None);
        assert_eq!(before.wrapped_key, None);

        session
            .install_platform_slot(
                "windows-hello-v2-ab".to_owned(),
                "Hello".to_owned(),
                vec![7; 64],
            )
            .unwrap();
        let after = crate::platform_slot_info(path.clone()).unwrap();
        assert_eq!(after.vault_id, before.vault_id);
        assert_eq!(after.slot_id.as_deref(), Some("windows-hello-v2-ab"));
        assert_eq!(after.wrapped_key, Some(vec![7; 64]));
        assert_eq!(
            crate::platform_slot_id(path.clone()).unwrap(),
            after.slot_id
        );
        assert_eq!(
            crate::platform_wrapped_key(path).unwrap(),
            after.wrapped_key
        );
    }

    #[test]
    fn unlock_with_vault_key_still_opens_after_taking_ownership_of_the_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, session) = tiny_vault(&dir, "v.kagivault", "pw");
        let key = session.export_vault_key_for_platform_wrapping();
        drop(session);
        let reopened = past_every_backoff(
            VaultSession::unlock_with_vault_key(path.clone(), key).expect("unlock"),
        );
        assert!(verifies(&reopened, "pw"));
        assert!(matches!(
            VaultSession::unlock_with_vault_key(path, vec![0; 32]),
            Err(FfiError::WrongCredential)
        ));
    }
}

#[cfg(test)]
mod agent_visibility_tests {
    use super::*;
    use crate::types::FieldDraft;

    fn session() -> (tempfile::TempDir, Arc<VaultSession>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.kagivault").display().to_string();
        let session = VaultSession::create(
            path,
            "pw".to_owned(),
            "Personal".to_owned(),
            Some(64),
            Some(1),
        )
        .expect("create");
        (dir, session)
    }

    fn vault_id(session: &VaultSession) -> String {
        session.vaults().first().expect("a vault").id.clone()
    }

    fn tagged(session: &VaultSession, title: &str, tag: &str) -> ItemView {
        let item = session
            .create_item(None, "login".to_owned(), title.to_owned())
            .expect("item");
        session
            .save_item(ItemDraft {
                id: item.id.clone(),
                category: item.category.clone(),
                title: item.title.clone(),
                fields: item
                    .fields
                    .iter()
                    .map(|f| FieldDraft {
                        id: Some(f.id.clone()),
                        label: f.label.clone(),
                        kind: f.kind,
                        concealed: f.concealed,
                        value: None,
                        section: f.section.clone(),
                        agent_visible: f.agent_visible,
                    })
                    .collect(),
                tags: vec![tag.to_owned()],
                urls: Vec::new(),
                notes: None,
                revision: item.revision.clone(),
            })
            .expect("save")
    }

    fn all_items(session: &VaultSession) -> Vec<ItemView> {
        session.list_items(ItemFilter::All, None, ItemSort::Title)
    }

    #[test]
    fn a_new_item_is_visible_with_every_field_and_the_setting_is_on() {
        let (_dir, session) = session();
        assert!(session.vaults()[0].new_items_agent_visible);
        let item = session
            .create_item(None, "login".to_owned(), "A".to_owned())
            .expect("item");
        assert!(item.agent_visible);
        assert!(item.fields.iter().all(|f| f.agent_visible));
    }

    #[test]
    fn with_the_setting_off_a_new_item_stays_hidden() {
        let (_dir, session) = session();
        assert!(
            session
                .set_new_items_agent_visible(vault_id(&session), false)
                .expect("set")
        );
        assert!(!session.vaults()[0].new_items_agent_visible);
        let item = session
            .create_item(None, "login".to_owned(), "A".to_owned())
            .expect("item");
        assert!(!item.agent_visible);
        assert!(item.fields.iter().all(|f| !f.agent_visible));
    }

    #[test]
    fn bulk_by_tag_and_by_selection_write_one_count_only_audit_entry_each() {
        let (_dir, session) = session();
        session
            .set_new_items_agent_visible(vault_id(&session), false)
            .expect("set");
        let a = tagged(&session, "A", "imported:chromium");
        let b = tagged(&session, "B", "imported:chromium");
        let c = tagged(&session, "C", "work");
        let before = session.audit_count();

        let result = session
            .set_agent_visible_bulk(
                AgentVisibilityScopeView::Tag {
                    tag: "imported:chromium".to_owned(),
                },
                true,
            )
            .expect("bulk");
        assert_eq!(
            result,
            BulkVisibilityView {
                matched: 2,
                changed: 2
            }
        );
        assert_eq!(session.audit_count(), before + 1);
        let row = &session.audit_page(1, 0)[0];
        assert_eq!(row.tool, "set_agent_visible_bulk");
        assert_eq!(
            row.detail.as_deref(),
            Some("scope=tag visible=on matched=2 changed=2")
        );
        for item in all_items(&session) {
            let expected = item.id != c.id;
            assert_eq!(item.agent_visible, expected);
            assert!(item.fields.iter().all(|f| f.agent_visible == expected));
        }

        let hidden = session
            .set_agent_visible_bulk(
                AgentVisibilityScopeView::Items {
                    item_ids: vec![a.id.clone(), c.id.clone(), "not-an-id".to_owned()],
                },
                false,
            )
            .expect("bulk");
        assert_eq!(
            hidden,
            BulkVisibilityView {
                matched: 2,
                changed: 1
            }
        );
        assert_eq!(session.audit_count(), before + 2);
        let visible: Vec<String> = all_items(&session)
            .into_iter()
            .filter(|i| i.agent_visible)
            .map(|i| i.id)
            .collect();
        assert_eq!(visible, vec![b.id]);
    }

    #[test]
    fn show_all_reaches_every_live_item() {
        let (_dir, session) = session();
        session
            .set_new_items_agent_visible(vault_id(&session), false)
            .expect("set");
        tagged(&session, "A", "x");
        tagged(&session, "B", "y");
        let result = session
            .set_agent_visible_bulk(AgentVisibilityScopeView::All, true)
            .expect("bulk");
        assert_eq!(result.matched, 2);
        assert!(all_items(&session).iter().all(|i| i.agent_visible));
    }

    #[test]
    fn the_test_login_switch_creates_its_vault_and_domains_are_registrable_only() {
        let (_dir, session) = session();
        assert!(!session.agent_test_login_settings().enabled);
        // Turning it off when there is nothing to turn off creates nothing.
        session.set_agent_test_logins(false).unwrap();
        assert!(session.agent_test_login_settings().vault_id.is_none());

        session.set_agent_test_logins(true).unwrap();
        let settings = session.agent_test_login_settings();
        assert!(settings.enabled);
        let vault_id = settings.vault_id.expect("created");

        assert_eq!(
            session
                .add_agent_test_login_domain("https://staging.example-partner.com".to_owned())
                .unwrap(),
            "example-partner.com"
        );
        for refused in ["127.0.0.1", "localhost", "co.uk"] {
            assert!(
                session
                    .add_agent_test_login_domain(refused.to_owned())
                    .is_err(),
                "{refused}"
            );
        }
        assert_eq!(
            session.agent_test_login_settings().auto_domains,
            ["example-partner.com"]
        );
        assert!(
            session
                .remove_agent_test_login_domain("Example-Partner.com".to_owned())
                .unwrap()
        );
        assert!(session.agent_test_login_settings().auto_domains.is_empty());

        let in_test_vault = session
            .create_item(Some(vault_id), "login".to_owned(), "t".to_owned())
            .unwrap();
        assert!(in_test_vault.in_agent_test_vault);
        let ordinary = session
            .create_item(None, "login".to_owned(), "o".to_owned())
            .unwrap();
        assert!(!ordinary.in_agent_test_vault);
        assert!(session.item(in_test_vault.id).unwrap().in_agent_test_vault);

        session.set_agent_test_logins(false).unwrap();
        assert!(!session.agent_test_login_settings().enabled);
    }
}
