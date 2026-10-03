//! Shared vaults, attached to the agent (ADR-0035 §14, Phase 4).
//!
//! # What is attached, and by whom
//!
//! A shared vault is not in the personal vault file: it is a replica beside it, opened with a
//! device key the personal vault holds (`kagisecure-shared`). The host that opened it — the app's
//! `SharedVaultSession`, or `kagisecure daemon` with a [`ReplicaSource`] — attaches it to the
//! personal vault's [`VaultHandle`] ([`VaultHandle::attach_shared`]) as a [`SharedSource`], and
//! from then on every agent-facing request reads it beside the personal vault through a
//! [`crate::catalog::Catalog`]: the MCP tools, `request_fill`, and the browser extension's fills.
//!
//! The attachment lasts until the host drops the [`SharedAttachment`] it was handed, or the
//! personal vault locks: [`VaultHandle::take`] detaches every shared vault before its lock hooks
//! run, so no request is ever served from a shared vault once the personal vault — which holds
//! its device key — is locked.
//!
//! # What an agent can do with one
//!
//! Read it, exactly as the personal vault: the same agent-visibility rule (this device's own
//! setting, default hidden), the same approval sheets, leases and presence rules, and releases
//! recorded in the personal vault's audit log with the shared vault's id (decision 24). What it
//! cannot do is write to it, or change who it is shared with: nothing here writes a record, and
//! the only thing this module ever writes is [`SharedSource::record_approved`], this device's
//! own note of what it approved (decision 26), which no other member receives.
//!
//! # Lock order
//!
//! The personal vault's handle first, then a shared vault's state, then file locks — the order
//! the app's own shared-vault code keeps. A release reads its shared snapshot inside the personal
//! vault's transaction ([`crate::release`]), so under the handle's mutex and the personal file
//! lock; a [`SharedSource`] never takes the personal vault's handle.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use kagisecure_core::Vault;
use kagisecure_core::proto::VaultId;
use kagisecure_shared::read::{Approvals, SharedSnapshot, record_approved};
use kagisecure_shared::replica::{Replica, list_replicas, replica_path};
use kagisecure_shared::{DeviceSecret, SharedError};

use crate::vault::VaultHandle;

/// One shared vault, open on this computer, as the agent reads it (module documentation).
///
/// Implemented by the app's shared-vault session over the copy it already holds, and by
/// [`ReplicaSource`] for `kagisecure daemon` and the tests.
pub trait SharedSource: Send + Sync {
    /// The shared vault's id.
    fn vault_id(&self) -> VaultId;

    /// Pick up what another process — the CLI, a second app — wrote to this vault's copy on
    /// disk. Cheap when nothing changed; called at the start of every agent request.
    fn refresh(&self);

    /// What this device reads of the vault now, or `None` when it cannot be read: the copy is
    /// damaged, or the personal vault locked.
    fn snapshot(&self) -> Option<Arc<SharedSnapshot>>;

    /// Remember that this device's person approved releasing these values (decision 26), so
    /// the next sheet names only what changed since. `false` if it could not be recorded, which
    /// only means the next sheet names the same values again.
    fn record_approved(&self, approvals: &Approvals) -> bool;
}

/// The shared vaults attached to one [`VaultHandle`].
#[derive(Default)]
pub(crate) struct SharedSet {
    entries: Mutex<Vec<(u64, Arc<dyn SharedSource>)>>,
    next_id: AtomicU64,
}

impl SharedSet {
    fn entries(&self) -> MutexGuard<'_, Vec<(u64, Arc<dyn SharedSource>)>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Attach `source`, replacing whatever was attached for the same vault.
    fn attach(&self, source: Arc<dyn SharedSource>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let vault = source.vault_id();
        let mut entries = self.entries();
        entries.retain(|(_, s)| s.vault_id() != vault);
        entries.push((id, source));
        id
    }

    fn detach(&self, id: u64) {
        self.entries().retain(|(entry, _)| *entry != id);
    }

    /// Detach everything; what was attached is dropped once nothing else holds it.
    pub(crate) fn clear(&self) {
        let taken = std::mem::take(&mut *self.entries());
        drop(taken);
    }

    /// Every attached source, in the order attached. The set's own lock is released before any
    /// source is asked anything, so a slow source never holds up another attach or detach.
    pub(crate) fn sources(&self) -> Vec<Arc<dyn SharedSource>> {
        self.entries().iter().map(|(_, s)| Arc::clone(s)).collect()
    }
}

/// A token for one shared vault attached with [`VaultHandle::attach_shared`]. Dropping it
/// detaches exactly that vault, if it is still attached; locking the personal vault detaches it
/// anyway.
#[must_use = "the shared vault is detached as soon as this is dropped"]
pub struct SharedAttachment {
    handle: Weak<VaultHandle>,
    id: u64,
}

impl std::fmt::Debug for SharedAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedAttachment").finish_non_exhaustive()
    }
}

impl Drop for SharedAttachment {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.upgrade() {
            handle.shared_set().detach(self.id);
        }
    }
}

impl VaultHandle {
    /// Serve shared vault `source` to agents beside the personal vault until the returned
    /// attachment is dropped or the personal vault locks (module documentation). Attaching a
    /// vault that is attached already replaces it. Attaching to a locked handle attaches
    /// nothing.
    pub fn attach_shared(self: &Arc<Self>, source: Arc<dyn SharedSource>) -> SharedAttachment {
        let id = if self.is_unlocked() {
            let id = self.shared_set().attach(source);
            // A lock that ran between the check and the attach has already cleared the set once;
            // clear again rather than serve a vault whose device key is gone.
            if !self.is_unlocked() {
                self.shared_set().clear();
            }
            id
        } else {
            u64::MAX
        };
        SharedAttachment {
            handle: Arc::downgrade(self),
            id,
        }
    }

    /// The ids of the shared vaults attached now.
    #[must_use]
    pub fn attached_shared(&self) -> Vec<VaultId> {
        self.shared_set()
            .sources()
            .iter()
            .map(|s| s.vault_id())
            .collect()
    }

    /// Ask every attached shared vault to pick up what other processes wrote
    /// ([`SharedSource::refresh`]).
    pub fn refresh_shared(&self) {
        for source in self.shared_set().sources() {
            source.refresh();
        }
    }

    /// The snapshot of every attached shared vault that can be read now. Empty once locked.
    #[must_use]
    pub fn shared_snapshots(&self) -> Vec<Arc<SharedSnapshot>> {
        self.shared_set()
            .sources()
            .iter()
            .filter_map(|s| s.snapshot())
            .collect()
    }

    /// Record `approvals` for shared vault `vault_id`, if it is still attached. See
    /// [`SharedSource::record_approved`].
    pub fn record_shared_approvals(&self, vault_id: &VaultId, approvals: &Approvals) -> bool {
        if approvals.is_empty() {
            return true;
        }
        self.shared_set()
            .sources()
            .iter()
            .find(|s| s.vault_id() == *vault_id)
            .is_some_and(|s| s.record_approved(approvals))
    }
}

/// What a file looked like when it was last read: its length and modification time. A refresh
/// skips reading a replica whose stamp has not moved, so a request that finds nothing new costs a
/// `stat` rather than reading and authenticating the whole file ([`SharedSource::refresh`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStamp {
    len: u64,
    modified: Option<std::time::SystemTime>,
}

impl FileStamp {
    /// `path`'s stamp now, or `None` if it cannot be read.
    #[must_use]
    pub fn of(path: &Path) -> Option<Self> {
        let metadata = std::fs::metadata(path).ok()?;
        Some(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

/// A shared vault's replica opened by the agent's own host: `kagisecure daemon`, and the tests.
/// The app attaches the copy its shared-vault session already holds instead.
///
/// Holds this device's secret keys for the vault ([`DeviceSecret`], zeroized on drop) for as long
/// as it lives; attached, that is until the personal vault locks, which detaches and drops it.
pub struct ReplicaSource {
    vault_id: VaultId,
    state: Mutex<ReplicaState>,
}

struct ReplicaState {
    replica: Replica,
    device: DeviceSecret,
    /// The last snapshot, and the (record count, file generation) it was built at: a replica
    /// only ever gains records, and every change to its local state is a new generation.
    cached: Option<(usize, u64, Arc<SharedSnapshot>)>,
    /// The file as it was when last read.
    seen: Option<FileStamp>,
}

impl std::fmt::Debug for ReplicaSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplicaSource")
            .field("vault_id", &self.vault_id)
            .finish_non_exhaustive()
    }
}

impl ReplicaSource {
    /// Open the replica at `path` with `device`.
    ///
    /// # Errors
    ///
    /// As [`Replica::open`].
    pub fn open(path: &Path, device: DeviceSecret) -> Result<Self, SharedError> {
        let replica = Replica::open(path, &device)?;
        Ok(Self {
            vault_id: *replica.vault_id(),
            state: Mutex::new(ReplicaState {
                replica,
                device,
                cached: None,
                seen: None,
            }),
        })
    }

    /// Every shared vault beside the personal vault at `personal_path` that one of `personal`'s
    /// device keys opens. A replica no key opens, or one that does not open at all, is left out
    /// and named on stderr (the app shows those; the daemon can only say so).
    #[must_use]
    pub fn open_all(personal_path: &Path, personal: &Vault) -> Vec<Arc<Self>> {
        let Ok(ids) = list_replicas(personal_path) else {
            return Vec::new();
        };
        let mut opened = Vec::new();
        for id in ids {
            let path = replica_path(personal_path, &id);
            let mut found = None;
            for key in personal.active_device_keys() {
                let Ok(device) = DeviceSecret::from_device_key(key) else {
                    continue;
                };
                match Self::open(&path, device) {
                    Ok(source) => {
                        found = Some(source);
                        break;
                    }
                    Err(SharedError::ReplicaMismatch(_)) => {}
                    Err(e) => {
                        eprintln!("kagisecure: shared vault {id} does not open: {e}");
                        break;
                    }
                }
            }
            if let Some(source) = found {
                opened.push(Arc::new(source));
            }
        }
        opened
    }

    fn state(&self) -> MutexGuard<'_, ReplicaState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl SharedSource for ReplicaSource {
    fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    fn refresh(&self) {
        let mut state = self.state();
        let now = FileStamp::of(state.replica.path());
        if now.is_some() && now == state.seen {
            return;
        }
        let ReplicaState {
            replica,
            device,
            seen,
            ..
        } = &mut *state;
        match replica.transact(device, |_| Ok(())) {
            Ok(()) => *seen = FileStamp::of(replica.path()),
            Err(e) => eprintln!(
                "kagisecure: could not re-read shared vault {}; serving it from memory: {e}",
                self.vault_id
            ),
        }
    }

    fn snapshot(&self) -> Option<Arc<SharedSnapshot>> {
        let mut state = self.state();
        let key = (
            state.replica.records().count(),
            state.replica.header().generation(),
        );
        if let Some((records, generation, snapshot)) = &state.cached
            && (*records, *generation) == key
        {
            return Some(Arc::clone(snapshot));
        }
        match SharedSnapshot::read(&state.replica, &state.device) {
            Ok(snapshot) => {
                let snapshot = Arc::new(snapshot);
                state.cached = Some((key.0, key.1, Arc::clone(&snapshot)));
                Some(snapshot)
            }
            Err(e) => {
                eprintln!(
                    "kagisecure: shared vault {} cannot be read: {e}",
                    self.vault_id
                );
                None
            }
        }
    }

    fn record_approved(&self, approvals: &Approvals) -> bool {
        let mut state = self.state();
        let ReplicaState {
            replica, device, ..
        } = &mut *state;
        record_approved(replica, device, approvals).is_ok()
    }
}

/// What a release from a shared vault adds to its approval sheet and its audit entry (ADR-0035
/// §14): the vault, the source fact, the "changed since approval" facts, and what a granted
/// sheet records so the next one names only later changes.
pub(crate) struct SheetFacts {
    /// The shared vault, for the audit entry (decision 24).
    pub(crate) vault_id: VaultId,
    /// [`source_fact`].
    pub(crate) source: String,
    /// [`change_facts`]; empty when nothing changed since this device last approved it.
    pub(crate) changes: Vec<String>,
    /// What approving it records.
    pub(crate) approvals: Approvals,
}

impl SheetFacts {
    /// The facts for releasing variables `names` of shared environment `env`.
    pub(crate) fn for_environment(
        snapshot: &SharedSnapshot,
        env: &kagisecure_core::proto::EnvId,
        names: &[String],
    ) -> Self {
        Self {
            vault_id: *snapshot.vault_id(),
            source: source_fact(snapshot),
            changes: change_facts(
                &snapshot.env_changes(env, names),
                kagisecure_core::unix_now(),
            ),
            approvals: snapshot.env_approvals(env, names),
        }
    }

    /// The facts for filling shared item `item`: its password when `password`, its one-time
    /// code when `code`. A username is not a secret and is not tracked.
    pub(crate) fn for_fill(
        snapshot: &SharedSnapshot,
        item: &kagisecure_core::model::Item,
        password: bool,
        code: bool,
    ) -> Self {
        let mut fields = Vec::new();
        if password && let Some(field) = item.primary_secret_field() {
            fields.push(field.id);
        }
        if code && let Some(field) = item.totp_field() {
            fields.push(field.id);
        }
        Self {
            vault_id: *snapshot.vault_id(),
            source: source_fact(snapshot),
            changes: change_facts(
                &snapshot.item_changes(&item.id, &fields),
                kagisecure_core::unix_now(),
            ),
            approvals: snapshot.item_approvals(&item.id, &fields),
        }
    }

    /// Whether a value changed since this device last approved it: the sheet must be shown in
    /// full, whatever lease or earlier review would otherwise stand in for it.
    pub(crate) fn changed(&self) -> bool {
        !self.changes.is_empty()
    }

    /// Put the source and change facts on `request`.
    pub(crate) fn state_on(&self, request: &mut crate::approval::ApprovalRequest) {
        request.shared_source = Some(self.source.clone());
        request.changed_since_approval.clone_from(&self.changes);
    }

    /// Record, best-effort, that the human approved what the sheet showed.
    pub(crate) fn record_approved(&self, handle: &VaultHandle) {
        let _ = handle.record_shared_approvals(&self.vault_id, &self.approvals);
    }
}

/// The source fact an approval sheet states for a release from `snapshot` (ADR-0035 §14):
/// `Shared vault “Ops” — 4 members`.
#[must_use]
pub fn source_fact(snapshot: &SharedSnapshot) -> String {
    let members = snapshot.member_count();
    format!(
        "Shared vault “{}” — {members} {}",
        snapshot.name(),
        if members == 1 { "member" } else { "members" }
    )
}

/// The "changed since you approved it" facts for `changes`, one line each, at `now`:
/// `DATABASE_URL changed by Alice, 2 days ago`, or `… first released from this computer; last
/// changed by …` for a value this device never approved (decision 26).
#[must_use]
pub fn change_facts(changes: &[kagisecure_shared::read::Change], now: u64) -> Vec<String> {
    changes
        .iter()
        .map(|change| {
            let when = ago(change.at, now);
            if change.first_release {
                format!(
                    "{} is released from this computer for the first time; last changed by {}, {when}",
                    change.part, change.author
                )
            } else {
                format!("{} changed by {}, {when}", change.part, change.author)
            }
        })
        .collect()
}

/// `at` relative to `now`, in words. A time ahead of `now` — a clock set ahead — is "just now".
fn ago(at: u64, now: u64) -> String {
    let seconds = now.saturating_sub(at);
    let (count, unit) = match seconds {
        0..60 => return "just now".to_owned(),
        60..3_600 => (seconds / 60, "minute"),
        3_600..86_400 => (seconds / 3_600, "hour"),
        _ => (seconds / 86_400, "day"),
    };
    format!("{count} {unit}{} ago", if count == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::ago;

    #[test]
    fn times_read_as_words() {
        assert_eq!(ago(100, 100), "just now");
        assert_eq!(ago(200, 100), "just now");
        assert_eq!(ago(0, 60), "1 minute ago");
        assert_eq!(ago(0, 7_200), "2 hours ago");
        assert_eq!(ago(0, 2 * 86_400 + 5), "2 days ago");
    }
}
