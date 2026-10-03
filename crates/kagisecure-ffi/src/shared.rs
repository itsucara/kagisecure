//! Shared vaults for the app (ADR-0035, Phase 5): creating, joining, reading and writing a
//! shared vault, its members, and syncing it through a folder.
//!
//! # The shape
//!
//! Every shared vault needs the personal vault unlocked — its device keys live there (ADR-0035
//! §5) — so the entry points are on [`VaultSession`]: [`VaultSession::open_shared_vaults`] at
//! unlock, [`VaultSession::create_shared_vault`] and [`VaultSession::join_shared_vault`]. Each
//! returns a [`SharedVaultSession`] per shared vault, which the app keeps beside the personal
//! session and uses exactly the way it uses that one for items: the same [`ItemView`],
//! [`ItemDraft`], [`ItemFilter`] and [`ItemSort`], and the same presence-gated releases
//! ([`FieldRelease`], [`TotpRelease`], [`NotesRelease`], `crate::release::Source::Shared`).
//!
//! # What differs from the personal vault
//!
//! * **No conflicts.** The merge is last-writer-wins (decision 80), so `save_item` never answers
//!   [`FfiError::ItemChangedElsewhere`]: `ItemDraft::revision` is not checked, and a save always
//!   writes a new version. The app shows no reload alert for a shared item.
//! * **No trash.** Moving a shared item to the trash deletes it for everyone (a deletion version;
//!   a later edit on another device brings it back, decision 80).
//! * **Local settings stay local.** Favourites and agent visibility are this device's own
//!   (decision 22): they are written to the replica's local state, never to a record, so toggling
//!   one writes nothing another member receives.
//!
//! # Agents
//!
//! Every open shared vault is attached to the personal vault's handle for the agent
//! (`kagisecure_agent::shared`, ADR-0035 §14): the MCP tools, `request_fill` and the browser
//! extension read it beside the personal vault, with the same approval sheets and presence rules,
//! and see only what this device made visible to agents ([`SharedVaultSession::set_agent_visible`],
//! default hidden). The sheet names the shared vault and any value changed since this device last
//! approved releasing it. Agents never write to a shared vault.
//!
//! # Locking
//!
//! A [`SharedVaultSession`] holds this device's secret keys for its vault (a `DeviceSecret`,
//! zeroized on drop) and the items it decrypted, for as long as the personal vault is unlocked,
//! exactly as the personal vault holds its own key and items. It registers a lock hook on the
//! personal vault's handle: the moment the personal vault locks — [`VaultSession::lock`], a drop,
//! the agent's lock request — every shared vault drops its keys and items, and every call answers
//! [`FfiError::VaultLocked`] from then on. The lock order is the personal vault's handle first and
//! a shared vault's state second; nothing here takes the handle while holding a shared vault.
//!
//! # Secrets that cross this boundary
//!
//! One more, beside ADR-0008's table (`crate` documentation; its pointer of 2026-09-27): an
//! invitation's passphrase comes **out** of [`SharedVaultSession::invite_member`] or
//! [`SharedVaultSession::invite_device`] once, for the person to hand over, and goes **in** at
//! [`VaultSession::join_shared_vault`], which stretches it without holding the personal vault.
//! The invitation file itself is written and read here, by path; its bytes never cross.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use kagisecure_agent::shared::FileStamp;
use kagisecure_agent::vault::LockHookGuard;
use kagisecure_agent::{SharedAttachment, SharedSource, VaultHandle};
use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::model::{Environment, Item, ItemId, VarSource};
use kagisecure_core::proto::{Category, EnvId, VaultId};
use kagisecure_core::unix_now;
use kagisecure_shared::admin::enroll::{self, Joining};
use kagisecure_shared::admin::{create, exchange, remove};
use kagisecure_shared::merge::{materialize_all, materialize_env, materialize_item};
use kagisecure_shared::read::{
    Approvals, SharedSnapshot, apply_local, apply_local_env, record_approved,
};
use kagisecure_shared::replica::{LocalState, RebuildSource, Replica, list_replicas, replica_path};
use kagisecure_shared::rotation::rotation_list;
use kagisecure_shared::view::{ObjectId, SharedView};
use kagisecure_shared::{
    DeviceSecret, MemberId, RemovalReason, Role, RosterWarning, SharedError, write,
};
use zeroize::Zeroizing;

use crate::presence::{Presence, ReleasePurpose};
use crate::release::{FieldRelease, NotesRelease, Releaser, Source, TotpRelease};
use crate::session::{
    APP_LOCK_TIMEOUT, RevisionKey, VaultSession, apply_draft, draft_problem, select_items,
    valid_var_name,
};
use crate::types::{EnvironmentView, ItemDraft, ItemFilter, ItemSort, ItemView};
use crate::{FfiError, FfiResult};

/// The personal vault's audit actor for a device key [`VaultSession::create_shared_vault`] adds.
const CREATE_ACTOR: &str = "shared-create";

/// What a shared vault is called when this device does not know its name.
const UNNAMED_VAULT: &str = "Shared vault";

/// What a member is called when nobody on this device named them.
const UNNAMED_MEMBER: &str = "Unnamed member";

/// How many of a fingerprint's ten groups make up [`device_label`]'s fallback: enough to tell
/// two nameless members apart without the whole fingerprint's ten groups.
const DEVICE_LABEL_FINGERPRINT_GROUPS: usize = 2;

/// A fallback label built from `devices`' fingerprints, for a member nobody on this device
/// named (ADR-0035 decision 81: roster labels' sealing is undecided, so no name syncs). `None`
/// if `devices` is empty — the caller falls back to [`UNNAMED_MEMBER`] itself then.
fn device_label(devices: &[SharedDeviceView]) -> Option<String> {
    let first = devices.first()?;
    let short = first
        .fingerprint
        .split(' ')
        .take(DEVICE_LABEL_FINGERPRINT_GROUPS)
        .collect::<Vec<_>>()
        .join(" ");
    Some(format!("Device {short}"))
}

// MARK: - Types

/// A member's role in a shared vault (ADR-0035 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SharedRole {
    /// Reads.
    Reader,
    /// Also adds, edits and deletes items.
    Writer,
    /// Also invites, removes and changes roles.
    Admin,
}

impl SharedRole {
    const fn from_core(role: Role) -> Self {
        match role {
            Role::Reader => Self::Reader,
            Role::Writer => Self::Writer,
            Role::Admin => Self::Admin,
        }
    }

    const fn to_core(self) -> Role {
        match self {
            Self::Reader => Role::Reader,
            Self::Writer => Role::Writer,
            Self::Admin => Role::Admin,
        }
    }
}

/// One shared vault, for the sidebar and its header.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SharedVaultSummary {
    /// The shared vault's id, 32 lower-case hex digits.
    pub id: String,
    /// Its name, as this device knows it.
    pub name: String,
    /// This device's role; `None` once this device was removed from the vault.
    pub my_role: Option<SharedRole>,
    /// How many members it has now.
    pub member_count: u32,
    /// How many items it has now.
    pub item_count: u32,
    /// The folder it syncs through, if one is set.
    pub folder: Option<String>,
    /// Why it cannot be read right now, if it cannot: a damaged local copy (rebuild it from its
    /// folder, [`SharedVaultSession::rebuild`]), or a locked vault. Metadata only.
    pub problem: Option<String>,
    /// Something about the roster worth telling this device's person, if there is anything:
    /// empty while it cannot be read (`problem` says why instead).
    pub warnings: Vec<SharedRosterWarning>,
}

/// Something about a shared vault's roster worth telling its members (ADR-0035 addendum;
/// `kagisecure_shared::roster::RosterWarning`, and the CLI's `shared status`, which already
/// prints these).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SharedRosterWarning {
    /// Fewer than two admins are left: losing the last one would freeze the roster.
    FewAdmins,
    /// No admin is left: the roster is frozen and cannot change — nobody can be added, removed
    /// or given another role.
    Frozen,
}

impl SharedRosterWarning {
    const fn from_core(warning: RosterWarning) -> Self {
        match warning {
            RosterWarning::FewAdmins => Self::FewAdmins,
            RosterWarning::Frozen => Self::Frozen,
        }
    }
}

/// One device of a member.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SharedDeviceView {
    /// The device key's id, 64 lower-case hex digits.
    pub id: String,
    /// Its fingerprint, ten groups of five digits (ADR-0035 §10).
    pub fingerprint: String,
    /// Whether it is this computer.
    pub is_this_device: bool,
}

/// One member of a shared vault.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SharedMemberView {
    /// The member's id, 32 lower-case hex digits.
    pub id: String,
    /// The name this device knows them by.
    pub name: String,
    /// Their role.
    pub role: SharedRole,
    /// Whether this computer is one of their devices.
    pub is_you: bool,
    /// Their devices in the vault now.
    pub devices: Vec<SharedDeviceView>,
}

/// An invitation just written: where, and the passphrase that opens it.
///
/// `Debug` is not derived: the passphrase is a secret, shown once and never logged.
#[derive(Clone, uniffi::Record)]
pub struct SharedInvitation {
    /// Where the invitation file was written.
    pub path: String,
    /// The six words that open it — to be handed over another way than the file.
    pub passphrase: String,
    /// The member it invites.
    pub member_id: String,
}

impl std::fmt::Debug for SharedInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedInvitation")
            .field("path", &self.path)
            .field("member_id", &self.member_id)
            .finish_non_exhaustive()
    }
}

/// What a sync brought in, by name only (decision 85).
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct SharedSyncSummary {
    /// How many records were new to this device.
    pub records_added: u32,
    /// The titles of the items that changed.
    pub items_changed: Vec<String>,
    /// Whether someone was added or removed, or a role changed.
    pub members_changed: bool,
}

/// What a removed member's device could have read (decision 84): informational only.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SharedExposure {
    /// Who it was.
    pub member_name: String,
    /// The items with a version it held the key to.
    pub item_titles: Vec<String>,
}

// MARK: - Errors

/// A shared-vault failure, as the app shows it. Nothing here carries a value: `SharedError`'s
/// own rule (its module documentation).
fn shared_error(error: SharedError) -> FfiError {
    match error {
        SharedError::Core(e) => e.into(),
        SharedError::Io(e) => FfiError::Io {
            message: e.to_string(),
        },
        // A wrong passphrase and an altered invitation are not told apart, as a wrong password
        // and a tampered vault are not.
        SharedError::Decrypt => FfiError::WrongCredential,
        SharedError::Refused(why) => FfiError::invalid(capitalized(why)),
        other => FfiError::invalid(capitalized(&other.to_string())),
    }
}

/// `text` with its first letter capitalized, for an alert.
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_member(reference: &str) -> FfiResult<MemberId> {
    let missing = || FfiError::missing("member", reference);
    if reference.len() != 32 {
        return Err(missing());
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(reference.get(2 * i..2 * i + 2).ok_or_else(missing)?, 16)
            .map_err(|_| missing())?;
    }
    Ok(MemberId::from_bytes(bytes))
}

fn parse_item(reference: &str) -> FfiResult<ItemId> {
    ItemId::parse_canonical(reference).ok_or_else(|| FfiError::missing("item", reference))
}

fn parse_env(reference: &str) -> FfiResult<EnvId> {
    EnvId::parse_canonical(reference).ok_or_else(|| FfiError::missing("environment", reference))
}

/// A name a person typed: trimmed, not empty, at most 128 characters.
fn clean_name(name: &str, what: &str) -> FfiResult<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(FfiError::invalid(format!("{what} cannot be empty")));
    }
    if name.chars().count() > kagisecure_shared::admin::MAX_LABEL_CHARS {
        return Err(FfiError::invalid(format!(
            "{what} can be at most {} characters",
            kagisecure_shared::admin::MAX_LABEL_CHARS
        )));
    }
    Ok(name.to_owned())
}

// MARK: - One open shared vault

/// A shared vault's state behind its session: open, damaged, or locked.
pub(crate) struct SharedCore {
    vault_id: VaultId,
    path: PathBuf,
    state: Mutex<State>,
}

enum State {
    /// Readable and writable, as this device's role allows.
    Open(Box<Open>),
    /// The local copy does not open; says why. Rebuilt from its folder.
    Damaged(String),
    /// The personal vault locked: the keys and the items are gone.
    Closed,
}

struct Open {
    replica: Replica,
    device: DeviceSecret,
    cache: Option<Cache>,
    /// What the agent is served ([`SharedSource::snapshot`]), with the record count and file
    /// generation it was built at: records are only ever added, and every change to this
    /// device's settings is a new generation.
    agent: Option<(usize, u64, Arc<SharedSnapshot>)>,
    /// The file as the agent's last refresh read it ([`SharedSource::refresh`]).
    seen: Option<FileStamp>,
}

/// The view and the merged items, computed once per record set: records only ever get added
/// to a replica, so their count says whether this is still current.
struct Cache {
    records: usize,
    view: SharedView,
    /// Every item that is not deleted, with this device's local settings applied.
    items: Vec<Item>,
}

impl Open {
    fn new(mut replica: Replica, device: DeviceSecret) -> Self {
        replica.set_lock_timeout(APP_LOCK_TIMEOUT);
        Self {
            replica,
            device,
            cache: None,
            agent: None,
            seen: None,
        }
    }

    /// The agent's snapshot of the records and settings held now, built again only if either
    /// changed.
    fn agent_snapshot(&mut self) -> FfiResult<Arc<SharedSnapshot>> {
        let key = (
            self.replica.records().count(),
            self.replica.header().generation(),
        );
        if let Some((records, generation, snapshot)) = &self.agent
            && (*records, *generation) == key
        {
            return Ok(Arc::clone(snapshot));
        }
        self.fresh()?;
        let cache = self.cache.as_ref().expect("computed just above");
        let snapshot = Arc::new(
            SharedSnapshot::build(&self.replica, &cache.view, &self.device.id())
                .map_err(shared_error)?,
        );
        self.agent = Some((key.0, key.1, Arc::clone(&snapshot)));
        Ok(snapshot)
    }

    /// The view and items for the records held now, computed if they changed.
    fn fresh(&mut self) -> FfiResult<&mut Cache> {
        let records = self.replica.records().count();
        if self.cache.as_ref().is_none_or(|c| c.records != records) {
            self.cache = None;
            let view = SharedView::compute(
                self.replica.vault_id(),
                &self.replica.genesis(),
                &self.replica.envelopes(),
                &self.device,
            )
            .map_err(shared_error)?;
            let (items, _) = materialize_all(&view).map_err(shared_error)?;
            let items = items.into_iter().filter_map(|m| m.item).collect();
            self.cache = Some(Cache {
                records,
                view,
                items,
            });
        }
        let local = self.replica.local();
        let cache = self.cache.as_mut().expect("computed just above");
        for item in &mut cache.items {
            apply_local(item, local);
        }
        Ok(cache)
    }

    /// Item `id`, merged afresh and owned — what an edit is applied to — with this device's
    /// settings applied, so writing it keeps them.
    fn owned_item(&mut self, id: ItemId) -> FfiResult<Item> {
        let cache = self.fresh()?;
        let mut item = materialize_item(&cache.view, id)
            .map_err(shared_error)?
            .and_then(|m| m.item)
            .ok_or_else(|| FfiError::missing("item", id.to_string()))?;
        apply_local(&mut item, self.replica.local());
        Ok(item)
    }

    /// Environment `id`, merged afresh and owned — what an edit is applied to — with this
    /// device's own agent-visibility and default paths applied, so writing it keeps them.
    fn owned_env(&mut self, id: EnvId) -> FfiResult<Environment> {
        let cache = self.fresh()?;
        let mut env = materialize_env(&cache.view, id)
            .map_err(shared_error)?
            .and_then(|m| m.env)
            .ok_or_else(|| FfiError::missing("environment", id.to_string()))?;
        apply_local_env(&mut env, self.replica.local());
        Ok(env)
    }

    /// Change this device's own settings, writing nothing another member receives.
    fn local(&mut self, f: impl FnOnce(&mut LocalState)) -> FfiResult<()> {
        self.replica
            .transact(&self.device, |tx| {
                f(tx.local_mut());
                Ok(())
            })
            .map_err(shared_error)
    }
}

impl SharedCore {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn with_open<T>(&self, f: impl FnOnce(&mut Open) -> FfiResult<T>) -> FfiResult<T> {
        match &mut *self.state() {
            State::Open(open) => f(open),
            State::Damaged(problem) => Err(FfiError::invalid(problem.clone())),
            State::Closed => Err(FfiError::VaultLocked),
        }
    }

    /// Drop the keys and the items: the personal vault locked.
    fn close(&self) {
        *self.state() = State::Closed;
    }

    /// Apply `f` to item `id` as this device reads it now, or answer `NotPresent` — for a
    /// release (`crate::release::Source::Shared`).
    pub(crate) fn read_item<T>(
        &self,
        id: &ItemId,
        f: impl FnOnce(&Item) -> FfiResult<T>,
    ) -> FfiResult<T> {
        self.with_open(|open| {
            let cache = open.fresh()?;
            let item = cache
                .items
                .iter()
                .find(|item| item.id == *id)
                .ok_or_else(|| FfiError::missing("item", id.to_string()))?;
            f(item)
        })
    }
}

/// The agent reads the copy this session holds (ADR-0035 §14): attached to the personal vault's
/// handle by [`SharedVaultSession`], detached when the session is dropped or the personal vault
/// locks. Every call takes this vault's state only — never the personal vault's handle, which the
/// agent may be holding (the one lock order, module documentation).
impl SharedSource for SharedCore {
    fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    fn refresh(&self) {
        let _ = self.with_open(|open| {
            // The CLI's write to this vault's copy — `env agent-access --shared-vault`, say — is
            // picked up here; with nothing new this writes nothing, and a file that has not
            // changed since is not even read.
            let now = FileStamp::of(open.replica.path());
            if now.is_some() && now == open.seen {
                return Ok(());
            }
            open.replica
                .transact(&open.device, |_| Ok(()))
                .map_err(shared_error)?;
            open.seen = FileStamp::of(open.replica.path());
            Ok(())
        });
    }

    fn snapshot(&self) -> Option<Arc<SharedSnapshot>> {
        self.with_open(Open::agent_snapshot).ok()
    }

    fn record_approved(&self, approvals: &Approvals) -> bool {
        self.with_open(|open| {
            record_approved(&mut open.replica, &open.device, approvals).map_err(shared_error)
        })
        .is_ok()
    }
}

/// Open the replica at `path` with whichever of `devices` it belongs to.
fn open_replica(path: &Path, devices: Vec<DeviceSecret>) -> State {
    let mut problem = None;
    for device in devices {
        match Replica::open(path, &device) {
            Ok(replica) => return State::Open(Box::new(Open::new(replica, device))),
            // Another device's replica: try the next key.
            Err(SharedError::ReplicaMismatch(_)) => {}
            Err(e) => problem = Some(e),
        }
    }
    State::Damaged(match problem {
        Some(e) => format!(
            "This shared vault's copy on this Mac does not open ({e}). Rebuild it from its folder."
        ),
        None => "No key on this Mac opens this shared vault's copy. Join it again with an \
                 invitation."
            .to_owned(),
    })
}

/// Every device key the personal vault holds, as shared-vault device secrets. A key that does
/// not load is skipped: it cannot open anything anyway.
fn device_secrets(handle: &VaultHandle) -> FfiResult<Vec<DeviceSecret>> {
    handle
        .with(|vault| {
            vault
                .active_device_keys()
                .filter_map(|key| DeviceSecret::from_device_key(key).ok())
                .collect()
        })
        .ok_or(FfiError::VaultLocked)
}

// MARK: - The session object

/// One shared vault, open for as long as the personal vault is unlocked (module documentation).
#[derive(uniffi::Object)]
pub struct SharedVaultSession {
    core: Arc<SharedCore>,
    handle: Arc<VaultHandle>,
    presence: Arc<Presence>,
    /// What [`ItemView::revision`] is keyed with. A shared save does not check it (last writer
    /// wins), but the edit sheet carries one, so it is computed the same way.
    revision_key: RevisionKey,
    /// Closes `core` when the personal vault locks; dropped with this session.
    _lock_hook: LockHookGuard,
    /// Serves `core` to agents beside the personal vault until this session is dropped or the
    /// personal vault locks (`kagisecure_agent::shared`).
    _attachment: SharedAttachment,
}

impl std::fmt::Debug for SharedVaultSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedVaultSession")
            .field("vault_id", &hex(self.core.vault_id.0.as_bytes()))
            .finish_non_exhaustive()
    }
}

impl SharedVaultSession {
    fn new(
        session: &VaultSession,
        vault_id: VaultId,
        path: PathBuf,
        state: State,
    ) -> FfiResult<Arc<Self>> {
        let handle = session.handle();
        let core = Arc::new(SharedCore {
            vault_id,
            path,
            state: Mutex::new(state),
        });
        let weak = Arc::downgrade(&core);
        let hook = handle.add_lock_hook(Box::new(move || {
            if let Some(core) = weak.upgrade() {
                core.close();
            }
        }));
        // A lock that ran before the hook was in place.
        if !handle.is_unlocked() {
            core.close();
            return Err(FfiError::VaultLocked);
        }
        let source: Arc<dyn SharedSource> = Arc::clone(&core) as Arc<dyn SharedSource>;
        let attachment = handle.attach_shared(source);
        Ok(Arc::new(Self {
            core,
            handle,
            presence: session.presence(),
            revision_key: RevisionKey::generate()?,
            _lock_hook: hook,
            _attachment: attachment,
        }))
    }

    fn view(&self, item: &Item) -> ItemView {
        ItemView::from_core(item, &self.revision_key)
    }

    fn releaser(&self) -> Releaser {
        Releaser {
            handle: Arc::clone(&self.handle),
            presence: Arc::clone(&self.presence),
            source: Source::Shared(Arc::clone(&self.core)),
        }
    }

    /// Item `id` as it is now, after a change.
    fn item_now(&self, open: &mut Open, id: ItemId) -> FfiResult<ItemView> {
        let cache = open.fresh()?;
        cache
            .items
            .iter()
            .find(|item| item.id == id)
            .map(|item| self.view(item))
            .ok_or_else(|| FfiError::missing("item", id.to_string()))
    }

    /// Write `item` as a new version, and answer it as it is now.
    fn put(&self, open: &mut Open, item: Item) -> FfiResult<ItemView> {
        let id = item.id;
        write::put_item(&mut open.replica, &open.device, item, unix_now()).map_err(shared_error)?;
        self.item_now(open, id)
    }

    /// Environment `id` as it is now, after a change.
    fn environment_now(&self, open: &mut Open, id: EnvId) -> FfiResult<EnvironmentView> {
        Ok(EnvironmentView::from_core(&open.owned_env(id)?))
    }

    /// Write `env` as a new version, and answer it as it is now.
    fn put_env(&self, open: &mut Open, env: Environment) -> FfiResult<EnvironmentView> {
        let id = env.id;
        write::put_env(&mut open.replica, &open.device, env, unix_now()).map_err(shared_error)?;
        self.environment_now(open, id)
    }

    /// Write an invitation for `joining` to `out_path`, labelled `label`. For a new member,
    /// `kagisecure_shared::admin::enroll::invite_with_kdf` itself takes `label` as this device's
    /// own local name for them, so it need not be set here too.
    fn invite(
        &self,
        joining: Joining,
        label: &str,
        out_path: &str,
        kdf_m_kib: Option<u32>,
        kdf_t: Option<u32>,
    ) -> FfiResult<SharedInvitation> {
        let defaults = KdfParams::defaults()?;
        let kdf = if kdf_m_kib.is_some() || kdf_t.is_some() {
            KdfParams::new(
                kdf_m_kib.unwrap_or(defaults.m_kib),
                kdf_t.unwrap_or(defaults.t),
                defaults.p,
            )?
        } else {
            defaults
        };
        self.core.with_open(|open| {
            let invite = enroll::invite_with_kdf(
                &mut open.replica,
                &open.device,
                joining,
                label,
                kdf,
                unix_now(),
            )
            .map_err(shared_error)?;
            std::fs::write(out_path, &invite.file).map_err(|e| FfiError::Io {
                message: format!("the invitation could not be saved: {e}"),
            })?;
            let member = open
                .fresh()?
                .view
                .roster()
                .snapshot()
                .device(&invite.device)
                .map(|d| d.member)
                .ok_or_else(|| FfiError::invalid("the invited device is not in the vault"))?;
            let passphrase = invite
                .passphrase
                .expose_str()
                .ok_or_else(|| FfiError::invalid("the passphrase is not text"))?
                .to_owned();
            Ok(SharedInvitation {
                path: out_path.to_owned(),
                passphrase,
                member_id: hex(member.as_bytes()),
            })
        })
    }
}

#[uniffi::export]
impl SharedVaultSession {
    /// The shared vault's id, 32 lower-case hex digits.
    pub fn vault_id(&self) -> String {
        hex(self.core.vault_id.0.as_bytes())
    }

    /// What the sidebar shows. Never fails: a vault that cannot be read says why in `problem`.
    pub fn summary(&self) -> SharedVaultSummary {
        let id = self.vault_id();
        let unreadable = |id: String, problem: String| SharedVaultSummary {
            id,
            name: UNNAMED_VAULT.to_owned(),
            my_role: None,
            member_count: 0,
            item_count: 0,
            folder: None,
            problem: Some(problem),
            warnings: Vec::new(),
        };
        let mut state = self.core.state();
        let open = match &mut *state {
            State::Open(open) => open,
            State::Damaged(problem) => return unreadable(id, problem.clone()),
            State::Closed => return unreadable(id, "The vault is locked.".to_owned()),
        };
        let name = open
            .replica
            .local()
            .vault_name
            .clone()
            .unwrap_or_else(|| UNNAMED_VAULT.to_owned());
        let folder = open.replica.local().exchange_dir.clone();
        let me = open.device.id();
        match open.fresh() {
            Ok(cache) => {
                let roster = cache.view.roster();
                let snapshot = roster.snapshot();
                let members = snapshot.members().filter(|m| m.active).count();
                let items = cache.items.iter().filter(|i| !i.is_trashed()).count();
                SharedVaultSummary {
                    id,
                    name,
                    my_role: roster.role_of(&me).map(SharedRole::from_core),
                    member_count: u32::try_from(members).unwrap_or(u32::MAX),
                    item_count: u32::try_from(items).unwrap_or(u32::MAX),
                    folder,
                    problem: None,
                    warnings: roster
                        .warnings()
                        .into_iter()
                        .map(SharedRosterWarning::from_core)
                        .collect(),
                }
            }
            Err(e) => SharedVaultSummary {
                name,
                folder,
                ..unreadable(id, e.to_string())
            },
        }
    }

    /// Rename the vault on this device. The name is this device's own (decision 81): other
    /// members keep theirs.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] for an empty or over-long name; [`FfiError::VaultLocked`].
    pub fn rename(&self, name: String) -> FfiResult<()> {
        let name = clean_name(&name, "A shared vault's name")?;
        self.core
            .with_open(|open| open.local(|local| local.vault_name = Some(name)))
    }

    // MARK: Items

    /// The items for one section, as [`VaultSession::list_items`] lists the personal vault's.
    /// Empty once locked, or if the vault cannot be read.
    pub fn list_items(
        &self,
        filter: ItemFilter,
        query: Option<String>,
        sort: ItemSort,
    ) -> Vec<ItemView> {
        self.core
            .with_open(|open| {
                let cache = open.fresh()?;
                Ok(select_items(&cache.items, &filter, query, sort)
                    .into_iter()
                    .map(|item| self.view(item))
                    .collect())
            })
            .unwrap_or_default()
    }

    /// One item by id.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], [`FfiError::VaultLocked`].
    pub fn item(&self, item_id: String) -> FfiResult<ItemView> {
        let id = parse_item(&item_id)?;
        self.core.with_open(|open| self.item_now(open, id))
    }

    /// Create an item from its category's template, and write it.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] if this device may not write (a reader), and as a write.
    pub fn create_item(&self, category: String, title: String) -> FfiResult<ItemView> {
        self.core.with_open(|open| {
            let category: Category = category.parse().unwrap_or(Category::Login);
            let item = Item::from_template(*open.replica.vault_id(), category, title);
            self.put(open, item)
        })
    }

    /// Save what the edit sheet produced, as [`VaultSession::save_item`] does — but with no
    /// conflict check: the last writer wins (decision 80), so `draft.revision` is not compared
    /// and [`FfiError::ItemChangedElsewhere`] is never answered.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] for a draft [`VaultSession::save_item`] would refuse, or if this
    /// device may not write; [`FfiError::NotPresent`]; [`FfiError::VaultLocked`].
    pub fn save_item(&self, draft: ItemDraft) -> FfiResult<ItemView> {
        let id = parse_item(&draft.id)?;
        self.core.with_open(|open| {
            let mut item = open.owned_item(id)?;
            if let Some(message) = draft_problem(&item, &draft) {
                return Err(FfiError::Invalid { message });
            }
            apply_draft(&mut item, draft);
            self.put(open, item)
        })
    }

    /// Mark an item a favourite on this device, or not. Writes nothing others receive.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], [`FfiError::VaultLocked`].
    pub fn set_favorite(&self, item_id: String, favorite: bool) -> FfiResult<ItemView> {
        let id = parse_item(&item_id)?;
        self.core.with_open(|open| {
            self.item_now(open, id)?;
            open.local(|local| {
                if favorite {
                    local.favorites.insert(id);
                } else {
                    local.favorites.remove(&id);
                }
            })?;
            self.item_now(open, id)
        })
    }

    /// Archive an item, or bring it back: a new version, for everyone.
    ///
    /// # Errors
    ///
    /// As [`SharedVaultSession::save_item`].
    pub fn set_archived(&self, item_id: String, archived: bool) -> FfiResult<ItemView> {
        let id = parse_item(&item_id)?;
        self.core.with_open(|open| {
            let mut item = open.owned_item(id)?;
            item.archived = archived;
            item.updated_at = unix_now();
            self.put(open, item)
        })
    }

    /// Moving a shared item to the trash deletes it for everyone (module documentation); `false`
    /// clears a trash mark another build set. Answers the item as it was.
    ///
    /// # Errors
    ///
    /// As [`SharedVaultSession::save_item`].
    pub fn set_trashed(&self, item_id: String, trashed: bool) -> FfiResult<ItemView> {
        let id = parse_item(&item_id)?;
        self.core.with_open(|open| {
            let mut item = open.owned_item(id)?;
            if trashed {
                item.trashed_at = Some(unix_now());
                let view = self.view(&item);
                write::delete_item(&mut open.replica, &open.device, id, unix_now())
                    .map_err(shared_error)?;
                Ok(view)
            } else {
                item.trashed_at = None;
                item.updated_at = unix_now();
                self.put(open, item)
            }
        })
    }

    /// Delete an item for everyone. `revision` is not checked (last writer wins).
    ///
    /// # Errors
    ///
    /// As [`SharedVaultSession::save_item`].
    pub fn delete_item(&self, item_id: String, revision: String) -> FfiResult<()> {
        let _ = revision;
        let id = parse_item(&item_id)?;
        self.core.with_open(|open| {
            open.owned_item(id)?;
            write::delete_item(&mut open.replica, &open.device, id, unix_now())
                .map_err(shared_error)?;
            Ok(())
        })
    }

    /// Let this device's agents see an item, or not (decision 22: this device's own setting).
    /// Turning an item off turns its fields off too.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], [`FfiError::VaultLocked`].
    pub fn set_agent_visible(&self, item_id: String, visible: bool) -> FfiResult<ItemView> {
        let id = parse_item(&item_id)?;
        self.core.with_open(|open| {
            self.item_now(open, id)?;
            open.local(|local| {
                if visible {
                    local.agent_visible_items.insert(id);
                } else {
                    local.agent_visible_items.remove(&id);
                    local.agent_visible_fields.remove(&id);
                }
            })?;
            self.item_now(open, id)
        })
    }

    /// One field's agent visibility on this device.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`] for an unknown item or field, [`FfiError::VaultLocked`].
    pub fn set_field_agent_visible(
        &self,
        item_id: String,
        field_id: String,
        visible: bool,
    ) -> FfiResult<ItemView> {
        let id = parse_item(&item_id)?;
        self.core.with_open(|open| {
            let field = open
                .fresh()?
                .items
                .iter()
                .find(|item| item.id == id)
                .ok_or_else(|| FfiError::missing("item", item_id.clone()))?
                .fields
                .iter()
                .find(|f| f.id.to_string() == field_id)
                .map(|f| f.id)
                .ok_or_else(|| FfiError::missing("field", field_id.clone()))?;
            open.local(|local| {
                let fields = local.agent_visible_fields.entry(id).or_default();
                if visible {
                    fields.insert(field);
                } else {
                    fields.remove(&field);
                }
                if fields.is_empty() {
                    local.agent_visible_fields.remove(&id);
                }
            })?;
            self.item_now(open, id)
        })
    }

    // MARK: Environments

    /// Every environment in this shared vault, names only (ui-spec.md §16), the same shape
    /// [`VaultSession::environments`] answers for the personal vault. Empty once locked, or if
    /// the vault cannot be read.
    pub fn environments(&self) -> Vec<EnvironmentView> {
        self.core
            .with_open(|open| {
                let merged = {
                    let cache = open.fresh()?;
                    materialize_all(&cache.view).map_err(shared_error)?.1
                };
                let local = open.replica.local();
                Ok(merged
                    .into_iter()
                    .filter_map(|m| m.env)
                    .map(|mut env| {
                        apply_local_env(&mut env, local);
                        EnvironmentView::from_core(&env)
                    })
                    .collect())
            })
            .unwrap_or_default()
    }

    /// One environment by id.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], [`FfiError::VaultLocked`].
    pub fn environment(&self, environment_id: String) -> FfiResult<EnvironmentView> {
        let id = parse_env(&environment_id)?;
        self.core.with_open(|open| self.environment_now(open, id))
    }

    /// Create an empty environment, invisible to agents until this device shares it
    /// ([`SharedVaultSession::set_environment_agent_visible`]) — as
    /// [`VaultSession::create_environment`], for this shared vault.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] for an empty or over-long name, or if this device may not write;
    /// [`FfiError::VaultLocked`].
    pub fn create_environment(
        &self,
        name: String,
        description: Option<String>,
    ) -> FfiResult<EnvironmentView> {
        let name = clean_name(&name, "An environment's name")?;
        self.core.with_open(|open| {
            let mut env = Environment::new(*open.replica.vault_id(), name);
            env.description = description.filter(|d| !d.trim().is_empty());
            self.put_env(open, env)
        })
    }

    /// Rename the environment on every member's copy. Unlike a shared vault's own name
    /// ([`SharedVaultSession::rename`]), this is a record every member sees the same way — an
    /// environment has one name, not one per Mac.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] for an empty or over-long name, or if this device may not write;
    /// [`FfiError::NotPresent`]; [`FfiError::VaultLocked`].
    pub fn rename_environment(
        &self,
        environment_id: String,
        name: String,
    ) -> FfiResult<EnvironmentView> {
        let id = parse_env(&environment_id)?;
        let name = clean_name(&name, "An environment's name")?;
        self.core.with_open(|open| {
            let mut env = open.owned_env(id)?;
            env.name = name;
            env.updated_at = unix_now();
            self.put_env(open, env)
        })
    }

    /// Let this device's agents see the environment, or not — this device's own setting
    /// (module documentation, decision 22), like an item's agent visibility
    /// ([`SharedVaultSession::set_agent_visible`]). Written to this device's local state, never
    /// as a new version of the environment, so a reader may flip it exactly as a writer can — it
    /// changes nothing anyone else's copy holds.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], [`FfiError::VaultLocked`].
    pub fn set_environment_agent_visible(
        &self,
        environment_id: String,
        visible: bool,
    ) -> FfiResult<EnvironmentView> {
        let id = parse_env(&environment_id)?;
        self.core.with_open(|open| {
            open.owned_env(id)?;
            open.local(|local| {
                if visible {
                    local.agent_visible_envs.insert(id);
                } else {
                    local.agent_visible_envs.remove(&id);
                }
            })?;
            self.environment_now(open, id)
        })
    }

    /// Set a variable to a value typed here, as [`VaultSession::set_variable_value`] does for the
    /// personal vault.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] for a name that is not an identifier, or if this device may not
    /// write; [`FfiError::NotPresent`]; [`FfiError::VaultLocked`].
    pub fn set_variable_value(
        &self,
        environment_id: String,
        name: String,
        value: String,
    ) -> FfiResult<EnvironmentView> {
        let id = parse_env(&environment_id)?;
        let name = valid_var_name(&name)?;
        self.core.with_open(|open| {
            let mut env = open.owned_env(id)?;
            env.set_var(
                name.clone(),
                VarSource::Literal(kagisecure_core::Secret::from_string(value)),
            );
            env.updated_at = unix_now();
            self.put_env(open, env)
        })
    }

    /// Bind a variable to a field of an item of this same shared vault (module documentation:
    /// "references stay inside the vault") — the preferred shape, as
    /// [`VaultSession::bind_variable`] is for the personal vault.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] for a name that is not an identifier, or if this device may not
    /// write; [`FfiError::NotPresent`] if the environment, item or field does not exist;
    /// [`FfiError::VaultLocked`].
    pub fn bind_variable(
        &self,
        environment_id: String,
        name: String,
        item_id: String,
        field_id: String,
    ) -> FfiResult<EnvironmentView> {
        let id = parse_env(&environment_id)?;
        let name = valid_var_name(&name)?;
        let item = parse_item(&item_id)?;
        self.core.with_open(|open| {
            let field = {
                let cache = open.fresh()?;
                cache
                    .items
                    .iter()
                    .find(|i| i.id == item)
                    .ok_or_else(|| FfiError::missing("item", item_id.clone()))?
                    .fields
                    .iter()
                    .find(|f| f.id.to_string() == field_id)
                    .map(|f| f.id)
                    .ok_or_else(|| FfiError::missing("field", field_id.clone()))?
            };
            let mut env = open.owned_env(id)?;
            env.set_var(name.clone(), VarSource::ItemField { item, field });
            env.updated_at = unix_now();
            self.put_env(open, env)
        })
    }

    /// Remove one variable from an environment, as [`VaultSession::remove_variable`] does.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], or if this device may not write; [`FfiError::VaultLocked`].
    pub fn remove_variable(
        &self,
        environment_id: String,
        name: String,
    ) -> FfiResult<EnvironmentView> {
        let id = parse_env(&environment_id)?;
        self.core.with_open(|open| {
            let mut env = open.owned_env(id)?;
            env.remove_var(&name);
            env.updated_at = unix_now();
            self.put_env(open, env)
        })
    }

    /// Delete an environment for everyone, as [`VaultSession::delete_environment`] does for the
    /// personal vault.
    ///
    /// # Errors
    ///
    /// [`FfiError::NotPresent`], or if this device may not write; [`FfiError::VaultLocked`].
    pub fn delete_environment(&self, environment_id: String) -> FfiResult<()> {
        let id = parse_env(&environment_id)?;
        self.core.with_open(|open| {
            open.owned_env(id)?;
            write::delete_env(&mut open.replica, &open.device, id, unix_now())
                .map_err(shared_error)?;
            Ok(())
        })
    }

    // MARK: Releases

    /// [`VaultSession::release_field`], for an item of this shared vault. The same presence
    /// gate, the same five-minute cap, recorded in the personal vault's audit log.
    ///
    /// # Errors
    ///
    /// As [`VaultSession::release_field`].
    pub async fn release_field(
        &self,
        item_id: String,
        field_id: String,
        purpose: ReleasePurpose,
    ) -> FfiResult<Arc<FieldRelease>> {
        self.releaser().field(item_id, field_id, purpose).await
    }

    /// [`VaultSession::release_totp`], for an item of this shared vault.
    ///
    /// # Errors
    ///
    /// As [`VaultSession::release_totp`].
    pub async fn release_totp(
        &self,
        item_id: String,
        field_id: Option<String>,
        purpose: ReleasePurpose,
    ) -> FfiResult<Arc<TotpRelease>> {
        self.releaser().totp(item_id, field_id, purpose).await
    }

    /// [`VaultSession::release_notes`], for an item of this shared vault.
    ///
    /// # Errors
    ///
    /// As [`VaultSession::release_notes`].
    pub async fn release_notes(
        &self,
        item_id: String,
        purpose: ReleasePurpose,
    ) -> FfiResult<Arc<NotesRelease>> {
        self.releaser().notes(item_id, purpose).await
    }

    // MARK: Members

    /// The members now, this device's first, then by name. Empty if the vault cannot be read.
    pub fn members(&self) -> Vec<SharedMemberView> {
        self.core
            .with_open(|open| {
                let me = open.device.id();
                let names = open.replica.local().member_names.clone();
                let cache = open.fresh()?;
                let snapshot = cache.view.roster().snapshot();
                let mut members: Vec<SharedMemberView> = snapshot
                    .members()
                    .filter(|m| m.active)
                    .map(|m| {
                        let devices: Vec<SharedDeviceView> = snapshot
                            .active_devices()
                            .filter(|d| d.member == m.id)
                            .map(|d| SharedDeviceView {
                                id: d.public.id().to_string(),
                                fingerprint: d.public.fingerprint().to_string(),
                                is_this_device: d.public.id() == me,
                            })
                            .collect();
                        let is_you = devices.iter().any(|d| d.is_this_device);
                        let name = names.get(&m.id).cloned().unwrap_or_else(|| {
                            if is_you {
                                "You".to_owned()
                            } else {
                                // Nobody on this device named them (decision 81: roster labels'
                                // sealing is undecided, so names never sync). A device's
                                // fingerprint at least tells one nameless member from another,
                                // rather than every one of them reading identically.
                                device_label(&devices).unwrap_or_else(|| UNNAMED_MEMBER.to_owned())
                            }
                        });
                        SharedMemberView {
                            id: hex(m.id.as_bytes()),
                            name,
                            role: SharedRole::from_core(m.role),
                            is_you,
                            devices,
                        }
                    })
                    .collect();
                members.sort_by_key(|m| (!m.is_you, m.name.to_lowercase()));
                Ok(members)
            })
            .unwrap_or_default()
    }

    /// Invite a new member called `name` with `role`: writes the invitation file to `out_path`
    /// and answers the passphrase that opens it (decision 86). The name becomes the member's
    /// name on this device and the joining computer's device-key label. No presence check
    /// (decision 86): the personal vault being unlocked is enough.
    ///
    /// `kdf_m_kib` and `kdf_t` override the passphrase's Argon2id cost, as
    /// [`VaultSession::create`]'s do; pass `None` for the personal vault's default.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] unless this device is an admin, or for an empty name;
    /// [`FfiError::Io`] if the file cannot be written.
    pub fn invite_member(
        &self,
        name: String,
        role: SharedRole,
        out_path: String,
        kdf_m_kib: Option<u32>,
        kdf_t: Option<u32>,
    ) -> FfiResult<SharedInvitation> {
        let name = clean_name(&name, "A member's name")?;
        self.invite(
            Joining::NewMember(role.to_core()),
            &name,
            &out_path,
            kdf_m_kib,
            kdf_t,
        )
    }

    /// Invite another computer of an existing member: as [`SharedVaultSession::invite_member`],
    /// with the member's role.
    ///
    /// # Errors
    ///
    /// As [`SharedVaultSession::invite_member`], and [`FfiError::Invalid`] for someone who is
    /// not a member.
    pub fn invite_device(
        &self,
        member_id: String,
        out_path: String,
        kdf_m_kib: Option<u32>,
        kdf_t: Option<u32>,
    ) -> FfiResult<SharedInvitation> {
        let member = parse_member(&member_id)?;
        let label = self
            .core
            .with_open(|open| Ok(open.replica.local().member_names.get(&member).cloned()))?
            .unwrap_or_else(|| "Another computer".to_owned());
        self.invite(
            Joining::ExistingMember(member),
            &label,
            &out_path,
            kdf_m_kib,
            kdf_t,
        )
    }

    /// Give a member another role.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] unless this device is an admin, or if no admin would be left.
    pub fn set_role(&self, member_id: String, role: SharedRole) -> FfiResult<()> {
        let member = parse_member(&member_id)?;
        self.core.with_open(|open| {
            remove::set_role(
                &mut open.replica,
                &open.device,
                member,
                role.to_core(),
                unix_now(),
            )
            .map_err(shared_error)?;
            Ok(())
        })
    }

    /// Remove a member and every computer of theirs: nothing written from now on reaches them
    /// (decision 83). What they could read before is listed by
    /// [`SharedVaultSession::rotation_list`].
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] unless this device is an admin, for this device's own member, or if
    /// no admin would be left.
    pub fn remove_member(&self, member_id: String) -> FfiResult<()> {
        let member = parse_member(&member_id)?;
        self.core.with_open(|open| {
            remove::remove_member(
                &mut open.replica,
                &open.device,
                member,
                RemovalReason::Left,
                unix_now(),
            )
            .map_err(shared_error)?;
            Ok(())
        })
    }

    /// Name a member on this device.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] for an empty or over-long name.
    pub fn set_member_name(&self, member_id: String, name: String) -> FfiResult<()> {
        let member = parse_member(&member_id)?;
        let name = clean_name(&name, "A member's name")?;
        self.core.with_open(|open| {
            open.local(|local| {
                local.member_names.insert(member, name);
            })
        })
    }

    /// What removed members could have read: the items to consider changing at their source
    /// (decision 84). Informational only.
    pub fn rotation_list(&self) -> Vec<SharedExposure> {
        self.core
            .with_open(|open| {
                let names = open.replica.local().member_names.clone();
                let cache = open.fresh()?;
                let snapshot = cache.view.roster().snapshot();
                Ok(rotation_list(&cache.view)
                    .into_iter()
                    .map(|exposure| {
                        let member_name = snapshot
                            .device(&exposure.device)
                            .and_then(|d| names.get(&d.member).cloned())
                            .unwrap_or_else(|| "A removed member".to_owned());
                        let item_titles = exposure
                            .objects
                            .iter()
                            .filter_map(|object| match object {
                                ObjectId::Item(id) => cache
                                    .items
                                    .iter()
                                    .find(|item| item.id == *id)
                                    .map(|item| item.title.clone()),
                                ObjectId::Env(_) => None,
                            })
                            .collect();
                        SharedExposure {
                            member_name,
                            item_titles,
                        }
                    })
                    .filter(|e| !e.item_titles.is_empty())
                    .collect())
            })
            .unwrap_or_default()
    }

    // MARK: Syncing

    /// The folder this vault syncs through, if one is set.
    pub fn folder(&self) -> Option<String> {
        self.core
            .with_open(|open| Ok(open.replica.local().exchange_dir.clone()))
            .ok()
            .flatten()
    }

    /// Sync through `folder` from now on — or through none — and sync once.
    ///
    /// # Errors
    ///
    /// [`FfiError::Io`] if the folder cannot be read or written; [`FfiError::VaultLocked`].
    pub fn set_folder(&self, folder: Option<String>) -> FfiResult<SharedSyncSummary> {
        self.core.with_open(|open| {
            exchange::set_exchange_dir(
                &mut open.replica,
                &open.device,
                folder.as_deref().map(Path::new),
            )
            .map_err(shared_error)
        })?;
        self.sync()
    }

    /// Pick up this computer's copy as it is on disk, then, with a folder set, take in every
    /// record the folder has that this device does not and hand on every record it is missing
    /// (decision 85). Cheap when nothing changed (decision 87): the app calls this on every
    /// change in the folder, when it becomes active and after each change of its own.
    ///
    /// # Errors
    ///
    /// [`FfiError::Io`] if the folder cannot be read or written; [`FfiError::VaultLocked`].
    pub fn sync(&self) -> FfiResult<SharedSyncSummary> {
        self.core.with_open(|open| {
            // Another process's write to the replica — the CLI — is picked up here; with nothing
            // new this writes nothing.
            open.replica
                .transact(&open.device, |_| Ok(()))
                .map_err(shared_error)?;
            if open.replica.local().exchange_dir.is_none() {
                return Ok(SharedSyncSummary::default());
            }
            let summary = exchange::sync(&mut open.replica, &open.device).map_err(shared_error)?;
            Ok(SharedSyncSummary {
                records_added: u32::try_from(summary.records_added).unwrap_or(u32::MAX),
                items_changed: summary.items,
                members_changed: summary.roster_changed,
            })
        })
    }

    /// Rebuild this vault's copy on this Mac from its folder, when it no longer opens
    /// (decision 85). The damaged file is kept beside the new one.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] if no key on this Mac is a device of the vault in that folder;
    /// [`FfiError::Io`]; [`FfiError::VaultLocked`].
    pub fn rebuild(&self, folder: String) -> FfiResult<()> {
        // The personal vault first, then this vault's state: the one lock order.
        let devices = device_secrets(&self.handle)?;
        let mut state = self.core.state();
        match &*state {
            State::Open(_) => return Ok(()),
            State::Closed => return Err(FfiError::VaultLocked),
            State::Damaged(_) => {}
        }
        let mut last = FfiError::invalid("No key on this Mac belongs to this shared vault.");
        for device in devices {
            match Replica::rebuild_from(
                &self.core.path,
                &device,
                RebuildSource::Dir(Path::new(&folder)),
                unix_now(),
            ) {
                Ok(replica) => {
                    *state = State::Open(Box::new(Open::new(replica, device)));
                    return Ok(());
                }
                Err(e) => last = shared_error(e),
            }
        }
        Err(last)
    }
}

// MARK: - The entry points on the personal vault

#[uniffi::export]
impl VaultSession {
    /// Every shared vault this personal vault has a copy of, opened (module documentation). A
    /// copy that does not open is still listed, with its `problem` in
    /// [`SharedVaultSession::summary`].
    ///
    /// # Errors
    ///
    /// [`FfiError::VaultLocked`]; [`FfiError::Io`] if the shared vaults' directory cannot be read.
    pub fn open_shared_vaults(&self) -> FfiResult<Vec<Arc<SharedVaultSession>>> {
        let personal = PathBuf::from(self.path());
        let ids = list_replicas(&personal).map_err(shared_error)?;
        ids.into_iter()
            .map(|id| {
                let path = replica_path(&personal, &id);
                let state = open_replica(&path, device_secrets(&self.handle())?);
                SharedVaultSession::new(self, id, path, state)
            })
            .collect()
    }

    /// Create a shared vault called `name`, with this Mac as its first admin — syncing through
    /// `folder` (an iCloud Drive or Dropbox folder, say) if one is given.
    ///
    /// Each vault this Mac creates gets a device key of its own in the personal vault. The first
    /// device key upgrades the personal vault file's format, keeping a `.bak-1` copy of it.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] for an empty or over-long name; [`FfiError::Io`] if the folder
    /// cannot be written; [`FfiError::VaultLocked`].
    pub fn create_shared_vault(
        &self,
        name: String,
        folder: Option<String>,
    ) -> FfiResult<Arc<SharedVaultSession>> {
        let name = clean_name(&name, "A shared vault's name")?;
        let now = unix_now();
        let device = DeviceSecret::generate().map_err(shared_error)?;
        let key = device.to_device_key(&name, now).map_err(shared_error)?;
        self.transact(|tx| tx.add_device_key(key, CREATE_ACTOR))?;
        let personal = PathBuf::from(self.path());
        let replica = create::create(
            &personal,
            &device,
            &name,
            folder.as_deref().map(Path::new),
            now,
        )
        .map_err(shared_error)?;
        let id = *replica.vault_id();
        let path = replica.path().to_owned();
        SharedVaultSession::new(
            self,
            id,
            path,
            State::Open(Box::new(Open::new(replica, device))),
        )
    }

    /// Join the shared vault an invitation file invites this Mac to, with the passphrase that
    /// came with it (decision 86) — syncing through `folder` if one is given. Joining a vault
    /// already joined adds the invitation's records to it.
    ///
    /// # Errors
    ///
    /// [`FfiError::WrongCredential`] for a wrong passphrase or an altered file;
    /// [`FfiError::Invalid`] for a file that is not an invitation; [`FfiError::Io`];
    /// [`FfiError::VaultLocked`].
    pub fn join_shared_vault(
        &self,
        invitation_path: String,
        passphrase: String,
        folder: Option<String>,
    ) -> FfiResult<Arc<SharedVaultSession>> {
        let passphrase = Zeroizing::new(passphrase);
        let io = |e: std::io::Error| FfiError::Io {
            message: format!("the invitation could not be read: {e}"),
        };
        let size = std::fs::metadata(&invitation_path).map_err(io)?.len();
        if size > enroll::MAX_INVITATION_BYTES {
            return Err(FfiError::invalid(
                "that file is too large to be an invitation",
            ));
        }
        let file = std::fs::read(&invitation_path).map_err(io)?;
        // Locked: say so before the passphrase is stretched for nothing.
        self.with_vault(|_| ())?;
        // The slow part — Argon2id, the records' signatures — with the personal vault not held,
        // so nothing else waits on it.
        let opened = enroll::open_invitation(&file, &passphrase).map_err(shared_error)?;
        let (replica, device) = {
            let mut vault = self.vault()?;
            enroll::join_opened(
                &mut vault,
                opened,
                folder.as_deref().map(Path::new),
                unix_now(),
            )
            .map_err(shared_error)?
        };
        let id = *replica.vault_id();
        let path = replica.path().to_owned();
        let session = SharedVaultSession::new(
            self,
            id,
            path,
            State::Open(Box::new(Open::new(replica, device))),
        )?;
        // Pick up what others wrote since the invitation was made. A folder that cannot be read
        // yet — a sync client still downloading — is not a failed join; the app syncs again.
        let _ = session.sync();
        Ok(session)
    }
}

// MARK: - For unattended copies (ADR-0042 §13, `crate::unattended_manage`)

impl SharedVaultSession {
    /// The shared vault's id.
    pub(crate) fn raw_vault_id(&self) -> VaultId {
        self.core.vault_id
    }

    /// The snapshot agents are served from: merged environments and items with where each value
    /// came from.
    pub(crate) fn unattended_snapshot(&self) -> FfiResult<Arc<SharedSnapshot>> {
        self.core.with_open(Open::agent_snapshot)
    }

    /// The vault's policy on unattended copies, and which devices hold one.
    pub(crate) fn unattended_state(
        &self,
    ) -> FfiResult<kagisecure_shared::unattended::UnattendedState> {
        self.core.with_open(|open| {
            Ok(kagisecure_shared::unattended::unattended_state(
                &open.fresh()?.view,
            ))
        })
    }

    /// Run `f` with this vault's replica and this device's key, to write a record.
    pub(crate) fn with_replica<T>(
        &self,
        f: impl FnOnce(&mut Replica, &DeviceSecret) -> FfiResult<T>,
    ) -> FfiResult<T> {
        self.core
            .with_open(|open| f(&mut open.replica, &open.device))
    }

    /// Whether this device is an admin of the vault.
    pub(crate) fn is_admin(&self) -> bool {
        self.core
            .with_open(|open| {
                let id = open.device.id();
                Ok(open.fresh()?.view.roster().role_of(&id) == Some(Role::Admin))
            })
            .unwrap_or(false)
    }
}

/// A shared-vault failure, for `crate::unattended_manage`.
pub(crate) fn shared_failure(error: SharedError) -> FfiError {
    shared_error(error)
}
