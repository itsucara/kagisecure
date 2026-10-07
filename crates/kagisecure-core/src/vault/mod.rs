//! Opening, creating and saving vault files (vault-format §2, §3, §9).
//!
//! # Several writers, one file
//!
//! One vault file is written by more than one process — the app, the CLI, the agent daemon —
//! and by more than one [`Vault`] value inside one process. Each holds the whole decrypted body
//! in memory, so a writer that simply serialised its own copy would silently erase whatever
//! another writer committed since it last read the file: a lost update, which for the audit log
//! means lost evidence. Writes are therefore transactions ([`Vault::transact`]):
//!
//! 1. take the sibling lock file ([`lock`]), waiting a bounded time ([`Error::VaultBusy`]);
//! 2. read and hash the file as it is *now*. If it is still the generation this session's memory
//!    descends from, keep memory; otherwise adopt the file as the in-memory state — after
//!    checking that it is still this vault (same `vault_id`, and its body opens with the key this
//!    session holds: the vault key never changes, a password change only re-wraps it) and that
//!    it still continues the audit log this session last saw on disk (the *continuity check*);
//! 3. chain the audit drafts still waiting to be saved (the *pending queue*) onto the fresh head;
//! 4. run the caller's closure — synchronous, in memory — against that fresh state;
//! 5. write the result atomically and record its *generation*;
//! 6. release the lock.
//!
//! If step 4 or 5 fails, the session is restored to exactly where it began (rollback by
//! reload): the file bytes read in step 2 — ciphertext, kept for the length of the transaction —
//! are decrypted again. That needs no disk, so a volume that vanishes mid-transaction cannot
//! leave the closure's uncommitted changes readable, and it avoids keeping a second decrypted
//! copy of the body around just for rollback (threat-model M-10). Under the lock those bytes are
//! also exactly what is on disk: `write_atomically` either replaced the file completely or left
//! it untouched. The drafts the transaction carried in go back into the pending queue.
//!
//! A write can also fail *ambiguously* — report an error after its rename took effect, with the
//! file then unreadable. Such a write is remembered and settled by content the next time the file
//! is read, so its audit entries are never chained a second time (see `UnconfirmedWrite`).
//!
//! A vault file is at most [`MAX_VAULT_FILE_LEN`] bytes, checked before reading and before
//! writing.
//!
//! A **generation** is the SHA-256 of a file's exact bytes: recorded when a vault is opened or
//! created (the bytes that were decrypted) and after every write (the bytes that were written).
//! It is how any writer — transactional or not — knows whether the file still is the version
//! its in-memory state descends from.
//!
//! The **continuity check** is what stops a transaction from building on a file that went
//! *backwards*: the fresh file's audit log must contain, at the same position, the last entry
//! this session knows reached the disk. A file restored from an older copy fails it
//! ([`Error::VaultDiverged`]) and is left exactly as found. It is the in-memory precursor of the
//! external freshness anchor the `audit` module documentation describes as missing: it detects a
//! rollback only while a session that saw the newer file is still unlocked.
//!
//! The lock is never held across anything slow or human: the closure is a synchronous `FnOnce`,
//! and the operations that need Argon2id — a new master password, a KDF upgrade, a new recovery
//! code — are split into a `prepare_*` half that runs before the transaction and a `Tx::install_*`
//! half that runs inside it ([`PreparedPasswordSlot`], [`PreparedRecoverySlot`]). A caller that
//! shares the vault behind a mutex of its own splits the password `prepare_*` further, so that
//! mutex is not held across Argon2id either ([`Vault::plan_master_password`]).
//!
//! Readers need no lock: the atomic rename means a read sees either the old file or the new one.
//! [`Vault::refresh_if_changed`] brings a long-lived session up to date between writes.
//!
//! # Every mutator lives on `Tx`
//!
//! [`Vault`] itself is read-only outside a transaction: [`Vault::items`], [`Vault::find_item`] and
//! their siblings borrow `&self`, and the crate's own body/header fields are private to this
//! module. The 19 operations that change the body or the header — adding or removing an item, an
//! environment, a logical vault, a shared-vault device key, the machine vault key, the machine
//! vault's jobs and grants, the agent-visibility switch, the audit chain, the platform slot, and
//! the two `install_*` steps of a header change — are inherent
//! methods on [`Tx`], reachable
//! only from inside [`Vault::transact`]'s closure while the lock is held. `Tx` derefs to `Vault`
//! for reads (`Deref`, not `DerefMut`): there is no way to reach a mutator, or the crate-private,
//! `#[cfg(test)]`-only non-transactional `Vault::save`, through it by accident, and no way to run
//! an Argon2id derivation ([`Vault::prepare_master_password`] and its siblings return `&self`, but
//! the `&mut self` operations that both derive *and* apply a slot no longer exist — only
//! `Tx::install_master_password` / `Tx::install_recovery_code` apply one, and they do no
//! cryptographic work of their own).
//!
//! `Vault::save` — the mutate-then-save API every caller used before transactions — still exists,
//! `pub(crate)`, purely as this module's own regression-tested fallback: nothing in the crate
//! calls it in production, and no other crate can name it. It cannot merge — it has no record of
//! what changed — so it is made *safe* instead: it takes the same lock, and if the file is no
//! longer the generation this session last read or wrote, it writes nothing and fails with
//! [`Error::VaultConflict`]. It never silently overwrites another writer's work.
//!
//! # The pending audit queue
//!
//! Audit drafts that could not be written yet — queued with [`Vault::queue_audit`], or carried
//! by a transaction whose write failed — wait in memory, un-chained, each with the time it was
//! recorded. The next successful transaction chains them onto the head the file has *then*, so
//! they survive another process having appended in the meantime. Entries a transaction's closure
//! chained with [`Tx::append_audit`] but that never reached disk because the write itself failed
//! are treated the same way: whenever the in-memory state is replaced by the file's, they are
//! turned back into drafts and re-queued rather than dropped. [`Vault::unsaved_audit_entries`]
//! counts both kinds.
//!
//! # When the file can no longer be built on
//!
//! A transaction refuses a file that is an older copy ([`Error::VaultDiverged`]), a different or
//! unreadable file ([`Error::VaultReplaced`], a parse error), or gone ([`Error::VaultNotFound`]),
//! and keeps refusing until a human decides which version is the vault. One of the two answers —
//! "lock and reopen from the file" — needs nothing from this module: dropping the `Vault` and
//! opening the file again already does it. The other — "keep this session's version" — is the
//! only write in this module that does not start from the file, so it is a separate, deliberate
//! entry point rather than a mode of `transact`: [`Vault::examine_conflict`] says what the file
//! holds that would be lost, and [`Vault::overwrite_with_this_session`], given exactly that
//! answer back, replaces the file with this session's header and body under the lock and records
//! in the written file's own audit log what it replaced.
//!
//! # Format versions and device keys
//!
//! Every file keeps the `format_ver` it was read with ([`Vault::format_ver`]); a write never
//! lowers it. A body holding a shared-vault device key ([`device`], ADR-0035 §5) is written as at
//! least [`header::DEVICE_KEYS_FORMAT_VERSION`], so that a build that predates the unknown-key
//! passthrough refuses the file instead of dropping the keys. The write that first raises a file's
//! version copies the file as it was to `<file>.bak-<old format_ver>` beforehand, under the lock
//! and with create-new semantics (vault-format §9 rule 3); see [`Vault::format_upgrade_backup`].
//!
//! # The machine vault
//!
//! A personal body may hold the key of this personal vault's machine vault ([`machine`],
//! ADR-0042 §2), and a body with a [`machine::MachineSection`] *is* a machine vault. Either is
//! written as at least [`header::MACHINE_VAULT_FORMAT_VERSION`], and every write of a machine
//! vault is checked against its structural rules first ([`machine`]'s module documentation);
//! a write that breaks one fails with [`Error::MachineVault`] and changes nothing.

pub mod atomic;
pub mod device;
pub mod header;
pub mod lock;
pub mod machine;
pub mod test_login;

use std::collections::BTreeMap;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::audit::{self, AuditDraft, AuditEntry};
use crate::crypto::kdf::KdfParams;
use crate::crypto::wrap::{self, WrappedKey};
use crate::crypto::{self, KEY_LEN, Key, aead};
use crate::error::{Error, Result};
use crate::model::{Environment, FieldKind, Item, VaultMeta};
use crate::proto::{Category, EnvironmentSummary, ItemId, ItemSummary, VaultId, VaultSummary};
use crate::recovery::RecoveryCode;
use atomic::{read_bounded, write_atomically, write_new_file};
use device::DEVICE_KEY_ID_LEN;
pub use device::DeviceKey;
use header::Header;
use lock::FileLock;
use machine::MachineSection;
pub use machine::MachineVaultKey;

/// The body schema version this build writes.
pub const BODY_SCHEMA_VERSION: u16 = 1;
/// Slot id of the master-password slot.
pub const SLOT_ID_MASTER: &str = "master";
/// Slot id of the recovery slot.
pub const SLOT_ID_RECOVERY: &str = "recovery";

/// The decrypted vault body (vault-format §2.2).
#[derive(Debug, Serialize, Deserialize)]
pub struct Body {
    /// Body schema version.
    pub schema: u16,
    /// Logical vaults inside this file.
    pub vaults: Vec<VaultMeta>,
    /// Items.
    pub items: Vec<Item>,
    /// Environments (vault-format §5.2).
    ///
    /// M1 reserved this key and carried it as raw CBOR; M2 gives it a type. An M1-era vault has
    /// an empty array here, which decodes unchanged.
    #[serde(default)]
    pub envs: Vec<Environment>,
    /// The append-only audit log (vault-format §8).
    ///
    /// The format doc names `audit_head` but not the array it summarises; this key is the
    /// minimal viable choice and is recorded in ADR-0007.
    #[serde(default)]
    pub audit: Vec<AuditEntry>,
    /// Head of the audit hash chain (vault-format §8). 32 zero bytes for an empty log.
    #[serde(default, with = "serde_bytes")]
    pub audit_head: Vec<u8>,
    /// This computer's shared-vault device keys (ADR-0035 §5): secret key material, readable only
    /// inside the encrypted body, and never an item. Absent from the encoding when empty, so a
    /// body without device keys encodes exactly as it did before the key existed.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "device::cbor_list"
    )]
    pub devices: Vec<DeviceKey>,
    /// Ids of device keys removed from this vault (ids only, no key material). Grow-only: a
    /// retired id is never added again and never brought back by combining two versions of the
    /// vault (see [`device`]). Absent from the encoding when empty.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "device::cbor_ids"
    )]
    pub retired_devices: Vec<[u8; DEVICE_KEY_ID_LEN]>,
    /// The key of this personal vault's machine vault (ADR-0042 §2): secret key material, never
    /// an item. Absent from the encoding when there is none.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "machine::cbor_key_opt"
    )]
    pub machine_key: Option<MachineVaultKey>,
    /// Present exactly when this file is a machine vault (ADR-0042 §2): its jobs, standing grants
    /// and armed state. Absent from the encoding in a personal vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<MachineSection>,
    /// Top-level body keys this build does not recognize, preserved verbatim so an older build
    /// opening a vault a newer one wrote never destroys them (vault-format §9 rule 1).
    ///
    /// As with [`header::Header::unknown`], only the *value* is guaranteed to survive, not the
    /// original byte position: nothing outside [`crate::audit::AuditEntry`] hashes the body, and
    /// every write re-encodes the whole `Body` from whatever this struct holds at that moment, so
    /// the AEAD tag it produces is always self-consistent regardless of map key order.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, ciborium::Value>,
}

impl Body {
    /// A body holding nothing at all, not even a logical vault: what a session shows after a
    /// rollback that could not restore anything (see `Tx::roll_back`), until it reads the file.
    fn emptied() -> Self {
        Self {
            schema: BODY_SCHEMA_VERSION,
            vaults: Vec::new(),
            items: Vec::new(),
            envs: Vec::new(),
            audit: Vec::new(),
            audit_head: audit::genesis(),
            devices: Vec::new(),
            retired_devices: Vec::new(),
            machine_key: None,
            machine: None,
            unknown: BTreeMap::new(),
        }
    }

    fn new(default_vault: VaultMeta) -> Self {
        Self {
            schema: BODY_SCHEMA_VERSION,
            vaults: vec![default_vault],
            items: Vec::new(),
            envs: Vec::new(),
            audit: Vec::new(),
            audit_head: audit::genesis(),
            devices: Vec::new(),
            retired_devices: Vec::new(),
            machine_key: None,
            machine: None,
            unknown: BTreeMap::new(),
        }
    }
}

/// The `tool` of the audit entry [`Tx::set_agent_visible_bulk`] records.
pub const TOOL_SET_AGENT_VISIBLE_BULK: &str = "set_agent_visible_bulk";

/// Which items a bulk agent-visibility change ([`Tx::set_agent_visible_bulk`]) applies to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentVisibilityScope {
    /// Exactly these items, by id — a multi-selection in the app. Ids that name no item are
    /// ignored. An item in the trash is included if it is named: the person chose it.
    Items(Vec<ItemId>),
    /// Every item, not in the trash, carrying this tag (exact match).
    Tag(String),
    /// Every item, not in the trash, of this category.
    Category(Category),
    /// Every item not in the trash: the one-time "Show all items to agents" action.
    All,
}

impl AgentVisibilityScope {
    /// The short machine-readable name the audit entry records. Never the tag itself, nor any
    /// title: the entry records the kind of scope and counts, nothing a person typed.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Items(_) => "items",
            Self::Tag(_) => "tag",
            Self::Category(_) => "category",
            Self::All => "all",
        }
    }

    fn matches(&self, item: &Item) -> bool {
        match self {
            Self::Items(ids) => ids.contains(&item.id),
            Self::Tag(tag) => !item.is_trashed() && item.tags.iter().any(|t| t == tag),
            Self::Category(category) => !item.is_trashed() && &item.category == category,
            Self::All => !item.is_trashed(),
        }
    }
}

/// What [`Tx::set_agent_visible_bulk`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BulkVisibility {
    /// Items the scope matched.
    pub matched: usize,
    /// Of those, items whose item or field flags actually changed.
    pub changed: usize,
}

/// How a vault was unlocked. Recorded so callers can require a fresh master password after a
/// recovery-code unlock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockedBy {
    /// The master password.
    Password,
    /// The printable recovery code.
    RecoveryCode,
    /// A platform keystore slot — Touch ID / Secure Enclave on macOS (ADR-0004).
    PlatformKey,
}

/// Options for [`Vault::create`].
#[derive(Clone, Debug)]
pub struct CreateOptions {
    /// KDF cost for the master-password slot.
    pub kdf: KdfParams,
    /// Display name of the first logical vault.
    pub vault_name: String,
    /// Optional human note stored in the header.
    pub kdf_hint: Option<String>,
}

impl CreateOptions {
    /// Defaults: the v1 desktop Argon2id profile and a logical vault called `Personal`.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the operating system's generator fails.
    pub fn new() -> Result<Self> {
        Ok(Self {
            kdf: KdfParams::defaults()?,
            vault_name: "Personal".to_owned(),
            kdf_hint: None,
        })
    }
}

/// The largest vault file this build reads or writes: 256 MiB.
///
/// vault-format.md sets no limit, and needs none for a real vault: attachments live outside the
/// body, so even tens of thousands of items and a very long audit log come to a few tens of
/// megabytes. The bound exists because a vault is read whole into memory — and then held twice
/// more, as plaintext and as the parsed body — so a corrupt, sparse or hostile file at the path
/// must be refused *before* anything is allocated for it rather than abort the process. It is
/// enforced on writing too, so this build never produces a file it would then refuse to open.
pub const MAX_VAULT_FILE_LEN: u64 = 256 << 20;

/// Refuse a vault file image of `len` bytes if it is over [`MAX_VAULT_FILE_LEN`].
fn ensure_within_limit(len: u64, path: &Path) -> Result<()> {
    if len > MAX_VAULT_FILE_LEN {
        return Err(Error::VaultTooLarge {
            path: path.to_owned(),
            max: MAX_VAULT_FILE_LEN,
        });
    }
    Ok(())
}

/// Whether `error` says the file is not there.
fn is_not_found(error: &Error) -> bool {
    matches!(error, Error::Io(e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// SHA-256 of a vault file's exact bytes: the identity of one on-disk version.
type Generation = [u8; 32];

fn generation_of(bytes: &[u8]) -> Generation {
    Sha256::digest(bytes).into()
}

/// A cheap identity for the file a path names, so [`Vault::refresh_if_changed`] can skip reading
/// and hashing a file that has not been replaced.
///
/// Every kagisecure writer replaces the file with a new inode, so `(dev, ino)` alone changes on
/// every write; size and modification time also catch a tool that rewrites in place. Only a
/// fast path: a transaction always reads and hashes. Windows has no stable `(dev, ino)` in std,
/// so there the fast path is simply off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
struct Fingerprint {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
}

#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)] // Same signature as the non-Unix version.
fn fingerprint(meta: &std::fs::Metadata) -> Option<Fingerprint> {
    use std::os::unix::fs::MetadataExt;
    Some(Fingerprint {
        dev: meta.dev(),
        ino: meta.ino(),
        len: meta.size(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
    })
}

#[cfg(not(unix))]
fn fingerprint(_meta: &std::fs::Metadata) -> Option<Fingerprint> {
    None
}

/// A vault file's bytes, read once, with the identity of the file they came from.
struct Snapshot {
    bytes: Vec<u8>,
    generation: Generation,
    fingerprint: Option<Fingerprint>,
}

/// Read the file at `path` through one handle, so the fingerprint describes exactly the file whose
/// bytes were read even if the path is replaced a moment later.
///
/// # Errors
///
/// [`Error::VaultTooLarge`] beyond [`MAX_VAULT_FILE_LEN`], checked before reading; otherwise I/O
/// errors (see [`is_not_found`]).
fn read_snapshot(path: &Path) -> Result<Snapshot> {
    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    let bytes = read_bounded(file, meta.len(), MAX_VAULT_FILE_LEN, path)?;
    Ok(Snapshot {
        generation: generation_of(&bytes),
        fingerprint: fingerprint(&meta),
        bytes,
    })
}

/// What this session knows about the file on disk.
#[derive(Clone, Debug)]
struct DiskState {
    /// The generation the in-memory state descends from: the file last read (open, reload) or
    /// last written by this session.
    ///
    /// `None` means the in-memory state descends from **no** on-disk version — before `create`'s
    /// first write, or after a rollback that could not restore anything — so nothing may write
    /// it without first replacing it with the file's contents.
    generation: Option<Generation>,
    /// The fingerprint of that file, when known.
    fingerprint: Option<Fingerprint>,
    /// How many audit entries that file holds.
    audit_len: usize,
    /// The chain head as of `audit_len`: the digest of entry `audit_len - 1`, or the genesis
    /// value. With `audit_len`, this is what the continuity check compares a fresh file against.
    audit_head: Vec<u8>,
    /// A write this session attempted on top of this version and could not confirm either way.
    unconfirmed: Option<UnconfirmedWrite>,
    /// That file's `format_ver` ([`header::FORMAT_VERSION`] before `create`'s first write). A
    /// write never goes below it: a file keeps the version it was read with (see
    /// [`Vault::format_ver`]).
    format_ver: u16,
}

impl DiskState {
    fn observed(
        generation: Generation,
        fingerprint: Option<Fingerprint>,
        body: &Body,
        format_ver: u16,
    ) -> Self {
        Self {
            generation: Some(generation),
            fingerprint,
            audit_len: body.audit.len(),
            audit_head: body.audit_head.clone(),
            unconfirmed: None,
            format_ver,
        }
    }
}

/// What [`Vault::examine_conflict`] found, with what an overwrite needs from the file.
struct Examined {
    conflict: Option<FileConflict>,
    /// The file's exact bytes, when there is a file.
    bytes: Option<Vec<u8>>,
    /// The file's body, decrypted, when the file is [`FileConflict::Diverged`] — the one kind
    /// this session's key opens.
    diverged_body: Option<Body>,
}

/// A vault file image decrypted with this session's key: its `format_ver`, header and body.
struct Decoded {
    format_ver: u16,
    header: Header,
    body: Body,
}

/// A write that reported failure and whose result could not be read back, so it may or may not
/// be on disk.
///
/// Without this, the drafts that write carried go back into the pending queue as though it had
/// certainly failed, and if it in fact landed, the next write chains them a second time: the log
/// would claim every one of those actions happened twice. The next time this session reads the
/// file, the question is settled by content, not by generation — the write landed exactly when
/// the file's audit log continues the log the write contained (`audit_len`, `audit_head`, the
/// same check as [`continues`]). That also recognises a landed write another writer has since
/// built on. If it landed, the first `drafts` drafts of the queue — which are precisely the ones
/// the write carried, see [`Vault::settle_unconfirmed`] — are dropped as already written.
///
/// A transaction whose outcome was unknown returned an error to its caller, so a landed one means
/// the caller was told "failed" about a change that did commit. That is the honest limit of an
/// unconfirmable write; what this prevents is the log then also recording it twice.
#[derive(Clone, Debug)]
struct UnconfirmedWrite {
    /// Length of the audit log the attempted write contained.
    audit_len: usize,
    /// Its head: the digest of its last entry.
    audit_head: Vec<u8>,
    /// How many drafts at the front of the pending queue (once unsaved entries are re-queued)
    /// were in that write.
    drafts: usize,
}

/// Whether a freshly read audit log continues the one this session knows reached the disk: it
/// holds at least `known_len` entries and entry `known_len - 1` is the very entry whose digest
/// was the known head.
///
/// Comparing one digest pins the whole prefix, because every entry's digest covers its `prev`,
/// which is the digest of the entry before it (vault-format §8).
fn continues(known_len: usize, known_head: &[u8], fresh: &[AuditEntry]) -> bool {
    let Some(last_known) = known_len.checked_sub(1) else {
        return true;
    };
    fresh.get(last_known).is_some_and(|entry| {
        entry.seq == last_known as u64 && audit::digest(entry).as_slice() == known_head
    })
}

/// Whether a decoded file continues what this session knows is on disk: its audit log continues
/// the known one ([`continues`]) and its `format_ver` is not lower than the known file's.
fn continues_known(known: &DiskState, file: &Decoded) -> bool {
    file.format_ver >= known.format_ver
        && continues(known.audit_len, &known.audit_head, &file.body.audit)
}

/// Exclusive access to a session's [`DiskState`] without locking: for `&mut Vault` holders.
///
/// A poisoned mutex is used anyway, as everywhere else in this module: the state is plain data
/// that each writer overwrites whole, so a panic elsewhere cannot have left it half-updated.
fn disk_mut(disk: &mut Mutex<DiskState>) -> &mut DiskState {
    disk.get_mut().unwrap_or_else(PoisonError::into_inner)
}

/// An audit draft waiting to be chained, with the time it was recorded.
#[derive(Clone, Debug)]
struct PendingDraft {
    draft: AuditDraft,
    recorded_at: u64,
}

impl PendingDraft {
    fn now(draft: AuditDraft) -> Self {
        Self {
            draft,
            recorded_at: crate::unix_now(),
        }
    }

    /// Turn an entry that was chained in memory but never reached the disk back into a draft,
    /// keeping its timestamp. Its `seq` and `prev` are dropped: they described a position in a
    /// log that is being replaced, and chaining assigns fresh ones.
    fn from_unsaved_entry(entry: AuditEntry) -> Self {
        Self {
            recorded_at: entry.timestamp,
            draft: AuditDraft {
                actor: entry.actor,
                client_pid: entry.client_pid,
                tool: entry.tool,
                vault_id: entry.vault_id,
                environment_id: entry.environment_id,
                item_id: entry.item_id,
                variables: entry.variables,
                target_path: entry.target_path,
                lease_id: entry.lease_id,
                outcome: entry.outcome,
                detail: entry.detail,
            },
        }
    }
}

/// The `tool` of the audit entry [`Vault::overwrite_with_this_session`] records.
pub const AUDIT_TOOL_OVERWRITE: &str = "vault_overwritten_after_conflict";

/// The `tool` of the audit entry [`Tx::add_device_key`] records.
pub const AUDIT_TOOL_DEVICE_KEY_ADDED: &str = "device_key_added";

/// The `tool` of the audit entry [`Tx::remove_device_key`] records.
pub const AUDIT_TOOL_DEVICE_KEY_REMOVED: &str = "device_key_removed";

/// The `tool` of the audit entry [`Tx::set_machine_vault_key`] records.
pub const AUDIT_TOOL_MACHINE_VAULT_KEY_ADDED: &str = "machine_vault_key_added";

/// The `tool` of the audit entry [`Tx::remove_machine_vault_key`] records.
pub const AUDIT_TOOL_MACHINE_VAULT_KEY_REMOVED: &str = "machine_vault_key_removed";

/// The audit `detail` naming a machine vault key: `vault_id=` and the machine vault's id in
/// lower-case hex. Nothing of the key itself.
fn machine_key_detail(key: &MachineVaultKey) -> String {
    format!(
        "vault_id={}",
        hex_prefix(key.vault_id(), machine::VAULT_ID_LEN)
    )
}

/// The audit `detail` naming a device key: `id=` and the id in lower-case hex. The id is public
/// (it names the device in every shared vault's roster); nothing else about the key is recorded.
fn device_key_detail(id: &[u8; DEVICE_KEY_ID_LEN]) -> String {
    format!("id={}", hex_prefix(id, DEVICE_KEY_ID_LEN))
}

fn device_key_audit(actor: &str, tool: &str, detail: String) -> AuditDraft {
    AuditDraft {
        actor: actor.to_owned(),
        tool: tool.to_owned(),
        outcome: crate::proto::Outcome::Allowed,
        detail: Some(detail),
        ..AuditDraft::default()
    }
}

/// Why the file at a vault's path is one no transaction of this session will build on — what
/// [`Vault::examine_conflict`] reports, and what [`Vault::overwrite_with_this_session`] must be
/// handed back before it replaces the file.
///
/// Every variant is described from the point of view of what an overwrite would *lose*: the
/// person choosing "keep this app's version" is choosing to discard the file, and this is what
/// the confirmation has to tell them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileConflict {
    /// The same vault — same `vault_id`, opens with this session's key — but its audit log does
    /// not continue the one this session last saw on disk: an older copy restored over it (a
    /// backup, a sync tool, a `cp`), or a copy that was changed separately after the two split.
    Diverged {
        /// SHA-256 of the file's exact bytes.
        file_sha256: [u8; 32],
        /// What the file holds that this session's version does not.
        lost: DivergedFile,
    },
    /// A readable vault file that is not this vault, as far as this session can tell: a
    /// different `vault_id`, or a body this session's key does not open. Everything in it is
    /// lost by an overwrite; this session cannot even say what that is.
    Replaced {
        /// SHA-256 of the file's exact bytes.
        file_sha256: [u8; 32],
    },
    /// Something at the path that this build cannot parse as a vault at all: not a kagisecure
    /// file, or a damaged one.
    Unreadable {
        /// SHA-256 of the file's exact bytes.
        file_sha256: [u8; 32],
    },
    /// A kagisecure vault file in a `format_ver` newer than this build reads — most likely this
    /// very vault, written by a newer kagisecure. **Never overwritten**:
    /// [`Vault::overwrite_with_this_session`] refuses it, because replacing it would destroy
    /// whatever the newer build keeps there with a version older builds can read. The fix is
    /// upgrading kagisecure.
    TooNew {
        /// SHA-256 of the file's exact bytes.
        file_sha256: [u8; 32],
        /// The file's `format_ver`.
        found: u16,
    },
    /// Nothing at the path. An overwrite recreates the vault there from this session.
    Missing,
}

impl FileConflict {
    /// SHA-256 of the file the conflict is about, or `None` if there is no file.
    #[must_use]
    pub fn file_sha256(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Diverged { file_sha256, .. }
            | Self::Replaced { file_sha256 }
            | Self::Unreadable { file_sha256 }
            | Self::TooNew { file_sha256, .. } => Some(file_sha256),
            Self::Missing => None,
        }
    }

    /// The short machine-readable name used in the override's audit entry.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Diverged { .. } => "diverged",
            Self::Replaced { .. } => "replaced",
            Self::Unreadable { .. } => "unreadable",
            Self::TooNew { .. } => "too_new",
            Self::Missing => "missing",
        }
    }
}

/// What a [`FileConflict::Diverged`] file holds that this session does not: exactly what
/// [`Vault::overwrite_with_this_session`] would discard.
///
/// Nothing here is secret: counts, and whether three header slots are the same wrap. What this
/// session holds and the file does not is not listed — an overwrite keeps it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DivergedFile {
    /// Entries in the file's audit log.
    pub audit_len: usize,
    /// How many leading entries the file's log shares, entry for entry, with this session's.
    /// `audit_len - shared_audit_len` entries exist only in the file.
    pub shared_audit_len: usize,
    /// Items, by id.
    pub items: Difference,
    /// Environments, by id.
    pub environments: Difference,
    /// Logical vaults, by id — including their agent-visibility switch.
    pub logical_vaults: Difference,
    /// Shared-vault device keys, by id. Unlike everything else here, the ones only in the file
    /// are **not** lost: an overwrite keeps them (see [`Vault::overwrite_with_this_session`]),
    /// because a device key has no other copy and losing it cuts this computer out of every
    /// shared vault it belongs to. `differing` counts keys both hold with a different entry (a
    /// label, say); this session's entry is the one written.
    pub device_keys: Difference,
    /// Device keys this session holds that the file has **retired** (removed, in the file's
    /// version): an overwrite honours the removal and drops them, because a removal is usually
    /// someone retiring a computer, and an older copy must not undo it. Keys this session retired
    /// are likewise never brought back from the file, and are not counted in `device_keys`.
    pub device_keys_retired_in_file: usize,
    /// The file's master-password slot, or the KDF cost it is derived with, is not this
    /// session's: whatever password opens the file today stops working after an overwrite, and
    /// the one this session's header was last written with works instead.
    pub master_password_differs: bool,
    /// The file's recovery slot is not this session's: the recovery code that opens the file
    /// today stops working, and the one in this session's header — possibly one a person has
    /// since replaced, and so believes retired — works again.
    pub recovery_code_differs: bool,
    /// The file's platform (Touch ID) slot is not this session's, or only one of them has one.
    pub platform_slot_differs: bool,
}

impl DivergedFile {
    /// Audit entries only the file has.
    #[must_use]
    pub fn audit_entries_only_in_file(&self) -> usize {
        self.audit_len.saturating_sub(self.shared_audit_len)
    }
}

/// How one keyed collection in a [`FileConflict::Diverged`] file differs from this session's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Difference {
    /// Present in the file, absent from this session: deleted by an overwrite.
    pub only_in_file: usize,
    /// Present in both with different contents: the file's version is replaced by this
    /// session's.
    pub differing: usize,
}

/// Count, by `key`, the entries of `file` that `session` lacks or holds differently.
///
/// "Differently" is decided on the canonical CBOR encoding, so every field — secret values
/// included — takes part without anything but a yes/no leaving this function. The encodings are
/// plaintext and live in zeroizing buffers for the length of one comparison.
fn difference<T: Serialize, K: Ord>(
    file: &[T],
    session: &[T],
    key: impl Fn(&T) -> K,
) -> Result<Difference> {
    fn encode<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::new());
        ciborium::into_writer(value, &mut *out).map_err(|e| Error::BodyDecode(e.to_string()))?;
        Ok(out)
    }
    let ours: BTreeMap<K, &T> = session.iter().map(|t| (key(t), t)).collect();
    let mut diff = Difference::default();
    for theirs in file {
        match ours.get(&key(theirs)) {
            None => diff.only_in_file += 1,
            Some(mine) => {
                if *encode(theirs)? != *encode(*mine)? {
                    diff.differing += 1;
                }
            }
        }
    }
    Ok(diff)
}

/// How many leading entries two audit logs share. The chain makes this a prefix: every entry's
/// digest covers the one before it, so once two logs differ at one position they differ at every
/// later one.
fn shared_audit_prefix(a: &[AuditEntry], b: &[AuditEntry]) -> usize {
    a.iter()
        .zip(b)
        .take_while(|(x, y)| audit::digest(x) == audit::digest(y))
        .count()
}

/// The `detail` of the audit entry [`Vault::overwrite_with_this_session`] records (see its
/// documentation for the format). `session_audit_len` is the length of the log the entry is
/// appended to.
fn overwrite_detail(
    found: &FileConflict,
    session_audit_len: usize,
    device_keys_kept: usize,
    device_keys_retired: usize,
    reason: &str,
) -> String {
    let file = found
        .file_sha256()
        .map_or_else(|| "none".to_owned(), |sha| hex_prefix(sha, 8));
    let (file_audit_len, shared_audit_len) = match found {
        FileConflict::Diverged { lost, .. } => (
            lost.audit_len.to_string(),
            lost.shared_audit_len.to_string(),
        ),
        FileConflict::Missing => ("0".to_owned(), "0".to_owned()),
        FileConflict::Replaced { .. }
        | FileConflict::Unreadable { .. }
        | FileConflict::TooNew { .. } => ("unknown".to_owned(), "unknown".to_owned()),
    };
    format!(
        "found={} file_sha256={file} file_audit_len={file_audit_len} \
         shared_audit_len={shared_audit_len} session_audit_len={session_audit_len} \
         device_keys_kept={device_keys_kept} device_keys_retired={device_keys_retired} \
         reason={reason}",
        found.as_str()
    )
}

/// A backup named `<stem>` or `<stem>-<8 hex>` in `dir` whose contents are exactly `bytes`, if
/// there is one. Files of another length are not read.
fn existing_backup_of(dir: &Path, stem: &str, bytes: &[u8]) -> Option<PathBuf> {
    let is_backup_name = |name: &str| {
        name == stem
            || name
                .strip_prefix(stem)
                .and_then(|rest| rest.strip_prefix('-'))
                .is_some_and(|hex| hex.len() == 8 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    std::fs::read_dir(dir).ok()?.flatten().find_map(|entry| {
        let name = entry.file_name();
        if !is_backup_name(&name.to_string_lossy()) {
            return None;
        }
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path).ok()?;
        if !meta.is_file() || meta.len() != bytes.len() as u64 {
            return None;
        }
        let existing = atomic::read_file_bounded(&path, MAX_VAULT_FILE_LEN).ok()?;
        (existing == bytes).then_some(path)
    })
}

/// The first `bytes` bytes of `digest`, in lower-case hex.
fn hex_prefix(digest: &[u8], bytes: usize) -> String {
    use std::fmt::Write;
    digest.iter().take(bytes).fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Unit-test fault injection for the next write in the current thread.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InjectedFault {
    None,
    /// Fail just before `write_atomically`, after the lock was taken and the new bytes sealed —
    /// where a full disk or a vanished directory fails, and a position integration tests can
    /// only reach on some platforms.
    BeforeWrite,
    /// Write, then report failure anyway — a network file system losing the rename's reply.
    AfterWrite,
    /// As `AfterWrite`, and the read-back that would confirm the write fails too: the outcome
    /// is genuinely unknown to the writer.
    AfterWriteUnconfirmed,
}

#[cfg(test)]
thread_local! {
    static INJECTED_FAULT: std::cell::Cell<InjectedFault> =
        const { std::cell::Cell::new(InjectedFault::None) };
    /// Set by `AfterWriteUnconfirmed`: the next confirming read-back in this thread fails.
    static FAIL_NEXT_READ_BACK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// An unlocked vault.
///
/// Holds the vault key for its lifetime and zeroizes it on drop. There is no decrypted-item cache
/// beyond the body itself (threat-model M-10); dropping this value is the "lock" operation.
///
/// See the module documentation for how writes from several `Vault` values and several processes
/// are kept from erasing each other.
pub struct Vault {
    path: PathBuf,
    header: Header,
    vault_key: Key,
    body: Body,
    unlocked_by: UnlockedBy,
    /// Audit drafts not yet chained into `body.audit`, oldest first (see the module
    /// documentation). Only ever emptied by chaining them into a state that is then written.
    pending_audit: Vec<PendingDraft>,
    /// What this session knows about the file on disk.
    ///
    /// Behind a mutex because [`Vault::save`] takes `&self` (so that `kagisecure-agent`'s
    /// `VaultHandle` can save through a shared reference) and must still record the generation
    /// it wrote. Every other writer holds `&mut self` and uses `get_mut`.
    disk: Mutex<DiskState>,
    /// The `Display` of the error from the most recent failed write (a [`Vault::save`], or the
    /// lock, re-read or write step of a [`Vault::transact`]), or `None` if the last attempt (or
    /// there has been none yet) succeeded. Cleared by the next successful write.
    ///
    /// Never carries secret material: every [`Error`] variant is written on the assumption its
    /// text may end up in a log (see this crate's `error` module doc), and nothing else goes in
    /// here.
    last_save_error: Mutex<Option<String>>,
    /// How long a write waits for another writer's lock.
    lock_timeout: Duration,
    /// Whether a [`Tx`] currently borrows this vault. `Tx` has no `DerefMut`, so a closure cannot
    /// reach [`Vault::transact`], [`Vault::refresh_if_changed`] or [`Vault::overwrite_with_this_session`]
    /// through it at all — that is now a compile error, not this flag. What this still guards is
    /// [`Vault::save`] (reachable read-only through `Tx`'s `Deref`, since it takes `&self`) and
    /// direct re-entrancy through a `&mut Vault` reached some other way (e.g. through interior
    /// mutability), so a nested write fails at once ([`Error::NestedTransaction`]) instead of
    /// waiting out its own lock.
    in_transaction: bool,
    /// Whether this session has already swept crashed writers' temporaries (done once, under
    /// the lock; see `FileLock::sweep_stale_temporaries`).
    swept_temporaries: AtomicBool,
    /// The backup the most recent write that raised the file's `format_ver` took, if any write
    /// of this session has.
    upgrade_backup: Option<PathBuf>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("items", &self.body.items.len())
            .field("unlocked_by", &self.unlocked_by)
            .field("unsaved_audit_entries", &self.unsaved_audit_entries())
            .finish_non_exhaustive()
    }
}

impl Vault {
    fn assemble(
        path: PathBuf,
        header: Header,
        vault_key: Key,
        body: Body,
        unlocked_by: UnlockedBy,
        disk: DiskState,
    ) -> Self {
        Self {
            path,
            header,
            vault_key,
            body,
            unlocked_by,
            pending_audit: Vec::new(),
            disk: Mutex::new(disk),
            last_save_error: Mutex::new(None),
            lock_timeout: lock::DEFAULT_LOCK_TIMEOUT,
            in_transaction: false,
            swept_temporaries: AtomicBool::new(false),
            upgrade_backup: None,
        }
    }

    /// Create a new vault file and return it together with its one-time recovery code.
    ///
    /// The recovery code is generated here, printed once by the caller and never stored: only its
    /// Argon2id-stretched wrap of the vault key goes into the header (vault-format §3.2).
    ///
    /// Both Argon2id derivations run before the lock is taken; the lock is then held across the
    /// check that nothing exists at `path` and the first write, so two processes creating the same
    /// vault cannot both succeed.
    ///
    /// # Errors
    ///
    /// [`Error::VaultExists`] if the path is taken, [`Error::VaultBusy`] /
    /// [`Error::LockUnsupported`] from the lock, plus any I/O, RNG or KDF failure.
    pub fn create(
        path: impl Into<PathBuf>,
        master_password: &[u8],
        options: &CreateOptions,
    ) -> Result<(Self, RecoveryCode)> {
        let path = path.into();
        // Checked again under the lock below; this early check only saves two Argon2id runs.
        if path.exists() {
            return Err(Error::VaultExists(path));
        }

        options.kdf.validate()?;
        let vault_id = crypto::random::array::<16>()?;
        let vault_key = crypto::random::key()?;

        let password_kdf = options.kdf.clone();
        let kek = password_kdf.derive(master_password)?;
        let password_slot = WrappedKey::wrap(
            &vault_id,
            wrap::KIND_PASSWORD,
            SLOT_ID_MASTER,
            "Master password",
            &kek,
            &vault_key,
            None,
        )?;
        drop(kek);

        let code = RecoveryCode::generate()?;
        let recovery_slot = wrap_recovery_slot(&vault_id, &code, &options.kdf, &vault_key)?;

        let header = Header {
            v: header::HEADER_SCHEMA_VERSION,
            vault_id: vault_id.to_vec(),
            created_at: crate::unix_now(),
            kdf: password_kdf,
            body_aead: aead::ALG_XCHACHA20POLY1305.to_owned(),
            wrapped_keys: vec![password_slot, recovery_slot],
            compression: header::COMPRESSION_NONE.to_owned(),
            kdf_hint: options.kdf_hint.clone(),
            unknown: BTreeMap::new(),
        };

        let body = Body::new(VaultMeta::new(options.vault_name.clone()));
        // Nothing is on disk yet; `write_new_file` records the first generation.
        let nothing_on_disk = DiskState {
            generation: None,
            fingerprint: None,
            audit_len: 0,
            audit_head: audit::genesis(),
            unconfirmed: None,
            format_ver: header::FORMAT_VERSION,
        };
        let vault = Self::assemble(
            path,
            header,
            vault_key,
            body,
            UnlockedBy::Password,
            nothing_on_disk,
        );
        vault.write_new_file()?;
        Ok((vault, code))
    }

    /// Open a vault with the master password.
    ///
    /// # Errors
    ///
    /// [`Error::VaultNotFound`], [`Error::Decrypt`] for a wrong password or a tampered file, and
    /// the header-validation errors. A wrong password and a tampered file are deliberately
    /// indistinguishable (threat-model M-8).
    pub fn open_with_password(path: impl Into<PathBuf>, master_password: &[u8]) -> Result<Self> {
        Self::open(
            path,
            wrap::KIND_PASSWORD,
            master_password,
            UnlockedBy::Password,
        )
    }

    /// Open a vault with its printable recovery code, independent of the master password.
    ///
    /// # Errors
    ///
    /// As [`Vault::open_with_password`], plus [`Error::NoSuchSlot`] if the file predates recovery
    /// codes.
    pub fn open_with_recovery_code(path: impl Into<PathBuf>, code: &RecoveryCode) -> Result<Self> {
        Self::open(
            path,
            wrap::KIND_RECOVERY,
            code.material(),
            UnlockedBy::RecoveryCode,
        )
    }

    /// Open a vault with a vault key that a platform keystore has already unwrapped.
    ///
    /// This is the second half of the Touch ID path (ADR-0004, ADR-0008): the app asks the Secure
    /// Enclave to decrypt the [`platform slot`](crate::crypto::wrap::KIND_PLATFORM)'s blob, and
    /// hands the 32 bytes that come back straight here. The bytes are copied into a
    /// [`Zeroizing`] buffer on entry and the caller's copy is its own to clear.
    ///
    /// There is no separate "is this the right key" check and none is needed: a wrong key fails
    /// to open the body, exactly as a wrong password does, and is reported the same way
    /// ([`Error::Decrypt`]) so the two are indistinguishable (threat-model M-8).
    ///
    /// # Errors
    ///
    /// [`Error::VaultNotFound`], [`Error::Malformed`] if `vault_key` is not 32 bytes,
    /// [`Error::Decrypt`] for a key that does not open this vault, plus the header-validation
    /// errors.
    pub fn open_with_vault_key(path: impl Into<PathBuf>, vault_key: &[u8]) -> Result<Self> {
        let path = path.into();
        if !path.exists() {
            return Err(Error::VaultNotFound(path));
        }
        let key: [u8; KEY_LEN] = vault_key.try_into().map_err(|_| Error::Malformed)?;
        let vault_key = Zeroizing::new(key);

        let snapshot = read_snapshot(&path)?;
        let parts = header::split(&snapshot.bytes)?;
        parts.header.validate()?;

        let vk: &[u8; KEY_LEN] = &vault_key;
        let body = decrypt_body(vk, &parts.body_nonce, parts.aad, parts.body_ct)?;
        let disk = DiskState::observed(
            snapshot.generation,
            snapshot.fingerprint,
            &body,
            parts.format_ver,
        );
        Ok(Self::assemble(
            path,
            parts.header,
            vault_key,
            body,
            UnlockedBy::PlatformKey,
            disk,
        ))
    }

    /// Create the machine vault file for `key` at `path` (ADR-0042 §2): an empty vault with one
    /// logical vault named `vault_name`, an empty [`MachineSection`], and **no** password,
    /// recovery or platform slot — `key`, held in the personal vault's body, is how it is opened
    /// ([`Vault::open_machine`]). Written as [`header::MACHINE_VAULT_FORMAT_VERSION`].
    ///
    /// # Errors
    ///
    /// [`Error::VaultExists`] if the path is taken, the lock's errors, and I/O or RNG failures.
    pub fn create_machine(
        path: impl Into<PathBuf>,
        key: &MachineVaultKey,
        vault_name: &str,
    ) -> Result<Self> {
        let path = path.into();
        if path.exists() {
            return Err(Error::VaultExists(path));
        }
        let vault_key: [u8; KEY_LEN] = key
            .key()
            .expose()
            .try_into()
            .map_err(|_| Error::MachineVault("a machine vault key is 32 bytes"))?;
        let header = Header {
            v: header::HEADER_SCHEMA_VERSION,
            vault_id: key.vault_id().to_vec(),
            created_at: crate::unix_now(),
            // Never used to derive anything — the file has no password slot — but the header
            // carries a default descriptor, and a valid one keeps every reader's checks as they
            // are.
            kdf: KdfParams::defaults()?,
            body_aead: aead::ALG_XCHACHA20POLY1305.to_owned(),
            wrapped_keys: Vec::new(),
            compression: header::COMPRESSION_NONE.to_owned(),
            kdf_hint: None,
            unknown: BTreeMap::new(),
        };
        let mut body = Body::new(VaultMeta::new(vault_name));
        body.machine = Some(MachineSection::default());
        let nothing_on_disk = DiskState {
            generation: None,
            fingerprint: None,
            audit_len: 0,
            audit_head: audit::genesis(),
            unconfirmed: None,
            format_ver: header::FORMAT_VERSION,
        };
        let vault = Self::assemble(
            path,
            header,
            Zeroizing::new(vault_key),
            body,
            UnlockedBy::PlatformKey,
            nothing_on_disk,
        );
        vault.write_new_file()?;
        Ok(vault)
    }

    /// Open the machine vault `key` belongs to — `key` read from the personal vault's body, or
    /// from the Keychain while armed ([`MachineVaultKey::from_keychain_bytes`]). Reported as
    /// unlocked by [`UnlockedBy::PlatformKey`]: a key held elsewhere, as for Touch ID.
    ///
    /// # Errors
    ///
    /// As [`Vault::open_with_vault_key`] ([`Error::Decrypt`] for a key that does not open it),
    /// and [`Error::MachineVault`] for a file that opens with the key but is not that machine
    /// vault — another `vault_id`, or no machine section.
    pub fn open_machine(path: impl Into<PathBuf>, key: &MachineVaultKey) -> Result<Self> {
        let vault = Self::open_with_vault_key(path, key.key().expose())?;
        if vault.header.vault_id.as_slice() != key.vault_id().as_slice() {
            return Err(Error::MachineVault(
                "this file is not the machine vault this key belongs to",
            ));
        }
        if !vault.is_machine() {
            return Err(Error::MachineVault("this file is not a machine vault"));
        }
        Ok(vault)
    }

    fn open(
        path: impl Into<PathBuf>,
        kind: &'static str,
        secret: &[u8],
        unlocked_by: UnlockedBy,
    ) -> Result<Self> {
        let path = path.into();
        if !path.exists() {
            return Err(Error::VaultNotFound(path));
        }
        let snapshot = read_snapshot(&path)?;
        let parts = header::split(&snapshot.bytes)?;
        let format_ver = parts.format_ver;
        let header = parts.header;
        header.validate()?;

        let slot = header.slot(kind).ok_or(Error::NoSuchSlot(kind))?;
        // Parameters come from the file, never from a hardcoded profile (roadmap M1).
        let kek = slot.effective_kdf(&header.kdf).derive(secret)?;
        let vault_key = slot.unwrap_with_kek(&header.vault_id, &kek)?;
        drop(kek);

        let vk: &[u8; KEY_LEN] = &vault_key;
        let body = decrypt_body(vk, &parts.body_nonce, parts.aad, parts.body_ct)?;
        let disk =
            DiskState::observed(snapshot.generation, snapshot.fingerprint, &body, format_ver);
        Ok(Self::assemble(
            path,
            header,
            vault_key,
            body,
            unlocked_by,
            disk,
        ))
    }

    /// Run `f` as one transaction against the vault file as it is on disk now, and write the
    /// result — the only write path that is safe with other writers around (see the module
    /// documentation for the steps).
    ///
    /// `f` sees, through [`Tx`], the state the file holds at the moment the lock was taken, plus
    /// any pending audit drafts chained onto it. (If the file is still the version this session
    /// last read or wrote, that is the session's memory as it stands — including anything the
    /// non-transactional mutators changed on top of that same version and not yet saved, which
    /// this transaction then commits. Do not interleave the two APIs on one `Vault`: a mutation
    /// left unsaved when a transaction starts is committed if the file is unchanged, and discarded
    /// with the rest of the stale memory if it is not.)
    ///
    /// Every read that decides a change belongs inside `f`; a decision made from a read taken
    /// before `transact` may be stale. `f` must be quick and must not wait on a human, an
    /// approval, Argon2id or a child process: the lock is held for as long as it runs. Use the
    /// `prepare_*` methods for the Argon2id-bound header changes.
    ///
    /// If `f` returns `Err`, or the write fails, the in-memory state is restored from the file,
    /// the error is returned, and nothing on disk has changed. Drafts that were pending before the
    /// call, or queued with [`Vault::queue_audit`] during it, go back into the pending queue;
    /// entries `f` itself appended with [`Tx::append_audit`] are part of the transaction and
    /// are discarded with it — they described something that did not happen.
    ///
    /// Also used, with a closure that changes nothing, to flush the pending queue; see
    /// [`Vault::flush_audit`].
    ///
    /// # Errors
    ///
    /// * [`Error::VaultBusy`] — another writer held the lock past [`Vault::lock_timeout`].
    /// * [`Error::LockUnsupported`], [`Error::LockLost`] — see [`lock`].
    /// * [`Error::VaultReplaced`] — the file is a different vault or no longer opens with this
    ///   session's key.
    /// * [`Error::VaultDiverged`] — the file does not continue this session's audit log.
    /// * [`Error::VaultNotFound`] — the file is gone. It is never recreated as a side effect.
    /// * [`Error::VaultTooLarge`] — the file, or the result, is over [`MAX_VAULT_FILE_LEN`].
    /// * [`Error::NestedTransaction`] — called through the `Tx` of a running transaction.
    /// * whatever `f` returns, and any I/O, decode or RNG failure.
    ///
    /// Failures other than `f`'s own are also recorded in [`Vault::last_save_error`].
    pub fn transact<T>(&mut self, f: impl FnOnce(&mut Tx<'_>) -> Result<T>) -> Result<T> {
        if self.in_transaction {
            return Err(Error::NestedTransaction);
        }
        let lock = match FileLock::acquire(&self.path, self.lock_timeout) {
            Ok(lock) => lock,
            Err(e) => {
                self.note_write_outcome(Some(&e));
                return Err(e);
            }
        };
        self.sweep_temporaries_once(&lock);
        let base = match self.catch_up_locked() {
            Ok(base) => base,
            Err(e) => {
                self.note_write_outcome(Some(&e));
                return Err(e);
            }
        };

        let carried = std::mem::take(&mut self.pending_audit);
        for pending in &carried {
            self.chain(pending.clone());
        }

        let mut tx = Tx::begin(self, &lock, base, carried);
        match f(&mut tx) {
            Ok(value) => tx.commit().map(|()| value),
            Err(e) => {
                tx.roll_back();
                Err(e)
            }
        }
    }

    /// Bring this session's in-memory state up to date with the file, if another writer changed
    /// it. Reports whether anything was replaced.
    ///
    /// Takes no lock: the atomic rename means the read sees one complete version. On Unix an
    /// unchanged `(dev, ino, size, mtime)` answers without reading the file; otherwise the file
    /// is read and hashed, and only a different generation is decrypted and adopted — after the
    /// same `vault_id`, key and continuity checks a transaction makes. Audit entries this session
    /// chained but never saved are re-queued as drafts, not dropped.
    ///
    /// A long-lived reader (the app, the agent) calls this before serving a request so it never
    /// shows or acts on a state another process has since changed. It is not needed before
    /// [`Vault::transact`], which always starts from the file.
    ///
    /// # Errors
    ///
    /// [`Error::VaultNotFound`] if the file is gone, [`Error::VaultReplaced`],
    /// [`Error::VaultDiverged`], [`Error::NestedTransaction`], and I/O or decode failures. On any
    /// error the in-memory state is left as it was.
    pub fn refresh_if_changed(&mut self) -> Result<bool> {
        if self.in_transaction {
            return Err(Error::NestedTransaction);
        }
        let known = disk_mut(&mut self.disk).clone();
        if known.generation.is_some()
            && let Some(fp) = known.fingerprint
        {
            match std::fs::metadata(&self.path) {
                Ok(meta) if fingerprint(&meta) == Some(fp) => return Ok(false),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Error::VaultNotFound(self.path.clone()));
                }
                _ => {}
            }
        }
        let snapshot = match read_snapshot(&self.path) {
            Ok(snapshot) => snapshot,
            Err(e) if is_not_found(&e) => return Err(Error::VaultNotFound(self.path.clone())),
            Err(e) => return Err(e),
        };
        if known.generation == Some(snapshot.generation) {
            let disk = disk_mut(&mut self.disk);
            disk.fingerprint = snapshot.fingerprint;
            // Still the version any unconfirmed write was attempted on: it did not land.
            disk.unconfirmed = None;
            return Ok(false);
        }
        let decoded = self.decode_continuation(&snapshot)?;
        self.adopt(decoded, &snapshot);
        Ok(true)
    }

    /// Record an audit draft to be written by the next successful transaction.
    ///
    /// For entries that must not be lost to a write failure but must not stop the caller either —
    /// the follow-up after a failed action, a denial answered while the disk is full. The draft
    /// keeps the time it was recorded, whenever it is finally chained. It is not in
    /// [`Vault::audit_entries`] until then, and counts towards [`Vault::unsaved_audit_entries`].
    ///
    /// Inside a transaction, a queued draft is chained at commit, after the closure's own entries;
    /// if the transaction fails it stays queued.
    pub fn queue_audit(&mut self, draft: AuditDraft) {
        self.pending_audit.push(PendingDraft::now(draft));
    }

    /// Write every unsaved audit entry now, in a transaction of its own. Does nothing, and takes
    /// no lock, when nothing is unsaved.
    ///
    /// # Errors
    ///
    /// As [`Vault::transact`]; on failure the entries stay unsaved.
    pub fn flush_audit(&mut self) -> Result<()> {
        if self.unsaved_audit_entries() == 0 {
            return Ok(());
        }
        self.transact(|_| Ok(()))
    }

    /// Whether the file at this vault's path is one this session's transactions refuse to build
    /// on, and if so what an overwrite ([`Vault::overwrite_with_this_session`]) would lose.
    ///
    /// `Ok(None)` means there is no conflict: the file is the version this session last read or
    /// wrote, or one that continues it — an ordinary transaction merges with it. Takes no lock
    /// and changes nothing, in memory or on disk; call it to build the confirmation a person
    /// reads before choosing to overwrite, and hand its answer to the overwrite unchanged.
    ///
    /// # Errors
    ///
    /// [`Error::VaultTooLarge`] or another I/O error reading the file: the file could not be
    /// examined, which is different from it being found in conflict. An I/O failure is never
    /// reported as [`FileConflict::Missing`].
    pub fn examine_conflict(&self) -> Result<Option<FileConflict>> {
        Ok(self.examine_file()?.conflict)
    }

    /// [`Vault::examine_conflict`], keeping what an overwrite needs from the file: its bytes and,
    /// for a diverged file, its decrypted body.
    fn examine_file(&self) -> Result<Examined> {
        let snapshot = match read_snapshot(&self.path) {
            Ok(snapshot) => snapshot,
            Err(e) if is_not_found(&e) => {
                return Ok(Examined {
                    conflict: Some(FileConflict::Missing),
                    bytes: None,
                    diverged_body: None,
                });
            }
            Err(e) => return Err(e),
        };
        let known = self.disk_state().clone();
        let found = |conflict, diverged_body| Examined {
            conflict,
            bytes: None,
            diverged_body,
        };
        let file_sha256 = snapshot.generation;
        let mut examined = if known.generation == Some(snapshot.generation) {
            found(None, None)
        } else {
            match self.decode_with_session_key(&snapshot.bytes) {
                Ok(file) if continues_known(&known, &file) => found(None, None),
                Ok(file) => found(
                    Some(FileConflict::Diverged {
                        file_sha256,
                        lost: self.diverged_file(&file.header, &file.body)?,
                    }),
                    Some(file.body),
                ),
                Err(Error::VaultReplaced(_)) => {
                    found(Some(FileConflict::Replaced { file_sha256 }), None)
                }
                // A parse, format-version or header-validation failure: the bytes were read, and
                // are not a vault this build can open. That is a finding about the file, not a
                // failure to examine it.
                Err(Error::UnsupportedFormatVersion { found: version, .. }) => found(
                    Some(FileConflict::TooNew {
                        file_sha256,
                        found: version,
                    }),
                    None,
                ),
                Err(_) => found(Some(FileConflict::Unreadable { file_sha256 }), None),
            }
        };
        examined.bytes = Some(snapshot.bytes);
        Ok(examined)
    }

    /// What a diverged file (`header`, `body`) holds that this session does not.
    fn diverged_file(&self, header: &Header, body: &Body) -> Result<DivergedFile> {
        let (device_keys, device_keys_retired_in_file) = device::difference(body, &self.body);
        let slot = |h: &Header, kind| SlotIdentity::of(h.slot(kind));
        Ok(DivergedFile {
            audit_len: body.audit.len(),
            shared_audit_len: shared_audit_prefix(&body.audit, &self.body.audit),
            items: difference(&body.items, &self.body.items, |i| i.id)?,
            environments: difference(&body.envs, &self.body.envs, |e| e.id)?,
            logical_vaults: difference(&body.vaults, &self.body.vaults, |v| v.id)?,
            device_keys,
            device_keys_retired_in_file,
            master_password_differs: header.kdf != self.header.kdf
                || slot(header, wrap::KIND_PASSWORD) != slot(&self.header, wrap::KIND_PASSWORD),
            recovery_code_differs: slot(header, wrap::KIND_RECOVERY)
                != slot(&self.header, wrap::KIND_RECOVERY),
            platform_slot_differs: slot(header, wrap::KIND_PLATFORM)
                != slot(&self.header, wrap::KIND_PLATFORM),
        })
    }

    /// Replace the vault file with this session's version — the explicit, human-confirmed answer
    /// to a file this session's transactions refuse ("keep this app's version"). The only write
    /// in this module that does not start from the file.
    ///
    /// `confirmed` must be what [`Vault::examine_conflict`] returned and what the person was
    /// shown. Under the vault's lock the file is examined again, and the overwrite only goes
    /// ahead if it still finds exactly that — the same file bytes and, for a diverged file, the
    /// same losses — so a person never discards something other than what they agreed to
    /// discard. In order:
    ///
    /// 1. take the lock ([`Error::VaultBusy`] after [`Vault::lock_timeout`]);
    /// 2. re-examine the file; refuse with [`Error::VaultNotInConflict`] if an ordinary
    ///    transaction could build on it again, or [`Error::VaultConflict`] if it is in conflict
    ///    differently from `confirmed`;
    /// 3. chain every pending audit draft ([`Vault::queue_audit`], or carried back by a failed
    ///    transaction) onto this session's log, then one entry recording the override (below);
    /// 4. write this session's header and body atomically, and adopt the result as the version
    ///    this session descends from — later transactions build on it as usual.
    ///
    /// If the file is missing ([`FileConflict::Missing`]) this recreates it; nothing else in this
    /// module ever does, once a vault is open.
    ///
    /// # Which header is written: this session's
    ///
    /// The file's header is not kept, even when it could be parsed. For a replaced or unreadable
    /// file it wraps some other key or none, so keeping it would produce a file nothing opens.
    /// For a diverged file it wraps the same vault key, but keeping it would write a vault that
    /// neither side ever had — the file's unlock methods over this session's contents — and the
    /// override is meant to restore one known version, not merge two. The session's header is
    /// the one its key and body belong with: the slots as this session last read or wrote them.
    ///
    /// So the unlock methods come with it, and the consequence is deliberate and must be stated
    /// to whoever confirms the overwrite ([`DivergedFile`] reports which ones differ):
    ///
    /// * **Master password.** If the file's password slot or KDF cost differs — the password was
    ///   changed in the file's version and this session never saw it — the password that opens
    ///   the file today stops working, and the one this session's header holds works again.
    /// * **Recovery code.** Likewise: a code issued in the file's version stops working, and the
    ///   code in this session's header works again — even if a person replaced it in the file's
    ///   version precisely because they believed it exposed.
    /// * **Touch ID.** The platform slot is this session's too; a slot enrolled only in the file
    ///   disappears, and one removed only in the file comes back.
    ///
    /// # The audit entry
    ///
    /// The written file's own log ends with an entry (`tool` [`AUDIT_TOOL_OVERWRITE`], `actor`
    /// as given, outcome allowed) whose `detail` records what was overwritten, machine-readably:
    /// `found=` the kind, `file_sha256=` the first 8 bytes of the replaced file's hash (`none`
    /// if missing), `file_audit_len=` its audit length (`unknown` unless diverged, `0` if
    /// missing), `shared_audit_len=` how much of it this session's log shares, `session_audit_len=`
    /// how many entries this session's log holds under the new entry, `device_keys_kept=` how many
    /// device keys were carried over from the file and `device_keys_retired=` how many of this
    /// session's the file had retired (below), then `reason=` and `reason`, last, so it may
    /// contain anything.
    ///
    /// # Device keys are kept, not replaced
    ///
    /// The one exception to "this session's version": shared-vault device keys (ADR-0035 §5) that
    /// only a diverged file holds are carried over into what is written, after this session's
    /// own. A device key has no other copy, and discarding it would cut this computer out of every
    /// shared vault it belongs to — a loss nobody could see in the confirmation or undo later.
    /// Where both hold a key with the same id, this session's entry is written. Removals are the
    /// other way round, and stick: the two sides' retired lists are combined, a key either side
    /// retired is not written, and one this session removed is never brought back from the file.
    /// [`DivergedFile::device_keys`] and [`DivergedFile::device_keys_retired_in_file`] report
    /// both.
    ///
    /// What is written is never at a lower `format_ver` than a diverged file it replaces: that
    /// file is this vault, and no write of a vault lowers its version. If what is written raises
    /// the file's `format_ver` (this session holds device keys, the file was version 1), the file
    /// is first copied to `<file>.bak-<its format_ver>` exactly as a transaction does.
    ///
    /// # Errors
    ///
    /// * [`Error::VaultNotInConflict`] — nothing to overwrite; use [`Vault::transact`].
    /// * [`Error::VaultConflict`] — the file is not what `confirmed` describes any more; examine
    ///   it again and ask again. Also returned if this session holds no version to write (memory
    ///   was emptied by a rollback that could not restore anything), which would otherwise
    ///   replace the vault with an empty one.
    /// * [`Error::VaultBusy`], [`Error::LockUnsupported`], [`Error::LockLost`] — see [`lock`].
    /// * [`Error::NestedTransaction`], [`Error::VaultSchemaTooNew`], [`Error::VaultTooLarge`],
    ///   and I/O or RNG failures.
    ///
    /// On any error the file is as it was and so is this session: pending drafts stay pending,
    /// nothing is chained. A write that reports failure is read back, exactly as a transaction's
    /// is; if its outcome cannot be determined it is remembered, so the next read of the file
    /// settles it and its drafts are never written twice.
    pub fn overwrite_with_this_session(
        &mut self,
        confirmed: &FileConflict,
        actor: &str,
        reason: &str,
    ) -> Result<()> {
        if self.in_transaction {
            return Err(Error::NestedTransaction);
        }
        if disk_mut(&mut self.disk).generation.is_none() {
            return Err(Error::VaultConflict(self.path.clone()));
        }
        let result = self.overwrite_unmerged(confirmed, actor, reason);
        // `VaultNotInConflict` and a stale `confirmed` are answers, not failed writes: the
        // durability indicator (`last_save_error`) is about writes that were attempted.
        if !matches!(
            result,
            Err(Error::VaultNotInConflict(_) | Error::VaultConflict(_))
        ) {
            self.note_write_outcome(result.as_ref().err());
        }
        result
    }

    fn overwrite_unmerged(
        &mut self,
        confirmed: &FileConflict,
        actor: &str,
        reason: &str,
    ) -> Result<()> {
        let lock = FileLock::acquire(&self.path, self.lock_timeout)?;
        self.sweep_temporaries_once(&lock);
        let examined = self.examine_file()?;
        let found = match examined.conflict {
            None => return Err(Error::VaultNotInConflict(self.path.clone())),
            Some(found) if found != *confirmed => {
                return Err(Error::VaultConflict(self.path.clone()));
            }
            Some(FileConflict::TooNew { found, .. }) => {
                return Err(Error::UnsupportedFormatVersion {
                    found,
                    supported: header::MAX_READ_FORMAT_VERSION,
                });
            }
            Some(found) => found,
        };

        // What to restore if the write fails: the audit chain, the device keys and the version
        // floor change below.
        let before_len = self.body.audit.len();
        let before_head = self.body.audit_head.clone();
        let before_retired = self.body.retired_devices.len();
        let before_format_ver = disk_mut(&mut self.disk).format_ver;

        // A diverged file is this vault: whatever it is replaced with keeps at least its
        // `format_ver`, as every other write of this vault does.
        if matches!(found, FileConflict::Diverged { .. })
            && let Some(on_disk) = &examined.bytes
            && let Ok(parts) = header::split(on_disk)
        {
            let disk = disk_mut(&mut self.disk);
            disk.format_ver = disk.format_ver.max(parts.format_ver);
        }

        // Retirements are grow-only: the file's are added to this session's, and a key either
        // side retired is dropped from what is written.
        let (file_devices, file_retired, file_machine_key) = examined
            .diverged_body
            .map(|b| (b.devices, b.retired_devices, b.machine_key))
            .unwrap_or_default();
        // Like a device key, a machine vault key only the file holds has no other copy (the
        // Keychain's, if armed, is not one this crate can count on): kept, not discarded.
        let machine_key_kept = self.body.machine_key.is_none() && file_machine_key.is_some();
        if machine_key_kept {
            self.body.machine_key = file_machine_key;
        }
        for id in file_retired {
            if !self.body.retired_devices.contains(&id) {
                self.body.retired_devices.push(id);
            }
        }
        let mut retired_from_session = Vec::new();
        let mut index = 0;
        while index < self.body.devices.len() {
            if self
                .body
                .retired_devices
                .contains(self.body.devices[index].id())
            {
                retired_from_session.push((
                    index + retired_from_session.len(),
                    self.body.devices.remove(index),
                ));
            } else {
                index += 1;
            }
        }
        let before_devices = self.body.devices.len();

        // Device keys only in the file, and retired by neither side, are kept, not discarded:
        // each is the only copy of a key pair a shared vault's roster names, and overwriting it
        // would silently cut this computer out of those vaults. They are appended after this
        // session's own.
        for key in file_devices {
            if !self.body.retired_devices.contains(key.id())
                && !self.body.devices.iter().any(|mine| mine.id() == key.id())
            {
                self.body.devices.push(key);
            }
        }
        let device_keys_kept = self.body.devices.len() - before_devices;
        let device_keys_retired = retired_from_session.len();

        let carried = std::mem::take(&mut self.pending_audit);
        for pending in &carried {
            self.chain(pending.clone());
        }
        let detail = overwrite_detail(
            &found,
            self.body.audit.len(),
            device_keys_kept,
            device_keys_retired,
            reason,
        );
        self.chain(PendingDraft::now(AuditDraft {
            actor: actor.to_owned(),
            tool: AUDIT_TOOL_OVERWRITE.to_owned(),
            outcome: crate::proto::Outcome::Allowed,
            detail: Some(detail),
            ..AuditDraft::default()
        }));

        let attempted = self.seal().and_then(|bytes| {
            // Under the lock, the file is still exactly the bytes just examined.
            if let Some(on_disk) = &examined.bytes
                && let Some(backup) = self.back_up_before_upgrade(on_disk)?
            {
                self.upgrade_backup = Some(backup);
            }
            let generation = generation_of(&bytes);
            let written = self.write_sealed_locked(&lock, &bytes, generation);
            Ok((generation, written))
        });
        let (error, attempted) = match attempted {
            Ok((_, Ok(()))) => return Ok(()),
            Ok((generation, Err(e))) => {
                if let Some(fingerprint) = self.confirm_landed(generation) {
                    self.record_written(generation, fingerprint);
                    return Ok(());
                }
                (e, true)
            }
            Err(e) => (e, false),
        };

        // Put the session back exactly as it was: the chain as before, the drafts pending.
        let attempted_write = UnconfirmedWrite {
            audit_len: self.body.audit.len(),
            audit_head: self.body.audit_head.clone(),
            // What a later reload re-queues at the front: the in-memory entries past what the
            // disk was known to hold, then the carried drafts. The override's own entry is not
            // among them — if the write in fact landed it is in the file; if not, it described
            // something that did not happen.
            drafts: before_len.saturating_sub(disk_mut(&mut self.disk).audit_len) + carried.len(),
        };
        self.body.audit.truncate(before_len);
        self.body.audit_head = before_head;
        self.body.devices.truncate(before_devices);
        for (index, key) in retired_from_session {
            self.body.devices.insert(index, key);
        }
        self.body.retired_devices.truncate(before_retired);
        if machine_key_kept {
            self.body.machine_key = None;
        }
        disk_mut(&mut self.disk).format_ver = before_format_ver;
        self.pending_audit = carried;
        if attempted {
            disk_mut(&mut self.disk).unconfirmed = Some(attempted_write);
        }
        Err(error)
    }

    /// How long a write waits for another writer before failing with [`Error::VaultBusy`].
    #[must_use]
    pub fn lock_timeout(&self) -> Duration {
        self.lock_timeout
    }

    /// Choose how long a write waits for another writer ([`lock::DEFAULT_LOCK_TIMEOUT`] unless
    /// set). An interactive UI wants a short wait and a clear message; a CLI can afford longer.
    pub fn set_lock_timeout(&mut self, timeout: Duration) {
        self.lock_timeout = timeout;
    }

    /// Write the vault back to disk atomically, mode `0600` on Unix (threat-model M-13) — the
    /// non-transactional path, kept `#[cfg(test)]` purely as this module's own regression-tested
    /// fallback (step 6 of ADR-0039): nothing calls it in production any more, and no other crate
    /// could even see it if it were compiled in — the mutators that used to make something worth
    /// saving outside a transaction (`add_item`, `append_audit`, …) are gone from `Vault`, so the
    /// only remaining callers are this module's own unit tests, exercising it directly through the
    /// private `chain` primitive `Tx::append_audit` itself calls. Still `&self` rather than
    /// `&mut self`, unchanged from when `kagisecure-agent`'s `VaultHandle` needed to
    /// call it through a shared reference — nothing does now, but the tests below exercise this
    /// exact signature, which is the property worth pinning.
    ///
    /// It cannot merge: it has no record of what changed in memory since the file was read. It is
    /// therefore only allowed to replace the exact version this session last read or wrote. Under
    /// the vault's lock it re-reads the file, and if its generation is not that one — another
    /// process or another `Vault` wrote in between — it writes nothing and fails with
    /// [`Error::VaultConflict`]. The in-memory state is left as it was; [`Vault::transact`] or
    /// [`Vault::refresh_if_changed`] replace it with the file's, re-queuing any unsaved audit
    /// entries. A missing file is recreated: there is no newer version to lose. (Unlike
    /// [`Vault::transact`], which refuses.)
    ///
    /// Like a transaction, a write that reports failure is read back: if the file holds exactly
    /// what was written, the save succeeded; if the file cannot be read, the write is remembered
    /// as unconfirmed so its entries are not written twice later.
    ///
    /// Pending drafts ([`Vault::queue_audit`]) are not written by this path: chaining them needs
    /// `&mut self`, which this does not take.
    ///
    /// # Errors
    ///
    /// [`Error::VaultConflict`], [`Error::VaultBusy`], [`Error::LockUnsupported`],
    /// [`Error::LockLost`], [`Error::NestedTransaction`] when called inside a transaction (which
    /// commits by itself), and any I/O or RNG failure. On failure the existing file is left
    /// untouched: the new contents are written to a temporary file in the same directory and
    /// renamed into place only once they are complete and flushed.
    ///
    /// A failure here is also recorded on the vault itself ([`Vault::unsaved_audit_entries`],
    /// [`Vault::last_save_error`]) rather than only returned, precisely because several callers
    /// (an audit-only append, a denial response) intentionally do not propagate this error to
    /// their own caller — the human still needs a way to learn the write never landed.
    #[cfg(test)]
    pub(crate) fn save(&self) -> Result<()> {
        let result = self.save_unmerged();
        self.note_write_outcome(result.as_ref().err());
        result
    }

    #[cfg(test)]
    fn save_unmerged(&self) -> Result<()> {
        if self.in_transaction {
            return Err(Error::NestedTransaction);
        }
        let lock = FileLock::acquire(&self.path, self.lock_timeout)?;
        self.sweep_temporaries_once(&lock);
        let known = self.disk_state().generation;
        match read_snapshot(&self.path) {
            Ok(current) if known == Some(current.generation) => {}
            Ok(_) => return Err(Error::VaultConflict(self.path.clone())),
            // Nothing to overwrite — unless memory no longer descends from any file version.
            Err(e) if is_not_found(&e) && known.is_some() => {}
            Err(e) if is_not_found(&e) => return Err(Error::VaultConflict(self.path.clone())),
            Err(e) => return Err(e),
        }
        let bytes = self.seal()?;
        let generation = generation_of(&bytes);
        match self.write_sealed_locked(&lock, &bytes, generation) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Same read-back as a transaction's (see `Tx::fail`): a write that landed despite
                // reporting failure is a save, and must not leave its entries counted as unsaved,
                // to be chained again later.
                if let Some(fingerprint) = self.confirm_landed(generation) {
                    self.record_written(generation, fingerprint);
                    return Ok(());
                }
                let mut disk = self.disk_state();
                let attempted = self.body.audit.len();
                // The entries this save carried are the in-memory tail past what is on disk;
                // the next reload re-queues exactly those at the front of the queue.
                disk.unconfirmed = Some(UnconfirmedWrite {
                    audit_len: attempted,
                    audit_head: self.body.audit_head.clone(),
                    drafts: attempted.saturating_sub(disk.audit_len),
                });
                Err(e)
            }
        }
    }

    /// Whether the file now holds exactly the bytes whose generation is `generation` — read back
    /// after a write reported failure. `Some(fingerprint)` if so; `None` if it does not, or if it
    /// cannot be read (the outcome is then unknown).
    fn confirm_landed(&self, generation: Generation) -> Option<Option<Fingerprint>> {
        #[cfg(test)]
        if FAIL_NEXT_READ_BACK.with(|f| f.replace(false)) {
            return None;
        }
        read_snapshot(&self.path)
            .ok()
            .filter(|current| current.generation == generation)
            .map(|current| current.fingerprint)
    }

    /// Record that the file now holds this session's in-memory state, as `generation`.
    ///
    /// Must be called with the in-memory state exactly as it was sealed, so that
    /// [`Vault::format_ver_to_write`] names the version the written bytes carry.
    fn record_written(&self, generation: Generation, fingerprint: Option<Fingerprint>) {
        let format_ver = self.format_ver_to_write();
        *self.disk_state() = DiskState::observed(generation, fingerprint, &self.body, format_ver);
    }

    /// The first write of a vault [`Vault::create`] just built: under the lock, refuse if anything
    /// appeared at the path meanwhile, then write.
    fn write_new_file(&self) -> Result<()> {
        let lock = FileLock::acquire(&self.path, self.lock_timeout)?;
        self.sweep_temporaries_once(&lock);
        // `symlink_metadata`, not `exists`: a dangling symlink is something too.
        if std::fs::symlink_metadata(&self.path).is_ok() {
            return Err(Error::VaultExists(self.path.clone()));
        }
        let bytes = self.seal()?;
        let generation = generation_of(&bytes);
        self.write_sealed_locked(&lock, &bytes, generation)
    }

    /// Refuse to write back a vault whose `body.schema` or `header.v` is newer than this build
    /// writes (vault-format §9).
    ///
    /// Reading such a vault already succeeds: [`decrypt_body`] and [`header::split`] apply no such
    /// check, and the unknown-key passthrough on [`Body`] and [`Header`] means nothing understood
    /// only additively is lost. A schema *bump* is different from an additive field by
    /// definition (§9's compatibility table: "additive changes do not bump it") — it says a
    /// structural change happened that this build's types may not represent faithfully, so writing
    /// the file back could silently corrupt what it does not model. Refusing the write is the safe
    /// default; nothing about opening or reading the vault is affected.
    fn ensure_schema_supported(&self) -> Result<()> {
        if self.body.schema > BODY_SCHEMA_VERSION {
            return Err(Error::VaultSchemaTooNew {
                field: "body.schema",
                found: self.body.schema,
                supported: BODY_SCHEMA_VERSION,
            });
        }
        if self.header.v > header::HEADER_SCHEMA_VERSION {
            return Err(Error::VaultSchemaTooNew {
                field: "header.v",
                found: self.header.v,
                supported: header::HEADER_SCHEMA_VERSION,
            });
        }
        Ok(())
    }

    /// The `format_ver` the next write uses: the version of the file this session descends from,
    /// never lower than [`header::FORMAT_VERSION`]. A file is never written back at a lower
    /// version than it was read with, so a newer build's file keeps the version that makes older
    /// builds refuse it (vault-format §9).
    ///
    /// A body holding any device key is written as at least
    /// [`header::DEVICE_KEYS_FORMAT_VERSION`], and one holding a machine vault key, or being a
    /// machine vault, as at least [`header::MACHINE_VAULT_FORMAT_VERSION`]. Removing the last one
    /// does not lower it again.
    fn format_ver_to_write(&self) -> u16 {
        let floor = if self.body.machine_key.is_some() || self.body.machine.is_some() {
            header::MACHINE_VAULT_FORMAT_VERSION
        } else if self.body.devices.is_empty() {
            header::FORMAT_VERSION
        } else {
            header::DEVICE_KEYS_FORMAT_VERSION
        };
        self.disk_state().format_ver.max(floor)
    }

    /// Before a write that raises the file's `format_ver`: copy `on_disk` — the file as it is
    /// now, read under the lock — to `<file>.bak-<its format_ver>`, or, if that name is taken,
    /// `<file>.bak-<its format_ver>-<8 hex>` (vault-format §9 rule 3). Never replaces an existing
    /// file. Returns where the copy went, or `None` when the write raises nothing (or `on_disk` is
    /// not a vault file whose version can be read).
    ///
    /// The caller holds the lock and must not write if this fails: a format upgrade without its
    /// backup is not one this build performs.
    fn back_up_before_upgrade(&self, on_disk: &[u8]) -> Result<Option<PathBuf>> {
        if on_disk.len() < header::PREFIX_LEN || on_disk[..8] != header::MAGIC {
            return Ok(None);
        }
        let from = u16::from_le_bytes([on_disk[8], on_disk[9]]);
        if from >= self.format_ver_to_write() {
            return Ok(None);
        }
        let name = self
            .path
            .file_name()
            .map_or_else(|| "vault".to_owned(), |n| n.to_string_lossy().into_owned());
        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        let plain = dir.join(format!("{name}.bak-{from}"));

        // A backup of exactly these bytes already exists — an earlier attempt at this same
        // upgrade took it and then failed to write — so it is the backup: taking another would
        // only pile up copies, one per failed attempt.
        if let Some(existing) = existing_backup_of(dir, &format!("{name}.bak-{from}"), on_disk) {
            return Ok(Some(existing));
        }

        match write_new_file(&plain, on_disk, &self.path) {
            Ok(()) => return Ok(Some(plain)),
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        // A few tries: eight random hex digits colliding with an existing backup is not a case
        // that happens, but create-new makes it harmless if it does.
        let mut last = None;
        for _ in 0..4 {
            let suffix = hex_prefix(&crypto::random::array::<4>()?, 4);
            let path = dir.join(format!("{name}.bak-{from}-{suffix}"));
            match write_new_file(&path, on_disk, &self.path) {
                Ok(()) => return Ok(Some(path)),
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    last = Some(Error::Io(e));
                }
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or(Error::Malformed))
    }

    /// Serialize and encrypt the current state into a complete vault file image.
    fn seal(&self) -> Result<Vec<u8>> {
        self.ensure_schema_supported()?;
        machine::check_body(&self.body)?;
        let header_cbor = self.header.to_cbor()?;
        let framed = header::framed_with_version(&header_cbor, self.format_ver_to_write());

        let mut plaintext = Zeroizing::new(Vec::new());
        ciborium::into_writer(&self.body, &mut *plaintext)
            .map_err(|e| Error::BodyDecode(e.to_string()))?;

        let vk: &[u8; KEY_LEN] = &self.vault_key;
        let body_key = crypto::body_key(vk);
        let nonce = aead::nonce()?;
        let ciphertext = aead::seal(&body_key, &nonce, &framed, &plaintext)?;

        let mut out = framed;
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        ensure_within_limit(out.len() as u64, &self.path)?;
        Ok(out)
    }

    /// Replace the file with `bytes` (whose generation is `generation`) and record it as the
    /// version this session's memory now matches. The caller holds `lock`.
    fn write_sealed_locked(
        &self,
        lock: &FileLock,
        bytes: &[u8],
        generation: Generation,
    ) -> Result<()> {
        lock.ensure_current()?;
        #[cfg(test)]
        let fault = INJECTED_FAULT.with(|f| f.replace(InjectedFault::None));
        #[cfg(test)]
        if fault == InjectedFault::BeforeWrite {
            return Err(Error::Io(std::io::Error::other("injected write failure")));
        }
        let written = write_atomically(&self.path, bytes)?;
        #[cfg(test)]
        if fault == InjectedFault::AfterWrite || fault == InjectedFault::AfterWriteUnconfirmed {
            if fault == InjectedFault::AfterWriteUnconfirmed {
                FAIL_NEXT_READ_BACK.with(|f| f.set(true));
            }
            return Err(Error::Io(std::io::Error::other("injected lost reply")));
        }
        self.record_written(generation, fingerprint(&written));
        Ok(())
    }

    /// Read the file under the lock and make sure the in-memory state descends from it — step 2
    /// of a transaction. Returns the file as read: the version the transaction starts from, and
    /// what a rollback restores.
    ///
    /// When the file is still the generation this session last read or wrote, memory already
    /// descends from it and is kept: re-decrypting would change nothing but the cost. Anything
    /// the non-transactional mutators changed in memory since then was changed on top of this
    /// very version, so committing it with the transaction loses nobody's update. Only a
    /// different generation is decrypted and adopted.
    ///
    /// A missing file is refused with [`Error::VaultNotFound`]. Writing memory back would
    /// recreate a vault someone deleted or moved — a decision for the user, not a side effect of
    /// the next write — and would leave a transaction nothing on disk to roll back to.
    fn catch_up_locked(&mut self) -> Result<Snapshot> {
        let snapshot = match read_snapshot(&self.path) {
            Ok(snapshot) => snapshot,
            Err(e) if is_not_found(&e) => return Err(Error::VaultNotFound(self.path.clone())),
            Err(e) => return Err(e),
        };
        if disk_mut(&mut self.disk).generation == Some(snapshot.generation) {
            let disk = disk_mut(&mut self.disk);
            disk.fingerprint = snapshot.fingerprint;
            // Still the version any unconfirmed write was attempted on: it did not land.
            disk.unconfirmed = None;
            // Not for the chain's sake — the entries are already chained onto the right head
            // and re-chaining reproduces them exactly — but so a rollback, which restores this
            // version, puts them back in the queue instead of dropping them.
            self.requeue_unsaved_audit();
        } else {
            let decoded = self.decode_continuation(&snapshot)?;
            self.adopt(decoded, &snapshot);
        }
        Ok(snapshot)
    }

    /// Decrypt a vault file image with this session's key. Changes nothing.
    ///
    /// # Errors
    ///
    /// [`Error::VaultReplaced`] for a different `vault_id` or a body this key does not open, plus
    /// the parse and header-validation errors.
    fn decode_with_session_key(&self, bytes: &[u8]) -> Result<Decoded> {
        let parts = header::split(bytes)?;
        if parts.header.vault_id != self.header.vault_id {
            return Err(Error::VaultReplaced(self.path.clone()));
        }
        parts.header.validate()?;
        let vk: &[u8; KEY_LEN] = &self.vault_key;
        let body = decrypt_body(vk, &parts.body_nonce, parts.aad, parts.body_ct).map_err(|e| {
            if matches!(e, Error::Decrypt) {
                Error::VaultReplaced(self.path.clone())
            } else {
                e
            }
        })?;
        Ok(Decoded {
            format_ver: parts.format_ver,
            header: parts.header,
            body,
        })
    }

    /// Decrypt `snapshot` with this session's key and check it continues what this session
    /// knows. Changes nothing.
    ///
    /// A file at a lower `format_ver` than the one this session descends from does not continue
    /// it, whatever its audit log says: no writer of this build lowers a file's version, so such a
    /// file is an older copy put back — by a sync tool, a restore, or a build that predates the
    /// version and still had the vault open — and adopting it would silently drop what the higher
    /// version holds (shared-vault device keys, ADR-0035 §16).
    fn decode_continuation(&self, snapshot: &Snapshot) -> Result<Decoded> {
        let decoded = self.decode_with_session_key(&snapshot.bytes)?;
        let known = self.disk_state().clone();
        if !continues_known(&known, &decoded) {
            return Err(Error::VaultDiverged(self.path.clone()));
        }
        Ok(decoded)
    }

    /// Replace the in-memory state with a decoded file, re-queuing unsaved audit entries first
    /// and settling any unconfirmed write against it.
    fn adopt(&mut self, decoded: Decoded, snapshot: &Snapshot) {
        let Decoded {
            format_ver,
            header,
            body,
        } = decoded;
        self.requeue_unsaved_audit();
        self.settle_unconfirmed(&body.audit);
        self.header = header;
        self.body = body;
        *disk_mut(&mut self.disk) = DiskState::observed(
            snapshot.generation,
            snapshot.fingerprint,
            &self.body,
            format_ver,
        );
    }

    /// Decide an [`UnconfirmedWrite`] now that the file's audit log `on_disk` is known, and clear
    /// it. Must run after [`Vault::requeue_unsaved_audit`].
    ///
    /// Why the first `drafts` of the queue are exactly the write's: a failed transaction puts
    /// what it carried back at the *front* of the queue; a failed save's entries are the
    /// in-memory tail, which a re-queue puts at the front; later drafts are only ever appended
    /// behind them, or chained in order by `append_audit` into the tail that is re-queued as a
    /// block. Nothing can have written them in between: a save on top of the version the write
    /// was attempted on proves it did not land (and clears this), and a save on any other
    /// version is refused.
    fn settle_unconfirmed(&mut self, on_disk: &[AuditEntry]) {
        let Some(write) = disk_mut(&mut self.disk).unconfirmed.take() else {
            return;
        };
        if continues(write.audit_len, &write.audit_head, on_disk) {
            let written = write.drafts.min(self.pending_audit.len());
            self.pending_audit.drain(..written);
        }
    }

    /// Move audit entries that were chained in memory but never reached the disk back to the
    /// front of the pending queue, as drafts with their original timestamps, and put the in-memory
    /// chain back to what the disk holds.
    ///
    /// They go to the *front*: any draft already queued was recorded after them, because
    /// [`Vault::transact`] chains the carried queue onto the fresh head before the closure —
    /// and so before anything it chains with [`Tx::append_audit`] — ever runs.
    fn requeue_unsaved_audit(&mut self) {
        let disk = disk_mut(&mut self.disk);
        let known = disk.audit_len.min(self.body.audit.len());
        if known == self.body.audit.len() {
            return;
        }
        let unsaved = self.body.audit.split_off(known);
        self.body.audit_head.clone_from(&disk.audit_head);
        let mut queue: Vec<PendingDraft> = unsaved
            .into_iter()
            .map(PendingDraft::from_unsaved_entry)
            .collect();
        queue.append(&mut self.pending_audit);
        self.pending_audit = queue;
    }

    /// Chain one pending draft into the in-memory log.
    fn chain(&mut self, pending: PendingDraft) {
        let head = audit::append_at(
            &mut self.body.audit,
            &self.body.audit_head,
            pending.draft,
            pending.recorded_at,
        );
        self.body.audit_head = head;
    }

    fn disk_state(&self) -> MutexGuard<'_, DiskState> {
        self.disk.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn sweep_temporaries_once(&self, lock: &FileLock) {
        if !self.swept_temporaries.swap(true, Ordering::SeqCst) {
            lock.sweep_stale_temporaries();
        }
    }

    fn note_write_outcome(&self, error: Option<&Error>) {
        *self
            .last_save_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = error.map(ToString::to_string);
    }

    /// How many audit entries have not yet survived a successful write: drafts in the pending
    /// queue plus entries chained in memory since the last save.
    ///
    /// Zero means every entry in [`Vault::audit_entries`] is on disk and nothing is queued. A
    /// caller that appends and saves in the same step will normally see zero; the callers worth
    /// watching are the ones that save best-effort and swallow the error, where this is the only
    /// remaining way to notice that writes have started failing.
    #[must_use]
    pub fn unsaved_audit_entries(&self) -> usize {
        let on_disk = self.disk_state().audit_len;
        self.pending_audit.len() + self.body.audit.len().saturating_sub(on_disk)
    }

    /// The error from the most recent failed write, or `None` if the last write (if any)
    /// succeeded.
    ///
    /// Returns an owned copy rather than a borrow: the string lives behind a mutex so it can be
    /// updated from `&self`, and there is nothing sensitive in it worth avoiding a clone for (see
    /// the field's doc comment).
    #[must_use]
    pub fn last_save_error(&self) -> Option<String> {
        self.last_save_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Where this vault lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How this vault was unlocked.
    #[must_use]
    pub fn unlocked_by(&self) -> UnlockedBy {
        self.unlocked_by
    }

    /// The header, for inspection. Contains no plaintext key material.
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The `format_ver` of the file version this session descends from — the one it last read
    /// or wrote.
    ///
    /// Each file keeps its own: a write never lowers it, so a vault read at version 2 is written
    /// back at version 2 even by a transaction that changed nothing that needs it, and a build
    /// older than that version keeps refusing the file (vault-format §9). [`Vault::create`]
    /// writes [`header::FORMAT_VERSION`].
    #[must_use]
    pub fn format_ver(&self) -> u16 {
        self.disk_state().format_ver
    }

    /// Where the most recent write of this session that raised the file's `format_ver` copied
    /// the file first (`<file>.bak-<old format_ver>`, or with an 8-hex-digit suffix if that name
    /// was taken), or `None` if no write of this session has raised it. For telling a person what
    /// changed and where the old file is (vault-format §9 rule 3).
    #[must_use]
    pub fn format_upgrade_backup(&self) -> Option<&Path> {
        self.upgrade_backup.as_deref()
    }

    /// This computer's shared-vault device keys, in the order they were added (ADR-0035 §5).
    ///
    /// Secret key material, for `kagisecure-shared` alone. Never an item, never agent-visible,
    /// never exported and never shown.
    #[must_use]
    pub fn device_keys(&self) -> &[DeviceKey] {
        &self.body.devices
    }

    /// The device keys that may be used: those in [`Vault::device_keys`] whose id is not in
    /// [`Vault::retired_device_keys`]. This build never writes a body where the two overlap, but
    /// another writer could; `kagisecure-shared` must use this, and must additionally skip a key
    /// the shared vault's own roster has removed (see [`device`]).
    pub fn active_device_keys(&self) -> impl Iterator<Item = &DeviceKey> {
        self.body
            .devices
            .iter()
            .filter(|key| !self.body.retired_devices.contains(key.id()))
    }

    /// Ids of the device keys removed from this vault. They can never be added again.
    #[must_use]
    pub fn retired_device_keys(&self) -> &[[u8; DEVICE_KEY_ID_LEN]] {
        &self.body.retired_devices
    }

    /// The key of this personal vault's machine vault, if it has one (ADR-0042 §2). Secret key
    /// material: never an item, never agent-visible, never exported with items.
    #[must_use]
    pub fn machine_vault_key(&self) -> Option<&MachineVaultKey> {
        self.body.machine_key.as_ref()
    }

    /// Whether this file is a machine vault.
    #[must_use]
    pub fn is_machine(&self) -> bool {
        self.body.machine.is_some()
    }

    /// This machine vault's jobs, grants and armed state; `None` for a personal vault.
    #[must_use]
    pub fn machine(&self) -> Option<&MachineSection> {
        self.body.machine.as_ref()
    }

    /// The id of the first logical vault, which is where the CLI puts new items.
    ///
    /// # Errors
    ///
    /// [`Error::BodyDecode`] if the body somehow contains no logical vault.
    pub fn default_vault_id(&self) -> Result<VaultId> {
        self.body
            .vaults
            .first()
            .map(|v| v.id)
            .ok_or_else(|| Error::BodyDecode("vault body has no logical vaults".to_owned()))
    }

    /// Whether a new item in logical vault `vault_id` starts out visible to agents with all its
    /// fields ([`VaultMeta::new_items_agent_visible`]). `true` for a vault id this file does not
    /// have, the setting's default.
    #[must_use]
    pub fn new_items_agent_visible(&self, vault_id: VaultId) -> bool {
        self.body
            .vaults
            .iter()
            .find(|v| v.id == vault_id)
            .is_none_or(|v| v.new_items_agent_visible)
    }

    /// Metadata for every logical vault.
    #[must_use]
    pub fn vault_summaries(&self) -> Vec<VaultSummary> {
        self.body
            .vaults
            .iter()
            .map(|v| {
                let items = self
                    .body
                    .items
                    .iter()
                    .filter(|i| i.vault_id == v.id)
                    .count();
                let envs = self.body.envs.iter().filter(|e| e.vault_id == v.id).count();
                v.summary(items, envs)
            })
            .collect()
    }

    /// Resolve a logical vault by id, unique id prefix, or exact name.
    ///
    /// # Errors
    ///
    /// [`Error::ItemNotFound`] when nothing matches.
    pub fn find_vault(&self, reference: &str) -> Result<VaultId> {
        let mut hits: Vec<VaultId> = Vec::new();
        for v in &self.body.vaults {
            let id = v.id.to_string();
            if id == reference
                || v.name == reference
                || (reference.len() >= 4 && id.starts_with(reference))
            {
                hits.push(v.id);
            }
        }
        match hits.len() {
            1 => Ok(hits[0]),
            0 => Err(Error::ItemNotFound(reference.to_owned())),
            _ => Err(Error::AmbiguousItem(reference.to_owned())),
        }
    }

    /// Every item, in insertion order.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.body.items
    }

    /// Metadata for every item. This is what may be printed, logged or handed to an agent.
    #[must_use]
    pub fn item_summaries(&self) -> Vec<ItemSummary> {
        self.body.items.iter().map(Item::summary).collect()
    }

    /// Resolve an item by id, by unique id prefix, or by exact title.
    ///
    /// **A human-facing convenience, for the command line.** A person typing
    /// `kagisecure item get GitHub` or an eight-character id prefix wants the one item they mean,
    /// and an "ambiguous" answer is a useful thing to tell them. None of that is right for a
    /// channel that releases a secret to a program — the browser extension, the app's presence-
    /// gated releases, an agent: a title or a prefix there turns the lookup into an oracle (an
    /// ambiguous answer says a second item, perhaps a trashed one, shares that title), lets
    /// whoever controls a title block a release by colliding with it, and leaves the audit entry
    /// naming whatever string was sent rather than the item. Those channels use
    /// [`Vault::item_by_id`], which accepts nothing but an exact [`ItemId`].
    ///
    /// # Errors
    ///
    /// [`Error::ItemNotFound`] or [`Error::AmbiguousItem`].
    pub fn find_item(&self, reference: &str) -> Result<&Item> {
        let idx = self.resolve(reference)?;
        Ok(&self.body.items[idx])
    }

    /// The item with exactly this id, if there is one — trashed and archived items included; the
    /// caller decides what those mean for it.
    ///
    /// No title, no prefix, no ambiguity: the lookup every secret-release channel uses (see
    /// [`Vault::find_item`] for why they must not use that one). A caller holding a string
    /// parses it with [`Vault::item_by_id_str`].
    #[must_use]
    pub fn item_by_id(&self, id: &ItemId) -> Option<&Item> {
        self.body.items.iter().find(|item| item.id == *id)
    }

    /// [`Vault::item_by_id`] for a reference that arrived as a string: only the canonical,
    /// lower-case hyphenated form of an item id ([`ItemId`]'s `Display`) is accepted, so the
    /// string a caller sent and the id an audit entry records are always the same text. Anything
    /// else — a title, a prefix, an id in another spelling — is answered exactly like an id that
    /// names no item: `None`.
    #[must_use]
    pub fn item_by_id_str(&self, reference: &str) -> Option<&Item> {
        self.item_by_id(&ItemId::parse_canonical(reference)?)
    }

    fn resolve(&self, reference: &str) -> Result<usize> {
        let mut hits: Vec<usize> = Vec::new();
        for (i, item) in self.body.items.iter().enumerate() {
            let id = item.id.to_string();
            let matches = id == reference
                || item.title == reference
                || (reference.len() >= 4 && id.starts_with(reference));
            if matches {
                hits.push(i);
            }
        }
        match hits.len() {
            0 => Err(Error::ItemNotFound(reference.to_owned())),
            1 => Ok(hits[0]),
            _ => Err(Error::AmbiguousItem(reference.to_owned())),
        }
    }

    /// Derive and wrap a new master-password slot, ready for [`Tx::install_master_password`].
    ///
    /// This is the Argon2id half of a password change, split out so it runs *before* a
    /// transaction takes the lock (see the module documentation). It uses the KDF cost of the
    /// header this session holds now, and remembers that header's KDF descriptor and password
    /// slot: installing it over anything else is refused, so a concurrent password change or KDF
    /// upgrade by another process is reported rather than silently undone. Nothing changes until
    /// it is installed.
    ///
    /// # Errors
    ///
    /// Any RNG or KDF failure.
    pub fn prepare_master_password(&self, new_password: &[u8]) -> Result<PreparedPasswordSlot> {
        let derived = self.plan_master_password()?.derive(new_password)?;
        self.wrap_master_password(derived)
    }

    /// The first of three steps of a password change for a caller that shares this vault behind
    /// a mutex and must not hold it across Argon2id: copy out the public header material a new
    /// master-password slot is derived against.
    ///
    /// [`Vault::prepare_master_password`] is the same three steps in one call, for a caller that
    /// owns the vault outright (the CLI). A caller that shares it — the app's session, whose one
    /// mutex the agent and the extension also take — runs them apart:
    ///
    /// 1. `plan_master_password` under the mutex, briefly: public facts only, no key;
    /// 2. [`MasterPasswordPlan::derive`] with **no lock at all** — the deliberately slow Argon2id;
    /// 3. [`Vault::wrap_master_password`] under the mutex again, briefly: one AEAD wrap of the
    ///    vault key, no KDF;
    ///
    /// then [`Tx::install_master_password`] in a transaction, as before. The plan remembers the
    /// KDF descriptor and password slot it was taken against, so a change another process made in
    /// between is refused at install rather than silently undone.
    ///
    /// # Errors
    ///
    /// Any RNG failure (rerolling the salt).
    pub fn plan_master_password(&self) -> Result<MasterPasswordPlan> {
        let mut kdf = self.header.kdf.clone();
        kdf.reroll_salt()?;
        Ok(MasterPasswordPlan {
            vault_id: self.header.vault_id.clone(),
            kdf,
            basis_kdf: self.header.kdf.clone(),
            basis_slot: SlotIdentity::of(self.header.slot(wrap::KIND_PASSWORD)),
        })
    }

    /// The third step ([`Vault::plan_master_password`]): wrap this session's vault key under the
    /// key-encryption key `derived` holds, ready for [`Tx::install_master_password`]. An AEAD
    /// wrap and nothing slower — the Argon2id work was done by [`MasterPasswordPlan::derive`].
    ///
    /// # Errors
    ///
    /// [`Error::VaultConflict`] if the plan was taken from another vault; any RNG failure.
    pub fn wrap_master_password(
        &self,
        derived: DerivedMasterPassword,
    ) -> Result<PreparedPasswordSlot> {
        let DerivedMasterPassword { plan, kek } = derived;
        if plan.vault_id != self.header.vault_id {
            return Err(Error::VaultConflict(self.path.clone()));
        }
        let vk: &[u8; KEY_LEN] = &self.vault_key;
        let slot = WrappedKey::wrap(
            &plan.vault_id,
            wrap::KIND_PASSWORD,
            SLOT_ID_MASTER,
            "Master password",
            &kek,
            vk,
            None,
        )?;
        drop(kek);
        Ok(PreparedPasswordSlot {
            vault_id: plan.vault_id,
            kdf: plan.kdf,
            slot,
            change: PasswordChange::NewPassword,
            basis_kdf: plan.basis_kdf,
            basis_slot: plan.basis_slot,
        })
    }

    /// Verify `current_password` and wrap the vault key under it again at `new_params`, ready for
    /// [`Tx::install_master_password`].
    ///
    /// The password is checked against the slot this session holds now, before the lock is ever
    /// taken; installing then refuses if the file's slot is no longer that one — so the check
    /// always concerns the slot being replaced, which is what "checks the password against the
    /// fresh slot" has to mean when Argon2id may not run under the lock.
    ///
    /// # Errors
    ///
    /// [`Error::Decrypt`] if `current_password` is wrong, [`Error::NoSuchSlot`] without a
    /// password slot, plus any RNG or KDF failure.
    pub fn prepare_kdf_upgrade(
        &self,
        current_password: &[u8],
        new_params: &KdfParams,
    ) -> Result<PreparedPasswordSlot> {
        new_params.validate()?;
        let slot = self
            .header
            .slot(wrap::KIND_PASSWORD)
            .ok_or(Error::NoSuchSlot(wrap::KIND_PASSWORD))?;
        let kek = slot
            .effective_kdf(&self.header.kdf)
            .derive(current_password)?;
        // Proves the password before anything is replaced.
        let _ = slot.unwrap_with_kek(&self.header.vault_id, &kek)?;
        drop(kek);

        let mut kdf = new_params.clone();
        kdf.reroll_salt()?;
        self.wrap_password_slot(current_password, kdf, PasswordChange::KdfUpgrade)
    }

    /// What checking a master password needs, copied out of the header this session holds: the
    /// password slot, its KDF descriptor and the vault id its AAD binds to. Public material
    /// only — no key — so the caller can drop every lock before [`PasswordCheck::open`] runs
    /// Argon2id (ADR-0038 user decision 7: the app's fallback when `LocalAuthentication` cannot
    /// run).
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchSlot`] if the vault has no master-password slot.
    pub fn password_check(&self) -> Result<PasswordCheck> {
        let slot = self
            .header
            .slot(wrap::KIND_PASSWORD)
            .ok_or(Error::NoSuchSlot(wrap::KIND_PASSWORD))?;
        Ok(PasswordCheck {
            vault_id: self.header.vault_id.clone(),
            kdf: slot.effective_kdf(&self.header.kdf).clone(),
            slot: slot.clone(),
        })
    }

    /// Whether `candidate` is this session's vault key, compared in constant time.
    ///
    /// The second half of a master-password check: [`PasswordCheck::open`] proves the password
    /// opens the slot, and this proves the slot opened *this* key, without the comparison's
    /// timing saying how many leading bytes matched.
    #[must_use]
    pub fn holds_vault_key(&self, candidate: &[u8; KEY_LEN]) -> bool {
        crypto::keys_equal(&self.vault_key, candidate)
    }

    fn wrap_password_slot(
        &self,
        password: &[u8],
        kdf: KdfParams,
        change: PasswordChange,
    ) -> Result<PreparedPasswordSlot> {
        let kek = kdf.derive(password)?;
        let vk: &[u8; KEY_LEN] = &self.vault_key;
        let slot = WrappedKey::wrap(
            &self.header.vault_id,
            wrap::KIND_PASSWORD,
            SLOT_ID_MASTER,
            "Master password",
            &kek,
            vk,
            None,
        )?;
        drop(kek);
        Ok(PreparedPasswordSlot {
            vault_id: self.header.vault_id.clone(),
            kdf,
            slot,
            change,
            basis_kdf: self.header.kdf.clone(),
            basis_slot: SlotIdentity::of(self.header.slot(wrap::KIND_PASSWORD)),
        })
    }

    /// Install a prepared password slot and its KDF descriptor.
    ///
    /// **The new slot replaces the old one wholesale, `unknown` keys included — on purpose.** A
    /// fresh wrap is this build's own ciphertext under this build's own semantics; a key a newer
    /// build attached to the *old* slot described that wrap (a device binding, say) and would be
    /// wrong on the new one, and a KDF parameter this build did not apply must not be claimed
    /// ([`KdfParams::reroll_salt`] drops those). A newer build that needs a slot key honoured by
    /// every writer bumps `header.v`, and then this write never happens: [`Error::VaultSchemaTooNew`]
    /// refuses the transaction before anything is sealed (vault-format §9 rule 2).
    fn apply_password_slot(&mut self, prepared: PreparedPasswordSlot) {
        self.header.kdf = prepared.kdf;
        match self.header.slot_mut(wrap::KIND_PASSWORD) {
            Some(existing) => *existing = prepared.slot,
            None => self.header.wrapped_keys.insert(0, prepared.slot),
        }
        if prepared.change == PasswordChange::NewPassword {
            self.unlocked_by = UnlockedBy::Password;
        }
    }

    /// Every environment, in insertion order.
    #[must_use]
    pub fn environments(&self) -> &[Environment] {
        &self.body.envs
    }

    /// Metadata for every environment. This is what may be handed to an agent.
    #[must_use]
    pub fn environment_summaries(&self) -> Vec<EnvironmentSummary> {
        self.body.envs.iter().map(Environment::summary).collect()
    }

    /// Resolve an environment by id, by unique id prefix, or by exact name.
    ///
    /// # Errors
    ///
    /// [`Error::EnvNotFound`] or [`Error::AmbiguousEnv`].
    pub fn find_environment(&self, reference: &str) -> Result<&Environment> {
        let index = self.resolve_env(reference)?;
        Ok(&self.body.envs[index])
    }

    fn resolve_env(&self, reference: &str) -> Result<usize> {
        let mut hits: Vec<usize> = Vec::new();
        for (i, env) in self.body.envs.iter().enumerate() {
            let id = env.id.to_string();
            if id == reference
                || env.name == reference
                || (reference.len() >= 4 && id.starts_with(reference))
            {
                hits.push(i);
            }
        }
        match hits.len() {
            1 => Ok(hits[0]),
            0 => Err(Error::EnvNotFound(reference.to_owned())),
            _ => Err(Error::AmbiguousEnv(reference.to_owned())),
        }
    }

    /// Materialize an environment's variables as injections.
    ///
    /// This is the one place environment values become plaintext, and it is only reachable from
    /// code that enabled `secret-material` (ADR-0002, ADR-0005). `wanted`, when given, selects a
    /// subset by name and preserves the caller's order; `None` takes every variable in the
    /// environment's own order.
    ///
    /// # Errors
    ///
    /// [`Error::EnvNotFound`] / [`Error::AmbiguousEnv`] for the environment reference,
    /// [`Error::VarNotPopulated`] for a variable the user has not filled in yet,
    /// [`Error::ItemNotFound`] / [`Error::FieldNotFound`] for a binding whose target has gone,
    /// [`Error::InvalidVarName`] for a stored name that is not an identifier — possible in a vault
    /// an older build or another tool wrote, and refused here, before any value is read, because
    /// the name would otherwise be rendered verbatim into a `.env` line or an environment block.
    pub fn resolve_environment(
        &self,
        reference: &str,
        wanted: Option<&[String]>,
    ) -> Result<Vec<crate::inject::EnvInjection>> {
        let env = self.find_environment(reference)?;
        crate::model::env::resolve_injections(
            env,
            wanted,
            |id| self.item_by_id(id),
            self.is_machine(),
        )
    }

    /// The audit log, oldest first.
    #[must_use]
    pub fn audit_entries(&self) -> &[AuditEntry] {
        &self.body.audit
    }

    /// The current chain head.
    #[must_use]
    pub fn audit_head(&self) -> &[u8] {
        &self.body.audit_head
    }

    /// Verify the audit hash chain.
    ///
    /// # Errors
    ///
    /// [`Error::AuditChain`] describing the first inconsistency.
    pub fn verify_audit(&self) -> Result<()> {
        audit::verify(&self.body.audit, &self.body.audit_head)?;
        Ok(())
    }

    /// Hand the raw vault key to a platform keystore for wrapping (ADR-0008).
    ///
    /// This is the **only** function in the crate that lets the vault key leave it, and it exists
    /// for exactly one caller: the enrolment half of the Touch ID flow, where the app must give
    /// the 32 bytes to the Secure Enclave to encrypt because nothing else can produce that
    /// ciphertext. The returned buffer zeroizes on drop; what the caller does with the copy the
    /// keystore takes is between the caller and the keystore.
    ///
    /// It is deliberately long-named and deliberately not called `vault_key()`. Every call site
    /// is expected to be justified in review, the same way [`crate::model::Secret::expose`] is
    /// (ADR-0005).
    #[must_use]
    pub fn export_vault_key_for_platform_wrapping(&self) -> Zeroizing<Vec<u8>> {
        let vk: &[u8; KEY_LEN] = &self.vault_key;
        Zeroizing::new(vk.to_vec())
    }

    /// The platform slot, if this vault has one.
    #[must_use]
    pub fn platform_slot(&self) -> Option<&WrappedKey> {
        self.header.slot(wrap::KIND_PLATFORM)
    }

    /// Generate a new recovery code and wrap the vault key under it, ready for
    /// [`Tx::install_recovery_code`] — the Argon2id half, run before any lock is taken.
    ///
    /// The prepared slot remembers which recovery slot it replaces. If another process reissues
    /// the code first, installing is refused: otherwise the code this caller is about to show
    /// would silently displace one another user was already shown and may have written down.
    /// Show the code only after the transaction that installs it has committed.
    ///
    /// # Errors
    ///
    /// Any RNG or KDF failure.
    pub fn prepare_recovery_code(&self) -> Result<(RecoveryCode, PreparedRecoverySlot)> {
        let code = RecoveryCode::generate()?;
        let vk: &[u8; KEY_LEN] = &self.vault_key;
        let slot = wrap_recovery_slot(&self.header.vault_id, &code, &self.header.kdf, vk)?;
        let prepared = PreparedRecoverySlot {
            vault_id: self.header.vault_id.clone(),
            slot,
            basis_slot: SlotIdentity::of(self.header.slot(wrap::KIND_RECOVERY)),
        };
        Ok((code, prepared))
    }

    /// Install a prepared recovery slot.
    ///
    /// **The new slot replaces the old one wholesale, `unknown` keys included — on purpose.** A
    /// fresh wrap is this build's own ciphertext under this build's own semantics; a key a newer
    /// build attached to the *old* slot described that wrap (a device binding, say) and would be
    /// wrong on the new one, and a KDF parameter this build did not apply must not be claimed
    /// ([`KdfParams::reroll_salt`] drops those). A newer build that needs a slot key honoured by
    /// every writer bumps `header.v`, and then this write never happens: [`Error::VaultSchemaTooNew`]
    /// refuses the transaction before anything is sealed (vault-format §9 rule 2).
    fn apply_recovery_slot(&mut self, prepared: PreparedRecoverySlot) {
        match self.header.slot_mut(wrap::KIND_RECOVERY) {
            Some(existing) => *existing = prepared.slot,
            None => self.header.wrapped_keys.push(prepared.slot),
        }
    }
}

/// A transaction in progress: the vault as the file held it when [`Vault::transact`] took the
/// lock, plus pending audit drafts chained onto it.
///
/// Every mutator — item and environment CRUD, the agent-visibility switch, a logical vault, the
/// audit chain, the platform slot, and installing a header change whose Argon2id work was done
/// beforehand — is an inherent method on `Tx`, usable only while the lock this value represents is
/// held. `Tx` dereferences to [`Vault`] for reads only (`Deref`, not `DerefMut`): every accessor
/// (`items`, `find_item`, `header`, …) is available through it, but there is no way to reach a
/// `&mut Vault` method through `Tx` at all, so calling one from inside the closure is a compile
/// error rather than a runtime [`Error::NestedTransaction`]:
///
/// ```compile_fail
/// use kagisecure_core::vault::{CreateOptions, Vault};
///
/// let dir = tempfile::tempdir().unwrap();
/// let path = dir.path().join("v.kagivault");
/// let options = CreateOptions::new().unwrap();
/// let (mut vault, _code) = Vault::create(&path, b"correct horse", &options).unwrap();
///
/// vault.transact(|tx| {
///     // `Tx` has no `DerefMut`, so `&mut Vault`-only methods are simply not there to call —
///     // this is `error[E0599]: no method named `transact` found for mutable reference
///     // `&mut vault::Tx<'_>``, not the `NestedTransaction` this used to be at runtime.
///     tx.transact(|_| Ok(()))
/// }).unwrap();
/// ```
///
/// `Tx` is committed by `transact` when the closure returns `Ok`, and rolled back — to the file as
/// it was read when the transaction began, and to the session's `unlocked_by` — when the closure
/// returns `Err`, when the write fails, or when the closure panics.
pub struct Tx<'v> {
    vault: &'v mut Vault,
    lock: &'v FileLock,
    /// The file as read under the lock when the transaction began — ciphertext only. Rolling
    /// back decrypts this again rather than re-reading the path, so a rollback needs no disk and
    /// cannot fail because the volume went away mid-transaction, and no second plaintext copy of
    /// the body is kept just in case (threat-model M-10).
    base: Snapshot,
    /// Session state that is not in the file but that the closure can change
    /// ([`Tx::install_master_password`]), restored by a rollback.
    base_unlocked_by: UnlockedBy,
    /// Drafts that must survive this transaction failing: those pending when it began, and (at
    /// commit) those queued while it ran.
    carried: Vec<PendingDraft>,
    /// Committed or rolled back; `Drop` rolls back an unsettled transaction.
    settled: bool,
}

impl<'v> Tx<'v> {
    fn begin(
        vault: &'v mut Vault,
        lock: &'v FileLock,
        base: Snapshot,
        carried: Vec<PendingDraft>,
    ) -> Self {
        vault.in_transaction = true;
        let base_unlocked_by = vault.unlocked_by;
        Self {
            vault,
            lock,
            base,
            base_unlocked_by,
            carried,
            settled: false,
        }
    }

    /// Install a master-password slot from [`Vault::prepare_master_password`] or
    /// [`Vault::prepare_kdf_upgrade`].
    ///
    /// # Errors
    ///
    /// [`Error::VaultConflict`] if this transaction's header — which is the file's — no longer
    /// has the KDF descriptor and password slot the slot was prepared against: another process
    /// changed the password or the KDF cost first. Prepare again from a refreshed vault.
    pub fn install_master_password(&mut self, prepared: PreparedPasswordSlot) -> Result<()> {
        let header = &self.vault.header;
        if prepared.vault_id != header.vault_id
            || prepared.basis_kdf != header.kdf
            || prepared.basis_slot != SlotIdentity::of(header.slot(wrap::KIND_PASSWORD))
        {
            return Err(Error::VaultConflict(self.vault.path.clone()));
        }
        self.vault.apply_password_slot(prepared);
        Ok(())
    }

    /// Install a recovery slot from [`Vault::prepare_recovery_code`].
    ///
    /// # Errors
    ///
    /// [`Error::VaultConflict`] if the file's recovery slot is no longer the one the code was
    /// prepared to replace: another process issued a code first.
    pub fn install_recovery_code(&mut self, prepared: PreparedRecoverySlot) -> Result<()> {
        let header = &self.vault.header;
        if prepared.vault_id != header.vault_id
            || prepared.basis_slot != SlotIdentity::of(header.slot(wrap::KIND_RECOVERY))
        {
            return Err(Error::VaultConflict(self.vault.path.clone()));
        }
        self.vault.apply_recovery_slot(prepared);
        Ok(())
    }

    /// Record an audit draft to be written by the next successful transaction
    /// ([`Vault::queue_audit`]), usable from inside a running one too: a draft queued here is
    /// chained at commit, after the closure's own entries, and stays queued if the transaction
    /// fails.
    pub fn queue_audit(&mut self, draft: AuditDraft) {
        self.vault.queue_audit(draft);
    }

    /// Set a logical vault's agent visibility, reporting whether the vault was found.
    ///
    /// Default-deny is the product's position (threat-model M-9); this is how a user opts in.
    pub fn set_vault_agent_visible(&mut self, id: VaultId, visible: bool) -> bool {
        match self.vault.body.vaults.iter_mut().find(|v| v.id == id) {
            Some(v) => {
                v.agent_visible = visible;
                true
            }
            None => false,
        }
    }

    /// Set a logical vault's "Show new items to agents" setting
    /// ([`VaultMeta::new_items_agent_visible`]), reporting whether the vault was found. Existing
    /// items are not touched; [`Tx::set_agent_visible_bulk`] is how those change.
    pub fn set_new_items_agent_visible(&mut self, id: VaultId, visible: bool) -> bool {
        match self.vault.body.vaults.iter_mut().find(|v| v.id == id) {
            Some(v) => {
                v.new_items_agent_visible = visible;
                true
            }
            None => false,
        }
    }

    /// Add a newly created item, applying its logical vault's "Show new items to agents" setting
    /// ([`Vault::new_items_agent_visible`]): with it on, the item and every field start visible.
    /// With it off the item is added exactly as given. Every place that creates an item for a
    /// person — the app, the CLI, an import — goes through this rather than [`Tx::add_item`].
    pub fn add_new_item(&mut self, mut item: Item) {
        if self.vault.new_items_agent_visible(item.vault_id) {
            item.set_agent_visible_all(true);
        }
        self.add_item(item);
    }

    /// Show every item `scope` matches to agents, with all its fields, or hide each one and all
    /// its fields, and append **one** audit entry for the whole change.
    ///
    /// The entry's `detail` is `scope=<kind> visible=<on|off> matched=<n> changed=<n>`: the kind
    /// of scope and counts only — never a tag, a title, a field name or a value. One transaction,
    /// so either every item changes or none does. The entry is recorded even when nothing
    /// changed, so the attempt itself is on record.
    pub fn set_agent_visible_bulk(
        &mut self,
        scope: &AgentVisibilityScope,
        visible: bool,
        actor: &str,
    ) -> BulkVisibility {
        let mut result = BulkVisibility {
            matched: 0,
            changed: 0,
        };
        for item in self
            .vault
            .body
            .items
            .iter_mut()
            .filter(|i| scope.matches(i))
        {
            result.matched += 1;
            if item.set_agent_visible_all(visible) {
                result.changed += 1;
            }
        }
        self.append_audit(AuditDraft {
            actor: actor.to_owned(),
            tool: TOOL_SET_AGENT_VISIBLE_BULK.to_owned(),
            outcome: crate::proto::Outcome::Allowed,
            detail: Some(format!(
                "scope={} visible={} matched={} changed={}",
                scope.kind(),
                if visible { "on" } else { "off" },
                result.matched,
                result.changed
            )),
            ..AuditDraft::default()
        });
        result
    }

    /// Add a logical vault, returning its id.
    ///
    /// [`VaultMeta::new`] has always existed with nothing to hand the result to; import needs to
    /// recreate a source's vault layout, so this is the missing half.
    ///
    /// The name is not checked for uniqueness: [`Vault::find_vault`] already reports a duplicate
    /// as [`Error::AmbiguousItem`] rather than silently picking one, and refusing the second
    /// "Personal" here would make a caller that imports two accounts fail instead of asking.
    pub fn add_logical_vault(&mut self, meta: VaultMeta) -> VaultId {
        let id = meta.id;
        self.vault.body.vaults.push(meta);
        id
    }

    /// Add an item.
    pub fn add_item(&mut self, item: Item) {
        self.vault.body.items.push(item);
    }

    /// Mutable version of [`Vault::find_item`].
    ///
    /// # Errors
    ///
    /// [`Error::ItemNotFound`] or [`Error::AmbiguousItem`].
    pub fn find_item_mut(&mut self, reference: &str) -> Result<&mut Item> {
        let idx = self.vault.resolve(reference)?;
        Ok(&mut self.vault.body.items[idx])
    }

    /// Mutable version of [`Vault::item_by_id`]: exactly this id, nothing else.
    pub fn item_by_id_mut(&mut self, id: &ItemId) -> Option<&mut Item> {
        self.vault.body.items.iter_mut().find(|item| item.id == *id)
    }

    /// Remove the item with exactly this id, returning it; `None` if there is none.
    pub fn remove_item_by_id(&mut self, id: &ItemId) -> Option<Item> {
        let idx = self
            .vault
            .body
            .items
            .iter()
            .position(|item| item.id == *id)?;
        Some(self.vault.body.items.remove(idx))
    }

    /// Remove an item, returning it.
    ///
    /// # Errors
    ///
    /// [`Error::ItemNotFound`] or [`Error::AmbiguousItem`].
    pub fn remove_item(&mut self, reference: &str) -> Result<Item> {
        let idx = self.vault.resolve(reference)?;
        Ok(self.vault.body.items.remove(idx))
    }

    /// Add an environment.
    pub fn add_environment(&mut self, env: Environment) {
        self.vault.body.envs.push(env);
    }

    /// Mutable version of [`Vault::find_environment`].
    ///
    /// # Errors
    ///
    /// [`Error::EnvNotFound`] or [`Error::AmbiguousEnv`].
    pub fn find_environment_mut(&mut self, reference: &str) -> Result<&mut Environment> {
        let index = self.vault.resolve_env(reference)?;
        Ok(&mut self.vault.body.envs[index])
    }

    /// Remove an environment, returning it.
    ///
    /// # Errors
    ///
    /// [`Error::EnvNotFound`] or [`Error::AmbiguousEnv`].
    pub fn remove_environment(&mut self, reference: &str) -> Result<Environment> {
        let index = self.vault.resolve_env(reference)?;
        Ok(self.vault.body.envs.remove(index))
    }

    /// Add a shared-vault device key (ADR-0035 §5), recording it in the audit log as
    /// [`AUDIT_TOOL_DEVICE_KEY_ADDED`] under `actor`, with the key's id — never anything of its
    /// secret keys — as the detail.
    ///
    /// The entry is also what makes the addition part of the file's history: a copy of the file
    /// from before it no longer continues this session's audit log, so a transaction refuses to
    /// build on such a copy ([`Error::VaultDiverged`]) instead of adopting it and losing the key.
    ///
    /// The first device key in a `format_ver` 1 file makes this transaction's write a format
    /// upgrade: the file is written as [`header::DEVICE_KEYS_FORMAT_VERSION`], and copied to
    /// `<file>.bak-1` first (see [`Vault::format_upgrade_backup`]).
    ///
    /// # Errors
    ///
    /// [`Error::DeviceKey`] if the vault already holds a device key with this id, or retired one
    /// (a removed key is never added back; a returning computer gets a new key).
    pub fn add_device_key(&mut self, key: DeviceKey, actor: &str) -> Result<()> {
        if self.vault.body.devices.iter().any(|d| d.id() == key.id()) {
            return Err(Error::DeviceKey(
                "a device key with this id is already in the vault",
            ));
        }
        if self.vault.body.retired_devices.contains(key.id()) {
            return Err(Error::DeviceKey(
                "a device key with this id was removed from the vault and cannot be added again",
            ));
        }
        let detail = device_key_detail(key.id());
        self.vault.body.devices.push(key);
        self.append_audit(device_key_audit(actor, AUDIT_TOOL_DEVICE_KEY_ADDED, detail));
        Ok(())
    }

    /// Remove the device key with this id, returning it; `None`, and no change, if there is
    /// none. The id is added to the vault's retired list ([`Vault::retired_device_keys`]), so the
    /// key can never be added back or restored from an older copy, and the removal is recorded in
    /// the audit log as [`AUDIT_TOOL_DEVICE_KEY_REMOVED`] under `actor`, with the key's id as the
    /// detail.
    ///
    /// The file keeps its `format_ver`: removing the last device key does not write it back as
    /// version 1.
    pub fn remove_device_key(
        &mut self,
        id: &[u8; DEVICE_KEY_ID_LEN],
        actor: &str,
    ) -> Option<DeviceKey> {
        let index = self.vault.body.devices.iter().position(|d| d.id() == id)?;
        let removed = self.vault.body.devices.remove(index);
        self.vault.body.retired_devices.push(*id);
        self.append_audit(device_key_audit(
            actor,
            AUDIT_TOOL_DEVICE_KEY_REMOVED,
            device_key_detail(id),
        ));
        Some(removed)
    }

    /// Store the key of this personal vault's machine vault (ADR-0042 §2), recording
    /// [`AUDIT_TOOL_MACHINE_VAULT_KEY_ADDED`] under `actor` with the machine vault's id as the
    /// detail — never anything of the key.
    ///
    /// A `format_ver` 1 or 2 file is raised to [`header::MACHINE_VAULT_FORMAT_VERSION`] by this
    /// transaction's write, after the usual backup.
    ///
    /// # Errors
    ///
    /// [`Error::MachineVault`] if this vault already holds a machine vault key, or is itself a
    /// machine vault.
    pub fn set_machine_vault_key(&mut self, key: MachineVaultKey, actor: &str) -> Result<()> {
        if self.vault.body.machine.is_some() {
            return Err(Error::MachineVault(
                "a machine vault holds no machine vault key",
            ));
        }
        if self.vault.body.machine_key.is_some() {
            return Err(Error::MachineVault(
                "this vault already holds a machine vault key",
            ));
        }
        let detail = machine_key_detail(&key);
        self.vault.body.machine_key = Some(key);
        self.append_audit(device_key_audit(
            actor,
            AUDIT_TOOL_MACHINE_VAULT_KEY_ADDED,
            detail,
        ));
        Ok(())
    }

    /// Remove the machine vault key, returning it; `None`, and no change, if there is none.
    /// Recorded as [`AUDIT_TOOL_MACHINE_VAULT_KEY_REMOVED`]. Without it — and without the
    /// Keychain copy an armed Mac holds — the machine vault file can no longer be opened.
    pub fn remove_machine_vault_key(&mut self, actor: &str) -> Option<MachineVaultKey> {
        let key = self.vault.body.machine_key.take()?;
        self.append_audit(device_key_audit(
            actor,
            AUDIT_TOOL_MACHINE_VAULT_KEY_REMOVED,
            machine_key_detail(&key),
        ));
        Some(key)
    }

    /// This machine vault's jobs, grants and armed state, to change. The structural rules are
    /// checked when the transaction is written, not here.
    ///
    /// # Errors
    ///
    /// [`Error::MachineVault`] if this is not a machine vault.
    pub fn machine_mut(&mut self) -> Result<&mut MachineSection> {
        self.vault
            .body
            .machine
            .as_mut()
            .ok_or(Error::MachineVault("this is not a machine vault"))
    }

    /// Append an entry to the audit log and advance the chain head (vault-format §8).
    ///
    /// Nothing here touches the disk: the entry is part of this transaction, written at commit
    /// and discarded if the transaction fails.
    pub fn append_audit(&mut self, draft: AuditDraft) {
        self.vault.chain(PendingDraft::now(draft));
    }

    /// Store a platform keystore's wrapped copy of the vault key, replacing any existing one.
    ///
    /// `wrapped` is opaque to this crate (see [`crate::crypto::wrap::ALG_PLATFORM_OPAQUE`]).
    ///
    /// v1 keeps at most one platform slot per vault file: the design is "single owner, single
    /// Mac" (ui-spec.md §14), and a second device enrolling would otherwise silently accumulate
    /// slots that nothing can ever prune.
    ///
    /// **The new slot replaces the old one wholesale, `unknown` keys included — on purpose.** A
    /// fresh wrap is this build's own ciphertext under this build's own semantics; a key a newer
    /// build attached to the *old* slot described that wrap (a device binding, say) and would be
    /// wrong on the new one, and a KDF parameter this build did not apply must not be claimed
    /// ([`KdfParams::reroll_salt`] drops those). A newer build that needs a slot key honoured by
    /// every writer bumps `header.v`, and then this write never happens: [`Error::VaultSchemaTooNew`]
    /// refuses the transaction before anything is sealed (vault-format §9 rule 2).
    pub fn install_platform_slot(&mut self, slot_id: &str, label: &str, wrapped: Vec<u8>) {
        let slot = wrap::platform_slot(slot_id, label, wrapped);
        match self.vault.header.slot_mut(wrap::KIND_PLATFORM) {
            Some(existing) => *existing = slot,
            None => self.vault.header.wrapped_keys.push(slot),
        }
    }

    /// Drop the platform slot, reporting whether there was one.
    ///
    /// Used when the user turns Touch ID off, and when the app finds the Enclave key gone —
    /// `.biometryCurrentSet` invalidates it the moment the fingerprint set changes (ADR-0004), and
    /// a slot whose key no longer exists is dead weight that would make the lock screen offer an
    /// unlock it cannot perform.
    pub fn remove_platform_slot(&mut self) -> bool {
        let before = self.vault.header.wrapped_keys.len();
        self.vault
            .header
            .wrapped_keys
            .retain(|s| s.kind != wrap::KIND_PLATFORM);
        before != self.vault.header.wrapped_keys.len()
    }

    /// Chain whatever was queued during the closure, seal, write. On failure, roll back.
    fn commit(mut self) -> Result<()> {
        let queued = std::mem::take(&mut self.vault.pending_audit);
        for pending in &queued {
            self.vault.chain(pending.clone());
        }
        self.carried.extend(queued);

        let bytes = match self.vault.seal() {
            Ok(bytes) => bytes,
            Err(e) => return self.fail(e, None),
        };
        // `base` is the file as it is on disk now: read under the lock this transaction holds.
        match self.vault.back_up_before_upgrade(&self.base.bytes) {
            Ok(None) => {}
            Ok(Some(backup)) => self.vault.upgrade_backup = Some(backup),
            Err(e) => return self.fail(e, None),
        }
        let generation = generation_of(&bytes);
        match self
            .vault
            .write_sealed_locked(self.lock, &bytes, generation)
        {
            Ok(()) => {
                self.settled = true;
                self.vault.note_write_outcome(None);
                Ok(())
            }
            Err(e) => self.fail(e, Some(generation)),
        }
    }

    fn fail(mut self, error: Error, attempted: Option<Generation>) -> Result<()> {
        // A write can report failure after its rename took effect (a network file system losing
        // the reply). If the file is byte-for-byte what was attempted, the commit happened:
        // rolling back now would re-queue drafts that are already in the file and so write them
        // twice.
        if let Some(generation) = attempted
            && let Some(fingerprint) = self.vault.confirm_landed(generation)
        {
            self.vault.record_written(generation, fingerprint);
            self.settled = true;
            self.vault.note_write_outcome(None);
            return Ok(());
        }
        self.vault.note_write_outcome(Some(&error));
        let attempt = attempted.map(|_| {
            (
                self.vault.body.audit.len(),
                self.vault.body.audit_head.clone(),
            )
        });
        self.roll_back();
        if let Some((audit_len, audit_head)) = attempt {
            // Could not confirm either way: remember what was attempted, so the next read of the
            // file can tell whether the drafts just re-queued are in fact already there.
            let drafts = self.vault.pending_audit.len();
            disk_mut(&mut self.vault.disk).unconfirmed = Some(UnconfirmedWrite {
                audit_len,
                audit_head,
                drafts,
            });
        }
        Err(error)
    }

    /// Put the session back exactly as it was when the transaction began — the file's contents
    /// from [`Tx::base`], `unlocked_by` — and the carried drafts back into the pending queue.
    fn roll_back(&mut self) {
        self.settled = true;
        let vault = &mut *self.vault;
        let queued_during = std::mem::take(&mut vault.pending_audit);
        vault.unlocked_by = self.base_unlocked_by;

        match vault.decode_with_session_key(&self.base.bytes) {
            Ok(Decoded {
                format_ver,
                header,
                body,
            }) => {
                vault.header = header;
                vault.body = body;
                *disk_mut(&mut vault.disk) = DiskState::observed(
                    self.base.generation,
                    self.base.fingerprint,
                    &vault.body,
                    format_ver,
                );
            }
            Err(_) => {
                // Unreachable in practice: these are bytes this session either decoded moments
                // ago or wrote itself (their hash is the generation it recorded). Should decoding
                // them fail anyway, the closure's changes must still not stay readable as though
                // they had happened: drop the body entirely, keep the file's header if it parses,
                // and mark memory as descending from no version, so `save` refuses and the next
                // transaction or refresh replaces it from the file. What is known to be on disk
                // (`audit_len`, `audit_head`) is kept for that continuity check.
                if let Ok(parts) = header::split(&self.base.bytes) {
                    vault.header = parts.header;
                }
                vault.body = Body::emptied();
                let disk = disk_mut(&mut vault.disk);
                disk.generation = None;
                disk.fingerprint = None;
                disk.unconfirmed = None;
            }
        }

        let mut pending = std::mem::take(&mut self.carried);
        pending.extend(queued_during);
        vault.pending_audit = pending;
    }
}

impl Deref for Tx<'_> {
    type Target = Vault;

    fn deref(&self) -> &Vault {
        self.vault
    }
}

// Deliberately no `DerefMut`: every mutator on `Vault` is either an inherent method on `Tx`
// (above) or, for the non-transactional path (`Vault::save`, and the removed `Vault::append_audit`
// / `change_master_password` / `upgrade_kdf` / `reissue_recovery_code` / `install_platform_slot` /
// `remove_platform_slot` / item and environment mutators), not reachable from `Tx` at all. This is
// the structural half of "Argon2id never runs under the lock" (module docs, §6 of ADR-0039): the
// old `&mut self` methods that both derived a KEK *and* applied the resulting slot in one call
// were reachable through `Tx`'s `DerefMut` before this type stopped having one, which meant a
// closure could run an Argon2id derivation while the lock was held. `Vault::prepare_master_password`
// and its siblings still take `&self` and so are still visible through the `Deref` above, but they
// do no mutation — only `Tx::install_master_password` / `Tx::install_recovery_code` apply a
// prepared slot, and they do no cryptographic work of their own beyond a comparison. See the
// `compile_fail` doctest on `Tx`'s own documentation, below, for a demonstration.
impl Drop for Tx<'_> {
    fn drop(&mut self) {
        if !self.settled {
            // Only reachable by unwinding out of the closure: `transact` settles every other way
            // out. The rollback restores from `base` and needs neither the lock nor the disk.
            self.roll_back();
        }
        self.vault.in_transaction = false;
    }
}

impl std::fmt::Debug for Tx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tx")
            .field("vault", &self.vault)
            .finish_non_exhaustive()
    }
}

/// Which password operation a [`PreparedPasswordSlot`] came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PasswordChange {
    /// A new master password: installing it also makes the session count as password-unlocked,
    /// as a recovery-code unlock followed by setting a new password should.
    NewPassword,
    /// The same password at a new KDF cost.
    KdfUpgrade,
}

/// Enough of a wrapped-key slot to tell whether it is still the same wrap: its random nonce and
/// its ciphertext. Two independent wraps never share a nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SlotIdentity {
    nonce: Vec<u8>,
    ct: Vec<u8>,
}

impl SlotIdentity {
    fn of(slot: Option<&WrappedKey>) -> Option<Self> {
        slot.map(|s| Self {
            nonce: s.nonce.clone(),
            ct: s.ct.clone(),
        })
    }
}

/// The public header material a master-password check needs ([`Vault::password_check`]).
///
/// Holds no key and no password: the slot's ciphertext, its nonce, its KDF salt and cost, and the
/// vault id — all of it already in the file's plaintext header. `Debug` shows none of it anyway.
pub struct PasswordCheck {
    vault_id: Vec<u8>,
    kdf: KdfParams,
    slot: WrappedKey,
}

impl PasswordCheck {
    /// Derive the slot's key-encryption key from `password` (Argon2id, deliberately slow) and
    /// unwrap the vault key with it. Needs no vault and no lock.
    ///
    /// # Errors
    ///
    /// [`Error::Decrypt`] if `password` is wrong — the AEAD tag is what proves it, so a wrong
    /// password is indistinguishable from a tampered slot, as at unlock; KDF failures.
    pub fn open(&self, password: &[u8]) -> Result<Key> {
        let kek = self.kdf.derive(password)?;
        self.slot.unwrap_with_kek(&self.vault_id, &kek)
    }
}

impl std::fmt::Debug for PasswordCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordCheck").finish_non_exhaustive()
    }
}

/// The public header material a new master-password slot is derived against
/// ([`Vault::plan_master_password`]): the vault id, the KDF descriptor with a fresh salt, and the
/// KDF descriptor and password slot it will replace. Holds no key and no password.
pub struct MasterPasswordPlan {
    vault_id: Vec<u8>,
    /// The descriptor the new slot is derived with: the header's cost, a fresh salt.
    kdf: KdfParams,
    /// The header KDF descriptor this was planned against.
    basis_kdf: KdfParams,
    /// The password slot this replaces, as it was when planned.
    basis_slot: Option<SlotIdentity>,
}

impl MasterPasswordPlan {
    /// Derive the new slot's key-encryption key from `new_password` — Argon2id, deliberately
    /// slow. Needs no vault and no lock, which is the point: run it with none held.
    ///
    /// # Errors
    ///
    /// Any KDF failure.
    pub fn derive(self, new_password: &[u8]) -> Result<DerivedMasterPassword> {
        let kek = self.kdf.derive(new_password)?;
        Ok(DerivedMasterPassword { plan: self, kek })
    }
}

impl std::fmt::Debug for MasterPasswordPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterPasswordPlan").finish_non_exhaustive()
    }
}

/// A [`MasterPasswordPlan`] whose Argon2id derivation is done: the key-encryption key, zeroized
/// on drop, waiting for [`Vault::wrap_master_password`]. `Debug` shows none of it.
pub struct DerivedMasterPassword {
    plan: MasterPasswordPlan,
    kek: Key,
}

impl std::fmt::Debug for DerivedMasterPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedMasterPassword")
            .finish_non_exhaustive()
    }
}

/// A master-password slot whose Argon2id derivation is already done, waiting to be installed by
/// [`Tx::install_master_password`]. Holds a wrapped (never a plain) copy of the vault key.
pub struct PreparedPasswordSlot {
    vault_id: Vec<u8>,
    kdf: KdfParams,
    slot: WrappedKey,
    change: PasswordChange,
    /// The header KDF descriptor this was derived against.
    basis_kdf: KdfParams,
    /// The password slot this replaces, as it was when prepared.
    basis_slot: Option<SlotIdentity>,
}

impl std::fmt::Debug for PreparedPasswordSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedPasswordSlot")
            .field("change", &self.change)
            .finish_non_exhaustive()
    }
}

/// A recovery slot whose Argon2id derivation is already done, waiting to be installed by
/// [`Tx::install_recovery_code`]. The code itself is returned beside it, never stored in it.
pub struct PreparedRecoverySlot {
    vault_id: Vec<u8>,
    slot: WrappedKey,
    /// The recovery slot this replaces, as it was when prepared.
    basis_slot: Option<SlotIdentity>,
}

impl std::fmt::Debug for PreparedRecoverySlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRecoverySlot")
            .finish_non_exhaustive()
    }
}

fn decrypt_body(
    vault_key: &[u8; KEY_LEN],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Body> {
    let body_key = crypto::body_key(vault_key);
    let plaintext = aead::open(&body_key, nonce, aad, ciphertext)?;
    let mut body: Body = ciborium::from_reader(plaintext.as_slice())
        .map_err(|e| Error::BodyDecode(e.to_string()))?;
    for item in &mut body.items {
        fold_legacy_website_field_into_urls(item);
    }
    Ok(body)
}

/// Fold a legacy `website` field into [`Item::urls`] (ADR-0029).
///
/// Before ADR-0029 the `Login` template put a `website` field (`FieldKind::Url`) beside
/// `Item::urls`, so an item written by an older build may carry the same website in two places —
/// and the browser-extension allow-list (`saved_websites` in `kagisecure-agent`) had to read
/// both. This is not a `body.schema` migration in the vault-format.md §9 rule 3 sense: the schema
/// is unchanged, so it runs unconditionally every time a body is decoded, the same as any other
/// in-memory normalization, rather than needing the explicit-upgrade-and-backup flow that rule 3
/// reserves for actual schema changes. Nothing is destroyed (rule 1): the value moves from the
/// field into `urls` rather than being dropped, and nothing touches disk until the caller saves.
fn fold_legacy_website_field_into_urls(item: &mut Item) {
    let mut moved = Vec::new();
    item.fields.retain(|f| {
        if f.kind == FieldKind::Url && f.label.eq_ignore_ascii_case("website") {
            if let Some(value) = f.value.as_public()
                && !value.is_empty()
            {
                moved.push(value.to_owned());
            }
            false
        } else {
            true
        }
    });
    for url in moved {
        if !item.urls.contains(&url) {
            item.urls.push(url);
        }
    }
}

fn wrap_recovery_slot(
    vault_id: &[u8],
    code: &RecoveryCode,
    template: &KdfParams,
    vault_key: &[u8; KEY_LEN],
) -> Result<WrappedKey> {
    // Same algorithm and cost as the password path, its own salt (see `WrappedKey::kdf`).
    let mut kdf = template.clone();
    kdf.reroll_salt()?;
    let kek = kdf.derive(code.material())?;
    let slot = WrappedKey::wrap(
        vault_id,
        wrap::KIND_RECOVERY,
        SLOT_ID_RECOVERY,
        "One-time recovery code",
        &kek,
        vault_key,
        Some(kdf),
    )?;
    drop(kek);
    Ok(slot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Category;
    use crate::proto::Outcome;

    const PASSWORD: &[u8] = b"unit test password";

    fn cheap() -> CreateOptions {
        CreateOptions {
            kdf: KdfParams::new(64, 1, 1).unwrap(),
            vault_name: "Unit".to_owned(),
            kdf_hint: None,
        }
    }

    fn draft(tool: &str) -> AuditDraft {
        AuditDraft {
            actor: "unit".to_owned(),
            tool: tool.to_owned(),
            outcome: Outcome::Allowed,
            ..AuditDraft::default()
        }
    }

    fn tools(vault: &Vault) -> Vec<String> {
        vault
            .audit_entries()
            .iter()
            .map(|e| e.tool.clone())
            .collect()
    }

    fn add_item(tx: &mut Tx<'_>, title: &str) {
        let vault_id = tx.default_vault_id().unwrap();
        tx.add_item(Item::new(vault_id, Category::Login, title));
    }

    fn inject(fault: InjectedFault) {
        INJECTED_FAULT.with(|f| f.set(fault));
    }

    // -- the continuity check -----------------------------------------------------------------

    fn chain(tools: &[&str]) -> (Vec<AuditEntry>, Vec<u8>) {
        let mut entries = Vec::new();
        let mut head = audit::genesis();
        for tool in tools {
            head = audit::append_at(&mut entries, &head, draft(tool), 1);
        }
        (entries, head)
    }

    #[test]
    fn a_log_that_extends_the_known_one_continues_it() {
        let (known, known_head) = chain(&["a", "b"]);
        let mut fresh = known.clone();
        let _fresh_head = audit::append_at(&mut fresh, &known_head, draft("c"), 2);
        assert!(continues(known.len(), &known_head, &known));
        assert!(continues(known.len(), &known_head, &fresh));
    }

    #[test]
    fn nothing_known_is_continued_by_anything() {
        let (fresh, _) = chain(&["a"]);
        assert!(continues(0, &audit::genesis(), &fresh));
        assert!(continues(0, &audit::genesis(), &[]));
    }

    #[test]
    fn a_shorter_log_does_not_continue_the_known_one() {
        let (known, known_head) = chain(&["a", "b", "c"]);
        assert!(!continues(known.len(), &known_head, &known[..2]));
        assert!(!continues(known.len(), &known_head, &[]));
    }

    #[test]
    fn a_log_of_the_same_length_with_a_different_history_does_not_continue_it() {
        let (known, known_head) = chain(&["a", "b"]);
        let (other, _) = chain(&["a", "x"]);
        assert!(!continues(known.len(), &known_head, &other));
        // Differing only in the first entry changes the last one's `prev`, so its digest too.
        let (rewritten_start, _) = chain(&["z", "b"]);
        assert!(!continues(known.len(), &known_head, &rewritten_start));
    }

    // -- rollback by reload -------------------------------------------------------------------

    #[test]
    fn a_failed_write_rolls_the_transaction_back_by_reloading_and_keeps_pending_drafts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        vault
            .transact(|tx| {
                add_item(tx, "kept");
                tx.append_audit(draft("first"));
                Ok(())
            })
            .unwrap();
        let before = std::fs::read(&path).unwrap();

        vault.queue_audit(draft("queued-before"));
        // Recorded long before the disk came back; the timestamp must survive the wait.
        vault.pending_audit[0].recorded_at = 42;

        inject(InjectedFault::BeforeWrite);
        let result = vault.transact(|tx| {
            add_item(tx, "rolled back");
            tx.append_audit(draft("inside-failed"));
            tx.queue_audit(draft("queued-during"));
            Ok(())
        });
        assert!(matches!(result, Err(Error::Io(_))), "{result:?}");

        // Memory is the file again: the transaction's item and its own entry are gone...
        assert_eq!(std::fs::read(&path).unwrap(), before, "file untouched");
        let titles: Vec<&str> = vault.items().iter().map(|i| i.title.as_str()).collect();
        assert_eq!(titles, ["kept"]);
        assert_eq!(tools(&vault), ["first"]);
        // ...while both queued drafts wait, in the order they were recorded.
        assert_eq!(vault.unsaved_audit_entries(), 2);
        assert!(vault.last_save_error().unwrap().contains("injected"));
        assert!(!vault.in_transaction);

        vault.flush_audit().unwrap();
        assert_eq!(vault.unsaved_audit_entries(), 0);
        assert!(vault.last_save_error().is_none());
        assert_eq!(tools(&vault), ["first", "queued-before", "queued-during"]);
        assert_eq!(vault.audit_entries()[1].timestamp, 42);
        vault.verify_audit().unwrap();

        let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
        assert_eq!(
            tools(&reopened),
            ["first", "queued-before", "queued-during"]
        );
        assert_eq!(reopened.items().len(), 1);
    }

    #[test]
    fn a_closure_error_rolls_back_without_touching_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        vault.queue_audit(draft("carried"));
        let before = std::fs::read(&path).unwrap();

        let result: Result<()> = vault.transact(|tx| {
            add_item(tx, "never");
            tx.append_audit(draft("never"));
            Err(Error::ItemNotFound("x".to_owned()))
        });
        assert!(matches!(result, Err(Error::ItemNotFound(_))));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(vault.items().is_empty());
        assert!(vault.audit_entries().is_empty());
        assert_eq!(vault.unsaved_audit_entries(), 1);
        // A closure's own failure is not a failed write.
        assert!(vault.last_save_error().is_none());
    }

    #[test]
    fn a_panicking_closure_rolls_back_and_releases_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        vault.queue_audit(draft("carried"));

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = vault.transact(|tx| -> Result<()> {
                add_item(tx, "never");
                panic!("closure bug");
            });
        }));
        assert!(outcome.is_err());
        assert!(!vault.in_transaction);
        assert!(vault.items().is_empty());
        assert_eq!(vault.unsaved_audit_entries(), 1);

        // The lock went with the unwinding stack frame, so the next transaction proceeds.
        vault.set_lock_timeout(Duration::from_millis(200));
        vault.flush_audit().unwrap();
        assert_eq!(tools(&vault), ["carried"]);
    }

    #[test]
    fn a_write_that_landed_despite_reporting_failure_counts_as_committed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        vault.queue_audit(draft("carried"));

        inject(InjectedFault::AfterWrite);
        vault
            .transact(|tx| {
                add_item(tx, "landed");
                Ok(())
            })
            .unwrap();
        assert_eq!(vault.unsaved_audit_entries(), 0);
        assert!(vault.last_save_error().is_none());

        // Were it rolled back, "carried" would be queued again and written a second time here.
        vault.transact(|_| Ok(())).unwrap();
        assert_eq!(tools(&vault), ["carried"]);
        let reopened = Vault::open_with_password(&path, PASSWORD).unwrap();
        assert_eq!(tools(&reopened), ["carried"]);
        assert_eq!(reopened.items().len(), 1);
    }

    #[test]
    fn writes_from_inside_a_transaction_are_refused_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        vault
            .transact(|tx| {
                assert!(matches!(tx.save(), Err(Error::NestedTransaction)));
                // `Tx` has no `DerefMut`, so `vault.transact`/`refresh_if_changed` are not even
                // reachable as `tx.transact(...)` / `tx.refresh_if_changed()` any more — that is
                // now a compile error rather than the `NestedTransaction` this test used to check
                // for both. See the `compile_fail` doctest on `Tx`'s own documentation.
                Ok(())
            })
            .unwrap();
        // Outside the transaction, both work again.
        vault.save().unwrap();
        assert!(!vault.refresh_if_changed().unwrap());
    }

    #[test]
    fn entries_chained_in_a_transaction_and_never_saved_are_requeued_not_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut mine, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        let mut theirs = Vault::open_with_password(&path, PASSWORD).unwrap();

        // `chain` is this module's own private primitive: `Tx::append_audit` calls exactly this,
        // and using it directly here stands in for a transaction whose write never reached this
        // point — see `a_failed_write_rolls_the_transaction_back_by_reloading_and_keeps_pending_drafts`
        // for that path chained through a real, failing `transact`.
        mine.chain(PendingDraft::now(draft("mine-unsaved")));
        let recorded = mine.audit_entries()[0].timestamp;
        theirs
            .transact(|tx| {
                tx.append_audit(draft("theirs"));
                Ok(())
            })
            .unwrap();

        // The pub(crate) save path still cannot merge, so it refuses rather than erase "theirs".
        assert!(matches!(mine.save(), Err(Error::VaultConflict(_))));
        assert_eq!(mine.unsaved_audit_entries(), 1);

        // Adopting the file turns the unsaved entry back into a draft; the next write chains it
        // after the other writer's entry, keeping when it happened.
        assert!(mine.refresh_if_changed().unwrap());
        assert_eq!(tools(&mine), ["theirs"]);
        assert_eq!(mine.unsaved_audit_entries(), 1);
        mine.flush_audit().unwrap();
        assert_eq!(tools(&mine), ["theirs", "mine-unsaved"]);
        assert_eq!(mine.audit_entries()[1].timestamp, recorded);
        mine.verify_audit().unwrap();
    }

    // -- a write whose outcome the writer could not confirm -----------------------------------

    fn disk_tools(path: &Path) -> Vec<String> {
        tools(&Vault::open_with_password(path, PASSWORD).unwrap())
    }

    #[test]
    fn a_transaction_write_that_landed_unconfirmed_is_not_written_twice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        vault.queue_audit(draft("carried"));

        inject(InjectedFault::AfterWriteUnconfirmed);
        let result = vault.transact(|tx| {
            add_item(tx, "landed");
            tx.append_audit(draft("own"));
            tx.queue_audit(draft("queued-during"));
            Ok(())
        });
        assert!(
            result.is_err(),
            "the writer could not confirm, so it reports failure"
        );
        assert_eq!(
            disk_tools(&path),
            ["carried", "own", "queued-during"],
            "the write did land"
        );

        // The next transaction sees its own unconfirmed write on disk and must recognise the
        // re-queued drafts as already written.
        vault.flush_audit().unwrap();
        assert_eq!(vault.unsaved_audit_entries(), 0);
        assert_eq!(disk_tools(&path), ["carried", "own", "queued-during"]);
        assert_eq!(titles(&vault), ["landed"]);
        vault.verify_audit().unwrap();
    }

    #[test]
    fn an_unconfirmed_write_that_another_writer_built_on_is_not_written_twice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        vault.queue_audit(draft("carried"));

        inject(InjectedFault::AfterWriteUnconfirmed);
        assert!(vault.transact(|_| Ok(())).is_err());

        let mut other = Vault::open_with_password(&path, PASSWORD).unwrap();
        other
            .transact(|tx| {
                tx.append_audit(draft("other"));
                Ok(())
            })
            .unwrap();

        vault.flush_audit().unwrap();
        assert_eq!(disk_tools(&path), ["carried", "other"]);
    }

    #[test]
    fn an_unconfirmed_write_that_did_not_land_is_retried() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        vault.queue_audit(draft("carried"));

        inject(InjectedFault::BeforeWrite);
        FAIL_NEXT_READ_BACK.with(|f| f.set(true));
        assert!(vault.transact(|_| Ok(())).is_err());
        assert!(disk_tools(&path).is_empty());

        vault.flush_audit().unwrap();
        assert_eq!(disk_tools(&path), ["carried"]);
    }

    #[test]
    fn a_legacy_save_that_landed_despite_reporting_failure_counts_as_saved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        vault.chain(PendingDraft::now(draft("a")));

        inject(InjectedFault::AfterWrite);
        vault.save().unwrap();
        assert_eq!(vault.unsaved_audit_entries(), 0);
        assert!(vault.last_save_error().is_none());
        vault.chain(PendingDraft::now(draft("b")));
        vault.save().unwrap();
        assert_eq!(disk_tools(&path), ["a", "b"]);
    }

    #[test]
    fn an_unconfirmed_legacy_save_that_landed_is_not_written_twice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        vault.chain(PendingDraft::now(draft("a")));

        inject(InjectedFault::AfterWriteUnconfirmed);
        assert!(vault.save().is_err());
        assert_eq!(disk_tools(&path), ["a"], "the write did land");

        vault.flush_audit().unwrap();
        assert_eq!(vault.unsaved_audit_entries(), 0);
        assert_eq!(disk_tools(&path), ["a"]);
    }

    // -- rollback restores the whole session, not only the file's contents --------------------

    #[test]
    fn a_rolled_back_password_install_leaves_the_session_unlocked_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (vault, code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        drop(vault);
        let mut vault = Vault::open_with_recovery_code(&path, &code).unwrap();
        assert_eq!(vault.unlocked_by(), UnlockedBy::RecoveryCode);

        let prepared = vault.prepare_master_password(b"new password").unwrap();
        let result: Result<()> = vault.transact(|tx| {
            tx.install_master_password(prepared)?;
            Err(Error::ItemNotFound("x".to_owned()))
        });
        assert!(result.is_err());
        assert_eq!(
            vault.unlocked_by(),
            UnlockedBy::RecoveryCode,
            "a password change that never happened must not count as a password unlock"
        );
        Vault::open_with_password(&path, PASSWORD).unwrap();
    }

    #[test]
    fn a_transaction_refuses_a_vault_file_that_has_disappeared() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        vault.queue_audit(draft("carried"));
        std::fs::remove_file(&path).unwrap();

        let result = vault.transact(|tx| {
            add_item(tx, "never");
            Ok(())
        });
        assert!(matches!(result, Err(Error::VaultNotFound(_))), "{result:?}");
        assert!(
            !path.exists(),
            "a deleted vault is not recreated as a side effect"
        );
        assert!(vault.items().is_empty());
        assert_eq!(vault.unsaved_audit_entries(), 1);
    }

    #[test]
    fn a_rollback_never_leaves_uncommitted_changes_readable_even_when_the_file_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        vault
            .transact(|tx| {
                add_item(tx, "kept");
                tx.append_audit(draft("kept"));
                Ok(())
            })
            .unwrap();
        let good = std::fs::read(&path).unwrap();

        // The volume goes away while the closure runs, and the closure then fails.
        let result: Result<()> = vault.transact(|tx| {
            add_item(tx, "uncommitted");
            tx.append_audit(draft("uncommitted"));
            std::fs::remove_file(&path).unwrap();
            Err(Error::ItemNotFound("x".to_owned()))
        });
        assert!(result.is_err());
        assert_eq!(titles(&vault), ["kept"]);
        assert_eq!(tools(&vault), ["kept"]);

        // The session is not bricked: once the file is back, it writes again.
        std::fs::write(&path, &good).unwrap();
        vault
            .transact(|tx| {
                add_item(tx, "later");
                Ok(())
            })
            .unwrap();
        assert_eq!(
            titles(&Vault::open_with_password(&path, PASSWORD).unwrap()),
            ["kept", "later"]
        );
    }

    fn titles(vault: &Vault) -> Vec<String> {
        vault.items().iter().map(|i| i.title.clone()).collect()
    }

    // -- size limit ---------------------------------------------------------------------------

    #[test]
    fn a_vault_file_beyond_the_size_limit_is_refused_before_it_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        // Sparse on every file system this runs on: no disk space, and nothing is read.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_VAULT_FILE_LEN + 1)
            .unwrap();
        assert!(matches!(
            Vault::open_with_password(&path, PASSWORD),
            Err(Error::VaultTooLarge { .. })
        ));
        assert!(matches!(
            vault.transact(|_| Ok(())),
            Err(Error::VaultTooLarge { .. })
        ));
        assert!(matches!(
            vault.refresh_if_changed(),
            Err(Error::VaultTooLarge { .. })
        ));
    }

    #[test]
    fn a_file_that_is_longer_than_it_claims_is_still_bounded() {
        let data = vec![7u8; 64];
        // Metadata said 4 bytes; the reader keeps going. The bound holds regardless.
        let result = read_bounded(&data[..], 4, 16, Path::new("/v"));
        assert!(matches!(result, Err(Error::VaultTooLarge { max: 16, .. })));
        assert_eq!(
            read_bounded(&data[..], 64, 64, Path::new("/v")).unwrap(),
            data
        );
    }

    #[test]
    fn nothing_larger_than_the_limit_is_ever_written() {
        assert!(ensure_within_limit(MAX_VAULT_FILE_LEN, Path::new("/v")).is_ok());
        assert!(matches!(
            ensure_within_limit(MAX_VAULT_FILE_LEN + 1, Path::new("/v")),
            Err(Error::VaultTooLarge { .. })
        ));
    }

    // -- overwriting a file this session no longer builds on --------------------------------------

    /// A session whose file was restored from an older copy: `pending` is queued but unwritten,
    /// and the file on disk lacks the session's second entry.
    fn diverged_session(dir: &Path) -> (Vault, PathBuf, Vec<u8>) {
        let path = dir.join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        vault
            .transact(|tx| {
                tx.append_audit(draft("first"));
                Ok(())
            })
            .unwrap();
        let older = std::fs::read(&path).unwrap();
        vault
            .transact(|tx| {
                tx.append_audit(draft("second"));
                Ok(())
            })
            .unwrap();
        std::fs::write(&path, &older).unwrap();
        vault.queue_audit(draft("pending"));
        (vault, path, older)
    }

    #[test]
    fn a_failed_overwrite_keeps_pending_drafts_and_leaves_the_file_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, path, older) = diverged_session(dir.path());
        let confirmed = vault.examine_conflict().unwrap().unwrap();

        inject(InjectedFault::BeforeWrite);
        let result = vault.overwrite_with_this_session(&confirmed, "unit", "test");
        assert!(matches!(result, Err(Error::Io(_))), "{result:?}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            older,
            "the file is untouched"
        );
        assert_eq!(tools(&vault), ["first", "second"], "nothing was chained");
        assert_eq!(
            vault.unsaved_audit_entries(),
            1,
            "the draft is still pending"
        );
        assert!(vault.last_save_error().is_some());

        // The conflict is still there, unchanged, and the next attempt writes the draft.
        assert_eq!(vault.examine_conflict().unwrap(), Some(confirmed.clone()));
        vault
            .overwrite_with_this_session(&confirmed, "unit", "test")
            .unwrap();
        assert_eq!(
            disk_tools(&path),
            ["first", "second", "pending", AUDIT_TOOL_OVERWRITE]
        );
        assert_eq!(vault.unsaved_audit_entries(), 0);
        assert!(vault.last_save_error().is_none());
    }

    #[test]
    fn an_overwrite_that_landed_unconfirmed_is_not_written_twice() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, path, _older) = diverged_session(dir.path());
        let confirmed = vault.examine_conflict().unwrap().unwrap();

        inject(InjectedFault::AfterWriteUnconfirmed);
        assert!(
            vault
                .overwrite_with_this_session(&confirmed, "unit", "test")
                .is_err()
        );
        let landed = ["first", "second", "pending", AUDIT_TOOL_OVERWRITE];
        assert_eq!(disk_tools(&path), landed, "the write did land");
        // Memory is back where it was: the draft pending, the override entry not chained.
        assert_eq!(tools(&vault), ["first", "second"]);
        assert_eq!(vault.unsaved_audit_entries(), 1);

        // The file now continues this session, so there is nothing left to overwrite …
        assert_eq!(vault.examine_conflict().unwrap(), None);
        assert!(matches!(
            vault.overwrite_with_this_session(&confirmed, "unit", "test"),
            Err(Error::VaultNotInConflict(_))
        ));
        // … and the next ordinary write recognises the pending draft as already written.
        vault.flush_audit().unwrap();
        assert_eq!(vault.unsaved_audit_entries(), 0);
        assert_eq!(disk_tools(&path), landed);
        vault.verify_audit().unwrap();
    }

    #[test]
    fn an_overwrite_whose_write_landed_despite_reporting_failure_counts_as_done() {
        let dir = tempfile::tempdir().unwrap();
        let (mut vault, path, _older) = diverged_session(dir.path());
        let confirmed = vault.examine_conflict().unwrap().unwrap();

        inject(InjectedFault::AfterWrite);
        vault
            .overwrite_with_this_session(&confirmed, "unit", "test")
            .unwrap();
        assert_eq!(
            tools(&vault),
            ["first", "second", "pending", AUDIT_TOOL_OVERWRITE]
        );
        assert_eq!(vault.unsaved_audit_entries(), 0);
        assert_eq!(disk_tools(&path), tools(&vault));
    }

    fn device_key(tag: u8, label: &str) -> DeviceKey {
        DeviceKey::new(
            [tag; DEVICE_KEY_ID_LEN],
            device::SUITE_X25519_ED25519_V1,
            label,
            1,
            crate::model::Secret::new(vec![tag; device::X25519_ED25519_V1_SECRET_LEN]),
        )
        .unwrap()
    }

    fn labels(vault: &Vault) -> Vec<String> {
        vault
            .device_keys()
            .iter()
            .map(|d| d.label().to_owned())
            .collect()
    }

    fn backups_beside(path: &Path) -> Vec<String> {
        let prefix = format!("{}.bak-", path.file_name().unwrap().to_string_lossy());
        let mut names: Vec<String> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(&prefix))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn retrying_a_failed_upgrade_reuses_its_backup_instead_of_taking_another() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut vault, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        let version_1 = std::fs::read(&path).unwrap();

        for _ in 0..3 {
            inject(InjectedFault::BeforeWrite);
            assert!(
                vault
                    .transact(|tx| tx.add_device_key(device_key(1, "one"), "unit"))
                    .is_err()
            );
        }
        assert_eq!(backups_beside(&path), ["v.kagivault.bak-1"]);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            version_1,
            "nothing was written"
        );

        vault
            .transact(|tx| tx.add_device_key(device_key(1, "one"), "unit"))
            .unwrap();
        assert_eq!(backups_beside(&path), ["v.kagivault.bak-1"]);
        assert_eq!(
            vault.format_upgrade_backup(),
            Some(dir.path().join("v.kagivault.bak-1").as_path())
        );
        assert_eq!(
            std::fs::read(dir.path().join("v.kagivault.bak-1")).unwrap(),
            version_1
        );
        // No temporary from any attempt is left beside the vault.
        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(strays.is_empty(), "{strays:?}");
    }

    #[test]
    fn a_failed_overwrite_puts_the_session_s_device_keys_back_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault");
        let (mut session, _code) = Vault::create(&path, PASSWORD, &cheap()).unwrap();
        session
            .transact(|tx| {
                tx.add_device_key(device_key(1, "one"), "unit")?;
                tx.add_device_key(device_key(2, "two"), "unit")?;
                tx.add_device_key(device_key(3, "three"), "unit")
            })
            .unwrap();
        let older = std::fs::read(&path).unwrap();
        session
            .transact(|tx| {
                tx.append_audit(draft("only in the session"));
                Ok(())
            })
            .unwrap();

        // The file's version retires "two" and adds "four".
        std::fs::write(&path, &older).unwrap();
        let mut other = Vault::open_with_password(&path, PASSWORD).unwrap();
        other
            .transact(|tx| {
                tx.remove_device_key(&[2; DEVICE_KEY_ID_LEN], "unit");
                tx.add_device_key(device_key(4, "four"), "unit")
            })
            .unwrap();
        let file = std::fs::read(&path).unwrap();

        let confirmed = session.examine_conflict().unwrap().unwrap();
        inject(InjectedFault::BeforeWrite);
        assert!(
            session
                .overwrite_with_this_session(&confirmed, "unit", "test")
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), file, "the file is untouched");
        assert_eq!(labels(&session), ["one", "two", "three"]);
        assert!(session.retired_device_keys().is_empty());

        session
            .overwrite_with_this_session(&confirmed, "unit", "test")
            .unwrap();
        assert_eq!(labels(&session), ["one", "three", "four"]);
        assert_eq!(session.retired_device_keys(), [[2; DEVICE_KEY_ID_LEN]]);
    }

    #[test]
    fn the_overwrite_detail_names_what_was_replaced() {
        let lost = DivergedFile {
            audit_len: 3,
            shared_audit_len: 1,
            ..DivergedFile::default()
        };
        let detail = overwrite_detail(
            &FileConflict::Diverged {
                file_sha256: [0xab; 32],
                lost,
            },
            5,
            1,
            2,
            "the reason, with spaces",
        );
        assert_eq!(
            detail,
            "found=diverged file_sha256=abababababababab file_audit_len=3 shared_audit_len=1 \
             session_audit_len=5 device_keys_kept=1 device_keys_retired=2 \
             reason=the reason, with spaces"
        );
        assert_eq!(
            overwrite_detail(&FileConflict::Missing, 2, 0, 0, "r"),
            "found=missing file_sha256=none file_audit_len=0 shared_audit_len=0 \
             session_audit_len=2 device_keys_kept=0 device_keys_retired=0 reason=r"
        );
        assert!(
            overwrite_detail(
                &FileConflict::Replaced {
                    file_sha256: [1; 32]
                },
                2,
                0,
                0,
                "r"
            )
            .contains("file_audit_len=unknown")
        );
    }
}
