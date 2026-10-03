//! The machine vault (ADR-0042 §2): a separate vault file for machine credentials that
//! unattended jobs use, and the records that say which job may use what.
//!
//! # Two files, one key
//!
//! The machine vault is an ordinary vault file (vault-format §2) whose body carries a
//! [`MachineSection`]; that section is what makes a file a machine vault. The file has **no
//! password, recovery or platform slot** (ADR-0042 implementation decision 2). Its vault key
//! lives
//!
//! * in the personal vault's body, as a [`MachineVaultKey`] — usable exactly while the personal
//!   vault is unlocked, through the personal vault's own password, Touch ID or recovery slot, so
//!   recovering the personal vault recovers the machine vault too; and
//! * while armed, in the macOS login Keychain, where the app stores the bytes
//!   [`MachineVaultKey::to_keychain_bytes`] returns (implementation decision 1). Arming persists
//!   across restarts and has no expiry; this crate stores nothing about the Keychain itself.
//!
//! [`crate::vault::Vault::create_machine`] creates the file and
//! [`crate::vault::Vault::open_machine`] opens it with a [`MachineVaultKey`], checking that the
//! file is the machine vault that key belongs to.
//!
//! # Structural rules
//!
//! Enforced here, on every write of a machine vault ([`check_body`], called when the file is
//! sealed), not by any UI — ADR-0042 §2:
//!
//! 1. a website ([`crate::model::Item::urls`]) only on a Login item, and only as an exact https
//!    origin in its canonical serialization ([`canonical_https_origin`]);
//! 2. one-time-password fields only on Login items, and no environment variable bound to one — so
//!    a seed is never released as a variable; only a code, by the fill path, ever is;
//! 3. no references out: every environment binding resolves to an item and field in this file,
//!    every item and environment lives in one of this file's logical vaults, no field is a
//!    [`FieldKind::Reference`], and every job and grant names only jobs, environments and items
//!    of this file;
//! 4. no shared-vault device keys and no machine vault key inside a machine vault;
//! 5. jobs and grants within the bounds ADR-0042 §4, §5 and §12.2 set.
//!
//! A file that breaks them still opens (no build writes one); it cannot be written until the
//! transaction that would write it fixes what is wrong.
//!
//! # Records
//!
//! Jobs, command grants and login grants are metadata — paths, arguments, ids, limits — and hold
//! no secret. Their use counters and suspension state live in the same records (implementation
//! decision 7). Whether a value a grant releases changed since the grant was approved is decided
//! by comparing the grant's [`CommandGrant::approved_at`] with the item's and environment's
//! `updated_at` (implementation decision 3): no hash of any value is stored.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, KEY_LEN};
use crate::error::{Error, Result};
use crate::model::{Category, Environment, FieldKind, Item, Secret, VarSource};
use crate::proto::{EnvId, ItemId};

/// Length of a vault file's `vault_id` (vault-format §2.1).
pub const VAULT_ID_LEN: usize = 16;

/// Length of [`MachineVaultKey::to_keychain_bytes`]: the machine vault's `vault_id`, then its
/// vault key.
pub const KEYCHAIN_BYTES_LEN: usize = VAULT_ID_LEN + KEY_LEN;

/// What [`MachineVaultKey::to_keychain_bytes`] returns: the bytes in a buffer zeroized on drop.
pub type KeychainBytes = Zeroizing<Vec<u8>>;

/// The longest a job's run may last (ADR-0042 §4): six hours.
pub const MAX_RUN_DEADLINE_SECS: u32 = 6 * 60 * 60;
/// A job's run deadline unless the person chooses another (ADR-0042 §4): thirty minutes.
pub const DEFAULT_RUN_DEADLINE_SECS: u32 = 30 * 60;
/// The longest catch-up window a job may have: one day.
pub const MAX_CATCH_UP_SECS: u32 = 24 * 60 * 60;
/// The longest a standing grant may live, from its creation (owner's answer 5): ninety days.
pub const MAX_GRANT_LIFETIME_SECS: u64 = 90 * 24 * 60 * 60;
/// A grant's lifetime unless the person chooses another (owner's answer 5): thirty days.
pub const DEFAULT_GRANT_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;
/// Releases (or sign-ins) per run unless the person chooses another (owner's answer 5).
pub const DEFAULT_PER_RUN: u32 = 1;
/// Total uses of a grant unless the person chooses another (owner's answer 5).
pub const DEFAULT_TOTAL_USES: u32 = 60;
/// The longest name a job may have, in characters.
pub const MAX_JOB_NAME_CHARS: usize = 128;

/// Where the machine vault of the personal vault at `personal` lives: beside it, named after it
/// — `vault.kagivault` has `vault.machine.kagivault` (implementation decision 4: one machine
/// vault per personal vault, at a fixed place).
#[must_use]
pub fn machine_vault_path(personal: &Path) -> PathBuf {
    let stem = personal
        .file_stem()
        .map_or_else(|| "vault".to_owned(), |s| s.to_string_lossy().into_owned());
    personal.with_file_name(format!("{stem}.machine.kagivault"))
}

// ---------------------------------------------------------------------------------------------
// The key, as the personal vault holds it
// ---------------------------------------------------------------------------------------------

/// The machine vault's key, held in the personal vault's body (ADR-0042 §2).
///
/// Like a shared-vault device key it is not an item: never agent-visible, never listed, never
/// exported with items. No `Clone`, no `Serialize`, and a `Debug` that shows only the machine
/// vault's id.
pub struct MachineVaultKey {
    vault_id: [u8; VAULT_ID_LEN],
    key: Secret,
    created_at: u64,
    /// Keys of this entry this build does not recognize, preserved (vault-format §9 rule 1). Not
    /// zeroized, and not for secrets.
    unknown: BTreeMap<String, ciborium::Value>,
}

impl MachineVaultKey {
    /// A fresh key and a fresh `vault_id`, for a machine vault not yet created.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the operating system's generator fails.
    pub fn generate() -> Result<Self> {
        let key = crypto::random::key()?;
        Ok(Self {
            vault_id: crypto::random::array::<VAULT_ID_LEN>()?,
            key: Secret::new(key.to_vec()),
            created_at: crate::unix_now(),
            unknown: BTreeMap::new(),
        })
    }

    /// The `vault_id` of the machine vault file this key opens. Public: it is in that file's
    /// plaintext header.
    #[must_use]
    pub fn vault_id(&self) -> &[u8; VAULT_ID_LEN] {
        &self.vault_id
    }

    /// The machine vault's vault key.
    #[must_use]
    pub fn key(&self) -> &Secret {
        &self.key
    }

    /// Unix seconds when the key was made; 0 for one read back from the Keychain.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// The bytes the app stores in the macOS Keychain while the machine vault is armed
    /// (implementation decision 1): the `vault_id`, then the vault key — [`KEYCHAIN_BYTES_LEN`]
    /// bytes, in a buffer zeroized on drop. This is the machine vault key's one crossing out of
    /// Rust, which ADR-0008's list records.
    #[must_use]
    pub fn to_keychain_bytes(&self) -> KeychainBytes {
        let mut out = Zeroizing::new(Vec::with_capacity(KEYCHAIN_BYTES_LEN));
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(self.key.expose());
        out
    }

    /// Read back what [`MachineVaultKey::to_keychain_bytes`] wrote. The caller's copy is its own
    /// to clear.
    ///
    /// # Errors
    ///
    /// [`Error::MachineVault`] for anything but [`KEYCHAIN_BYTES_LEN`] bytes.
    pub fn from_keychain_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEYCHAIN_BYTES_LEN {
            return Err(Error::MachineVault(
                "the machine vault key from the Keychain is not 48 bytes",
            ));
        }
        let mut vault_id = [0u8; VAULT_ID_LEN];
        vault_id.copy_from_slice(&bytes[..VAULT_ID_LEN]);
        Ok(Self {
            vault_id,
            key: Secret::new(bytes[VAULT_ID_LEN..].to_vec()),
            created_at: 0,
            unknown: BTreeMap::new(),
        })
    }

    /// Whether two entries hold the same key for the same file (the key compared through
    /// [`Secret`]'s own comparison, so no copy is made).
    #[must_use]
    pub fn same_key(&self, other: &Self) -> bool {
        self.vault_id == other.vault_id && self.key == other.key
    }
}

impl std::fmt::Debug for MachineVaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id: String = self.vault_id.iter().map(|b| format!("{b:02x}")).collect();
        f.debug_struct("MachineVaultKey")
            .field("vault_id", &id)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct KeyWire {
    #[serde(with = "serde_bytes")]
    vault_id: Vec<u8>,
    #[serde(with = "crate::model::secret_cbor")]
    key: Secret,
    created_at: u64,
    #[serde(flatten)]
    unknown: BTreeMap<String, ciborium::Value>,
}

#[derive(Serialize)]
struct KeyWireRef<'a> {
    #[serde(with = "serde_bytes")]
    vault_id: &'a [u8],
    #[serde(with = "crate::model::secret_cbor")]
    key: &'a Secret,
    created_at: u64,
    #[serde(flatten)]
    unknown: &'a BTreeMap<String, ciborium::Value>,
}

/// The crate-private serde adapter `Body::machine_key` is encoded with. The only encoding of a
/// [`MachineVaultKey`] there is.
pub(crate) mod cbor_key_opt {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{KEY_LEN, KeyWire, KeyWireRef, MachineVaultKey, VAULT_ID_LEN};

    // `serde(with)` hands the field by reference, so the signature is fixed by serde.
    #[allow(clippy::ref_option)]
    pub(crate) fn serialize<S: Serializer>(
        key: &Option<MachineVaultKey>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        key.as_ref()
            .map(|k| KeyWireRef {
                vault_id: &k.vault_id,
                key: &k.key,
                created_at: k.created_at,
                unknown: &k.unknown,
            })
            .serialize(ser)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Option<MachineVaultKey>, D::Error> {
        let Some(w) = Option::<KeyWire>::deserialize(de)? else {
            return Ok(None);
        };
        let vault_id: [u8; VAULT_ID_LEN] = w
            .vault_id
            .as_slice()
            .try_into()
            .map_err(|_| D::Error::custom("a machine vault id is 16 bytes"))?;
        if w.key.len() != KEY_LEN {
            return Err(D::Error::custom("a machine vault key is 32 bytes"));
        }
        Ok(Some(MachineVaultKey {
            vault_id,
            key: w.key,
            created_at: w.created_at,
            unknown: w.unknown,
        }))
    }
}

// ---------------------------------------------------------------------------------------------
// Records in the machine vault's body
// ---------------------------------------------------------------------------------------------

macro_rules! machine_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// A fresh random (v4) identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                Ok(Self(s.parse()?))
            }
        }
    };
}

machine_id!(
    /// Identifies a job (ADR-0042 §4).
    JobId
);
machine_id!(
    /// Identifies a standing grant of either kind (ADR-0042 §5, §12.2).
    GrantId
);

/// What makes a file a machine vault: its jobs, its standing grants and whether it is armed.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MachineSection {
    /// Jobs kagisecure starts on a schedule (ADR-0042 §4).
    #[serde(default)]
    pub jobs: Vec<Job>,
    /// Command grants (ADR-0042 §5).
    #[serde(default)]
    pub command_grants: Vec<CommandGrant>,
    /// Login grants (ADR-0042 §12.2).
    #[serde(default)]
    pub login_grants: Vec<LoginGrant>,
    /// Set while the vault is armed. Arming has no expiry and persists across restarts
    /// (implementation decision 1); it ends only when a person, or a `lock` request, disarms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arm: Option<Arm>,
    /// Keys this build does not recognize, preserved (vault-format §9 rule 1).
    #[serde(flatten)]
    pub unknown: BTreeMap<String, ciborium::Value>,
}

impl MachineSection {
    /// The job with this id.
    #[must_use]
    pub fn job(&self, id: JobId) -> Option<&Job> {
        self.jobs.iter().find(|j| j.id == id)
    }

    /// Remove a job and every grant of it, returning the job. A grant never outlives its job.
    pub fn remove_job(&mut self, id: JobId) -> Option<Job> {
        let index = self.jobs.iter().position(|j| j.id == id)?;
        self.command_grants.retain(|g| g.job != id);
        self.login_grants.retain(|g| g.job != id);
        Some(self.jobs.remove(index))
    }

    /// Remove a grant of either kind; whether there was one.
    pub fn remove_grant(&mut self, id: GrantId) -> bool {
        let before = self.command_grants.len() + self.login_grants.len();
        self.command_grants.retain(|g| g.id != id);
        self.login_grants.retain(|g| g.id != id);
        before != self.command_grants.len() + self.login_grants.len()
    }

    /// The command grant with this id.
    #[must_use]
    pub fn command_grant(&self, id: GrantId) -> Option<&CommandGrant> {
        self.command_grants.iter().find(|g| g.id == id)
    }

    /// Suspend one grant of either kind, unless it is already suspended; whether it was
    /// suspended by this call.
    pub fn suspend_grant(&mut self, id: GrantId, at: u64, reason: &str) -> bool {
        let suspension = Suspension {
            at,
            reason: reason.to_owned(),
        };
        if let Some(g) = self.command_grants.iter_mut().find(|g| g.id == id) {
            if g.suspended.is_none() {
                g.suspended = Some(suspension);
                return true;
            }
            return false;
        }
        if let Some(g) = self.login_grants.iter_mut().find(|g| g.id == id)
            && g.suspended.is_none()
        {
            g.suspended = Some(suspension);
            return true;
        }
        false
    }

    /// Suspend every grant of a job, of both kinds, as one strike does (ADR-0042 §7). A grant
    /// already suspended keeps its first reason.
    pub fn suspend_job(&mut self, job: JobId, at: u64, reason: &str) {
        let suspension = || {
            Some(Suspension {
                at,
                reason: reason.to_owned(),
            })
        };
        for g in self.command_grants.iter_mut().filter(|g| g.job == job) {
            if g.suspended.is_none() {
                g.suspended = suspension();
            }
        }
        for g in self.login_grants.iter_mut().filter(|g| g.job == job) {
            if g.suspended.is_none() {
                g.suspended = suspension();
            }
        }
    }
}

/// Which presence path authorized a person's decision (ADR-0038's audit vocabulary).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresencePath {
    /// Touch ID, an Apple Watch, or the login password through LocalAuthentication.
    #[serde(rename = "PRESENCE_CONFIRMED")]
    Confirmed,
    /// The master-password fallback (W-20).
    #[serde(rename = "PRESENCE_CONFIRMED_MASTER_PASSWORD")]
    ConfirmedMasterPassword,
}

/// The armed state: when, and by which presence proof. No expiry (implementation decision 1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Arm {
    /// Unix seconds.
    pub armed_at: u64,
    /// The presence proof that armed it.
    pub presence: PresencePath,
    /// Keys this build does not recognize, preserved.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, ciborium::Value>,
}

/// How an executable is pinned (owner's answer 7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutablePin {
    /// By code-signing identity, for an executable that has a team identifier: any build its
    /// signer ships keeps the pin.
    CodeSigning {
        /// The team identifier.
        team_id: String,
        /// The signing identifier.
        signing_id: String,
    },
    /// By the SHA-256 of its bytes (32 bytes).
    Sha256(#[serde(with = "serde_bytes")] Vec<u8>),
}

/// An executable named by absolute path, and pinned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedExecutable {
    /// Absolute path; a bare name is refused, so `PATH` decides nothing.
    pub path: String,
    /// What the executable must still be at every release.
    pub pin: ExecutablePin,
}

/// A file a command grant pins by content (ADR-0042 §5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedFile {
    /// Absolute path.
    pub path: String,
    /// SHA-256 of the file's bytes when the grant was approved (32 bytes).
    #[serde(with = "serde_bytes")]
    pub sha256: Vec<u8>,
}

impl PinnedFile {
    /// Whether the file at [`PinnedFile::path`] still has the pinned SHA-256. A file that cannot
    /// be read does not hold.
    #[must_use]
    pub fn holds(&self) -> bool {
        file_sha256(Path::new(&self.path)).is_ok_and(|hash| hash.as_slice() == self.sha256)
    }
}

/// The SHA-256 of a file's bytes, for pinning an executable or an input (ADR-0042 §5), read in
/// chunks so a large executable is not held in memory at once.
///
/// # Errors
///
/// Whatever reading the file returns.
pub fn file_sha256(path: &Path) -> std::io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hasher.finalize().into())
}

/// A day of the week, for a weekly schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

/// One calendar time a job runs at, in the Mac's local time (ADR-0042 §4). No "every N seconds".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleTime {
    /// Every day at `hour:minute`.
    Daily {
        /// 0 to 23.
        hour: u8,
        /// 0 to 59.
        minute: u8,
    },
    /// Every week on `weekday` at `hour:minute`.
    Weekly {
        /// The day.
        weekday: Weekday,
        /// 0 to 23.
        hour: u8,
        /// 0 to 59.
        minute: u8,
    },
}

/// A job: a program kagisecure starts on a schedule, whose process tree alone may use grants
/// (ADR-0042 §4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Job {
    /// Identifier.
    pub id: JobId,
    /// Display name.
    pub name: String,
    /// The root executable.
    pub root: PinnedExecutable,
    /// Exact arguments, not including the executable itself.
    #[serde(default)]
    pub args: Vec<String>,
    /// Absolute working directory.
    pub working_dir: String,
    /// When it runs; at least one time.
    pub schedule: Vec<ScheduleTime>,
    /// How long a run may last, at most [`MAX_RUN_DEADLINE_SECS`].
    pub run_deadline_secs: u32,
    /// How late a missed run may still start, at most [`MAX_CATCH_UP_SECS`]; 0 for never.
    #[serde(default)]
    pub catch_up_secs: u32,
    /// The run browser, required for a job with a login grant (ADR-0042 §12.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_browser: Option<PinnedExecutable>,
    /// Unix seconds.
    pub created_at: u64,
    /// The presence proof that created it.
    pub presence: PresencePath,
    /// Keys this build does not recognize, preserved.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, ciborium::Value>,
}

/// Why a grant is suspended (ADR-0042 §7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suspension {
    /// Unix seconds.
    pub at: u64,
    /// The reason, from the audit vocabulary (`PIN_CHANGED`, `NO_GRANT`, ...).
    pub reason: String,
}

/// The bounds every standing grant carries (ADR-0042 §5, owner's answer 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantLimits {
    /// Releases (or sign-ins) per run, at least 1.
    pub per_run: u32,
    /// Total uses, at least 1.
    pub total_uses: u32,
    /// Hard expiry, Unix seconds: after the grant's creation, and at most
    /// [`MAX_GRANT_LIFETIME_SECS`] after it.
    pub expires_at: u64,
}

impl GrantLimits {
    /// The defaults, for a grant created at `created_at`.
    #[must_use]
    pub fn defaults(created_at: u64) -> Self {
        Self {
            per_run: DEFAULT_PER_RUN,
            total_uses: DEFAULT_TOTAL_USES,
            expires_at: created_at + DEFAULT_GRANT_LIFETIME_SECS,
        }
    }
}

/// A command grant: during a run of this job, may this exact command run with these variables
/// (ADR-0042 §5)? Output is always `none`, so it is not a field.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommandGrant {
    /// Identifier.
    pub id: GrantId,
    /// The one job whose runs may use it.
    pub job: JobId,
    /// A machine-vault environment.
    pub env: EnvId,
    /// Variable names of that environment; a request may ask for these or a subset.
    pub variables: Vec<String>,
    /// The executable.
    pub executable: PinnedExecutable,
    /// The whole argument list after the executable, exactly.
    #[serde(default)]
    pub args: Vec<String>,
    /// Absolute working directory, matched exactly.
    pub working_dir: String,
    /// Files pinned by content.
    #[serde(default)]
    pub pinned_inputs: Vec<PinnedFile>,
    /// The child's timeout, at most [`MAX_RUN_DEADLINE_SECS`] (and at most the run's remaining
    /// time, which the engine applies).
    pub timeout_secs: u32,
    /// Bounds.
    pub limits: GrantLimits,
    /// Uses so far.
    #[serde(default)]
    pub uses: u32,
    /// Unix seconds.
    pub created_at: u64,
    /// When a person last approved what it releases: at creation, and again when the person
    /// edits a value it releases with a presence proof (owner's answer 10). A value or binding
    /// changed later than this suspends it (implementation decision 3).
    pub approved_at: u64,
    /// The presence proof that created it.
    pub presence: PresencePath,
    /// Set while suspended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspended: Option<Suspension>,
    /// Keys this build does not recognize, preserved.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, ciborium::Value>,
}

/// A field a login grant may fill (ADR-0042 §12.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginField {
    /// The username.
    Username,
    /// The password.
    Password,
    /// A one-time code, only with [`LoginGrant::one_time_codes`] on.
    OneTimeCode,
}

/// A login grant: during a run of this job, may this login be typed into this one site, in the
/// run's own browser (ADR-0042 §12.2)?
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoginGrant {
    /// Identifier.
    pub id: GrantId,
    /// The one job whose runs may use it; it must declare a run browser.
    pub job: JobId,
    /// A Login item of this machine vault.
    pub item: ItemId,
    /// The fields it may fill.
    pub fields: Vec<LoginField>,
    /// One exact https origin, canonical, and one of the item's websites.
    pub origin: String,
    /// Exact https origins the sign-in may lead to within the flow window.
    #[serde(default)]
    pub follow_on_origins: Vec<String>,
    /// The one-time-code switch, off by default (ADR-0042 §12.5).
    #[serde(default)]
    pub one_time_codes: bool,
    /// Bounds.
    pub limits: GrantLimits,
    /// Uses so far.
    #[serde(default)]
    pub uses: u32,
    /// Unix seconds.
    pub created_at: u64,
    /// As [`CommandGrant::approved_at`].
    pub approved_at: u64,
    /// The presence proof that created it.
    pub presence: PresencePath,
    /// Set while suspended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspended: Option<Suspension>,
    /// Keys this build does not recognize, preserved.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, ciborium::Value>,
}

// ---------------------------------------------------------------------------------------------
// Exact https origins
// ---------------------------------------------------------------------------------------------

/// The canonical serialization of an exact https origin: `https://host` or `https://host:port`,
/// the host in lower case, the default port 443 left out, and no path, query, fragment or user
/// information. A single trailing `/` is accepted and dropped; anything else after the host and
/// port is refused, as is any other scheme. An internationalized host must be given in its
/// `xn--` form: this crate does no IDNA mapping (implementation decision 6).
///
/// # Errors
///
/// [`Error::MachineVault`] with the reason.
pub fn canonical_https_origin(input: &str) -> Result<String> {
    let rest = input
        .get(..8)
        .filter(|scheme| scheme.eq_ignore_ascii_case("https://"))
        .map(|_| &input[8..])
        .ok_or(Error::MachineVault("a website here is an https origin"))?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.contains(['/', '?', '#', '@', '\\']) || rest.chars().any(char::is_whitespace) {
        return Err(Error::MachineVault(
            "a website here is an origin only: no path, query, fragment or user name",
        ));
    }
    let (host, port) = if let Some(after_bracket) = rest.strip_prefix('[') {
        let (inside, after) = after_bracket
            .split_once(']')
            .ok_or(Error::MachineVault("an IPv6 host is closed with ]"))?;
        if inside.is_empty()
            || !inside
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return Err(Error::MachineVault("not an IPv6 host"));
        }
        let port = match after {
            "" => None,
            p => Some(
                p.strip_prefix(':')
                    .ok_or(Error::MachineVault("unexpected text after an IPv6 host"))?,
            ),
        };
        (format!("[{}]", inside.to_ascii_lowercase()), port)
    } else {
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        };
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            || host.split('.').any(str::is_empty)
        {
            return Err(Error::MachineVault(
                "a website's host is letters, digits, hyphens and dots (xn-- for other scripts)",
            ));
        }
        (host.to_ascii_lowercase(), port)
    };
    let port = match port {
        None => None,
        Some(p) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::MachineVault("a website's port is a number"));
            }
            match p.parse::<u16>() {
                Ok(0) | Err(_) => {
                    return Err(Error::MachineVault("a website's port is 1 to 65535"));
                }
                Ok(443) => None,
                Ok(n) => Some(n),
            }
        }
    };
    Ok(match port {
        None => format!("https://{host}"),
        Some(n) => format!("https://{host}:{n}"),
    })
}

/// Whether `s` is already an exact https origin in its canonical serialization.
#[must_use]
pub fn is_canonical_https_origin(s: &str) -> bool {
    canonical_https_origin(s).is_ok_and(|c| c == s)
}

// ---------------------------------------------------------------------------------------------
// The structural rules
// ---------------------------------------------------------------------------------------------

/// Check a body about to be written against the machine vault's rules (see the module
/// documentation). A personal vault's body, one with no [`MachineSection`], passes unchanged.
///
/// # Errors
///
/// [`Error::MachineVault`] naming the first rule broken.
pub(crate) fn check_body(body: &super::Body) -> Result<()> {
    let Some(machine) = &body.machine else {
        return Ok(());
    };
    if !body.devices.is_empty() {
        return Err(Error::MachineVault(
            "a machine vault holds no shared-vault device keys",
        ));
    }
    if body.machine_key.is_some() {
        return Err(Error::MachineVault(
            "a machine vault holds no machine vault key",
        ));
    }
    let vaults: BTreeSet<_> = body.vaults.iter().map(|v| v.id).collect();
    for item in &body.items {
        if !vaults.contains(&item.vault_id) {
            return Err(Error::MachineVault(
                "every item of a machine vault is in one of its logical vaults",
            ));
        }
        check_item(item)?;
    }
    for env in &body.envs {
        if !vaults.contains(&env.vault_id) {
            return Err(Error::MachineVault(
                "every environment of a machine vault is in one of its logical vaults",
            ));
        }
        check_environment(env, &body.items)?;
    }
    check_records(machine, &body.items, &body.envs)
}

fn check_item(item: &Item) -> Result<()> {
    if !item.urls.is_empty() && item.category != Category::Login {
        return Err(Error::MachineVault(
            "in a machine vault only a Login item may have a website",
        ));
    }
    if !item.urls.iter().all(|u| is_canonical_https_origin(u)) {
        return Err(Error::MachineVault(
            "a website in a machine vault is an exact https origin, such as https://example.com",
        ));
    }
    for field in &item.fields {
        if field.kind == FieldKind::Totp && item.category != Category::Login {
            return Err(Error::MachineVault(
                "in a machine vault only a Login item may have a one-time password",
            ));
        }
        if field.kind == FieldKind::Reference {
            return Err(Error::MachineVault(
                "a machine vault item refers to no other item",
            ));
        }
    }
    Ok(())
}

fn check_environment(env: &Environment, items: &[Item]) -> Result<()> {
    for var in &env.vars {
        if let VarSource::ItemField { item, field } = &var.source {
            let field = items
                .iter()
                .find(|i| i.id == *item)
                .and_then(|i| i.fields.iter().find(|f| f.id == *field))
                .ok_or(Error::MachineVault(
                    "a machine vault environment refers only to fields of items in the machine vault",
                ))?;
            if field.kind == FieldKind::Totp {
                return Err(Error::MachineVault(
                    "a one-time-password seed is never a variable",
                ));
            }
        }
    }
    Ok(())
}

/// An absolute path with no empty, `.` or `..` component and no trailing `/`. What a caller
/// hands in is expected to be canonical already; this is the lexical part of that.
fn is_plain_absolute(path: &str) -> bool {
    path == "/"
        || path.strip_prefix('/').is_some_and(|rest| {
            rest.split('/')
                .all(|c| !c.is_empty() && c != "." && c != "..")
        })
}

fn check_executable(exe: &PinnedExecutable) -> Result<()> {
    if exe.path == "/" || !is_plain_absolute(&exe.path) {
        return Err(Error::MachineVault(
            "an executable is named by absolute path, with no . or .. in it",
        ));
    }
    match &exe.pin {
        ExecutablePin::CodeSigning {
            team_id,
            signing_id,
        } if team_id.is_empty() || signing_id.is_empty() => Err(Error::MachineVault(
            "a code-signing pin names a team and a signing identifier",
        )),
        ExecutablePin::Sha256(hash) if hash.len() != 32 => {
            Err(Error::MachineVault("a SHA-256 pin is 32 bytes"))
        }
        _ => Ok(()),
    }
}

fn check_limits(limits: &GrantLimits, created_at: u64) -> Result<()> {
    if limits.per_run == 0 || limits.total_uses == 0 {
        return Err(Error::MachineVault(
            "a grant allows at least one use per run and in total",
        ));
    }
    if limits.expires_at <= created_at || limits.expires_at - created_at > MAX_GRANT_LIFETIME_SECS {
        return Err(Error::MachineVault(
            "a grant expires after it is created, and within 90 days",
        ));
    }
    Ok(())
}

fn check_job(job: &Job) -> Result<()> {
    if job.name.trim().is_empty() || job.name.chars().count() > MAX_JOB_NAME_CHARS {
        return Err(Error::MachineVault(
            "a job has a name of 1 to 128 characters",
        ));
    }
    check_executable(&job.root)?;
    if let Some(browser) = &job.run_browser {
        check_executable(browser)?;
    }
    if !is_plain_absolute(&job.working_dir) {
        return Err(Error::MachineVault(
            "a job's working directory is an absolute path, with no . or .. in it",
        ));
    }
    if job.schedule.is_empty() {
        return Err(Error::MachineVault("a job runs at one time or more"));
    }
    for time in &job.schedule {
        let (ScheduleTime::Daily { hour, minute } | ScheduleTime::Weekly { hour, minute, .. }) =
            *time;
        if hour > 23 || minute > 59 {
            return Err(Error::MachineVault("a job's time is 00:00 to 23:59"));
        }
    }
    if job.run_deadline_secs == 0 || job.run_deadline_secs > MAX_RUN_DEADLINE_SECS {
        return Err(Error::MachineVault("a run lasts at most six hours"));
    }
    if job.catch_up_secs > MAX_CATCH_UP_SECS {
        return Err(Error::MachineVault("a catch-up window is at most one day"));
    }
    Ok(())
}

fn check_command_grant(
    grant: &CommandGrant,
    machine: &MachineSection,
    envs: &[Environment],
) -> Result<()> {
    if machine.job(grant.job).is_none() {
        return Err(Error::MachineVault(
            "a grant names a job of this machine vault",
        ));
    }
    let env = envs
        .iter()
        .find(|e| e.id == grant.env)
        .ok_or(Error::MachineVault(
            "a command grant names an environment of this machine vault",
        ))?;
    if grant.variables.is_empty() || !grant.variables.iter().all(|v| env.var(v).is_some()) {
        return Err(Error::MachineVault(
            "a command grant names one or more variables of its environment",
        ));
    }
    check_executable(&grant.executable)?;
    if !is_plain_absolute(&grant.working_dir) {
        return Err(Error::MachineVault(
            "a grant's working directory is an absolute path, with no . or .. in it",
        ));
    }
    if !grant
        .pinned_inputs
        .iter()
        .all(|input| is_plain_absolute(&input.path) && input.sha256.len() == 32)
    {
        return Err(Error::MachineVault(
            "a pinned input is an absolute path with a 32-byte SHA-256",
        ));
    }
    if grant.timeout_secs == 0 || grant.timeout_secs > MAX_RUN_DEADLINE_SECS {
        return Err(Error::MachineVault(
            "a command's timeout is at most six hours",
        ));
    }
    check_limits(&grant.limits, grant.created_at)
}

fn check_login_grant(grant: &LoginGrant, machine: &MachineSection, items: &[Item]) -> Result<()> {
    let job = machine.job(grant.job).ok_or(Error::MachineVault(
        "a grant names a job of this machine vault",
    ))?;
    if job.run_browser.is_none() {
        return Err(Error::MachineVault(
            "a job with a login grant declares a run browser",
        ));
    }
    let item = items
        .iter()
        .find(|i| i.id == grant.item)
        .filter(|i| i.category == Category::Login)
        .ok_or(Error::MachineVault(
            "a login grant names a Login item of this machine vault",
        ))?;
    if !is_canonical_https_origin(&grant.origin) || !item.urls.contains(&grant.origin) {
        return Err(Error::MachineVault(
            "a login grant's origin is one of its item's websites",
        ));
    }
    if !grant
        .follow_on_origins
        .iter()
        .all(|o| is_canonical_https_origin(o))
    {
        return Err(Error::MachineVault(
            "a follow-on origin is an exact https origin",
        ));
    }
    let fields: BTreeSet<_> = grant.fields.iter().collect();
    if fields.is_empty() || fields.len() != grant.fields.len() {
        return Err(Error::MachineVault(
            "a login grant names each field it fills once",
        ));
    }
    if fields.contains(&LoginField::OneTimeCode)
        && (!grant.one_time_codes || item.totp_field().is_none())
    {
        return Err(Error::MachineVault(
            "a one-time code is filled only with the switch on, from the item's own setup",
        ));
    }
    check_limits(&grant.limits, grant.created_at)
}

fn check_records(machine: &MachineSection, items: &[Item], envs: &[Environment]) -> Result<()> {
    let mut job_ids = BTreeSet::new();
    for job in &machine.jobs {
        if !job_ids.insert(job.id) {
            return Err(Error::MachineVault("two jobs have the same id"));
        }
        check_job(job)?;
    }
    let mut grant_ids = BTreeSet::new();
    for grant in &machine.command_grants {
        if !grant_ids.insert(grant.id) {
            return Err(Error::MachineVault("two grants have the same id"));
        }
        check_command_grant(grant, machine, envs)?;
    }
    for grant in &machine.login_grants {
        if !grant_ids.insert(grant.id) {
            return Err(Error::MachineVault("two grants have the same id"));
        }
        check_login_grant(grant, machine, items)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_canonicalized_or_refused() {
        for (input, expected) in [
            ("https://example.com", "https://example.com"),
            ("HTTPS://Example.COM/", "https://example.com"),
            ("https://example.com:443", "https://example.com"),
            ("https://example.com:8443/", "https://example.com:8443"),
            (
                "https://xn--bcher-kva.example",
                "https://xn--bcher-kva.example",
            ),
            ("https://[::1]:8443", "https://[::1]:8443"),
            ("https://10.0.0.1", "https://10.0.0.1"),
        ] {
            assert_eq!(canonical_https_origin(input).unwrap(), expected, "{input}");
        }
        for bad in [
            "http://example.com",
            "example.com",
            "https://",
            "https://example.com/login",
            "https://example.com?x=1",
            "https://example.com#top",
            "https://user@example.com",
            "https://*.example.com",
            "https://exa mple.com",
            "https://example..com",
            "https://example.com:0",
            "https://example.com:99999",
            "https://example.com:",
            "https://b\u{fc}cher.example",
        ] {
            assert!(canonical_https_origin(bad).is_err(), "{bad}");
        }
        assert!(is_canonical_https_origin("https://example.com"));
        assert!(!is_canonical_https_origin("https://example.com/"));
        assert!(!is_canonical_https_origin("https://Example.com"));
    }

    #[test]
    fn the_keychain_bytes_round_trip_and_debug_shows_no_key() {
        let key = MachineVaultKey::generate().unwrap();
        let bytes = key.to_keychain_bytes();
        assert_eq!(bytes.len(), KEYCHAIN_BYTES_LEN);
        let back = MachineVaultKey::from_keychain_bytes(&bytes).unwrap();
        assert!(back.same_key(&key));
        assert!(MachineVaultKey::from_keychain_bytes(&bytes[1..]).is_err());

        let rendered = format!("{key:?} {key:#?}");
        let key_hex: String = key
            .key()
            .expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!rendered.contains(&key_hex), "{rendered}");
        assert!(rendered.contains("vault_id"), "{rendered}");
    }

    #[test]
    fn the_machine_vault_sits_beside_the_personal_one() {
        assert_eq!(
            machine_vault_path(Path::new("/data/vault.kagivault")),
            Path::new("/data/vault.machine.kagivault")
        );
    }

    #[test]
    fn plain_absolute_paths() {
        assert!(is_plain_absolute("/usr/bin/env"));
        assert!(is_plain_absolute("/"));
        for bad in [
            "usr/bin",
            "/usr/../bin",
            "/usr/./bin",
            "/usr//bin",
            "/usr/bin/",
            "",
        ] {
            assert!(!is_plain_absolute(bad), "{bad}");
        }
    }

    fn job(id: JobId) -> Job {
        Job {
            id,
            name: "nightly".to_owned(),
            root: PinnedExecutable {
                path: "/bin/true".to_owned(),
                pin: ExecutablePin::Sha256(vec![0; 32]),
            },
            args: Vec::new(),
            working_dir: "/".to_owned(),
            schedule: vec![ScheduleTime::Daily { hour: 1, minute: 0 }],
            run_deadline_secs: DEFAULT_RUN_DEADLINE_SECS,
            catch_up_secs: 0,
            run_browser: None,
            created_at: 1,
            presence: PresencePath::Confirmed,
            unknown: BTreeMap::new(),
        }
    }

    #[test]
    fn removing_a_job_removes_its_grants_and_a_strike_suspends_them_all() {
        let id = JobId::new();
        let mut section = MachineSection::default();
        section.jobs.push(job(id));
        section.login_grants.push(LoginGrant {
            id: GrantId::new(),
            job: id,
            item: ItemId::new(),
            fields: vec![LoginField::Password],
            origin: "https://example.com".to_owned(),
            follow_on_origins: Vec::new(),
            one_time_codes: false,
            limits: GrantLimits::defaults(1),
            uses: 0,
            created_at: 1,
            approved_at: 1,
            presence: PresencePath::Confirmed,
            suspended: None,
            unknown: BTreeMap::new(),
        });
        section.suspend_job(id, 5, "NO_GRANT");
        section.suspend_job(id, 9, "PIN_CHANGED");
        let suspension = section.login_grants[0].suspended.as_ref().unwrap();
        assert_eq!((suspension.at, suspension.reason.as_str()), (5, "NO_GRANT"));
        assert!(section.remove_job(id).is_some());
        assert!(section.login_grants.is_empty());
        assert!(section.remove_job(id).is_none());
    }
}
