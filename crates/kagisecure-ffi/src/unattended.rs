//! Unattended jobs, for the app (ADR-0042 Phase 3's calls, built with Phase 2's engine).
//!
//! # What crosses this boundary
//!
//! Metadata, and **one secret**: the machine vault's key, as the 48 bytes
//! [`unattended_arm`] returns and [`unattended_resume`] takes back, so that the app can keep it in
//! the login Keychain while the machine vault is armed and re-arm after a restart with nobody
//! present (ADR-0042 implementation decisions 1 and 5). That is the crossing ADR-0008's pointer of
//! 2026-09-27 records. The app must store the bytes this-device-only and never synchronized, and
//! delete the Keychain item on every disarm.

use std::sync::{Arc, Mutex};

use kagisecure_agent::unattended::UnattendedNotice;
use kagisecure_agent::{UnattendedConfig, UnattendedEngine, UnattendedError, VaultHandle};
use kagisecure_core::vault::machine::{JobId, PresencePath, machine_vault_path};
use kagisecure_core::vault::{MachineVaultKey, Vault};

use crate::session::VaultSession;
use crate::{FfiError, FfiResult};

/// The one engine this process may run.
static ENGINE: Mutex<Option<UnattendedEngine>> = Mutex::new(None);

fn engine() -> std::sync::MutexGuard<'static, Option<UnattendedEngine>> {
    ENGINE.lock().unwrap_or_else(|e| e.into_inner())
}

fn unattended_error(e: UnattendedError) -> FfiError {
    match e {
        UnattendedError::Core(core) => FfiError::from(core),
        other => FfiError::Invalid {
            message: other.to_string(),
        },
    }
}

/// Which presence proof authorized an arm (ADR-0038's vocabulary).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum UnattendedPresence {
    /// Touch ID, an Apple Watch, or the login password through LocalAuthentication.
    Confirmed,
    /// The master-password fallback.
    ConfirmedMasterPassword,
}

/// One live run.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnattendedRunView {
    /// The run's number.
    pub id: u64,
    /// The job's name.
    pub job: String,
    /// The root's pid.
    pub root_pid: u32,
    /// Unix seconds.
    pub started_at: u64,
}

/// The engine's state, for the menu bar and Agent access.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnattendedStatusView {
    /// Whether the engine is running at all.
    pub running: bool,
    /// Whether the machine vault is armed.
    pub armed: bool,
    /// When it was armed, Unix seconds.
    pub armed_at: Option<u64>,
    /// Where the unattended socket is.
    pub endpoint: String,
    /// Live runs.
    pub runs: Vec<UnattendedRunView>,
}

/// Something to tell the owner now, as a local notification. Never a value or a command line.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UnattendedNoticeView {
    /// `SUSPENDED`, `DISARMED`, `JOB_MISSED` or `JOB_NOT_STARTED`.
    pub kind: String,
    /// The job's name, when it is about one.
    pub job: Option<String>,
    /// Why.
    pub reason: String,
}

impl From<UnattendedNotice> for UnattendedNoticeView {
    fn from(n: UnattendedNotice) -> Self {
        Self {
            kind: n.kind,
            job: n.job,
            reason: n.reason,
        }
    }
}

/// Where the machine vault of the personal vault at `vault_path` lives.
#[uniffi::export]
#[must_use]
pub fn unattended_machine_vault_path(vault_path: String) -> String {
    machine_vault_path(std::path::Path::new(&vault_path))
        .to_string_lossy()
        .into_owned()
}

/// Create this personal vault's machine vault, if it has none: a new key in the personal body
/// and a new machine vault file beside it. Returns whether one was created.
///
/// # Errors
///
/// [`FfiError`] when the personal vault is locked or either write fails.
#[uniffi::export]
pub fn unattended_create_machine_vault(session: Arc<VaultSession>) -> FfiResult<bool> {
    let handle = session.handle();
    let path = handle
        .with(|v| (v.machine_vault_key().is_some(), v.path().to_path_buf()))
        .ok_or_else(|| FfiError::invalid("The vault is locked."))?;
    if path.0 {
        return Ok(false);
    }
    let machine_path = machine_vault_path(&path.1);
    let key = MachineVaultKey::generate()?;
    let machine = Vault::create_machine(&machine_path, &key, "Machine")?;
    drop(machine);
    handle
        .transact(kagisecure_agent::vault::REQUEST_LOCK_TIMEOUT, |tx| {
            tx.set_machine_vault_key(key, "app")
        })
        .ok_or_else(|| FfiError::invalid("The vault is locked."))??;
    Ok(true)
}

/// Start the engine for the machine vault at `machine_path`, disarmed. `socket_path` overrides
/// where the unattended socket goes (beside `daemon.sock` by default). Returns the endpoint.
///
/// # Errors
///
/// [`FfiError::Invalid`] when it is already running or the socket cannot be bound.
#[uniffi::export]
pub fn unattended_start(machine_path: String, socket_path: Option<String>) -> FfiResult<String> {
    let mut slot = engine();
    if let Some(existing) = slot.as_ref() {
        return Err(FfiError::invalid(format!(
            "Unattended jobs are already served on {}.",
            existing.endpoint()
        )));
    }
    let endpoint = match socket_path {
        Some(p) => Some(
            kagisecure_agent::Endpoint::parse(std::ffi::OsStr::new(&p))
                .map_err(|e| FfiError::invalid(e.to_string()))?,
        ),
        None => None,
    };
    let config = UnattendedConfig {
        endpoint,
        ..UnattendedConfig::new(machine_path.into())
    };
    let started = UnattendedEngine::start(&config).map_err(|e| FfiError::invalid(e.to_string()))?;
    let endpoint = started.endpoint();
    *slot = Some(started);
    Ok(endpoint)
}

/// Stop the engine: runs end, the socket closes. The arm stays recorded, so the next launch
/// resumes it.
#[uniffi::export]
pub fn unattended_stop() {
    if let Some(mut existing) = engine().take() {
        existing.stop();
    }
}

/// Arm, after the app's presence proof `presence`, creating the machine vault first when this
/// personal vault has none. Returns the machine vault key's 48 bytes for the app to store in the
/// Keychain (this device only, never synchronized).
///
/// # Errors
///
/// [`FfiError`] when the engine is not running, the personal vault is locked, or the machine
/// vault cannot be created, opened or written.
#[uniffi::export]
pub fn unattended_arm(
    session: Arc<VaultSession>,
    presence: UnattendedPresence,
) -> FfiResult<Vec<u8>> {
    let slot = engine();
    let engine = slot
        .as_ref()
        .ok_or_else(|| FfiError::invalid("Unattended jobs are not running."))?;
    // Arming a vault that has no machine vault yet creates it first (the owner's convenience):
    // the first arm is also the first use.
    unattended_create_machine_vault(Arc::clone(&session))?;
    let presence = match presence {
        UnattendedPresence::Confirmed => PresencePath::Confirmed,
        UnattendedPresence::ConfirmedMasterPassword => PresencePath::ConfirmedMasterPassword,
    };
    let bytes = engine
        .arm(&session.handle(), presence, "app")
        .map_err(unattended_error)?;
    Ok(bytes.to_vec())
}

/// Arm again from the Keychain's bytes, at launch. `false` when the machine vault is not armed
/// any more: delete the Keychain item.
///
/// # Errors
///
/// [`FfiError`] when the engine is not running or the bytes do not open the machine vault.
#[uniffi::export]
pub fn unattended_resume(keychain: Vec<u8>) -> FfiResult<bool> {
    let keychain = zeroizing(keychain);
    let slot = engine();
    let engine = slot
        .as_ref()
        .ok_or_else(|| FfiError::invalid("Unattended jobs are not running."))?;
    engine.resume(&keychain).map_err(unattended_error)
}

/// The Keychain's bytes, in a buffer that is wiped when dropped.
fn zeroizing(bytes: Vec<u8>) -> kagisecure_core::vault::machine::KeychainBytes {
    kagisecure_core::vault::machine::KeychainBytes::new(bytes)
}

/// Disarm (Pause). Needs no presence proof. Records it in the personal log too when `session`
/// is unlocked. Delete the Keychain item whatever this returns.
#[uniffi::export]
pub fn unattended_disarm(session: Option<Arc<VaultSession>>) -> bool {
    let personal = session.map(|s| s.handle());
    engine()
        .as_ref()
        .is_some_and(|e| e.disarm(personal.as_deref(), "app"))
}

/// The engine's state.
#[uniffi::export]
#[must_use]
pub fn unattended_status() -> UnattendedStatusView {
    match engine().as_ref() {
        None => UnattendedStatusView {
            running: false,
            armed: false,
            armed_at: None,
            endpoint: String::new(),
            runs: Vec::new(),
        },
        Some(e) => {
            let status = e.status();
            UnattendedStatusView {
                running: true,
                armed: status.armed,
                armed_at: status.armed_at,
                endpoint: status.endpoint,
                runs: status
                    .runs
                    .into_iter()
                    .map(|r| UnattendedRunView {
                        id: r.id,
                        job: r.job,
                        root_pid: r.root_pid,
                        started_at: r.started_at,
                    })
                    .collect(),
            }
        }
    }
}

/// Start `job_id` now ("Run now"). Returns the run's number.
///
/// # Errors
///
/// [`FfiError::Invalid`] when not armed, no such job, already running, or it cannot start.
#[uniffi::export]
pub fn unattended_run_now(job_id: String) -> FfiResult<u64> {
    let id: JobId = job_id
        .parse()
        .map_err(|_| FfiError::invalid("Not a job id."))?;
    engine()
        .as_ref()
        .ok_or_else(|| FfiError::invalid("Unattended jobs are not running."))?
        .run_now(id)
        .map_err(unattended_error)
}

/// What happened since the app last asked, for notifications.
#[uniffi::export]
#[must_use]
pub fn unattended_take_notices() -> Vec<UnattendedNoticeView> {
    engine().as_ref().map_or_else(Vec::new, |e| {
        e.take_notices().into_iter().map(Into::into).collect()
    })
}

/// Open this personal vault's machine vault for the ordinary socket (ADR-0042 §2): machine
/// environments are then listed and served beside the personal vault's, each release with the
/// ordinary sheet and presence proof. Call after [`crate::agent_start`]; a lock of the personal
/// vault drops it. Returns whether one was attached.
///
/// # Errors
///
/// [`FfiError`] when the machine vault cannot be opened.
#[uniffi::export]
pub fn agent_attach_machine_vault(session: Arc<VaultSession>) -> FfiResult<bool> {
    let handle = session.handle();
    let opened = handle
        .with(|v| {
            v.machine_vault_key().map(|key| {
                let path = machine_vault_path(v.path());
                Vault::open_machine(path, key)
            })
        })
        .flatten();
    let Some(opened) = opened else {
        return Ok(false);
    };
    let machine = VaultHandle::new(opened?);
    Ok(crate::agent::attach_machine_vault(Some(machine)))
}
