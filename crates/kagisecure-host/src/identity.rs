//! The host's key pair and the owner it trusts (ADR-0043, accepted scope §A2).
//!
//! The host's key pair is a shared-vault device key (X25519 for sealing, Ed25519 for identity):
//! bundles are sealed to it. It rests in one of two places, tried in order:
//!
//! 1. `$CREDENTIALS_DIRECTORY/kagisecure-host.key` — a systemd credential. With
//!    `LoadCredentialEncrypted=` and `systemd-creds encrypt --with-key=host+tpm2`, the key is
//!    sealed by the TPM, and kagisecure has no TPM code of its own (optional).
//! 2. `<state>/host.key` — a file, `0600`, owned by the service account (the default). Anything
//!    that can read it as that account, or as root, holds every value bundled for this host.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use kagisecure_core::model::Secret;
use kagisecure_core::vault::device::{DeviceKey, SUITE_X25519_ED25519_V1};
use kagisecure_shared::{DevicePublic, DeviceSecret};

use crate::{HostError, Result, hex, io, unhex};

/// The key file's name, in the state directory and in a credentials directory.
pub const KEY_FILE: &str = "host.key";
/// The systemd credential's name.
pub const CREDENTIAL_NAME: &str = "kagisecure-host.key";
/// The trusted owner's public key, hex of its CBOR, in the state directory.
pub const OWNER_FILE: &str = "owner.pub";

const KEY_MAGIC: &[u8; 8] = b"KGSHK\0\0\x01";

/// Where the key was found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// A systemd credential.
    Credential(PathBuf),
    /// The state directory's key file.
    File(PathBuf),
}

/// Create a new key pair and write it to `<state>/host.key`, `0600`, refusing to replace one.
///
/// # Errors
///
/// If the file exists, or cannot be written.
pub fn create(state: &Path) -> Result<DeviceSecret> {
    let secret = DeviceSecret::generate()?;
    let key = secret.to_device_key("kagisecure-host", kagisecure_core::unix_now())?;
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(8 + 32 + 64));
    bytes.extend_from_slice(KEY_MAGIC);
    bytes.extend_from_slice(key.id());
    bytes.extend_from_slice(key.secret_keys().expose());
    let path = state.join(KEY_FILE);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(io(format!("creating {}", path.display())))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(io(format!("writing {}", path.display())))?;
    Ok(secret)
}

/// Load the host's key pair: the systemd credential if there is one, else the key file.
///
/// # Errors
///
/// If neither exists, the file is readable by anyone but its owner, or it is malformed.
pub fn load(state: &Path) -> Result<(DeviceSecret, KeySource)> {
    if let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        let path = Path::new(&dir).join(CREDENTIAL_NAME);
        if path.exists() {
            return Ok((read_key(&path)?, KeySource::Credential(path)));
        }
    }
    let path = state.join(KEY_FILE);
    check_private(&path)?;
    Ok((read_key(&path)?, KeySource::File(path)))
}

#[cfg(unix)]
fn check_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(path).map_err(io(format!(
        "reading {} (run `kagisecure-host init` first)",
        path.display()
    )))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(HostError::Invalid(format!(
            "{} is readable by other accounts; it must be 0600",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path) -> Result<()> {
    Ok(())
}

fn read_key(path: &Path) -> Result<DeviceSecret> {
    let bytes = zeroize::Zeroizing::new(
        std::fs::read(path).map_err(io(format!("reading {}", path.display())))?,
    );
    if bytes.len() != 8 + 32 + 64 || &bytes[..8] != KEY_MAGIC {
        return Err(HostError::Invalid(format!(
            "{} is not a kagisecure-host key",
            path.display()
        )));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes[8..40]);
    let key = DeviceKey::new(
        id,
        SUITE_X25519_ED25519_V1,
        "kagisecure-host",
        0,
        Secret::new(bytes[40..].to_vec()),
    )?;
    Ok(DeviceSecret::from_device_key(&key)?)
}

/// A device's public keys as printed for a person to copy: hex of their CBOR.
#[must_use]
pub fn public_to_text(public: &DevicePublic) -> String {
    hex(&public.to_cbor())
}

/// Parse what [`public_to_text`] printed.
///
/// # Errors
///
/// If it is not hex, or not a device's public keys.
pub fn public_from_text(text: &str) -> Result<DevicePublic> {
    let bytes = unhex(text)
        .ok_or_else(|| HostError::Invalid("a public key is printed as hex".to_owned()))?;
    Ok(DevicePublic::from_cbor(&bytes)?)
}

/// Record `owner` as the one device whose bundles this host accepts.
///
/// # Errors
///
/// If the file cannot be written.
pub fn trust_owner(state: &Path, owner: &DevicePublic) -> Result<()> {
    crate::store::write_atomic(
        &state.join(OWNER_FILE),
        format!("{}\n", public_to_text(owner)).as_bytes(),
    )
}

/// The owner this host trusts.
///
/// # Errors
///
/// If none is recorded, or the file is malformed.
pub fn owner(state: &Path) -> Result<DevicePublic> {
    let path = state.join(OWNER_FILE);
    let text = std::fs::read_to_string(&path).map_err(io(format!(
        "reading {} (give `kagisecure-host init --owner`)",
        path.display()
    )))?;
    public_from_text(&text)
}
