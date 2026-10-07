//! What a host bundle carries (ADR-0043 §7), and making and opening one.
//!
//! The envelope — sealed to the host, signed by the owner's device — is
//! [`kagisecure_shared::host_bundle`]; this is its payload, deterministic CBOR of
//! [`BundleContents`]. A bundle is **complete**: importing it replaces every environment and grant
//! the host held, and resets every grant's uses and suspension, because re-signing is the owner
//! approving the grant again.

use std::collections::BTreeSet;

use kagisecure_core::proto::VarName;
use kagisecure_core::vault::machine::{
    ExecutablePin, MAX_GRANT_LIFETIME_SECS, MAX_JOB_NAME_CHARS, MAX_RUN_DEADLINE_SECS, PresencePath,
};
use kagisecure_shared::{DevicePublic, DeviceSecret, host_bundle};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::grant::HostGrant;
use crate::{HostError, Result};

/// The payload format this build writes and reads.
pub const CONTENTS_VERSION: u32 = 1;

/// A credential value inside a bundle. Wiped on drop; its `Debug` shows only its length.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Value(#[serde(with = "serde_bytes")] Vec<u8>);

impl Value {
    /// Wrap bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes. Only the release path reads them.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Value({} bytes)", self.0.len())
    }
}

/// One variable of a bundled environment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleVariable {
    /// Its name.
    pub name: String,
    /// Its value.
    pub value: Value,
}

/// A machine-vault environment, copied for one host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleEnvironment {
    /// The environment's name on the Mac.
    pub name: String,
    /// Its variables: only those some grant in the bundle releases.
    pub variables: Vec<BundleVariable>,
}

/// Everything a bundle carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleContents {
    /// [`CONTENTS_VERSION`].
    pub v: u32,
    /// The host's name, as the owner called it on the Mac.
    pub host_name: String,
    /// Unix seconds.
    pub created_at: u64,
    /// The presence proof the Mac took before signing.
    pub presence: PresencePath,
    /// Environments.
    pub environments: Vec<BundleEnvironment>,
    /// Grants.
    pub grants: Vec<HostGrant>,
}

impl BundleContents {
    /// Check everything a host relies on: names, references, pins, limits.
    ///
    /// # Errors
    ///
    /// [`HostError::Invalid`], saying what is wrong.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(HostError::Invalid(m));
        if self.v != CONTENTS_VERSION {
            return bad(format!(
                "bundle contents version {} is not supported",
                self.v
            ));
        }
        let mut env_names = BTreeSet::new();
        for env in &self.environments {
            if !env_names.insert(env.name.as_str()) {
                return bad(format!("environment {:?} appears twice", env.name));
            }
            let mut vars = BTreeSet::new();
            for var in &env.variables {
                VarName::new(var.name.clone())?;
                if !vars.insert(var.name.as_str()) {
                    return bad(format!(
                        "variable {} appears twice in {:?}",
                        var.name, env.name
                    ));
                }
            }
        }
        let mut grant_names = BTreeSet::new();
        for g in &self.grants {
            if g.name.is_empty()
                || g.name.chars().count() > MAX_JOB_NAME_CHARS
                || !g
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                return bad(format!(
                    "grant name {:?} must be ASCII letters, digits, '-', '_' or '.'",
                    g.name
                ));
            }
            if !grant_names.insert(g.name.as_str()) {
                return bad(format!("grant {:?} appears twice", g.name));
            }
            let Some(env) = self.environments.iter().find(|e| e.name == g.environment) else {
                return bad(format!(
                    "grant {:?} names environment {:?}, which the bundle does not carry",
                    g.name, g.environment
                ));
            };
            if g.variables.is_empty() {
                return bad(format!("grant {:?} releases no variable", g.name));
            }
            for v in &g.variables {
                if !env.variables.iter().any(|ev| &ev.name == v) {
                    return bad(format!(
                        "grant {:?} releases {v}, which {:?} does not carry",
                        g.name, env.name
                    ));
                }
            }
            if !g.executable.path.starts_with('/') || !g.working_dir.starts_with('/') {
                return bad(format!(
                    "grant {:?}: the executable and the working directory must be absolute paths",
                    g.name
                ));
            }
            match &g.executable.pin {
                ExecutablePin::Sha256(h) if h.len() == 32 => {}
                _ => {
                    return bad(format!(
                        "grant {:?}: a host grant pins its executable by SHA-256",
                        g.name
                    ));
                }
            }
            if g.timeout_secs == 0 || g.timeout_secs > MAX_RUN_DEADLINE_SECS {
                return bad(format!(
                    "grant {:?}: the timeout must be 1 to {MAX_RUN_DEADLINE_SECS} seconds",
                    g.name
                ));
            }
            if g.limits.total_uses == 0
                || g.limits.expires_at <= g.created_at
                || g.limits.expires_at > g.created_at + MAX_GRANT_LIFETIME_SECS
            {
                return bad(format!(
                    "grant {:?}: at least one use, and an expiry within 90 days of its creation",
                    g.name
                ));
            }
            if let Some(user) = &g.run_as
                && (user.is_empty() || user.contains([':', '/', '\n']))
            {
                return bad(format!(
                    "grant {:?}: {user:?} is not an account name",
                    g.name
                ));
            }
        }
        // Only what some grant releases travels.
        for env in &self.environments {
            for var in &env.variables {
                let used = self.grants.iter().any(|g| {
                    g.environment == env.name && g.variables.iter().any(|v| v == &var.name)
                });
                if !used {
                    return bad(format!(
                        "{} in {:?} is released by no grant; a bundle carries only what its grants \
                         release",
                        var.name, env.name
                    ));
                }
            }
        }
        Ok(())
    }

    /// The environment called `name`.
    #[must_use]
    pub fn environment(&self, name: &str) -> Option<&BundleEnvironment> {
        self.environments.iter().find(|e| e.name == name)
    }

    /// The grant called `name`.
    #[must_use]
    pub fn grant(&self, name: &str) -> Option<&HostGrant> {
        self.grants.iter().find(|g| g.name == name)
    }

    fn to_cbor(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let mut out = zeroize::Zeroizing::new(Vec::new());
        ciborium::into_writer(self, &mut *out)
            .map_err(|e| HostError::Invalid(format!("cannot encode the bundle: {e}")))?;
        Ok(out)
    }
}

/// Validate `contents`, seal them to `host` and sign them as `owner` (the Mac's half).
///
/// # Errors
///
/// [`BundleContents::validate`]'s, and the envelope's.
pub fn make(
    owner: &DeviceSecret,
    host: &DevicePublic,
    sequence: u64,
    contents: &BundleContents,
) -> Result<Vec<u8>> {
    contents.validate()?;
    let payload = contents.to_cbor()?;
    Ok(host_bundle::seal_and_sign(owner, host, sequence, &payload)?)
}

/// A bundle that verified, opened and validated.
#[derive(Debug)]
pub struct Opened {
    /// Its sequence number.
    pub sequence: u64,
    /// What it carries.
    pub contents: BundleContents,
}

/// Verify `bytes` against `owner` for `host` (above `after_sequence`), open and validate it.
///
/// # Errors
///
/// The envelope's refusals, and [`HostError::Invalid`] for contents that do not validate.
pub fn open(
    bytes: &[u8],
    owner: &DevicePublic,
    host: &DeviceSecret,
    after_sequence: Option<u64>,
) -> Result<Opened> {
    let opened = host_bundle::verify_and_open(bytes, owner, host, after_sequence)?;
    let contents: BundleContents = ciborium::from_reader(opened.payload.as_slice())
        .map_err(|_| HostError::Invalid("the bundle's contents do not decode".to_owned()))?;
    contents.validate()?;
    Ok(Opened {
        sequence: opened.sequence,
        contents,
    })
}
