//! The grants file the owner writes on the Mac for `kagisecure host-bundle export`.
//!
//! ```json
//! { "grants": [ {
//!     "name": "deploy-staging",
//!     "variables": ["ITSUSTAR_DEPLOY_SSH_KEY"],
//!     "command": ["/home/deploy/app/infra/deploy/deploy", "staging", "{commit}", "--key-from-stdin"],
//!     "working_dir": "/home/deploy/app",
//!     "run_as": "deploy",
//!     "hash_from": "/Users/me/Workspace/app/infra/deploy/deploy"
//! } ] }
//! ```
//!
//! `{commit}` is the one pattern ([`ArgPattern::CommitSha`]); every other argument is literal.
//! The executable is pinned by `executable_sha256` (hex) or, more conveniently, by hashing a copy
//! of the same file on the Mac (`hash_from`) — the same commit of the same repository has the
//! same bytes.

use std::path::{Path, PathBuf};

use kagisecure_core::vault::machine::{
    DEFAULT_RUN_DEADLINE_SECS, ExecutablePin, GrantLimits, MAX_GRANT_LIFETIME_SECS,
    PinnedExecutable, file_sha256,
};
use serde::Deserialize;

use crate::grant::{ArgPattern, HostGrant};
use crate::{HostError, Result, unhex};

/// The literal that stands for [`ArgPattern::CommitSha`].
pub const COMMIT_PLACEHOLDER: &str = "{commit}";

const DEFAULT_TOTAL_USES: u32 = 500;
const DEFAULT_EXPIRES_IN_DAYS: u64 = 90;

/// A grants file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantsFile {
    /// The grants.
    pub grants: Vec<GrantSpec>,
}

/// One grant as the owner writes it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSpec {
    /// Its name.
    pub name: String,
    /// Variables of the environment, written to standard input in this order.
    pub variables: Vec<String>,
    /// The command line as it will be run on the host, the executable first.
    pub command: Vec<String>,
    /// The working directory on the host.
    pub working_dir: String,
    /// The account on the host the command runs as.
    #[serde(default)]
    pub run_as: Option<String>,
    /// The executable's SHA-256, hex.
    #[serde(default)]
    pub executable_sha256: Option<String>,
    /// A local copy of the executable to hash instead.
    #[serde(default)]
    pub hash_from: Option<PathBuf>,
    /// Deadline, seconds (default 30 minutes).
    #[serde(default)]
    pub timeout_secs: Option<u32>,
    /// Total uses (default 500).
    #[serde(default)]
    pub total_uses: Option<u32>,
    /// Days until it expires, at most 90 (the default).
    #[serde(default)]
    pub expires_in_days: Option<u64>,
}

impl GrantsFile {
    /// Read and parse `path`.
    ///
    /// # Errors
    ///
    /// If it cannot be read or is not a grants file.
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(crate::io(format!("reading {}", path.display())))?;
        serde_json::from_str(&text).map_err(|e| {
            HostError::Invalid(format!("{} is not a grants file: {e}", path.display()))
        })
    }
}

impl GrantSpec {
    /// The grant, for `environment`, created at `now`. Relative `hash_from` paths resolve
    /// against `base`.
    ///
    /// # Errors
    ///
    /// For a spec that cannot become a grant: no command, no pin or two, an unreadable file.
    pub fn to_grant(&self, environment: &str, now: u64, base: &Path) -> Result<HostGrant> {
        let bad = |m: &str| HostError::Invalid(format!("grant {:?}: {m}", self.name));
        let Some((exe, args)) = self.command.split_first() else {
            return Err(bad("the command is empty"));
        };
        let hash = match (&self.executable_sha256, &self.hash_from) {
            (Some(hex), None) => unhex(hex)
                .filter(|h| h.len() == 32)
                .ok_or_else(|| bad("executable_sha256 must be 64 hex characters"))?,
            (None, Some(path)) => {
                let path = base.join(path);
                file_sha256(&path)
                    .map_err(|e| bad(&format!("cannot hash {}: {e}", path.display())))?
                    .to_vec()
            }
            _ => return Err(bad("give exactly one of executable_sha256 and hash_from")),
        };
        let days = self.expires_in_days.unwrap_or(DEFAULT_EXPIRES_IN_DAYS);
        let lifetime = days.saturating_mul(24 * 60 * 60);
        if days == 0 || lifetime > MAX_GRANT_LIFETIME_SECS {
            return Err(bad("expires_in_days must be 1 to 90"));
        }
        Ok(HostGrant {
            name: self.name.clone(),
            environment: environment.to_owned(),
            variables: self.variables.clone(),
            executable: PinnedExecutable {
                path: exe.clone(),
                pin: ExecutablePin::Sha256(hash),
            },
            args: args
                .iter()
                .map(|a| {
                    if a == COMMIT_PLACEHOLDER {
                        ArgPattern::CommitSha
                    } else {
                        ArgPattern::Literal(a.clone())
                    }
                })
                .collect(),
            working_dir: self.working_dir.clone(),
            run_as: self.run_as.clone(),
            timeout_secs: self.timeout_secs.unwrap_or(DEFAULT_RUN_DEADLINE_SECS),
            limits: GrantLimits {
                per_run: 1,
                total_uses: self.total_uses.unwrap_or(DEFAULT_TOTAL_USES),
                expires_at: now + lifetime,
            },
            created_at: now,
        })
    }
}
