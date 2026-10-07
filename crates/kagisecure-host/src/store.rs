//! The state directory: the bundle as received, what each grant has used, suspensions, and the
//! audit log. Owned by the service account, `0700` (systemd's `StateDirectory=`).
//!
//! The bundle is kept exactly as the Mac signed it and is verified again on every request, so the
//! credentials at rest are the sealed payload — no second copy, no second format. The mutable
//! state beside it (`state.json`) holds no value.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{HostError, Result, io};

/// The bundle, as imported.
pub const BUNDLE_FILE: &str = "bundle.kgsb";
/// Uses, suspensions and the imported sequence.
pub const STATE_FILE: &str = "state.json";
/// One JSON object per line; never a value.
pub const AUDIT_FILE: &str = "audit.log";

/// The default state directory.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/kagisecure-host";

/// A suspension (ADR-0042 §7): the grant answers nothing until a new bundle is imported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suspended {
    /// Unix seconds.
    pub at: u64,
    /// `PIN_CHANGED`, `ARGUMENTS_MISMATCH`, ...
    pub reason: String,
}

/// One grant's mutable state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantState {
    /// Releases so far.
    pub uses: u32,
    /// Set while suspended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspended: Option<Suspended>,
}

/// `state.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The imported bundle's sequence.
    pub sequence: Option<u64>,
    /// By grant name.
    #[serde(default)]
    pub grants: BTreeMap<String, GrantState>,
}

/// The state directory.
#[derive(Clone, Debug)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// The store at `dir`.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Its directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Create the directory, `0700`, if it does not exist.
    ///
    /// # Errors
    ///
    /// If it cannot be created.
    pub fn ensure_dir(&self) -> Result<()> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder
            .create(&self.dir)
            .map_err(io(format!("creating {}", self.dir.display())))
    }

    /// The imported bundle's bytes, if any.
    ///
    /// # Errors
    ///
    /// If it exists and cannot be read.
    pub fn bundle(&self) -> Result<Option<Vec<u8>>> {
        let path = self.dir.join(BUNDLE_FILE);
        match std::fs::read(&path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(HostError::Io {
                what: format!("reading {}", path.display()),
                source: e,
            }),
        }
    }

    /// Replace the bundle and reset the state to `sequence` with no uses and no suspensions.
    ///
    /// # Errors
    ///
    /// If either file cannot be written.
    pub fn replace_bundle(&self, bytes: &[u8], sequence: u64) -> Result<()> {
        write_atomic(&self.dir.join(BUNDLE_FILE), bytes)?;
        self.save_state(&State {
            sequence: Some(sequence),
            grants: BTreeMap::new(),
        })
    }

    /// `state.json`, or the empty state.
    ///
    /// # Errors
    ///
    /// If it exists and cannot be read or parsed.
    pub fn state(&self) -> Result<State> {
        let path = self.dir.join(STATE_FILE);
        match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| HostError::Invalid(format!("{} is malformed: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(HostError::Io {
                what: format!("reading {}", path.display()),
                source: e,
            }),
        }
    }

    /// Write `state.json`.
    ///
    /// # Errors
    ///
    /// If it cannot be written.
    pub fn save_state(&self, state: &State) -> Result<()> {
        let json = serde_json::to_vec_pretty(state)
            .map_err(|e| HostError::Invalid(format!("cannot encode the state: {e}")))?;
        write_atomic(&self.dir.join(STATE_FILE), &json)
    }

    /// Append one audit entry and flush it to disk before returning — a release happens only
    /// after its entry is durable (ADR-0040).
    ///
    /// # Errors
    ///
    /// If the entry cannot be written.
    pub fn audit(&self, grant: &str, event: &str, detail: &str) -> Result<()> {
        let line = serde_json::json!({
            "at": kagisecure_core::unix_now(),
            "grant": grant,
            "event": event,
            "detail": detail,
        });
        let path = self.dir.join(AUDIT_FILE);
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(io(format!("opening {}", path.display())))?;
        writeln!(file, "{line}")
            .and_then(|()| file.sync_data())
            .map_err(io(format!("writing {}", path.display())))
    }

    /// The audit log's lines.
    ///
    /// # Errors
    ///
    /// If it exists and cannot be read.
    pub fn audit_lines(&self) -> Result<Vec<String>> {
        let path = self.dir.join(AUDIT_FILE);
        match std::fs::read_to_string(&path) {
            Ok(s) => Ok(s.lines().map(str::to_owned).collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(HostError::Io {
                what: format!("reading {}", path.display()),
                source: e,
            }),
        }
    }
}

/// Write `bytes` to `path` through a temporary file in the same directory, `0600`, synced, then
/// renamed over it.
///
/// # Errors
///
/// If any step fails.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(io(format!("creating {}", tmp.display())))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(io(format!("writing {}", tmp.display())))?;
    std::fs::rename(&tmp, path).map_err(io(format!("replacing {}", path.display())))
}
