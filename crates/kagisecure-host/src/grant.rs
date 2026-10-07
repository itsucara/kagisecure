//! Host grants, and whether a request is exactly what one names (ADR-0043, accepted scope §A3).
//!
//! A host grant is ADR-0042's command grant with one widening and three narrowings:
//!
//! - **Widened:** an argument may be a pattern rather than a literal. The only pattern is
//!   [`ArgPattern::CommitSha`], a full 40-hex commit id, so that one grant covers "deploy this
//!   commit" for every commit without covering anything else.
//! - **Narrowed:** the executable is pinned by SHA-256 only; the values are delivered on standard
//!   input only (the ADR-0047 frame, the exception ADR-0043 makes to ADR-0047 §8); and the grant
//!   is named by the caller, so a request is matched against one grant, never searched for.

use std::path::Path;

use kagisecure_core::vault::machine::{ExecutablePin, GrantLimits, PinnedExecutable, file_sha256};
use serde::{Deserialize, Serialize};

/// One argument of a granted command line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgPattern {
    /// Exactly this string.
    Literal(String),
    /// A full commit id: exactly 40 lower-case hex digits.
    CommitSha,
}

impl ArgPattern {
    /// Whether `arg` matches.
    #[must_use]
    pub fn matches(&self, arg: &str) -> bool {
        match self {
            Self::Literal(s) => s == arg,
            Self::CommitSha => {
                arg.len() == 40 && arg.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            }
        }
    }

    /// The pattern as written in a grants file: the literal, or `{commit}`.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Literal(s) => s.clone(),
            Self::CommitSha => "{commit}".to_owned(),
        }
    }
}

/// A standing grant for one exact command on one host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostGrant {
    /// The name a caller asks for it by, e.g. `deploy-staging`.
    pub name: String,
    /// The bundled environment its values come from.
    pub environment: String,
    /// The variables written to the command's standard input, in this order.
    pub variables: Vec<String>,
    /// The executable, by absolute path, pinned by SHA-256.
    pub executable: PinnedExecutable,
    /// The arguments after the executable, one pattern each, all of them.
    pub args: Vec<ArgPattern>,
    /// Absolute working directory, matched exactly after resolving symbolic links.
    pub working_dir: String,
    /// The account the command runs as; `None` for the host's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as: Option<String>,
    /// The command's deadline, in seconds.
    pub timeout_secs: u32,
    /// Total uses and expiry (`per_run` is unused on a host: every request is one run).
    pub limits: GrantLimits,
    /// Unix seconds.
    pub created_at: u64,
}

/// Why a request is not what its grant names. A mismatch is a strike: the grant is suspended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mismatch {
    /// The first element of the argument vector is not the executable's path.
    Executable,
    /// The arguments differ in number or do not match their patterns.
    Arguments,
    /// The working directory is not the grant's.
    WorkingDir,
}

impl Mismatch {
    /// For the audit log and the refusal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Executable => "EXECUTABLE_MISMATCH",
            Self::Arguments => "ARGUMENTS_MISMATCH",
            Self::WorkingDir => "CWD_MISMATCH",
        }
    }
}

impl HostGrant {
    /// Whether `argv` (the executable first) run in `cwd` is exactly this grant's command.
    ///
    /// # Errors
    ///
    /// The first [`Mismatch`] found.
    pub fn matches(&self, argv: &[String], cwd: &str) -> Result<(), Mismatch> {
        let Some((exe, args)) = argv.split_first() else {
            return Err(Mismatch::Executable);
        };
        if *exe != self.executable.path {
            return Err(Mismatch::Executable);
        }
        if args.len() != self.args.len() || !self.args.iter().zip(args).all(|(p, a)| p.matches(a)) {
            return Err(Mismatch::Arguments);
        }
        let resolved = std::fs::canonicalize(cwd).ok();
        let granted = std::fs::canonicalize(&self.working_dir).ok();
        if resolved.is_none()
            || resolved != granted
            || granted.as_deref() != Some(Path::new(&self.working_dir))
        {
            return Err(Mismatch::WorkingDir);
        }
        Ok(())
    }

    /// Whether the executable on disk still has the pinned SHA-256. Unreadable does not hold.
    #[must_use]
    pub fn pin_holds(&self) -> bool {
        match &self.executable.pin {
            ExecutablePin::Sha256(h) => {
                file_sha256(Path::new(&self.executable.path)).is_ok_and(|a| a.as_slice() == h)
            }
            ExecutablePin::CodeSigning { .. } => false,
        }
    }

    /// The command line the grant allows, for people: `/path/deploy staging {commit} ...`.
    #[must_use]
    pub fn command_line(&self) -> String {
        std::iter::once(self.executable.path.clone())
            .chain(self.args.iter().map(ArgPattern::display))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_commit_sha_is_exactly_forty_lower_hex() {
        let p = ArgPattern::CommitSha;
        assert!(p.matches(&"a".repeat(40)));
        assert!(p.matches("0123456789abcdef0123456789abcdef01234567"));
        for bad in [
            "a".repeat(39),
            "a".repeat(41),
            "A".repeat(40),
            "g".repeat(40),
            format!("{}\n", "a".repeat(39)),
            "HEAD".to_owned(),
            "--upload-pack=x".to_owned(),
            String::new(),
        ] {
            assert!(!p.matches(&bad), "{bad:?} matched");
        }
    }
}
