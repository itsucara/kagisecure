//! Error type for `kagisecure-core`.
//!
//! Every variant is written on the assumption that its `Display` output may end up in a terminal,
//! a log file or a crash report. **No variant may ever carry a secret value.** Item titles and
//! field labels are metadata and are disclosed by design (threat-model A4); field *values* are
//! not, and are never formatted here.

use std::path::PathBuf;

/// Convenience alias for results from this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong inside `kagisecure-core`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The vault file does not exist.
    #[error("no vault at {0}")]
    VaultNotFound(PathBuf),

    /// A vault file is already present where one was about to be created.
    #[error("a vault already exists at {0}")]
    VaultExists(PathBuf),

    /// Another writer held the vault's lock file for longer than this caller was willing to wait
    /// (`vault::lock`). Nothing was written; retrying later is safe.
    #[error(
        "another kagisecure process is writing to the vault at {path}; gave up waiting after {waited:?}"
    )]
    VaultBusy {
        /// The vault, not its lock file: the path a user recognises.
        path: PathBuf,
        /// The timeout that ran out.
        waited: std::time::Duration,
    },

    /// The file system holding the vault does not support file locks (`ENOTSUP`, `ENOLCK`).
    ///
    /// Writes are refused rather than attempted unlocked, because an unlocked write is exactly
    /// the silent lost update the lock exists to prevent. Reading still works.
    #[error(
        "the file system holding {0} does not support file locks, so kagisecure will not write to it"
    )]
    LockUnsupported(PathBuf),

    /// The vault's lock file was renamed or deleted while this process held it, so another
    /// process may have taken a lock of its own. Nothing was written.
    #[error("the lock file for {0} was moved or deleted while in use; nothing was written")]
    LockLost(PathBuf),

    /// The vault file changed on disk after this session last read or wrote it, and the write
    /// that noticed cannot merge (the non-transactional `Vault::save`). Nothing was written.
    #[error(
        "the vault at {0} was changed by another process since this session last read it; nothing was written"
    )]
    VaultConflict(PathBuf),

    /// The vault file on disk no longer continues the audit log this session saw on disk — it is
    /// shorter, or its entries differ — which is what restoring an older copy looks like.
    /// Nothing was written, so the file stays exactly as found.
    #[error(
        "the vault at {0} does not continue this session's audit log (was an older copy restored?); nothing was written"
    )]
    VaultDiverged(PathBuf),

    /// The file at the vault's path is no longer the vault this session unlocked: a different
    /// `vault_id`, or a body the session's vault key does not open. Nothing was written.
    #[error("the file at {0} is no longer the vault this session unlocked; nothing was written")]
    VaultReplaced(PathBuf),

    /// `Vault::overwrite_with_this_session` was asked to overwrite a file that this session can
    /// build on again: it is the version the session last read or wrote, or one that continues
    /// it. There is nothing to overwrite; an ordinary transaction merges with it instead. Nothing
    /// was written.
    #[error(
        "the vault at {0} continues this session again, so there is nothing to overwrite; nothing was written"
    )]
    VaultNotInConflict(PathBuf),

    /// A write (`save`, `transact`, `refresh_if_changed`) was started from inside a transaction
    /// on the same vault. A transaction commits once, when its closure returns.
    #[error("a vault write was started from inside a transaction on the same vault")]
    NestedTransaction,

    /// A transaction's closure declined to commit, for a reason its caller holds separately (the
    /// closure's own error type is not this one). Returning it from the closure rolls the
    /// transaction back like any other error; nothing was written.
    #[error("the transaction was abandoned by its caller; nothing was written")]
    TransactionAborted,

    /// The vault file is larger than this build will read or write.
    #[error("the vault file at {path} is larger than the {max} bytes this build accepts")]
    VaultTooLarge {
        /// The vault.
        path: PathBuf,
        /// The limit, in bytes.
        max: u64,
    },

    /// The file does not start with the kagisecure magic bytes.
    #[error("not a kagisecure vault file")]
    BadMagic,

    /// The file's `format_ver` is newer than this build understands. Never guess (vault-format §9).
    #[error("vault format version {found} is newer than this build supports (max {supported})")]
    UnsupportedFormatVersion {
        /// Version read from the file.
        found: u16,
        /// Highest version this build can read.
        supported: u16,
    },

    /// `body.schema` or `header.v` is newer than the version this build writes.
    ///
    /// Opening still succeeds — unknown fields survive via passthrough (vault-format §9 rule 1) —
    /// but this build refuses to write the vault back, because a schema bump (unlike an additive
    /// field) may mean a structural change this build cannot faithfully reproduce. Upgrading
    /// kagisecure, not editing the vault, is the fix.
    #[error(
        "this vault's {field} is {found}, newer than the {supported} this build writes; upgrade kagisecure before saving to it"
    )]
    VaultSchemaTooNew {
        /// Which schema field is too new: `"body.schema"` or `"header.v"`.
        field: &'static str,
        /// The version found in the file.
        found: u16,
        /// The highest version this build writes.
        supported: u16,
    },

    /// The file is truncated, or a length prefix does not agree with the file size.
    #[error("vault file is truncated or malformed")]
    Malformed,

    /// The plaintext header could not be CBOR-decoded.
    #[error("vault header could not be decoded: {0}")]
    HeaderDecode(String),

    /// The decrypted body could not be CBOR-decoded.
    #[error("vault body could not be decoded: {0}")]
    BodyDecode(String),

    /// AEAD authentication failed. Deliberately indistinguishable between causes.
    #[error(
        "decryption failed: wrong password or recovery code, or the vault has been tampered with"
    )]
    Decrypt,

    /// The vault header has no wrapped-key slot of the requested kind.
    #[error("this vault has no {0} key slot")]
    NoSuchSlot(&'static str),

    /// The vault asks for an algorithm or option this build does not implement.
    #[error("unsupported {what}: {value}")]
    Unsupported {
        /// What kind of thing was unsupported, e.g. `"body AEAD"`.
        what: &'static str,
        /// The offending value as read from the file.
        value: String,
    },

    /// The header's KDF parameters are outside the accepted range.
    #[error("invalid Argon2id parameters in vault header: {0}")]
    KdfParams(String),

    /// Argon2id itself failed (almost always: could not allocate the requested memory).
    #[error("key derivation failed (could not allocate {0} KiB?)")]
    KdfFailed(u32),

    /// A recovery code did not parse, or its checksum did not match.
    #[error("that recovery code is not valid (wrong characters or failed checksum)")]
    BadRecoveryCode,

    /// No item matched the reference the caller gave.
    #[error("no item matches {0:?}")]
    ItemNotFound(String),

    /// More than one item matched the reference the caller gave.
    #[error("{0:?} matches more than one item; use the item id")]
    AmbiguousItem(String),

    /// The item exists but has no such field.
    #[error("item {item:?} has no field {field:?}")]
    FieldNotFound {
        /// The item reference as given.
        item: String,
        /// The field label or id as given.
        field: String,
    },

    /// The field exists but holds a public value, not a secret.
    #[error("field {0:?} does not hold a secret value")]
    NotASecret(String),

    /// A secret value was needed as a process environment value but is not valid UTF-8.
    #[error("the value of {0:?} is not valid UTF-8 and cannot be placed in a process environment")]
    NonUtf8EnvValue(String),

    /// A `.env` file name was not a plain file name.
    #[error("{0:?} is not a usable file name for a .env file")]
    InvalidEnvFileName(String),

    /// The target `.env` file exists and the caller did not ask to overwrite it.
    #[error("{0} already exists; pass --overwrite to replace it")]
    EnvFileExists(PathBuf),

    /// A path was not absolute, not a directory, or otherwise refused by policy.
    #[error("{0} is not a usable path")]
    InvalidPath(PathBuf),

    /// No environment matched the reference the caller gave.
    #[error("no environment matches {0:?}")]
    EnvNotFound(String),

    /// More than one environment matched the reference the caller gave.
    #[error("{0:?} matches more than one environment; use the environment id")]
    AmbiguousEnv(String),

    /// The environment has no variable of that name.
    #[error("environment {1:?} has no variable {0:?}")]
    VarNotFound(String, String),

    /// An environment variable has no value available yet.
    #[error("{0:?} has no value yet; set it with `kagisecure env add-var`")]
    VarNotPopulated(String),

    /// A variable name is not `^[A-Za-z_][A-Za-z0-9_]*$` (at most 128 bytes), so it cannot be
    /// written into a `.env` file or a process environment without becoming something else.
    #[error(
        "{0:?} is not a usable variable name: use letters, digits and underscores, not starting \
         with a digit, at most 128 characters"
    )]
    InvalidVarName(String),

    /// The audit log's hash chain does not verify.
    #[error("the audit log is not intact: {0}")]
    AuditChain(#[from] crate::audit::ChainError),

    /// Filesystem or process I/O failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// The operating system CSPRNG failed.
    #[error("the operating system random number generator failed")]
    Rng,

    /// A password-generator recipe could not be satisfied.
    ///
    /// The payload is `&'static str` rather than `String` so that the type itself makes it
    /// impossible to interpolate a generated password into the message.
    #[error("this password recipe cannot be satisfied: {0}")]
    Generator(&'static str),

    /// A TOTP secret, parameter set or `otpauth://` URI was not usable.
    ///
    /// `&'static str` for the same reason as [`Error::Generator`], and here it matters more: the
    /// input to a failing parse is an `otpauth://` URI, which *is* the credential.
    #[error("this one-time password is not usable: {0}")]
    Totp(&'static str),

    /// A shared-vault device key was refused: the wrong suite or key length, an over-long label,
    /// or an id the vault already holds (ADR-0035 §5).
    ///
    /// `&'static str` for the same reason as [`Error::Generator`]: the input is key material.
    #[error("device key refused: {0}")]
    DeviceKey(&'static str),

    /// A machine vault, its key, or one of its records broke a rule of ADR-0042 §2: a website
    /// that is not an exact https origin on a Login item, a one-time-password seed bound to a
    /// variable, a reference out of the machine vault, a job or grant out of bounds, or a key
    /// that does not belong to the file.
    ///
    /// `&'static str` for the same reason as [`Error::Generator`]: nothing the caller supplied is
    /// echoed.
    #[error("machine vault: {0}")]
    MachineVault(&'static str),

    /// A child process could not be started.
    #[error("could not run {program:?}: {reason}")]
    Spawn {
        /// The program that was to be executed.
        program: String,
        /// The OS error, rendered.
        reason: String,
    },
}

#[cfg(feature = "test-support")]
impl Error {
    /// One placeholder instance of every variant, named, so a downstream crate can test that it
    /// maps every variant of this `#[non_exhaustive]` enum on purpose.
    ///
    /// `#[non_exhaustive]` only stops a `match` *outside* this crate from being exhaustive; inside
    /// it, ordinary exhaustiveness checking still applies. The private `assert_every_variant`
    /// below has no wildcard arm, so this function fails to compile the moment a variant is added
    /// without also being taught to it — which is what keeps the list honest. It does not, by
    /// itself, guarantee the list below was extended too: that still takes a human noticing the
    /// compile error and adding a sample a few lines up in the same function. What it does
    /// guarantee is that nobody can add a variant and have this function silently keep compiling
    /// as if nothing changed.
    ///
    /// Gated behind the `test-support` feature so none of this — not even the strings — ships in
    /// a release binary; `kagisecure-cli` enables it only in `[dev-dependencies]`.
    #[doc(hidden)]
    #[must_use]
    pub fn all_variants_for_test() -> Vec<(&'static str, Error)> {
        let p = || std::path::PathBuf::from("/test");
        let s = || String::new();
        let all: Vec<(&'static str, Error)> = vec![
            ("VaultNotFound", Error::VaultNotFound(p())),
            ("VaultExists", Error::VaultExists(p())),
            (
                "VaultBusy",
                Error::VaultBusy {
                    path: p(),
                    waited: std::time::Duration::from_secs(1),
                },
            ),
            ("LockUnsupported", Error::LockUnsupported(p())),
            ("LockLost", Error::LockLost(p())),
            ("VaultConflict", Error::VaultConflict(p())),
            ("VaultDiverged", Error::VaultDiverged(p())),
            ("VaultReplaced", Error::VaultReplaced(p())),
            ("VaultNotInConflict", Error::VaultNotInConflict(p())),
            ("NestedTransaction", Error::NestedTransaction),
            ("TransactionAborted", Error::TransactionAborted),
            ("VaultTooLarge", Error::VaultTooLarge { path: p(), max: 1 }),
            ("BadMagic", Error::BadMagic),
            (
                "UnsupportedFormatVersion",
                Error::UnsupportedFormatVersion {
                    found: 99,
                    supported: 1,
                },
            ),
            (
                "VaultSchemaTooNew",
                Error::VaultSchemaTooNew {
                    field: "body.schema",
                    found: 2,
                    supported: 1,
                },
            ),
            ("Malformed", Error::Malformed),
            ("HeaderDecode", Error::HeaderDecode(s())),
            ("BodyDecode", Error::BodyDecode(s())),
            ("Decrypt", Error::Decrypt),
            ("NoSuchSlot", Error::NoSuchSlot("test")),
            (
                "Unsupported",
                Error::Unsupported {
                    what: "test",
                    value: s(),
                },
            ),
            ("KdfParams", Error::KdfParams(s())),
            ("KdfFailed", Error::KdfFailed(1)),
            ("BadRecoveryCode", Error::BadRecoveryCode),
            ("ItemNotFound", Error::ItemNotFound(s())),
            ("AmbiguousItem", Error::AmbiguousItem(s())),
            (
                "FieldNotFound",
                Error::FieldNotFound {
                    item: s(),
                    field: s(),
                },
            ),
            ("NotASecret", Error::NotASecret(s())),
            ("NonUtf8EnvValue", Error::NonUtf8EnvValue(s())),
            ("InvalidEnvFileName", Error::InvalidEnvFileName(s())),
            ("EnvFileExists", Error::EnvFileExists(p())),
            ("InvalidPath", Error::InvalidPath(p())),
            ("EnvNotFound", Error::EnvNotFound(s())),
            ("AmbiguousEnv", Error::AmbiguousEnv(s())),
            ("VarNotFound", Error::VarNotFound(s(), s())),
            ("VarNotPopulated", Error::VarNotPopulated(s())),
            ("InvalidVarName", Error::InvalidVarName(s())),
            (
                "AuditChain",
                Error::AuditChain(crate::audit::ChainError::HeadMismatch),
            ),
            ("Io", Error::Io(std::io::Error::other("test"))),
            ("Rng", Error::Rng),
            ("Generator", Error::Generator("test")),
            ("Totp", Error::Totp("test")),
            ("DeviceKey", Error::DeviceKey("test")),
            ("MachineVault", Error::MachineVault("test")),
            (
                "Spawn",
                Error::Spawn {
                    program: s(),
                    reason: s(),
                },
            ),
        ];

        fn assert_every_variant(e: &Error) {
            match e {
                Error::VaultNotFound(_)
                | Error::VaultExists(_)
                | Error::VaultBusy { .. }
                | Error::LockUnsupported(_)
                | Error::LockLost(_)
                | Error::VaultConflict(_)
                | Error::VaultDiverged(_)
                | Error::VaultReplaced(_)
                | Error::VaultNotInConflict(_)
                | Error::NestedTransaction
                | Error::TransactionAborted
                | Error::VaultTooLarge { .. }
                | Error::BadMagic
                | Error::UnsupportedFormatVersion { .. }
                | Error::VaultSchemaTooNew { .. }
                | Error::Malformed
                | Error::HeaderDecode(_)
                | Error::BodyDecode(_)
                | Error::Decrypt
                | Error::NoSuchSlot(_)
                | Error::Unsupported { .. }
                | Error::KdfParams(_)
                | Error::KdfFailed(_)
                | Error::BadRecoveryCode
                | Error::ItemNotFound(_)
                | Error::AmbiguousItem(_)
                | Error::FieldNotFound { .. }
                | Error::NotASecret(_)
                | Error::NonUtf8EnvValue(_)
                | Error::InvalidEnvFileName(_)
                | Error::EnvFileExists(_)
                | Error::InvalidPath(_)
                | Error::EnvNotFound(_)
                | Error::AmbiguousEnv(_)
                | Error::VarNotFound(..)
                | Error::VarNotPopulated(_)
                | Error::InvalidVarName(_)
                | Error::AuditChain(_)
                | Error::Io(_)
                | Error::Rng
                | Error::Generator(_)
                | Error::Totp(_)
                | Error::DeviceKey(_)
                | Error::MachineVault(_)
                | Error::Spawn { .. } => {}
            }
        }
        for (_, e) in &all {
            assert_every_variant(e);
        }
        all
    }
}
