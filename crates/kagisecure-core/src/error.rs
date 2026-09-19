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

    /// A child process could not be started.
    #[error("could not run {program:?}: {reason}")]
    Spawn {
        /// The program that was to be executed.
        program: String,
        /// The OS error, rendered.
        reason: String,
    },
}
