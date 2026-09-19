//! `kagisecure-ffi` — the explicit, reviewable list of things a native app may ask the core to do.
//!
//! This crate is a thin adapter, not a second implementation. It owns no vault logic: every
//! function here translates FFI-shaped arguments into a call on [`kagisecure_core`] and translates
//! the result back. If a rule about items, categories or slots lives in this crate rather than in
//! the core, that is a layering bug (architecture.md §2.4/§2.5).
//!
//! # The shape of the boundary
//!
//! Per [architecture.md](../../../docs/architecture.md) §4 and
//! [ADR-0001](../../../docs/decisions/0001-rust-core-native-ui.md), everything exported here is:
//!
//! * **synchronous** — no `async`, no futures, no runtime;
//! * **app → Rust** — Rust never calls up into Swift, so there are no foreign callbacks and no
//!   foreign trait objects. The approval flow that would want a callback goes over IPC instead
//!   (architecture.md §4.1), and that is M4's problem, not this crate's;
//! * **value-returning** — every call returns a value or a [`FfiError`].
//!
//! That is UniFFI's well-trodden path, and it is what makes the eventual C# fallback in
//! [ADR-0003](../../../docs/decisions/0003-uniffi-vs-csbindgen.md) tractable.
//!
//! # Secrets that cross this boundary
//!
//! The FFI boundary is in-process: the app and the core share an address space and a trust
//! domain, so plaintext *may* cross it (architecture.md §4). "May" is not "should", and
//! [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md) enumerates every crossing this
//! crate has, why it exists and what the alternative would have cost. There are five:
//!
//! 1. a master password or recovery code going **in** at unlock;
//! 2. a field value going **in** at save and coming **out** of [`VaultSession::reveal_field`];
//! 3. the raw vault key coming **out** of
//!    [`VaultSession::export_vault_key_for_platform_wrapping`], for the Secure Enclave to encrypt;
//! 4. the unwrapped vault key going **in** at [`VaultSession::unlock_with_vault_key`], after the
//!    Secure Enclave has decrypted it;
//! 5. **added in M5** — a generated password coming **out** of [`generate_password`], and a
//!    one-time-password code coming **out** of [`totp_preview`] and
//!    [`VaultSession::totp_code`], with the `otpauth://` URI that seeds them going **in**.
//!
//! Crossings 3 and 4 exist because only the keystore can produce and consume its own ciphertext.
//! Nothing else about the platform slot is Swift's business: the blob is stored, selected and
//! removed by the core. Crossing 5 exists because the value the user asked to see *is* the
//! feature; see `crate::generate` and ADR-0008 §6.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod agent;
mod generate;
mod import;
mod session;
mod types;

pub use agent::{
    AgentStatusView, ApprovalAction, ApprovalDecision, ApprovalRequestView, AuditRowView,
    ClientVerificationView, LeaseView, McpSetupView, McpSnippetView, agent_leases,
    agent_next_request, agent_pending_requests, agent_resolve, agent_revoke_all_leases,
    agent_revoke_lease, agent_start, agent_status, agent_stop, agent_take_lock_request, mcp_setup,
};
pub use generate::{
    GeneratorLimits, GeneratorMode, GeneratorRecipe, StrengthBucket, StrengthView, TotpAlgorithm,
    TotpCodeView, TotpParamsView, WordSeparator, generate_password, generator_limits,
    password_strength, recipe_strength, totp_describe, totp_preview, totp_uri_from_parts,
    totp_uri_is_valid,
};
pub use import::{
    DropNoteView, DuplicatePolicyView, ImportActionCount, ImportCategoryCount, ImportDecisionView,
    ImportDropKindView, ImportFormat, ImportFormatInfo, ImportItemActionView, ImportItemRow,
    ImportOutcomeView, ImportPlanHandle, ImportReportView, ImportTotals, ShredOutcomeView,
    import_formats, shred_caveat, shred_source_file,
};
pub use session::VaultSession;
pub use types::{
    CategoryInfo, EnvVarView, EnvironmentView, FieldDraft, FieldKind, FieldView, ItemDraft,
    ItemFilter, ItemSort, ItemView, SidebarCounts, TagCount, UnlockKind, VarBinding, VaultView,
};

uniffi::setup_scaffolding!();

/// Everything that can go wrong on the way down into the core.
///
/// Deliberately coarse. The app renders these to the user, and a lock screen that distinguishes
/// "wrong password" from "tampered file" would be telling an attacker something the core
/// deliberately does not (threat-model M-8) — so both arrive as [`FfiError::WrongCredential`].
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiError {
    /// There is no vault file at that path.
    #[error("no vault at {path}")]
    NotFound {
        /// The path that was tried.
        path: String,
    },
    /// There is already a vault file at that path.
    #[error("a vault already exists at {path}")]
    AlreadyExists {
        /// The path that was tried.
        path: String,
    },
    /// The password, recovery code or platform key does not open this vault — or the file has
    /// been tampered with. The two are not distinguished, on purpose.
    #[error("that did not unlock the vault")]
    WrongCredential,
    /// The vault has no slot of the kind that was asked for; typically, Touch ID was offered on a
    /// vault that was never enrolled.
    #[error("this vault has no {kind} slot")]
    NoSuchSlot {
        /// `"password"`, `"platform"` or `"recovery"`.
        kind: String,
    },
    /// No item, field, environment or logical vault with that identifier.
    #[error("{what} not found: {reference}")]
    NotPresent {
        /// What kind of thing was being looked for.
        what: String,
        /// The identifier that was used.
        reference: String,
    },
    /// The argument was not of a shape the core accepts.
    #[error("{message}")]
    Invalid {
        /// What was wrong with it.
        message: String,
    },
    /// Reading or writing the vault file failed.
    #[error("{message}")]
    Io {
        /// The underlying failure.
        message: String,
    },
}

/// The result type every exported function uses.
pub type FfiResult<T> = std::result::Result<T, FfiError>;

impl FfiError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid {
            message: message.into(),
        }
    }

    fn missing(what: &str, reference: impl Into<String>) -> Self {
        Self::NotPresent {
            what: what.to_owned(),
            reference: reference.into(),
        }
    }
}

impl From<kagisecure_core::Error> for FfiError {
    fn from(e: kagisecure_core::Error) -> Self {
        use kagisecure_core::Error as E;
        match e {
            E::VaultNotFound(p) => Self::NotFound {
                path: p.display().to_string(),
            },
            E::VaultExists(p) => Self::AlreadyExists {
                path: p.display().to_string(),
            },
            // A wrong credential and a tampered file are indistinguishable by design, and the
            // mapping keeps them that way rather than leaking the difference through a variant.
            E::Decrypt | E::Malformed | E::BadMagic => Self::WrongCredential,
            E::NoSuchSlot(kind) => Self::NoSuchSlot {
                kind: kind.to_owned(),
            },
            E::ItemNotFound(r) => Self::missing("item", r),
            E::EnvNotFound(r) => Self::missing("environment", r),
            E::VarNotFound(name, env) => Self::missing("variable", format!("{name} in {env}")),
            E::FieldNotFound { item, field } => {
                Self::missing("field", format!("{field} on {item}"))
            }
            E::Io(io) => Self::Io {
                message: io.to_string(),
            },
            other => Self::invalid(other.to_string()),
        }
    }
}

/// Whether a vault file exists at `path`.
///
/// The app asks this before it decides between the "create your first vault" empty state
/// (ui-spec.md §12) and the unlock card (§6.1).
#[uniffi::export]
#[must_use]
pub fn vault_exists(path: String) -> bool {
    std::path::Path::new(&path).is_file()
}

/// The default location of the user's vault file.
///
/// One place decides this, so the CLI, the daemon and the app cannot drift apart about where a
/// user's vault lives.
///
/// Two environment variables, in this order:
///
/// * **`KAGISECURE_VAULT`** names the vault **file** itself, and wins outright. This is the
///   variable `kagisecure --vault` reads (`kagisecure_cli::paths::resolve`), so until M6 the CLI
///   and the app disagreed about how to point at a scratch vault: `KAGISECURE_VAULT=/tmp/x.kagivault
///   kagisecure ls` worked and the app ignored it. Supporting it here is what makes "run the CLI
///   and the app against the same test vault" a single variable rather than two that have to be
///   kept consistent by hand.
/// * **`KAGISECURE_HOME`** names the **directory** the default `default.kagivault` lives in. Kept
///   unchanged, because it is what every existing note and script sets.
#[uniffi::export]
#[must_use]
pub fn default_vault_path() -> String {
    vault_path_from(
        std::env::var_os("KAGISECURE_VAULT"),
        std::env::var_os("KAGISECURE_HOME"),
        std::env::var_os("HOME"),
    )
}

/// The pure half of [`default_vault_path`], so the precedence can be tested.
///
/// Reading the process environment inside a test is either racy (other tests share it) or
/// `unsafe` (edition 2024 made `set_var` so), and the interesting thing here is three lines of
/// precedence rather than three calls to `var_os`.
fn vault_path_from(
    vault: Option<std::ffi::OsString>,
    home_override: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> String {
    if let Some(explicit) = vault {
        let explicit = std::path::PathBuf::from(explicit);
        if !explicit.as_os_str().is_empty() {
            return explicit.display().to_string();
        }
    }
    let base = home_override
        .map(std::path::PathBuf::from)
        .or_else(|| {
            home.map(|h| std::path::PathBuf::from(h).join("Library/Application Support/kagisecure"))
        })
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    base.join("default.kagivault").display().to_string()
}

/// Read a vault's header without unlocking it, and report whether it has a platform slot.
///
/// The lock screen needs this before any credential exists: it decides whether to auto-trigger
/// the Touch ID sheet (ui-spec.md §6.1) or go straight to the password field. Reading a header is
/// not privileged — it is the plaintext part of the file (vault-format.md §2.1).
///
/// # Errors
///
/// [`FfiError::NotFound`] if there is no file, [`FfiError::WrongCredential`] if the bytes are not
/// a kagisecure vault at all.
#[uniffi::export]
pub fn platform_slot_id(path: String) -> FfiResult<Option<String>> {
    Ok(read_platform_slot(&path)?.map(|(id, _)| id))
}

/// The platform slot's wrapped key, for the keystore to decrypt.
///
/// The bytes are opaque ciphertext, not key material this process can use — see
/// [`kagisecure_core::crypto::wrap::ALG_PLATFORM_OPAQUE`]. Swift hands them to
/// `SecKeyCreateDecryptedData` and passes the plaintext back through
/// [`VaultSession::unlock_with_vault_key`].
///
/// # Errors
///
/// As [`platform_slot_id`].
#[uniffi::export]
pub fn platform_wrapped_key(path: String) -> FfiResult<Option<Vec<u8>>> {
    Ok(read_platform_slot(&path)?.map(|(_, ct)| ct))
}

fn read_platform_slot(path: &str) -> FfiResult<Option<(String, Vec<u8>)>> {
    use kagisecure_core::crypto::wrap::KIND_PLATFORM;
    use kagisecure_core::vault::header;

    let p = std::path::Path::new(path);
    if !p.is_file() {
        return Err(FfiError::NotFound {
            path: path.to_owned(),
        });
    }
    let bytes = std::fs::read(p).map_err(|e| FfiError::Io {
        message: e.to_string(),
    })?;
    let parts = header::split(&bytes)?;
    Ok(parts
        .header
        .slot(KIND_PLATFORM)
        .map(|s| (s.id.clone(), s.ct.clone())))
}

/// Every category a "+ New item" menu should offer, with its display name and SF Symbol.
///
/// The table lives in the core (`Category::first_class`), so the app never hardcodes a category
/// list that could drift from the one the vault format knows about.
#[uniffi::export]
#[must_use]
pub fn category_catalog() -> Vec<CategoryInfo> {
    kagisecure_core::proto::Category::first_class()
        .into_iter()
        .map(|c| CategoryInfo::from_core(&c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(value: &str) -> Option<std::ffi::OsString> {
        Some(std::ffi::OsString::from(value))
    }

    #[test]
    fn kagisecure_vault_names_the_file_and_wins_outright() {
        // The variable the CLI has always read. Before M6 the app ignored it, so pointing both at
        // one scratch vault took two variables that had to agree.
        assert_eq!(
            vault_path_from(
                os("/tmp/scratch.kagivault"),
                os("/ignored"),
                os("/Users/nobody")
            ),
            "/tmp/scratch.kagivault"
        );
    }

    #[test]
    fn kagisecure_home_names_the_directory_the_default_file_lives_in() {
        assert_eq!(
            vault_path_from(None, os("/tmp/home"), os("/Users/nobody")),
            "/tmp/home/default.kagivault"
        );
    }

    #[test]
    fn with_neither_set_the_vault_is_under_application_support() {
        assert_eq!(
            vault_path_from(None, None, os("/Users/nobody")),
            "/Users/nobody/Library/Application Support/kagisecure/default.kagivault"
        );
    }

    #[test]
    fn an_empty_kagisecure_vault_is_ignored_rather_than_obeyed() {
        // An exported-but-empty variable is the shell's way of saying nothing, and obeying it
        // would put the vault at `/default.kagivault`.
        assert_eq!(
            vault_path_from(os(""), os("/tmp/home"), None),
            "/tmp/home/default.kagivault"
        );
    }

    #[test]
    fn with_nothing_at_all_the_path_is_relative_rather_than_absent() {
        assert_eq!(vault_path_from(None, None, None), "./default.kagivault");
    }
}
