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
//! * **synchronous**, with one deliberate exception: the presence-gated release calls
//!   (`VaultSession::release_field`, `release_totp`, `release_notes`, and the same three on
//!   `SharedVaultSession`) are `async`, because they await a person (ADR-0038). They need no
//!   runtime — Swift's executor polls them;
//! * **app → Rust**, with one deliberate exception: [`PresenceGate`], the app's presence check,
//!   is a foreign trait Rust awaits (ADR-0038). It carries a sentence *into* Swift — built from
//!   a title and a label, never a value — and an outcome back; no secret crosses through it;
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
//! crate had, why it exists and what the alternative would have cost. There are six:
//!
//! 1. a master password or recovery code going **in** at unlock (and, for the presence gate's
//!    fallback, at [`VaultSession::verify_master_password`]);
//! 2. a field value — or an item's notes — going **in** at save and coming **out** of a
//!    [`FieldRelease`] or [`NotesRelease`], each behind a fresh presence check (ADR-0038) — the
//!    only way out: the ungated `reveal_field` and `reveal_notes` are gone;
//! 3. the raw vault key coming **out** of
//!    [`VaultSession::export_vault_key_for_platform_wrapping`], for the Secure Enclave to encrypt;
//! 4. the unwrapped vault key going **in** at [`VaultSession::unlock_with_vault_key`], after the
//!    Secure Enclave has decrypted it;
//! 5. **added in M5** — a generated password coming **out** of [`generate_password`], and a
//!    one-time-password code coming **out** of [`totp_preview`] (for a seed the user is typing)
//!    and a [`TotpRelease`] (for a stored one, behind a presence check — the ungated `totp_code`
//!    and `item_totp_code` are gone), with the `otpauth://` URI that seeds them going **in**;
//! 6. **added with shared vaults (ADR-0035 Phase 5)** — an invitation's six-word passphrase
//!    coming **out** of [`SharedVaultSession::invite_member`] once, for the person to hand over,
//!    and going **in** at [`VaultSession::join_shared_vault`]. Not yet in ADR-0008's list.
//!
//! Crossings 3 and 4 exist because only the keystore can produce and consume its own ciphertext.
//! Nothing else about the platform slot is Swift's business: the blob is stored, selected and
//! removed by the core. Crossing 5 exists because the value the user asked to see *is* the
//! feature; see `crate::generate` and ADR-0008 §6. Crossing 6 exists because a person has to say
//! the words to another person; see `crate::shared`.

// The C ABI behind the `capi` feature (ADR-0003's C# fallback) cannot be written without
// `unsafe`; nothing else in this crate needs it. So the default build — the one the Swift app
// links — forbids it outright, exactly as before, and a `capi` build denies it everywhere except
// the one module that opts back in.
#![cfg_attr(not(feature = "capi"), forbid(unsafe_code))]
#![cfg_attr(feature = "capi", deny(unsafe_code))]
#![warn(missing_docs)]

mod agent;
#[cfg(feature = "capi")]
pub mod capi;
mod generate;
mod import;
mod presence;
mod release;
mod session;
mod shared;
mod types;
mod unattended;
mod unattended_logins;
mod unattended_manage;

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
#[doc(hidden)]
pub use presence::Clock;
pub use presence::{MasterPasswordCheck, PresenceGate, PresenceOutcome, ReleasePurpose};
pub use release::{FieldRelease, NotesRelease, TotpRelease};
pub use session::VaultSession;
pub use shared::{
    SharedDeviceView, SharedExposure, SharedInvitation, SharedMemberView, SharedRole,
    SharedRosterWarning, SharedSyncSummary, SharedVaultSession, SharedVaultSummary,
};
pub use types::{
    AgentVisibilityScopeView, BulkVisibilityView, CategoryInfo, DivergedFileView, EnvVarView,
    EnvironmentView, FieldDraft, FieldKind, FieldView, ItemDraft, ItemFilter, ItemSort, ItemView,
    KeepAppVersionOutcome, SidebarCounts, TagCount, UnlockKind, VarBinding,
    VaultConflictDetailsView, VaultConflictKindView, VaultView,
};
pub use unattended::{
    UnattendedNoticeView, UnattendedPresence, UnattendedRunView, UnattendedStatusView,
    agent_attach_machine_vault, unattended_arm, unattended_create_machine_vault, unattended_disarm,
    unattended_machine_vault_path, unattended_resume, unattended_run_now, unattended_start,
    unattended_status, unattended_stop, unattended_take_notices,
};
pub use unattended_logins::{
    MachineLoginView, UnattendedLoginDraft, UnattendedLoginGrantView, unattended_copy_login,
    unattended_default_run_browser, unattended_login_grants, unattended_machine_logins,
    unattended_run_browser_ready,
};
pub use unattended_manage::{
    MachineEnvironmentView, UnattendedGrantView, UnattendedJobDraft, UnattendedJobView,
    UnattendedOverviewView, UnattendedSummaryView, UnattendedTimeView,
    unattended_acknowledge_summary, unattended_audit_page, unattended_copy_environment,
    unattended_create_job, unattended_overview, unattended_reenable_grant,
    unattended_remove_environment, unattended_revoke_job, unattended_summary,
};
pub use unattended_manage::{
    SharedEnvironmentChoice, SharedUnattendedCopyView, shared_environments_for_copy,
    shared_set_unattended_copies_allowed, shared_unattended_copies,
    shared_unattended_copies_allowed, unattended_copy_shared_environment,
    unattended_remove_shared_copy, unattended_stale_copies,
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
    /// Another kagisecure process (or another handle in this one) held the vault's lock past the
    /// app's wait, or the lock file was moved while held ([`kagisecure_core::Error::VaultBusy`],
    /// [`kagisecure_core::Error::LockLost`]). Nothing was written; retrying shortly is safe.
    #[error("{message}")]
    Busy {
        /// The underlying failure, safe to show as-is.
        message: String,
    },
    /// The vault file on disk is no longer the one this session's writes build on: an older copy
    /// was restored over it, a different file or vault sits at the path now, or the file is gone
    /// ([`kagisecure_core::Error::VaultDiverged`], [`kagisecure_core::Error::VaultReplaced`], or
    /// [`kagisecure_core::Error::VaultNotFound`] surfacing *after* this session was already
    /// unlocked, or a file at the path this build cannot parse). Nothing was written, and nothing
    /// will be until the human picks a side — [`VaultSession::conflict`],
    /// [`VaultSession::conflict_details`] and [`VaultSession::keep_app_version_over_conflict`]
    /// are the rest of that flow.
    #[error("{message}")]
    Diverged {
        /// The underlying failure, safe to show as-is.
        message: String,
    },
    /// [`VaultSession::save_item`] refused to write because the item changed on disk after the
    /// edit sheet read it — a different process, or another window, saved it first. Nothing was
    /// written; the app should reload the item and let the user redo their edit.
    #[error("{message}")]
    ItemChangedElsewhere {
        /// A message safe to show as-is.
        message: String,
    },
    /// The vault is locked: [`VaultSession::lock`] ran, or the session is being destroyed. Nothing
    /// was read or released. A release whose presence prompt was still up when the vault locked
    /// ends here too, whatever the prompt then answered (ADR-0038 §4).
    #[error("the vault is locked")]
    VaultLocked,
    /// No [`PresenceGate`] is installed on this session ([`VaultSession::set_presence_gate`]), so
    /// nothing can be released: with no gate, every release fails closed (ADR-0038 §1).
    #[error("no presence check is available, so nothing was released")]
    NoPresenceGate,
    /// The person dismissed the presence prompt, or it failed. Nothing was released.
    #[error("the request was not confirmed, so nothing was released")]
    PresenceCancelled,
    /// The presence check could not run on this Mac right now (no biometrics, no passcode, a
    /// policy that refuses). Nothing was released; the app may offer the master-password fallback
    /// ([`VaultSession::verify_master_password`], ADR-0038 user decision 7).
    #[error("the presence check is not available right now, so nothing was released")]
    PresenceUnavailable,
    /// Another presence prompt is already up. Refused rather than queued, so requests cannot pile
    /// up behind a legitimate one (ADR-0037 §3, ADR-0038 §6). Nothing was released.
    #[error("another confirmation is already in progress")]
    PresenceBusy,
    /// A release object ([`FieldRelease`], [`TotpRelease`], [`NotesRelease`]) is no longer live:
    /// it was closed, it passed its five-minute cap, or it was a copy and has already been used.
    /// Ask again — which means another presence prompt.
    #[error("{message}")]
    ReleaseEnded {
        /// Which of the three it was, safe to show as-is.
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

    fn ended(message: impl Into<String>) -> Self {
        Self::ReleaseEnded {
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
    /// The general mapping, used by every call that cannot yet have taken the vault's file lock
    /// (unlocking, `prepare_*`, a plain lookup): [`kagisecure_core::Error::VaultNotFound`] here
    /// always means "no vault at this path yet", because nothing before a lock is ever taken can
    /// have observed one and then lost it. Code that runs *after* a vault is open — inside
    /// [`VaultSession`]'s `transact` helper — uses `VaultSession::map_write_error` instead, which
    /// reinterprets that same core variant as [`FfiError::Diverged`]: there, the file existed a
    /// moment ago and now does not, which is what disappeared-out-from-under-us means once a
    /// session already holds a key.
    fn from(e: kagisecure_core::Error) -> Self {
        use kagisecure_core::Error as E;
        // Computed once, up front, because several of the arms below want the rendered message
        // and a `match` on `e` by value would otherwise have already consumed it.
        let message = e.to_string();
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
            // Another writer held the lock past the wait, or the lock file moved under a holder —
            // both are "nothing was written, try again", never "look at the file".
            E::VaultBusy { .. } | E::LockLost(_) => Self::Busy { message },
            // The file itself proved it is not a version this session can build on: it does not
            // decrypt as the same vault, or its audit log does not continue what this session
            // last saw. `VaultNotFound` is deliberately *not* folded in here — see this impl's
            // doc comment.
            E::VaultDiverged(_) | E::VaultReplaced(_) => Self::Diverged { message },
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
        .or_else(|| home.map(default_data_dir_for_home))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    base.join("default.kagivault").display().to_string()
}

/// The platform's per-user data directory for `home`, without `default.kagivault`.
///
/// This must resolve to the same directory `kagisecure_cli::paths::default_vault_path` uses
/// (`directories::ProjectDirs::from("", "", "kagisecure").data_dir()`), or the app and the CLI
/// open different vaults. On macOS the two are already the same path by construction — `home`
/// joined with `Library/Application Support/kagisecure` is exactly what `ProjectDirs` computes
/// from `$HOME` on this platform — so this keeps the historical, directly-testable macOS join
/// rather than adding an indirection that would read the live environment instead of the
/// injected `home`. Off macOS, `ProjectDirs` is called directly: this branch is not covered by
/// the unit tests below (they assert the macOS shape), but it replaces what used to be the same
/// macOS-only hardcoded join applied unconditionally on every platform, which is the actual bug.
#[cfg(target_os = "macos")]
fn default_data_dir_for_home(home: std::ffi::OsString) -> std::path::PathBuf {
    std::path::PathBuf::from(home).join("Library/Application Support/kagisecure")
}

#[cfg(not(target_os = "macos"))]
fn default_data_dir_for_home(_home: std::ffi::OsString) -> std::path::PathBuf {
    directories::ProjectDirs::from("", "", "kagisecure")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
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

/// What a platform keystore needs from a vault's header before unlocking it, read in **one** read
/// of the file: the vault file's id, and the platform slot's id and wrapped key if there is one.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PlatformSlotInfo {
    /// The header's random vault-file identifier (see [`VaultSession::vault_file_id`]).
    pub vault_id: Vec<u8>,
    /// The platform slot's identifier, or `None` when there is no platform slot.
    pub slot_id: Option<String>,
    /// The platform slot's opaque wrapped key, or `None` when there is no platform slot.
    pub wrapped_key: Option<Vec<u8>>,
}

/// [`platform_slot_id`], [`platform_wrapped_key`] and the vault-file id together, from a single
/// read of the header — so they cannot come from two different versions of a file that was
/// replaced in between (the Windows Hello unlock, ADR-0033).
///
/// # Errors
///
/// As [`platform_slot_id`].
#[uniffi::export]
pub fn platform_slot_info(path: String) -> FfiResult<PlatformSlotInfo> {
    let header = read_header(&path)?;
    let slot = header.slot(kagisecure_core::crypto::wrap::KIND_PLATFORM);
    Ok(PlatformSlotInfo {
        vault_id: header.vault_id.clone(),
        slot_id: slot.map(|s| s.id.clone()),
        wrapped_key: slot.map(|s| s.ct.clone()),
    })
}

fn read_platform_slot(path: &str) -> FfiResult<Option<(String, Vec<u8>)>> {
    use kagisecure_core::crypto::wrap::KIND_PLATFORM;

    Ok(read_header(path)?
        .slot(KIND_PLATFORM)
        .map(|s| (s.id.clone(), s.ct.clone())))
}

fn read_header(path: &str) -> FfiResult<kagisecure_core::vault::header::Header> {
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
    Ok(header::split(&bytes)?.header)
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

    /// The expected value is built with the same `Path::join` the production code uses, rather
    /// than typed out with a literal `/`, so the assertion does not depend on the platform's
    /// separator — `join` renders `\` on Windows and `/` everywhere else, and both are correct.
    fn joined(dir: &str, file: &str) -> String {
        std::path::PathBuf::from(dir)
            .join(file)
            .display()
            .to_string()
    }

    #[test]
    fn kagisecure_home_names_the_directory_the_default_file_lives_in() {
        assert_eq!(
            vault_path_from(None, os("/tmp/home"), os("/Users/nobody")),
            joined("/tmp/home", "default.kagivault")
        );
    }

    /// macOS-only: off macOS, `default_data_dir_for_home` ignores the injected `home` entirely
    /// and defers to `directories::ProjectDirs`, which reads the real per-user data directory —
    /// there is no injectable `home` value this literal could assert against on that branch. See
    /// `with_neither_set_the_vault_defers_to_the_platform_data_dir` below for the non-macOS half
    /// of this same property.
    #[test]
    #[cfg(target_os = "macos")]
    fn with_neither_set_the_vault_is_under_application_support() {
        assert_eq!(
            vault_path_from(None, None, os("/Users/nobody")),
            "/Users/nobody/Library/Application Support/kagisecure/default.kagivault"
        );
    }

    /// The non-macOS counterpart of the test above: with neither override set, the resolved path
    /// must be exactly `ProjectDirs`'s own data directory joined with `default.kagivault` — not
    /// the macOS-shaped literal, and not the "nothing configured" `.` fallback used only when
    /// `ProjectDirs` itself cannot resolve a home directory. This mirrors
    /// `default_data_dir_for_home`'s non-macOS branch rather than re-deriving it, so it is a
    /// routing test (did the right branch run?), not a claim about what `ProjectDirs` returns.
    #[test]
    #[cfg(not(target_os = "macos"))]
    fn with_neither_set_the_vault_defers_to_the_platform_data_dir() {
        let dir = directories::ProjectDirs::from("", "", "kagisecure")
            .map(|dirs| dirs.data_dir().to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        assert_eq!(
            vault_path_from(None, None, os("/Users/nobody")),
            dir.join("default.kagivault").display().to_string()
        );
    }

    #[test]
    fn an_empty_kagisecure_vault_is_ignored_rather_than_obeyed() {
        // An exported-but-empty variable is the shell's way of saying nothing, and obeying it
        // would put the vault at `/default.kagivault`.
        assert_eq!(
            vault_path_from(os(""), os("/tmp/home"), None),
            joined("/tmp/home", "default.kagivault")
        );
    }

    #[test]
    fn with_nothing_at_all_the_path_is_relative_rather_than_absent() {
        assert_eq!(
            vault_path_from(None, None, None),
            joined(".", "default.kagivault")
        );
    }
}
