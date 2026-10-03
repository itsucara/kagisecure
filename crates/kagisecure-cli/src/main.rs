//! `kagisecure` — the command line interface.
//!
//! The CLI is a trusted local tool: it holds the vault key while it runs, and it is the one place
//! where a secret value legitimately reaches a process the user asked for (`kagisecure run`) or,
//! on explicit request, their own terminal (`item show --reveal`). No error message and no
//! diagnostic printed here ever contains a value.

// `deny`, not `forbid`: `commands::generate::copy_via_windows_clipboard` is `#[allow(unsafe_code)]`
// for the direct Win32 clipboard calls `--copy` needs on Windows (`OpenClipboard` et al. have no
// safe wrapper this crate is willing to add a dependency for), and `forbid` cannot be downgraded
// by an inner `#[allow]` anywhere in the crate, even in one function. Every other module is
// exactly as unsafe-free as it was.
#![deny(unsafe_code)]
#![warn(missing_docs)]

mod cli;
mod commands;
mod paths;
mod prompt;

use std::process::ExitCode;

use clap::Parser;

use cli::{
    Cli, Command, EnvCommand, ItemCommand, McpCommand, SharedCommand, SharedEnvCommand,
    SharedItemCommand, VaultCommand,
};
use prompt::SecretInput;

fn main() -> ExitCode {
    let args = Cli::parse();
    match dispatch(&args) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            report(&err);
            ExitCode::from(exit_code_for(&err))
        }
    }
}

fn dispatch(args: &Cli) -> anyhow::Result<u8> {
    let path = paths::resolve(args.vault.clone())?;
    let mut input = SecretInput::new(args.reads_stdin())?;

    match &args.command {
        Command::Vault(VaultCommand::Init(a)) => commands::vault::init(&path, a, &mut input)?,
        Command::Vault(VaultCommand::Unlock) => commands::vault::unlock(&path, &mut input)?,
        Command::Vault(VaultCommand::NewItemsAgentVisible(a)) => {
            commands::vault::new_items_agent_visible(&path, a, &mut input)?;
        }
        Command::Item(ItemCommand::Add(a)) => commands::item::add(&path, a, &mut input)?,
        Command::Item(ItemCommand::List(a)) => commands::item::list(&path, a, &mut input)?,
        Command::Item(ItemCommand::Show(a)) => commands::item::show(&path, a, &mut input)?,
        Command::Item(ItemCommand::Rm(a)) => commands::item::rm(&path, a, &mut input)?,
        Command::Item(ItemCommand::AgentVisible(a)) => {
            commands::item::agent_visible(&path, a, &mut input)?;
        }
        Command::Recover(a) => commands::recover::recover(&path, a, &mut input)?,
        Command::Env(EnvCommand::Create(a)) => commands::env::create(&path, a, &mut input)?,
        Command::Env(EnvCommand::List(a)) => commands::env::list(&path, a, &mut input)?,
        Command::Env(EnvCommand::AddVar(a)) => commands::env::add_var(&path, a, &mut input)?,
        Command::Env(EnvCommand::Rm(a)) => commands::env::rm(&path, a, &mut input)?,
        Command::Env(EnvCommand::Write(a)) => commands::env::write(&path, a, &mut input)?,
        Command::Env(EnvCommand::AgentAccess(a)) => {
            commands::env::agent_access(&path, a, &mut input)?;
        }
        Command::Daemon(a) => commands::daemon::run(&path, a, &mut input)?,
        Command::Lock => commands::audit::lock()?,
        Command::Audit(a) => commands::audit::audit(&path, a, &mut input)?,
        Command::Generate(a) => commands::generate::generate(a)?,
        Command::Totp(a) => commands::generate::totp(&path, a, &mut input)?,
        Command::Mcp(McpCommand::Path) => commands::mcp::path()?,
        Command::Mcp(McpCommand::Install(a)) => commands::mcp::install(a)?,
        Command::Import(a) => commands::import::import(&path, a, &mut input)?,
        Command::Shared(SharedCommand::Create(a)) => {
            commands::shared::create(&path, a, &mut input)?
        }
        Command::Shared(SharedCommand::List(a)) => commands::shared::list(&path, a, &mut input)?,
        Command::Shared(SharedCommand::Status(a)) => {
            commands::shared::status(&path, a, &mut input)?
        }
        Command::Shared(SharedCommand::Item(SharedItemCommand::Add(a))) => {
            commands::shared::item::add(&path, a, &mut input)?;
        }
        Command::Shared(SharedCommand::Item(SharedItemCommand::Set(a))) => {
            commands::shared::item::set(&path, a, &mut input)?;
        }
        Command::Shared(SharedCommand::Item(SharedItemCommand::Rm(a))) => {
            commands::shared::item::rm(&path, a, &mut input)?;
        }
        Command::Shared(SharedCommand::Item(SharedItemCommand::Show(a))) => {
            commands::shared::item::show(&path, a, &mut input)?;
        }
        Command::Shared(SharedCommand::Env(SharedEnvCommand::Create(a))) => {
            commands::shared::env::create(&path, a, &mut input)?;
        }
        Command::Shared(SharedCommand::Env(SharedEnvCommand::AddVar(a))) => {
            commands::shared::env::add_var(&path, a, &mut input)?;
        }
        Command::Shared(SharedCommand::Invite(a)) => {
            commands::shared::invite(&path, a, &mut input)?
        }
        Command::Shared(SharedCommand::Join(a)) => commands::shared::join(&path, a, &mut input)?,
        Command::Shared(SharedCommand::Remove(a)) => {
            commands::shared::remove(&path, a, &mut input)?
        }
        Command::Shared(SharedCommand::Role(a)) => commands::shared::role(&path, a, &mut input)?,
        Command::Shared(SharedCommand::RotationList(a)) => {
            commands::shared::rotation_list(&path, a, &mut input)?;
        }
        Command::Shared(SharedCommand::Sync(a)) => commands::shared::sync(&path, a, &mut input)?,
        Command::Shared(SharedCommand::Import(a)) => {
            commands::shared::import(&path, a, &mut input)?
        }
        Command::Shared(SharedCommand::Export(a)) => {
            commands::shared::export(&path, a, &mut input)?
        }
        Command::Shared(SharedCommand::Rebuild(a)) => {
            commands::shared::rebuild(&path, a, &mut input)?
        }
        Command::Shared(SharedCommand::SetDir(a)) => {
            commands::shared::set_dir(&path, a, &mut input)?
        }
        Command::ClipboardClear(a) => commands::generate::clipboard_clear_helper(a)?,
        // `run` is the one command whose exit status is not its own.
        Command::Run(a) => return commands::run::run(&path, a, &mut input),
    }
    Ok(0)
}

/// Print the error chain to stderr.
///
/// Every layer that could hold plaintext refuses to render it (`Secret`'s `Debug`,
/// `kagisecure_core::Error`'s messages), so this is safe to print verbatim — but the rule is
/// enforced there, not by filtering here.
fn report(err: &anyhow::Error) {
    eprintln!("kagisecure: {err}");
    for cause in err.chain().skip(1) {
        eprintln!("  caused by: {cause}");
    }
}

/// Map a failure to the exit code `--help` promises for it.
///
/// # Why a usage error exits 2 and not 1
///
/// Exit 2 is documented as "usage error (bad arguments)", and clap produces it on its own for a
/// grammar mistake. A rule clap cannot express — `--auto-approve` is refused outside a debug build
/// (ADR-0007) — is the same category of mistake and has to land in the same place, or a script
/// that branches on 2 to mean "I invoked this wrongly" gets a 1 that reads as "an unexpected error,
/// report it" for an invocation it could have fixed itself.
///
/// # Why a damaged or tampered file exits 3 and not 1
///
/// Exit 3 is documented as "could not unlock: wrong password or recovery code, **or the vault was
/// tampered with**", so a vault whose bytes have been changed has to land there. Four errors mean
/// exactly that:
///
/// * [`kagisecure_core::Error::Decrypt`] — the AEAD tag did not verify. Deliberately indistinguishable between a
///   wrong password and an edited ciphertext.
/// * [`kagisecure_core::Error::Malformed`] — a length prefix disagrees with the file size.
/// * [`kagisecure_core::Error::HeaderDecode`] — the plaintext header is no longer well-formed CBOR.
/// * [`kagisecure_core::Error::KdfParams`] — the header decoded, but its Argon2id parameters are
///   outside the accepted range: the same "header is broken" family as the one above, just caught
///   a validation step later.
///
/// One error is a *stronger* tamper signal than any of the four above, because it is found only
/// after a **successful** decryption: [`kagisecure_core::Error::AuditChain`] means the vault
/// opened with the right password and the audit log's hash chain still does not verify, which
/// exit 3's "or the vault was tampered with" describes exactly.
///
/// The first three used to fall through to `EXIT_ERROR`, which reads as "an unexpected error,
/// report it" — so a script that branched on 3 to say "your vault is damaged or your password is
/// wrong" told the truth about a flipped bit in the *ciphertext* and not about a flipped bit eight
/// bytes earlier, in the header the ciphertext is authenticated against. Which of the two a
/// corruption lands in is a detail of where the bytes fell, and it is not something a caller can
/// reason about.
///
/// Two neighbours deliberately stay at `EXIT_ERROR`:
///
/// * [`kagisecure_core::Error::BadMagic`] — the file is not a vault at all, which in practice means `--vault` points
///   at the wrong file rather than that anything was tampered with.
/// * [`kagisecure_core::Error::BodyDecode`] — only reachable *after* a successful decryption, so it is a format
///   problem in a vault that opened correctly, not a damaged one.
///
/// # Busy, locked-out and changed vaults
///
/// [`kagisecure_core::Error::VaultBusy`] and [`kagisecure_core::Error::LockLost`] (exit
/// [`cli::EXIT_VAULT_BUSY`]) both mean nothing was written and retrying shortly is safe — the
/// second is a lock file that was moved or deleted out from under this process, which by
/// construction means another process may already hold a lock of its own, the same situation a
/// caller would see from an ordinary busy wait. [`kagisecure_core::Error::VaultDiverged`] /
/// [`kagisecure_core::Error::VaultReplaced`] / [`kagisecure_core::Error::VaultConflict`] (exit
/// [`cli::EXIT_VAULT_CHANGED`]) instead mean retrying cannot help until a human resolves which
/// version of the file is the vault. These are the outcomes of
/// [`kagisecure_core::vault::Vault::transact`] — see `commands::transact_patiently` for the wait
/// and retry every write command runs through.
///
/// [`kagisecure_core::Error::LockUnsupported`] (exit [`cli::EXIT_LOCK_UNSUPPORTED`]) is a third,
/// distinct shape: not busy, not changed, but a file system that cannot ever take the lock a write
/// needs. The vault still opens and reads; only writes are refused, permanently, until the file
/// moves to a file system that supports locking.
///
/// [`kagisecure_core::Error::VaultSchemaTooNew`] and
/// [`kagisecure_core::Error::UnsupportedFormatVersion`] (exit [`cli::EXIT_VAULT_TOO_NEW`]) both
/// mean a newer kagisecure wrote this file: the first refuses only to *write* a vault this build
/// can still read; the second cannot even read it. A script does not need to tell them apart —
/// both say "upgrade kagisecure", never "retry".
///
/// # Audit-first releases
///
/// `env write` and `run` wrap the *same* transaction errors in [`commands::AuditUnavailable`] when
/// they come from the audit-first gate rather than from an ordinary mutation, and that always maps
/// to [`cli::EXIT_AUDIT_UNAVAILABLE`] regardless of which `Core` variant is inside — checked before
/// the `Core` match below finds the wrapped error and tries to categorize it by the wrong rule.
///
/// # Everything else
///
/// `Error` is `#[non_exhaustive]`, so the match below still needs a trailing wildcard whatever it
/// names explicitly — a new variant cannot make the match fail to compile the way it would inside
/// `kagisecure-core` itself. What stands in for that is
/// `tests::every_core_error_variant_is_mapped_on_purpose`: it walks
/// `kagisecure_core::Error::all_variants_for_test` — one instance of every variant, which fails
/// to compile inside `kagisecure-core` if a variant is ever added there without a sample — against
/// a table this test owns of every variant name this crate currently knows about and the code it
/// deliberately maps to. A variant missing from that table fails the test loudly, instead of
/// silently falling through the wildcard below and reading as "an unexpected error" forever.
fn exit_code_for(err: &anyhow::Error) -> u8 {
    // Checked before the vault errors: a usage error is not about a vault, and nothing here can be
    // both.
    if err.downcast_ref::<cli::UsageError>().is_some() {
        return cli::EXIT_USAGE;
    }
    // A `kagisecure shared ...` `<vault>` argument that resolved to nothing, or to more than one
    // shared vault: the same "no such X" category `Core::ItemNotFound` and its siblings are
    // below, but for a shared vault, which has no `kagisecure_core::Error` variant of its own
    // (see the type's doc comment in `cli.rs`).
    if err.downcast_ref::<cli::NoSuchSharedVault>().is_some() {
        return cli::EXIT_NOT_FOUND;
    }
    if err.downcast_ref::<commands::AuditUnavailable>().is_some() {
        return cli::EXIT_AUDIT_UNAVAILABLE;
    }
    // `kagisecure_import::ImportError` is its own error type, not a `Core` variant — even the
    // `Vault(Core)` case, which wraps one, is caught here first because the propagated error's
    // own concrete type is `ImportError`. Every variant maps to the same exit code: whatever
    // went wrong, the import did not happen, including a format this build does not support.
    if err
        .downcast_ref::<kagisecure_import::ImportError>()
        .is_some()
    {
        return cli::EXIT_IMPORT_FAILED;
    }
    // A `kagisecure shared ...` failure. `SharedError::Core` wraps exactly the same
    // `kagisecure_core::Error` an ordinary vault operation could return — the personal vault
    // refusing a lock, a write or a device key — and is mapped by `core_exit_code`, the identical
    // rule a bare `Core` error gets below. `SharedError::Refused` is shared-vault-specific: this
    // device does not hold the role or the epoch key a change needs, or the change would leave no
    // admin (`kagisecure_shared::admin`'s doc comments name every case) — `EXIT_SHARED_REFUSED`,
    // not `EXIT_ERROR`, so a script can tell "not allowed" apart from "something broke". Every
    // other `SharedError` variant (a malformed or oversize file, a bad signature, an unsupported
    // suite or version) is a shared vault's own record or file refusing to parse — nothing above
    // names that category more specifically, so, like the `Core` wildcard below, it is
    // `EXIT_ERROR`.
    if let Some(shared) = err.downcast_ref::<kagisecure_shared::SharedError>() {
        return match shared {
            kagisecure_shared::SharedError::Core(inner) => core_exit_code(inner),
            kagisecure_shared::SharedError::Refused(_) => cli::EXIT_SHARED_REFUSED,
            _ => cli::EXIT_ERROR,
        };
    }
    err.downcast_ref::<kagisecure_core::Error>()
        .map_or(cli::EXIT_ERROR, core_exit_code)
}

/// The exit code a [`kagisecure_core::Error`] maps to, whether it reached `main` on its own or
/// wrapped in a [`kagisecure_shared::SharedError::Core`] — see [`exit_code_for`]'s doc comments
/// above each check, and its own doc comment below, for the reasoning behind every arm.
fn core_exit_code(e: &kagisecure_core::Error) -> u8 {
    use kagisecure_core::Error as Core;
    match e {
        // Tampered or damaged: decryption failed, something a successful decryption should never
        // have left unreadable did, or — the strongest signal of the four, because it is found
        // only *after* a successful decryption — the audit log's hash chain does not verify.
        Core::Decrypt
        | Core::BadRecoveryCode
        | Core::Malformed
        | Core::HeaderDecode(_)
        | Core::KdfParams(_)
        | Core::AuditChain(_) => cli::EXIT_UNLOCK_FAILED,
        Core::VaultNotFound(_) => cli::EXIT_NO_VAULT,
        // A variable name that is not an identifier is a bad argument (`env add-var`, `run
        // --env`) — or, read back from a vault, a name no command will write out. Either way the
        // fix is the name, not a retry.
        Core::InvalidVarName(_) => cli::EXIT_USAGE,
        Core::VaultExists(_) => cli::EXIT_VAULT_EXISTS,
        // "No such X": items, fields, environments and variables are one category to a script —
        // none of them exist to inject or write, whichever kind of reference it was, and whichever
        // vault — personal or shared — it was resolved against.
        Core::ItemNotFound(_)
        | Core::AmbiguousItem(_)
        | Core::FieldNotFound { .. }
        | Core::NotASecret(_)
        | Core::EnvNotFound(_)
        | Core::AmbiguousEnv(_)
        | Core::VarNotFound(..)
        | Core::VarNotPopulated(_) => cli::EXIT_NOT_FOUND,
        // Busy: nothing was written, retrying shortly is safe. `LockLost` belongs here, not with
        // `EXIT_ERROR`: another process may already hold a fresh lock by the time this one
        // noticed its own was moved or deleted, which is exactly what a busy wait also means.
        Core::VaultBusy { .. } | Core::LockLost(_) => cli::EXIT_VAULT_BUSY,
        // Changed: nothing was written, and nothing will be until a human resolves which version
        // of the file is the vault. `VaultConflict` is the non-transactional `save` path only.
        Core::VaultDiverged(_) | Core::VaultReplaced(_) | Core::VaultConflict(_) => {
            cli::EXIT_VAULT_CHANGED
        }
        // A file system that cannot ever take the lock a write needs. Distinct from "busy":
        // retrying changes nothing here.
        Core::LockUnsupported(_) => cli::EXIT_LOCK_UNSUPPORTED,
        // A newer kagisecure wrote this file. `VaultSchemaTooNew` still opens;
        // `UnsupportedFormatVersion` does not — a script needs "upgrade", not the distinction.
        Core::VaultSchemaTooNew { .. } | Core::UnsupportedFormatVersion { .. } => {
            cli::EXIT_VAULT_TOO_NEW
        }
        // Everything else lands on `EXIT_ERROR` deliberately, not by falling through unnoticed —
        // `tests::every_core_error_variant_is_mapped_on_purpose` below pins the full list by name
        // so a newly added variant fails that test until it is added there too, rather than
        // silently joining this arm. None of the following is reachable from a documented CLI
        // outcome today: `VaultNotInConflict` is only ever produced by the app's "keep this
        // session's version" overwrite, which the CLI does not expose; `NestedTransaction` is now
        // a compile error to trigger rather than a runtime one; `TransactionAborted` is
        // `kagisecure-agent`'s own internal sentinel and is never returned to this crate's
        // callers. The rest are rare, unrecoverable conditions this build cannot give a more
        // specific answer to: a vault over the size limit, a format this build does not
        // implement, an env value or file name this build refuses, a spawn or key-derivation
        // failure, plain I/O. `EXIT_ERROR` — "an unexpected error, report it" — is the honest
        // answer for all of them, and for any variant added to `kagisecure_core::Error` after
        // this match was last updated.
        _ => cli::EXIT_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `kagisecure_core::Error` variant this crate knows about, and the exit code
    /// `exit_code_for` deliberately gives it. Keyed by the same name
    /// [`kagisecure_core::Error::all_variants_for_test`] uses for that variant.
    ///
    /// This table, not the `match` in `exit_code_for`, is what makes a new variant fail loudly:
    /// `Error` being `#[non_exhaustive]` means that `match` always compiles whether or not it
    /// lists a given variant, but this table is a plain `match` on `&str` with no wildcard, so
    /// [`every_core_error_variant_is_mapped_on_purpose`] fails to compile — not just to pass — the
    /// moment `kagisecure-core` starts naming a variant this test has never heard of.
    fn expected_exit_code(variant: &str) -> u8 {
        match variant {
            "Decrypt" | "BadRecoveryCode" | "Malformed" | "HeaderDecode" | "KdfParams"
            | "AuditChain" => cli::EXIT_UNLOCK_FAILED,
            "VaultNotFound" => cli::EXIT_NO_VAULT,
            "InvalidVarName" => cli::EXIT_USAGE,
            "VaultExists" => cli::EXIT_VAULT_EXISTS,
            "ItemNotFound" | "AmbiguousItem" | "FieldNotFound" | "NotASecret" | "EnvNotFound"
            | "AmbiguousEnv" | "VarNotFound" | "VarNotPopulated" => cli::EXIT_NOT_FOUND,
            "VaultBusy" | "LockLost" => cli::EXIT_VAULT_BUSY,
            "VaultDiverged" | "VaultReplaced" | "VaultConflict" => cli::EXIT_VAULT_CHANGED,
            "LockUnsupported" => cli::EXIT_LOCK_UNSUPPORTED,
            "VaultSchemaTooNew" | "UnsupportedFormatVersion" => cli::EXIT_VAULT_TOO_NEW,
            "VaultNotInConflict" | "NestedTransaction" | "TransactionAborted" | "VaultTooLarge"
            | "BadMagic" | "BodyDecode" | "NoSuchSlot" | "Unsupported" | "KdfFailed"
            | "NonUtf8EnvValue" | "InvalidEnvFileName" | "EnvFileExists" | "InvalidPath" | "Io"
            | "Rng" | "Generator" | "Totp" | "DeviceKey" | "MachineVault" | "Spawn" => {
                cli::EXIT_ERROR
            }
            other => panic!(
                "kagisecure_core::Error::{other} has no exit-code mapping in this test's table \
                 (see expected_exit_code in kagisecure-cli's main.rs) or in exit_code_for itself. \
                 Decide deliberately where it belongs — see exit_code_for's doc comment — then \
                 add it to both."
            ),
        }
    }

    /// Walks every constructible `kagisecure_core::Error` variant and checks two things: that
    /// `exit_code_for` gives it the code this test's own table says it should, and — the point of
    /// the exercise — that a variant `kagisecure-core` adds later cannot pass this test silently.
    /// A new variant makes `Error::all_variants_for_test` grow (or fails to compile inside
    /// `kagisecure-core` until it does), which makes this test call `expected_exit_code` with a
    /// name its `match` has never seen, which panics rather than falling through to a default.
    #[test]
    fn every_core_error_variant_is_mapped_on_purpose() {
        let mut seen = std::collections::BTreeSet::new();
        for (name, error) in kagisecure_core::Error::all_variants_for_test() {
            assert!(
                seen.insert(name),
                "{name} appears twice in all_variants_for_test"
            );
            let wrapped: anyhow::Error = error.into();
            let expected = expected_exit_code(name);
            let actual = exit_code_for(&wrapped);
            assert_eq!(
                actual, expected,
                "kagisecure_core::Error::{name} maps to exit {actual}, but this test's table \
                 says it should be {expected}"
            );
        }
        // Sanity check on the test itself: if `all_variants_for_test` ever returned nothing (a
        // refactor gone wrong), the loop above would pass vacuously and hide every regression.
        assert!(!seen.is_empty());
    }

    #[test]
    fn a_usage_error_exits_2_even_though_it_carries_no_core_variant() {
        let err: anyhow::Error = cli::UsageError("test".to_owned()).into();
        assert_eq!(exit_code_for(&err), cli::EXIT_USAGE);
    }

    #[test]
    fn an_audit_gate_failure_exits_9_regardless_of_which_core_variant_it_wraps() {
        let err: anyhow::Error = commands::AuditUnavailable(kagisecure_core::Error::VaultBusy {
            path: std::path::PathBuf::from("/test"),
            waited: std::time::Duration::from_secs(30),
        })
        .into();
        assert_eq!(exit_code_for(&err), cli::EXIT_AUDIT_UNAVAILABLE);
    }

    #[test]
    fn an_unrecognised_error_exits_1() {
        let err = anyhow::anyhow!("something this crate has never heard of");
        assert_eq!(exit_code_for(&err), cli::EXIT_ERROR);
    }

    #[test]
    fn a_shared_vault_refusal_exits_13() {
        let err: anyhow::Error =
            kagisecure_shared::SharedError::Refused("only an admin device may do that").into();
        assert_eq!(exit_code_for(&err), cli::EXIT_SHARED_REFUSED);
    }

    #[test]
    fn a_core_error_wrapped_in_a_shared_error_maps_like_the_bare_core_error() {
        let wrapped: anyhow::Error =
            kagisecure_shared::SharedError::Core(kagisecure_core::Error::VaultBusy {
                path: std::path::PathBuf::from("/test"),
                waited: std::time::Duration::from_secs(1),
            })
            .into();
        let bare: anyhow::Error = kagisecure_core::Error::VaultBusy {
            path: std::path::PathBuf::from("/test"),
            waited: std::time::Duration::from_secs(1),
        }
        .into();
        assert_eq!(exit_code_for(&wrapped), exit_code_for(&bare));
        assert_eq!(exit_code_for(&wrapped), cli::EXIT_VAULT_BUSY);
    }

    #[test]
    fn a_shared_vault_reference_that_does_not_resolve_exits_6_like_an_item_reference() {
        let err: anyhow::Error =
            cli::NoSuchSharedVault("no shared vault matches \"x\"".to_owned()).into();
        assert_eq!(exit_code_for(&err), cli::EXIT_NOT_FOUND);
    }
}
