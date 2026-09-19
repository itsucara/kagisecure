//! `kagisecure` — the command line interface.
//!
//! The CLI is a trusted local tool: it holds the vault key while it runs, and it is the one place
//! where a secret value legitimately reaches a process the user asked for (`kagisecure run`) or,
//! on explicit request, their own terminal (`item show --reveal`). No error message and no
//! diagnostic printed here ever contains a value.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cli;
mod commands;
mod paths;
mod prompt;

use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, Command, EnvCommand, ItemCommand, McpCommand, VaultCommand};
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
        Command::Item(ItemCommand::Add(a)) => commands::item::add(&path, a, &mut input)?,
        Command::Item(ItemCommand::List(a)) => commands::item::list(&path, a, &mut input)?,
        Command::Item(ItemCommand::Show(a)) => commands::item::show(&path, a, &mut input)?,
        Command::Item(ItemCommand::Rm(a)) => commands::item::rm(&path, a, &mut input)?,
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
/// # Why a damaged file exits 3 and not 1
///
/// Exit 3 is documented as "could not unlock: wrong password or recovery code, **or the vault was
/// tampered with**", so a vault whose bytes have been changed has to land there. Three errors mean
/// exactly that:
///
/// * [`kagisecure_core::Error::Decrypt`] — the AEAD tag did not verify. Deliberately indistinguishable between a
///   wrong password and an edited ciphertext.
/// * [`kagisecure_core::Error::Malformed`] — a length prefix disagrees with the file size.
/// * [`kagisecure_core::Error::HeaderDecode`] — the plaintext header is no longer well-formed CBOR.
///
/// The last two used to fall through to `EXIT_ERROR`, which reads as "an unexpected error, report
/// it" — so a script that branched on 3 to say "your vault is damaged or your password is wrong"
/// told the truth about a flipped bit in the *ciphertext* and not about a flipped bit eight bytes
/// earlier, in the header the ciphertext is authenticated against. Which of the two a corruption
/// lands in is a detail of where the bytes fell, and it is not something a caller can reason
/// about.
///
/// Two neighbours deliberately stay at `EXIT_ERROR`:
///
/// * [`kagisecure_core::Error::BadMagic`] — the file is not a vault at all, which in practice means `--vault` points
///   at the wrong file rather than that anything was tampered with.
/// * [`kagisecure_core::Error::BodyDecode`] — only reachable *after* a successful decryption, so it is a format
///   problem in a vault that opened correctly, not a damaged one.
fn exit_code_for(err: &anyhow::Error) -> u8 {
    use kagisecure_core::Error as Core;
    // Checked before the vault errors: a usage error is not about a vault, and nothing here can be
    // both.
    if err.downcast_ref::<cli::UsageError>().is_some() {
        return cli::EXIT_USAGE;
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
    match err.downcast_ref::<Core>() {
        Some(Core::Decrypt | Core::BadRecoveryCode | Core::Malformed | Core::HeaderDecode(_)) => {
            cli::EXIT_UNLOCK_FAILED
        }
        Some(Core::VaultNotFound(_)) => cli::EXIT_NO_VAULT,
        Some(Core::VaultExists(_)) => cli::EXIT_VAULT_EXISTS,
        Some(
            Core::ItemNotFound(_)
            | Core::AmbiguousItem(_)
            | Core::FieldNotFound { .. }
            | Core::NotASecret(_),
        ) => cli::EXIT_NOT_FOUND,
        _ => cli::EXIT_ERROR,
    }
}
