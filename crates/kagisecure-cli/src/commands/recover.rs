//! `kagisecure recover` — unlock with the printable recovery code and set a new master password.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::{RecoveryCode, Vault};

use crate::cli::RecoverArgs;
use crate::commands::{cli_draft, transact_patiently};
use crate::prompt::{SecretInput, require_non_empty};

/// Unlock with the recovery code, then set a new master password.
///
/// # Errors
///
/// If the code does not parse or does not open the vault, if the new password entries differ, or
/// on any I/O failure.
pub fn recover(path: &Path, args: &RecoverArgs, input: &mut SecretInput) -> Result<()> {
    crate::commands::ensure_exists(path)?;
    let typed = input.read("Recovery code")?;
    let code = RecoveryCode::parse(&typed)?;
    drop(typed);

    let mut vault = Vault::open_with_recovery_code(path, &code)?;
    println!(
        "Unlocked {} with the recovery code ({} item(s)).",
        vault.path().display(),
        vault.items().len()
    );

    let password = input.read_confirmed("New master password")?;
    require_non_empty(&password)?;

    // The Argon2id work for both slots runs here, before any lock is taken — never hold it across
    // a KDF derivation. What is installed inside the transaction is just the already-wrapped key
    // material, checked there against whatever the file's header actually holds.
    let mut prepared_password = Some(vault.prepare_master_password(password.as_bytes())?);
    drop(password);
    let mut prepared_recovery = if args.reissue_recovery_code {
        Some(vault.prepare_recovery_code()?)
    } else {
        None
    };

    let reissued = transact_patiently(&mut vault, |tx| {
        tx.install_master_password(
            prepared_password
                .take()
                .expect("the transaction commits at most once"),
        )?;
        // Recorded inside the transaction that makes each change (ADR-0040 step 10): a credential
        // change and its audit entry reach the file together or not at all.
        tx.append_audit(AuditDraft {
            detail: Some("RECOVERY_CODE".to_owned()),
            ..cli_draft("change_master_password")
        });
        let reissued = match prepared_recovery.take() {
            Some((new_code, prepared)) => {
                tx.install_recovery_code(prepared)?;
                tx.append_audit(cli_draft("reissue_recovery_code"));
                Some(new_code)
            }
            None => None,
        };
        Ok(reissued)
    })?;

    println!("The master password has been replaced. The old one no longer opens this vault.");

    match reissued {
        Some(new_code) => {
            let printed = new_code.display();
            println!();
            println!("Your new one-time recovery code:");
            println!();
            println!("    {}", *printed);
            println!();
            println!("Write it down now. The code you just used has been retired.");
        }
        None => {
            println!(
                "The recovery code you just used still works. Re-issue it with \
                 `kagisecure recover --reissue-recovery-code` if it may have been seen."
            );
        }
    }

    offer_to_delete_backups(path, args.delete_backups)?;
    Ok(())
}

/// Every `<vault>.bak-*` format-upgrade backup beside `vault_path` (threat-model.md W-22): each
/// one is a plain copy of an earlier version of the file, created the first time a device key
/// raised it to `format_ver` 2, kept forever because nothing else deletes it.
fn backup_files(vault_path: &Path) -> Vec<PathBuf> {
    let (Some(name), Some(dir)) = (
        vault_path.file_name().and_then(|n| n.to_str()),
        vault_path.parent(),
    ) else {
        return Vec::new();
    };
    let prefix = format!("{name}.bak-");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix))
        })
        .collect();
    found.sort();
    found
}

/// Ask before deleting; declining, or having nothing to read the answer from (a scripted
/// `--password-stdin` run has nothing left on standard input by this point), both mean "no".
///
/// # Errors
///
/// If standard output cannot be flushed.
fn confirm_delete(backups: &[PathBuf]) -> Result<bool> {
    print!("Delete these {} file(s) now? [y/N] ", backups.len());
    std::io::stdout().flush().context("writing the prompt")?;
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return Ok(false);
    }
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Every format-upgrade backup beside `vault_path` still opens with the master password and
/// recovery code that were current when it was made — **even after this command just replaced
/// them**, since neither changes the vault key itself (threat-model.md W-22). Deleting them is the
/// only thing that closes that door, so every credential change offers it, whether or not this
/// particular run is the one that created a backup.
///
/// # Errors
///
/// If the confirmation prompt cannot be read or written.
fn offer_to_delete_backups(vault_path: &Path, delete_without_asking: bool) -> Result<()> {
    let backups = backup_files(vault_path);
    if backups.is_empty() {
        return Ok(());
    }
    println!();
    println!(
        "This vault has {} format-upgrade backup file(s) beside it. Each one still opens with the \
         master password and recovery code that were current when it was made — including the \
         ones just replaced — and holds every item this vault held then:",
        backups.len()
    );
    for backup in &backups {
        println!("    {}", backup.display());
    }
    if delete_without_asking || confirm_delete(&backups)? {
        for backup in &backups {
            if let Err(e) = std::fs::remove_file(backup) {
                eprintln!(
                    "kagisecure: warning: could not delete {}: {e}",
                    backup.display()
                );
            }
        }
        println!("Deleted.");
    } else {
        println!(
            "Kept. Delete them yourself, with `--delete-backups` next time or by hand, once you are sure you will not need them."
        );
    }
    Ok(())
}
