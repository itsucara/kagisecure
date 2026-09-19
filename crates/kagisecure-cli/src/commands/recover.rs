//! `kagisecure recover` — unlock with the printable recovery code and set a new master password.

use std::path::Path;

use anyhow::Result;
use kagisecure_core::{RecoveryCode, Vault};

use crate::cli::RecoverArgs;
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
    vault.change_master_password(password.as_bytes())?;

    let reissued = if args.reissue_recovery_code {
        Some(vault.reissue_recovery_code()?)
    } else {
        None
    };

    vault.save()?;
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
    Ok(())
}
