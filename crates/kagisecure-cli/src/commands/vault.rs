//! `kagisecure vault init` and `kagisecure vault unlock`.

use std::path::Path;

use anyhow::{Context, Result};
use kagisecure_core::Vault;
use kagisecure_core::crypto::kdf::KdfParams;
use kagisecure_core::vault::CreateOptions;

use crate::cli::InitArgs;
use crate::prompt::{SecretInput, require_non_empty};

/// Create a vault and print its one-time recovery code.
///
/// # Errors
///
/// If a vault already exists, if the password entries do not match, or on any I/O or crypto
/// failure.
pub fn init(path: &Path, args: &InitArgs, input: &mut SecretInput) -> Result<()> {
    if path.exists() {
        // Reported here rather than after the KDF so the user does not wait 300 ms to be told no.
        return Err(kagisecure_core::Error::VaultExists(path.to_path_buf()).into());
    }

    let password = input.read_confirmed("New master password")?;
    require_non_empty(&password)?;

    let mut kdf = KdfParams::new(args.kdf_m_kib, args.kdf_t, args.kdf_p)
        .context("the Argon2id parameters were rejected")?;
    kdf.reroll_salt()?;
    let options = CreateOptions {
        kdf,
        vault_name: args.name.clone(),
        kdf_hint: args.kdf_hint.clone(),
    };

    let (vault, code) = Vault::create(path, password.as_bytes(), &options)?;
    let printed = code.display();

    println!("Created {}", vault.path().display());
    println!();
    println!("Your one-time recovery code:");
    println!();
    println!("    {}", *printed);
    println!();
    println!("Write it down now. It is shown once and is not stored anywhere.");
    println!("It unlocks this vault on its own, without the master password.");
    println!("Anyone who has it has your vault: treat it like the vault itself.");
    Ok(())
}

/// Open the vault to prove the password works, and print a summary. Never prints a value.
///
/// # Errors
///
/// If the vault is missing or the password is wrong.
pub fn unlock(path: &Path, input: &mut SecretInput) -> Result<()> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    let vault = Vault::open_with_password(path, password.as_bytes())?;

    let items = vault.items().len();
    println!("Unlocked {}", vault.path().display());
    for summary in vault.vault_summaries() {
        println!(
            "  vault {:<24} {} item(s){}",
            summary.name,
            summary.item_count,
            if summary.agent_visible {
                ""
            } else {
                "  (not visible to agents)"
            }
        );
    }
    println!("  {items} item(s) in total");
    let kdf = &vault.header().kdf;
    println!(
        "  kdf {} m={} KiB t={} p={}{}",
        kdf.alg,
        kdf.m_kib,
        kdf.t,
        kdf.p,
        vault
            .header()
            .kdf_hint
            .as_deref()
            .map(|h| format!("  ({h})"))
            .unwrap_or_default()
    );
    let slots: Vec<&str> = vault
        .header()
        .wrapped_keys
        .iter()
        .map(|s| s.kind.as_str())
        .collect();
    println!("  key slots: {}", slots.join(", "));
    Ok(())
}
