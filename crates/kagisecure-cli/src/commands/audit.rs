//! `kagisecure audit` and `kagisecure lock`.
//!
//! `audit` reads the log out of the vault file directly, so it works whether or not a daemon is
//! running. `lock` is only meaningful with a daemon: locking means dropping a key that a running
//! process is holding, and if nothing is holding one there is nothing to drop.

use std::path::Path;

use anyhow::{Context, Result};
use kagisecure_core::Vault;
use kagisecure_core::audit::AuditEntry;
use kagisecure_ipc::Endpoint;
use kagisecure_ipc::client::{Client, self_info};
use kagisecure_ipc::protocol::{Request, Response};

use crate::cli::AuditArgs;
use crate::commands::ymd;
use crate::prompt::SecretInput;

/// Print the audit log.
///
/// # Errors
///
/// If the vault cannot be opened.
pub fn audit(path: &Path, args: &AuditArgs, input: &mut SecretInput) -> Result<()> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    let vault = Vault::open_with_password(path, password.as_bytes())?;
    drop(password);

    let entries = vault.audit_entries();
    let start = entries.len().saturating_sub(args.limit);
    let page: &[AuditEntry] = &entries[start..];

    if args.json {
        println!("{}", serde_json::to_string_pretty(page)?);
    } else if page.is_empty() {
        println!("The audit log is empty.");
    } else {
        println!(
            "{:<5}  {:<10}  {:<10}  {:<20}  {:<8}  DETAIL",
            "SEQ", "DATE", "ACTOR", "TOOL", "OUTCOME"
        );
        for entry in page {
            let names = if entry.variables.is_empty() {
                String::new()
            } else {
                entry.variables.join(",")
            };
            let target = entry.target_path.as_deref().unwrap_or("");
            println!(
                "{:<5}  {:<10}  {:<10}  {:<20}  {:<8}  {}",
                entry.seq,
                ymd(entry.timestamp),
                crate::commands::item::truncate(&entry.actor, 10),
                crate::commands::item::truncate(&entry.tool, 20),
                entry.outcome,
                [
                    entry.detail.clone().unwrap_or_default(),
                    names,
                    target.to_owned()
                ]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("  ")
            );
        }
        println!();
        println!(
            "{} entr{} in total. Entries record names, never values.",
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" }
        );
    }

    if args.verify {
        match vault.verify_audit() {
            Ok(()) => println!("Hash chain intact ({} entries).", entries.len()),
            Err(e) => {
                println!("HASH CHAIN BROKEN: {e}");
                anyhow::bail!("the audit log did not verify");
            }
        }
    }
    Ok(())
}

/// Tell a running daemon to lock.
///
/// # Errors
///
/// If no daemon is listening, or it refuses.
pub fn lock() -> Result<()> {
    let endpoint = Endpoint::discover().context("could not find the daemon socket")?;
    let mut client = Client::connect(
        &endpoint,
        self_info("kagisecure-cli", env!("CARGO_PKG_VERSION")),
    )
    .with_context(|| {
        format!("no kagisecure daemon is listening on {endpoint}. Nothing to lock.")
    })?;
    match client.call(&Request::Lock)? {
        Response::Locked => {
            println!("Locked. The vault key and every lease are gone.");
            Ok(())
        }
        Response::Error { code, message } => anyhow::bail!("{code}: {message}"),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}
