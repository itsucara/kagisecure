//! `kagisecure test-logins list | trash` — the person's own view of agent test logins
//! ([ADR-0048](../../../../docs/decisions/0048-agent-test-logins.md)) from a terminal.
//!
//! Both work on **sealed** logins in the "Agent test logins" vault only — the same set
//! `list_test_logins` shows an agent — and neither prints a password. Unlike the agent's
//! `trash_test_logins`, `trash` here is the person's act: it is not limited to logins at allowed
//! origins, and it works with the switch off. It is still a soft trash in one transaction with one
//! audit entry; emptying the trash stays in the app.

use std::path::Path;

use anyhow::Result;
use kagisecure_agent::test_login::{self, audit_detail};
use kagisecure_core::Vault;
use kagisecure_core::proto::ItemId;
use kagisecure_extension_ipc::origin::Origin;

use crate::cli::{TestLoginsListArgs, TestLoginsTrashArgs, UsageError};
use crate::commands::{cli_draft, transact_patiently};
use crate::prompt::SecretInput;

/// The audit `tool` of a trash from the terminal: the same name the agent's tool records, with
/// actor `cli`.
const AUDIT_TOOL: &str = "trash_test_logins";

fn open(path: &Path, input: &mut SecretInput) -> Result<Vault> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    Ok(Vault::open_with_password(path, password.as_bytes())?)
}

/// `--website` as an origin, or a usage error naming the flag (never echoing a long input).
fn website(input: Option<&str>) -> Result<Option<Origin>> {
    input
        .map(|w| {
            Origin::parse(w).map_err(|_| {
                UsageError(
                    "--website must be an http or https URL, such as http://localhost:47800"
                        .to_owned(),
                )
                .into()
            })
        })
        .transpose()
}

/// List sealed agent test logins, oldest first.
///
/// # Errors
///
/// If `--website` is not an http(s) URL, or the vault cannot be opened.
pub fn list(path: &Path, args: &TestLoginsListArgs, input: &mut SecretInput) -> Result<()> {
    let website = website(args.website.as_deref())?;
    let vault = open(path, input)?;
    let summaries: Vec<_> = test_login::matching(&vault, website.as_ref(), args.tag.as_deref())
        .into_iter()
        .map(test_login::summary)
        .collect();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&summaries)?);
        return Ok(());
    }
    if summaries.is_empty() {
        println!("No agent test logins.");
        return Ok(());
    }
    println!(
        "{:<10}  {:<32}  {:<28}  WEBSITES",
        "ID", "TITLE", "USERNAME"
    );
    for s in &summaries {
        let id = s.item_id.to_string();
        println!(
            "{:<10}  {:<32}  {:<28}  {}",
            &id[..8],
            crate::commands::item::truncate(&s.title, 32),
            crate::commands::item::truncate(&s.username, 28),
            s.websites.join(" ")
        );
    }
    Ok(())
}

/// Move the matching sealed agent test logins to the trash: one transaction, one audit entry
/// (`TEST_LOGINS_TRASHED matched=<n>`, actor `cli`), recorded even when nothing matched.
///
/// # Errors
///
/// If `--website` is not an http(s) URL, the vault cannot be opened, or the write fails.
pub fn trash(path: &Path, args: &TestLoginsTrashArgs, input: &mut SecretInput) -> Result<()> {
    let website = website(args.website.as_deref())?;
    let mut vault = open(path, input)?;
    let trashed = transact_patiently(&mut vault, |tx| {
        let ids: Vec<ItemId> = test_login::matching(tx, website.as_ref(), args.tag.as_deref())
            .into_iter()
            .map(|item| item.id)
            .collect();
        let now = kagisecure_core::unix_now();
        for id in &ids {
            if let Some(item) = tx.item_by_id_mut(id) {
                item.trashed_at = Some(now);
                item.updated_at = now;
            }
        }
        tx.append_audit(kagisecure_core::audit::AuditDraft {
            vault_id: tx.agent_test_vault().map(|v| v.id),
            detail: Some(audit_detail::test_logins_trashed(ids.len())),
            ..cli_draft(AUDIT_TOOL)
        });
        Ok(ids)
    })?;
    println!("Moved {} test login(s) to the trash.", trashed.len());
    for id in &trashed {
        println!("  {id}");
    }
    Ok(())
}
