//! `kagisecure env agent-access --shared-vault …`: which of a shared vault's items, fields and
//! environments this computer's agents may see (ADR-0035 §14).
//!
//! The setting is this computer's own: it is kept in the local section of its copy of the
//! shared vault and never sent to the other members, so no member can make something visible to
//! someone else's agents. Everything starts hidden, as in the personal vault.

use std::path::Path;

use anyhow::{Result, bail};
use kagisecure_shared::admin::visibility;
use kagisecure_shared::read::SharedSnapshot;

use super::{open_personal, resolve_vault};
use crate::cli::AgentAccessArgs;
use crate::prompt::SecretInput;

/// Show, or with `change` set, change what this computer's agents may see of shared vault
/// `reference`.
///
/// # Errors
///
/// If the personal vault or the shared vault cannot be opened, or a reference does not resolve
/// to exactly one item, field or environment.
pub fn agent_access(
    path: &Path,
    reference: &str,
    args: &AgentAccessArgs,
    change: Option<bool>,
    input: &mut SecretInput,
) -> Result<()> {
    let personal = open_personal(path, input)?;
    let mut opened = resolve_vault(path, &personal, reference)?;
    drop(personal);
    let snapshot = SharedSnapshot::read(&opened.replica, &opened.device)?;

    let Some(visible) = change else {
        println!("{:<12}  {:<28}  AGENT", "KIND", "NAME");
        for e in snapshot.environments() {
            println!(
                "{:<12}  {:<28}  {}",
                "environment",
                crate::commands::item::truncate(&e.name, 28),
                yes_no(e.agent_visible)
            );
        }
        for i in snapshot.items() {
            println!(
                "{:<12}  {:<28}  {}",
                "item",
                crate::commands::item::truncate(&i.title, 28),
                yes_no(i.agent_visible)
            );
        }
        println!();
        println!(
            "This is this computer's own setting for the shared vault {:?}; the other members \
             keep theirs. Pass --allow or --deny with --item (optionally with --field) or \
             --environment to change one.",
            snapshot.name()
        );
        return Ok(());
    };

    if args.item.is_none() && args.environment.is_none() {
        bail!("nothing to change: pass --item or --environment with --shared-vault");
    }

    let mut changed = Vec::new();
    if let Some(item_ref) = &args.item {
        let item = find_one(
            snapshot.items(),
            item_ref,
            "item",
            |i| i.id.to_string(),
            |i| &i.title,
        )?;
        if let Some(field_ref) = &args.field {
            let field = item
                .fields
                .iter()
                .find(|f| f.id.to_string() == *field_ref || f.label == *field_ref)
                .ok_or_else(|| anyhow::anyhow!("item {} has no field {field_ref:?}", item.id))?;
            visibility::set_field(
                &mut opened.replica,
                &opened.device,
                item.id,
                field.id,
                visible,
            )?;
            changed.push(format!("shared item {} field {}", item.id, field.id));
        } else {
            visibility::set_item(&mut opened.replica, &opened.device, item.id, visible)?;
            changed.push(format!("shared item {}", item.id));
        }
    }
    if let Some(env_ref) = &args.environment {
        let env = find_one(
            snapshot.environments(),
            env_ref,
            "environment",
            |e| e.id.to_string(),
            |e| &e.name,
        )?;
        visibility::set_env(&mut opened.replica, &opened.device, env.id, visible)?;
        changed.push(format!("shared environment {}", env.id));
    }
    for target in changed {
        println!(
            "{target}: agent access {} on this computer",
            if visible { "allowed" } else { "denied" }
        );
    }
    Ok(())
}

fn yes_no(visible: bool) -> &'static str {
    if visible { "yes" } else { "no" }
}

/// The one entry `reference` names — by id, unique id prefix of at least four characters, or
/// exact name — the convention [`kagisecure_core::Vault::find_item`] uses.
fn find_one<'a, T>(
    entries: &'a [T],
    reference: &str,
    what: &str,
    id_of: impl Fn(&T) -> String,
    name_of: impl Fn(&T) -> &String,
) -> Result<&'a T> {
    let hits: Vec<&T> = entries
        .iter()
        .filter(|e| {
            let id = id_of(e);
            id == reference
                || name_of(e) == reference
                || (reference.len() >= 4 && id.starts_with(reference))
        })
        .collect();
    match hits.as_slice() {
        [one] => Ok(one),
        [] => bail!("no {what} in that shared vault matches {reference:?}"),
        _ => bail!("{reference:?} matches more than one {what} in that shared vault; use its id"),
    }
}
