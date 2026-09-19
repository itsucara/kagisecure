//! `kagisecure env create | list | add-var | rm | write | agent-access`.
//!
//! Environments are the structure the MCP tools operate on (vault-format §5.2). Everything here
//! prints names, never values — `env write` is the one command that materializes them, and it
//! writes them into a `0600` file rather than onto the terminal.

use std::path::Path;

use anyhow::{Context, Result, bail};
use kagisecure_core::Vault;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::inject::envfile;
use kagisecure_core::model::{EnvVar, Environment, Secret, VarSource};
use kagisecure_core::proto::{Outcome, VarSourceKind};

use crate::cli::{
    AgentAccessArgs, EnvAddVarArgs, EnvCreateArgs, EnvListArgs, EnvRmArgs, EnvWriteArgs,
};
use crate::prompt::SecretInput;

fn open(path: &Path, input: &mut SecretInput) -> Result<Vault> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    Ok(Vault::open_with_password(path, password.as_bytes())?)
}

fn cli_draft(tool: &str) -> AuditDraft {
    AuditDraft {
        actor: "cli".to_owned(),
        tool: tool.to_owned(),
        outcome: Outcome::Allowed,
        ..AuditDraft::default()
    }
}

/// Create an empty environment.
///
/// # Errors
///
/// If the vault cannot be opened or saved.
pub fn create(path: &Path, args: &EnvCreateArgs, input: &mut SecretInput) -> Result<()> {
    let mut vault = open(path, input)?;
    let vault_id = vault.default_vault_id()?;
    let mut env = Environment::new(vault_id, args.name.clone());
    env.description.clone_from(&args.description);
    env.agent_visible = args.agent_visible;
    let id = env.id;
    vault.add_environment(env);
    vault.append_audit(AuditDraft {
        vault_id: Some(vault_id),
        environment_id: Some(id),
        ..cli_draft("env create")
    });
    vault.save()?;

    println!("Created {id}");
    if args.agent_visible {
        println!("It is visible to agents.");
    } else {
        println!(
            "It is not visible to agents. Run `kagisecure env agent-access --allow --environment {id}`"
        );
        println!(
            "to change that — and `--allow --logical-vault <name>` for the vault it lives in."
        );
    }
    Ok(())
}

/// List environments and their variable names.
///
/// # Errors
///
/// If the vault cannot be opened.
pub fn list(path: &Path, args: &EnvListArgs, input: &mut SecretInput) -> Result<()> {
    let vault = open(path, input)?;
    let summaries = vault.environment_summaries();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&summaries)?);
        return Ok(());
    }

    if summaries.is_empty() {
        println!("No environments yet. Create one with `kagisecure env create <name>`.");
        return Ok(());
    }

    println!("{:<10}  {:<28}  {:<6}  VARIABLES", "ID", "NAME", "AGENT");
    for env in &summaries {
        let id = env.id.to_string();
        let vars: Vec<String> = env
            .variables
            .iter()
            .map(|v| match v.kind {
                VarSourceKind::Pending => format!("{}(pending)", v.name),
                VarSourceKind::ItemField => format!("{}(→item)", v.name),
                VarSourceKind::Literal => v.name.clone(),
            })
            .collect();
        println!(
            "{:<10}  {:<28}  {:<6}  {}",
            &id[..8],
            crate::commands::item::truncate(&env.name, 28),
            if env.agent_visible { "yes" } else { "no" },
            if vars.is_empty() {
                "(none)".to_owned()
            } else {
                vars.join(", ")
            }
        );
    }
    println!();
    println!("Values are never printed. `kagisecure env write` puts them in a 0600 file.");
    Ok(())
}

/// Add or replace a variable.
///
/// # Errors
///
/// If the vault cannot be opened, the reference does not resolve, or neither `--bind` nor
/// `--literal` was given.
pub fn add_var(path: &Path, args: &EnvAddVarArgs, input: &mut SecretInput) -> Result<()> {
    let mut vault = open(path, input)?;

    let source = match (&args.bind, args.literal) {
        (Some(spec), false) => {
            let Some((item_ref, field_ref)) = spec.rsplit_once('/') else {
                bail!("--bind expects ITEM/FIELD, got {spec:?}");
            };
            let item = vault.find_item(item_ref)?;
            let field =
                item.field(field_ref)
                    .ok_or_else(|| kagisecure_core::Error::FieldNotFound {
                        item: item_ref.to_owned(),
                        field: field_ref.to_owned(),
                    })?;
            VarSource::ItemField {
                item: item.id,
                field: field.id,
            }
        }
        (None, true) => {
            let value = input.read(&format!("Value for {}", args.name))?;
            VarSource::Literal(Secret::from_string(value.to_string()))
        }
        (None, false) => bail!("pass either --bind ITEM/FIELD or --literal"),
        (Some(_), true) => bail!("--bind and --literal are mutually exclusive"),
    };

    let kind = source.kind();
    let env = vault.find_environment_mut(&args.environment)?;
    let env_id = env.id;
    env.set_var(EnvVar {
        name: args.name.clone(),
        source,
    });

    vault.append_audit(AuditDraft {
        environment_id: Some(env_id),
        variables: vec![args.name.clone()],
        ..cli_draft("env add-var")
    });
    vault.save()?;

    println!("Set {} in {env_id} ({kind})", args.name);
    Ok(())
}

/// Remove a variable or a whole environment.
///
/// # Errors
///
/// If the vault cannot be opened or the reference does not resolve.
pub fn rm(path: &Path, args: &EnvRmArgs, input: &mut SecretInput) -> Result<()> {
    let mut vault = open(path, input)?;

    match &args.var {
        Some(name) => {
            let env = vault.find_environment_mut(&args.environment)?;
            let env_id = env.id;
            if !env.remove_var(name) {
                bail!("{:?} has no variable {name:?}", args.environment);
            }
            vault.append_audit(AuditDraft {
                environment_id: Some(env_id),
                variables: vec![name.clone()],
                ..cli_draft("env rm")
            });
            vault.save()?;
            println!("Removed {name} from {env_id}");
        }
        None => {
            let env = vault.remove_environment(&args.environment)?;
            let id = env.id;
            let count = env.vars.len();
            drop(env);
            vault.append_audit(AuditDraft {
                environment_id: Some(id),
                ..cli_draft("env rm")
            });
            vault.save()?;
            println!("Removed {id} and its {count} variable(s)");
        }
    }
    Ok(())
}

/// Write an environment into a `.env` file.
///
/// # Errors
///
/// If the vault cannot be opened, a variable has no value yet, or the file cannot be written.
pub fn write(path: &Path, args: &EnvWriteArgs, input: &mut SecretInput) -> Result<()> {
    let mut vault = open(path, input)?;

    let dir = args
        .dir
        .canonicalize()
        .with_context(|| format!("{} does not exist", args.dir.display()))?;

    let wanted = (!args.vars.is_empty()).then(|| args.vars.clone());
    let injections = vault.resolve_environment(&args.environment, wanted.as_deref())?;
    let written = envfile::write(&dir, &args.filename, &injections, args.overwrite)?;
    drop(injections);

    let env_id = vault.find_environment(&args.environment)?.id;
    vault.append_audit(AuditDraft {
        environment_id: Some(env_id),
        variables: written.variables.clone(),
        target_path: Some(written.path.display().to_string()),
        ..cli_draft("env write")
    });
    vault.save()?;

    println!(
        "Wrote {} ({} bytes, mode 0600): {}",
        written.path.display(),
        written.bytes,
        written.variables.join(", ")
    );
    match written.gitignored {
        Some(false) => {
            println!();
            println!("WARNING: that file is inside a git work tree and nothing ignores it.");
            println!("Add it to .gitignore before you commit anything.");
        }
        Some(true) => println!("It is covered by .gitignore."),
        None => {}
    }
    Ok(())
}

/// Show or change agent visibility.
///
/// # Errors
///
/// If the vault cannot be opened or a reference does not resolve.
pub fn agent_access(path: &Path, args: &AgentAccessArgs, input: &mut SecretInput) -> Result<()> {
    let mut vault = open(path, input)?;

    let change = match (args.allow, args.deny) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        (false, false) => None,
        (true, true) => bail!("--allow and --deny are mutually exclusive"),
    };

    let Some(visible) = change else {
        println!("{:<12}  {:<28}  AGENT", "KIND", "NAME");
        for v in vault.vault_summaries() {
            println!(
                "{:<12}  {:<28}  {}",
                "vault",
                crate::commands::item::truncate(&v.name, 28),
                if v.agent_visible { "yes" } else { "no" }
            );
        }
        for e in vault.environment_summaries() {
            println!(
                "{:<12}  {:<28}  {}",
                "environment",
                crate::commands::item::truncate(&e.name, 28),
                if e.agent_visible { "yes" } else { "no" }
            );
        }
        for i in vault.item_summaries() {
            println!(
                "{:<12}  {:<28}  {}",
                "item",
                crate::commands::item::truncate(&i.title, 28),
                if i.agent_visible { "yes" } else { "no" }
            );
        }
        println!();
        println!(
            "Pass --allow or --deny with --logical-vault, --item or --environment to change one."
        );
        return Ok(());
    };

    let mut touched = 0;
    if let Some(reference) = &args.vault_ref {
        let id = vault.find_vault(reference)?;
        vault.set_vault_agent_visible(id, visible);
        println!("vault {id}: agent access {}", word(visible));
        touched += 1;
    }
    if let Some(reference) = &args.item {
        let item = vault.find_item_mut(reference)?;
        item.agent_visible = visible;
        let id = item.id;
        println!("item {id}: agent access {}", word(visible));
        touched += 1;
    }
    if let Some(reference) = &args.environment {
        let env = vault.find_environment_mut(reference)?;
        env.agent_visible = visible;
        let id = env.id;
        println!("environment {id}: agent access {}", word(visible));
        touched += 1;
    }
    if touched == 0 {
        bail!("nothing to change: pass --logical-vault, --item or --environment");
    }

    vault.append_audit(cli_draft("env agent-access"));
    vault.save()?;
    Ok(())
}

fn word(visible: bool) -> &'static str {
    if visible { "allowed" } else { "denied" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_matches_the_flag() {
        assert_eq!(word(true), "allowed");
        assert_eq!(word(false), "denied");
    }
}
