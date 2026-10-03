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
use kagisecure_core::model::{Environment, Secret, VarSource};
use kagisecure_core::proto::{Outcome, VarName, VarSourceKind};

use crate::cli::{
    AgentAccessArgs, EnvAddVarArgs, EnvCreateArgs, EnvListArgs, EnvRmArgs, EnvWriteArgs,
};
use crate::commands::{
    AuditUnavailable, cli_draft, failure_detail, record_audit_best_effort, transact_patiently,
};
use crate::prompt::SecretInput;

fn open(path: &Path, input: &mut SecretInput) -> Result<Vault> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    Ok(Vault::open_with_password(path, password.as_bytes())?)
}

/// Create an empty environment.
///
/// # Errors
///
/// If the vault cannot be opened or saved.
pub fn create(path: &Path, args: &EnvCreateArgs, input: &mut SecretInput) -> Result<()> {
    let mut vault = open(path, input)?;

    let id = transact_patiently(&mut vault, |tx| {
        let vault_id = tx.default_vault_id()?;
        let mut env = Environment::new(vault_id, args.name.clone());
        env.description.clone_from(&args.description);
        env.agent_visible = args.agent_visible;
        let id = env.id;
        tx.add_environment(env);
        tx.append_audit(AuditDraft {
            vault_id: Some(vault_id),
            environment_id: Some(id),
            ..cli_draft("env create")
        });
        Ok(id)
    })?;

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
    // Before the password prompt: a name that is not an identifier is a usage mistake (exit 2),
    // and one that would otherwise be written verbatim as a `.env` key or an environment-block
    // key, where `=` or a newline becomes syntax.
    let name = VarName::new(args.name.clone())?;
    let mut vault = open(path, input)?;

    // A malformed `--bind` is a usage mistake, reported up front rather than after a prompt or a
    // lock wait: re-checking its syntax against fresh vault state would not make it any less
    // malformed.
    let bind_ref = match (&args.bind, args.literal) {
        (Some(spec), false) => {
            let Some((item_ref, field_ref)) = spec.rsplit_once('/') else {
                bail!("--bind expects ITEM/FIELD, got {spec:?}");
            };
            Some((item_ref, field_ref))
        }
        (None, true) => None,
        (None, false) => bail!("pass either --bind ITEM/FIELD or --literal"),
        (Some(_), true) => bail!("--bind and --literal are mutually exclusive"),
    };

    // Only `--literal` needs a prompt, and it happens here — never while the lock is held.
    let mut literal = match bind_ref {
        Some(_) => None,
        None => Some(input.read(&format!("Value for {}", args.name))?.to_string()),
    };

    let (env_id, kind) = transact_patiently(&mut vault, |tx| {
        // The item/field a `--bind` names is resolved fresh: it could have been renamed, edited
        // or removed by another writer since this process opened the vault.
        let source = match bind_ref {
            Some((item_ref, field_ref)) => {
                let item = tx.find_item(item_ref)?;
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
            None => VarSource::Literal(Secret::from_string(
                literal
                    .take()
                    .expect("the transaction commits at most once"),
            )),
        };

        let kind = source.kind();
        let env = tx.find_environment_mut(&args.environment)?;
        let env_id = env.id;
        env.set_var(name.clone(), source);

        tx.append_audit(AuditDraft {
            environment_id: Some(env_id),
            variables: vec![args.name.clone()],
            ..cli_draft("env add-var")
        });
        Ok((env_id, kind))
    })?;

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
            let env_id = transact_patiently(&mut vault, |tx| {
                let env = tx.find_environment_mut(&args.environment)?;
                let env_id = env.id;
                if !env.remove_var(name) {
                    return Err(kagisecure_core::Error::VarNotFound(
                        name.clone(),
                        args.environment.clone(),
                    ));
                }
                tx.append_audit(AuditDraft {
                    environment_id: Some(env_id),
                    variables: vec![name.clone()],
                    ..cli_draft("env rm")
                });
                Ok(env_id)
            })?;
            println!("Removed {name} from {env_id}");
        }
        None => {
            let (id, count) = transact_patiently(&mut vault, |tx| {
                let env = tx.remove_environment(&args.environment)?;
                let id = env.id;
                let count = env.vars.len();
                drop(env);
                tx.append_audit(AuditDraft {
                    environment_id: Some(id),
                    ..cli_draft("env rm")
                });
                Ok((id, count))
            })?;
            println!("Removed {id} and its {count} variable(s)");
        }
    }
    Ok(())
}

/// Write an environment into a `.env` file.
///
/// Audit-first (design doc "transactions-and-audit", part B, step 9): the `Allowed` entry
/// naming every variable this run is about to write is appended and durably saved *before* any
/// byte reaches the `.env` file — never the other way around, which used to leave a written file
/// on disk with no committed record of it if the audit save itself failed. If that transaction
/// cannot be made durable — the vault is busy past the usual wait, diverged, replaced, or a save
/// fails outright — this refuses with exit 9 ([`crate::cli::EXIT_AUDIT_UNAVAILABLE`]) and writes
/// nothing at all.
///
/// The file write happens after the lock is released, so a slow disk never holds the vault's lock.
/// If it fails, the permission already granted is not undone — the vault's own log gained a real
/// `Allowed` entry — so a best-effort `Failed` follow-up is queued and flushed instead, and the
/// error is still returned to the caller.
///
/// # Errors
///
/// If the vault cannot be opened, a variable has no value yet, permission cannot be made durable
/// (exit 9), or the file cannot be written.
pub fn write(path: &Path, args: &EnvWriteArgs, input: &mut SecretInput) -> Result<()> {
    let mut vault = open(path, input)?;

    let dir = args
        .dir
        .canonicalize()
        .with_context(|| format!("{} does not exist", args.dir.display()))?;

    // A malformed file name is a usage mistake independent of vault state, checked up front so it
    // is reported before a prompt or a lock wait — and so the audit entry below records the path
    // this run will actually try to write.
    envfile::validate_filename(&args.filename)?;
    let target_path = dir.join(&args.filename);

    let wanted = (!args.vars.is_empty()).then(|| args.vars.clone());

    // Step 1 — audit first. The values and the environment's id are read fresh, inside the
    // transaction, so a rename or a variable added by another writer since this process opened the
    // vault is reflected in what the audit entry — and, in step 2, the file — actually says. Only
    // once this commits does anything leave this process.
    let resolved = transact_patiently(&mut vault, |tx| {
        let injections = tx.resolve_environment(&args.environment, wanted.as_deref())?;
        let env_id = tx.find_environment(&args.environment)?.id;
        let variables: Vec<String> = injections.iter().map(|i| i.name.to_string()).collect();
        tx.append_audit(AuditDraft {
            environment_id: Some(env_id),
            variables: variables.clone(),
            target_path: Some(target_path.display().to_string()),
            ..cli_draft("env write")
        });
        let allowed_seq = tx
            .audit_entries()
            .last()
            .expect("append_audit just added one")
            .seq;
        Ok((injections, env_id, variables, allowed_seq))
    });
    let (injections, env_id, variables, allowed_seq) = match resolved {
        Ok(v) => v,
        // A reference that never resolved (`EnvNotFound`, `VarNotPopulated`, …) is a usage
        // mistake, not a durability failure: the closure returned before ever calling
        // `append_audit`, so nothing was left half-committed. It keeps its ordinary exit code
        // instead of becoming `AuditUnavailable`.
        Err(e) if crate::commands::is_audit_gate_failure(&e) => {
            return Err(AuditUnavailable(e).into());
        }
        Err(e) => return Err(e.into()),
    };

    // Step 2 — act. The lock is already released: a slow disk here cannot hold up another writer.
    let written = match envfile::write(&dir, &args.filename, &injections, args.overwrite) {
        Ok(written) => written,
        Err(e) => {
            drop(injections);
            record_audit_best_effort(
                &mut vault,
                AuditDraft {
                    environment_id: Some(env_id),
                    variables,
                    target_path: Some(target_path.display().to_string()),
                    outcome: Outcome::Failed,
                    detail: Some(failure_detail(write_failure_code(&e), allowed_seq)),
                    ..cli_draft("env write")
                },
            );
            return Err(e.into());
        }
    };
    drop(injections);

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

/// A short machine-readable code for why the `.env` write itself failed, for the best-effort
/// `Failed` follow-up entry — never shown to the user, only written to the audit log.
fn write_failure_code(e: &kagisecure_core::Error) -> &'static str {
    match e {
        kagisecure_core::Error::EnvFileExists(_) => "ENV_FILE_EXISTS",
        kagisecure_core::Error::InvalidPath(_) | kagisecure_core::Error::InvalidEnvFileName(_) => {
            "INVALID_PATH"
        }
        _ => "WRITE_FAILED",
    }
}

/// Show or change agent visibility.
///
/// # Errors
///
/// If the vault cannot be opened or a reference does not resolve.
pub fn agent_access(path: &Path, args: &AgentAccessArgs, input: &mut SecretInput) -> Result<()> {
    let change = match (args.allow, args.deny) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        (false, false) => None,
        (true, true) => bail!("--allow and --deny are mutually exclusive"),
    };
    if let Some(shared) = &args.shared_vault {
        return crate::commands::shared::agent_access(path, shared, args, change, input);
    }
    let mut vault = open(path, input)?;

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
            "Pass --allow or --deny with --logical-vault, --item (optionally with --field) or \
             --environment to change one."
        );
        return Ok(());
    };

    // Which target flags were passed does not depend on vault state, so this is checked up front
    // rather than inside the transaction.
    if args.vault_ref.is_none() && args.item.is_none() && args.environment.is_none() {
        bail!("nothing to change: pass --logical-vault, --item or --environment");
    }

    // The closure only decides and returns what it changed; nothing is printed until the
    // transaction has committed. A line printed inside it would claim a change that a later
    // target's failure (or the write itself) then rolled back — and would be written to stdout
    // while the vault's lock is held.
    let changed = transact_patiently(&mut vault, |tx| {
        let mut changed = Vec::new();
        if let Some(reference) = &args.vault_ref {
            let id = tx.find_vault(reference)?;
            tx.set_vault_agent_visible(id, visible);
            changed.push(format!("vault {id}"));
        }
        if let Some(reference) = &args.item {
            let item = tx.find_item_mut(reference)?;
            if let Some(field_ref) = &args.field {
                let item_id = item.id;
                let field = item
                    .fields
                    .iter_mut()
                    .find(|f| f.id.to_string() == *field_ref || f.label == *field_ref)
                    .ok_or_else(|| kagisecure_core::Error::FieldNotFound {
                        item: item_id.to_string(),
                        field: field_ref.clone(),
                    })?;
                field.agent_visible = visible;
                changed.push(format!("item {item_id} field {}", field.id));
            } else {
                item.agent_visible = visible;
                // Mirrors the app's `set_agent_visible` (KagisecureFFI/session.rs): turning the
                // item off turns every field's own override off with it, so an item re-exposed
                // later does not silently bring back a per-field grant the user forgot about.
                if !visible {
                    for field in &mut item.fields {
                        field.agent_visible = false;
                    }
                }
                changed.push(format!("item {}", item.id));
            }
        }
        if let Some(reference) = &args.environment {
            let env = tx.find_environment_mut(reference)?;
            env.agent_visible = visible;
            changed.push(format!("environment {}", env.id));
        }
        tx.append_audit(cli_draft("env agent-access"));
        Ok(changed)
    })?;
    for target in changed {
        println!("{target}: agent access {}", word(visible));
    }
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
