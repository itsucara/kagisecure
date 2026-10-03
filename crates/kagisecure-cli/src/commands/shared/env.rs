//! `kagisecure shared env create | add-var`.

use std::path::Path;

use anyhow::{Result, bail};
use kagisecure_core::model::{Environment, Secret, VarSource};
use kagisecure_core::proto::{EnvId, VarName};
use kagisecure_shared::merge::{
    MaterializedEnv, materialize_all, materialize_env, materialize_item,
};
use kagisecure_shared::write;

use crate::cli::{SharedEnvAddVarArgs, SharedEnvCreateArgs};
use crate::prompt::SecretInput;

use super::item::resolve_item;
use super::{open_personal, resolve_vault, view_of};

/// Resolve an environment by id, unique id prefix, or exact name, among a shared vault's merged
/// environments — the same convention [`kagisecure_core::Vault::find_environment`] uses.
fn resolve_env(envs: &[MaterializedEnv], reference: &str) -> Result<EnvId> {
    let mut hits = Vec::new();
    for m in envs {
        let id_text = m.id.to_string();
        let name_matches = m.env.as_ref().is_some_and(|e| e.name == reference);
        if id_text == reference
            || name_matches
            || (reference.len() >= 4 && id_text.starts_with(reference))
        {
            hits.push(m.id);
        }
    }
    match hits.len() {
        1 => Ok(hits[0]),
        0 => Err(kagisecure_core::Error::EnvNotFound(reference.to_owned()).into()),
        _ => Err(kagisecure_core::Error::AmbiguousEnv(reference.to_owned()).into()),
    }
}

/// Create an empty environment in a shared vault.
///
/// # Errors
///
/// If the personal vault cannot be opened, `--vault` does not resolve, or this device may not
/// write to the shared vault.
pub fn create(path: &Path, args: &SharedEnvCreateArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let mut opened = resolve_vault(path, &personal, &args.shared_vault)?;

    let mut env = Environment::new(*opened.replica.vault_id(), args.name.clone());
    env.description.clone_from(&args.description);
    env.agent_visible = args.agent_visible;
    let id = env.id;

    let now = kagisecure_core::unix_now();
    write::put_env(&mut opened.replica, &opened.device, env, now)?;
    println!("Created {id} in shared vault {}", opened.replica.vault_id());
    Ok(())
}

/// Add or replace a variable in a shared vault's environment.
///
/// # Errors
///
/// If the personal vault cannot be opened, a reference does not resolve, or neither `--bind` nor
/// `--literal` was given.
pub fn add_var(path: &Path, args: &SharedEnvAddVarArgs, input: &mut SecretInput) -> Result<()> {
    // Before the password prompt: a name that is not an identifier is a usage mistake, exactly
    // like `kagisecure env add-var`.
    let name = VarName::new(args.name.clone())?;
    let personal = open_personal(path, input)?;
    let mut opened = resolve_vault(path, &personal, &args.shared_vault)?;

    let bind_ref = match (&args.bind, args.literal) {
        (Some(spec), false) => {
            let Some((item_ref, field_ref)) = spec.rsplit_once('/') else {
                bail!("--bind expects ITEM/FIELD, got {spec:?}");
            };
            Some((item_ref.to_owned(), field_ref.to_owned()))
        }
        (None, true) => None,
        (None, false) => bail!("pass either --bind ITEM/FIELD or --literal"),
        (Some(_), true) => bail!("--bind and --literal are mutually exclusive"),
    };
    // Only `--literal` needs a prompt, and it happens before the view is read, like the personal
    // `env add-var`'s own ordering.
    let mut literal = match &bind_ref {
        Some(_) => None,
        None => Some(input.read(&format!("Value for {}", args.name))?.to_string()),
    };

    let view = view_of(&opened)?;
    let (items, envs) = materialize_all(&view)?;
    let env_id = resolve_env(&envs, &args.environment)?;
    let mut env = materialize_env(&view, env_id)?
        .and_then(|m| m.env)
        .ok_or_else(|| kagisecure_core::Error::EnvNotFound(args.environment.clone()))?;

    let source = match bind_ref {
        Some((item_ref, field_ref)) => {
            let item_id = resolve_item(&items, &item_ref)?;
            let item = materialize_item(&view, item_id)?
                .and_then(|m| m.item)
                .ok_or_else(|| kagisecure_core::Error::ItemNotFound(item_ref.clone()))?;
            let field =
                item.field(&field_ref)
                    .ok_or_else(|| kagisecure_core::Error::FieldNotFound {
                        item: item_ref.clone(),
                        field: field_ref.clone(),
                    })?;
            VarSource::ItemField {
                item: item.id,
                field: field.id,
            }
        }
        None => VarSource::Literal(Secret::from_string(
            literal.take().expect("checked above: not a --bind"),
        )),
    };
    let kind_name = match &source {
        VarSource::Literal(_) => "literal",
        VarSource::ItemField { .. } => "item field",
        VarSource::Pending { .. } => "pending",
    };
    env.set_var(name, source);

    let now = kagisecure_core::unix_now();
    write::put_env(&mut opened.replica, &opened.device, env, now)?;
    println!("Set {} in {env_id} ({kind_name})", args.name);
    Ok(())
}
