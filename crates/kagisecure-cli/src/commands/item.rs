//! `kagisecure item add | list | show | rm`.

use std::path::Path;

use anyhow::{Result, bail};
use kagisecure_core::model::{Category, Field, FieldValue, Item, Secret};
use kagisecure_core::{Error, Vault};

use crate::cli::{AddArgs, ListArgs, RmArgs, ShowArgs};
use crate::commands::ymd;
use crate::prompt::SecretInput;

fn open(path: &Path, input: &mut SecretInput) -> Result<Vault> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    Ok(Vault::open_with_password(path, password.as_bytes())?)
}

/// Add an item. Concealed values come from a prompt or standard input, never from argv.
///
/// # Errors
///
/// If the vault cannot be opened, a `--field` is malformed, or a value cannot be read.
pub fn add(path: &Path, args: &AddArgs, input: &mut SecretInput) -> Result<()> {
    // The master password is read first so that the secret values follow it on standard input in
    // a predictable order.
    let mut vault = open(path, input)?;

    let category: Category = args.category.parse().unwrap_or(Category::Login);
    let mut item = Item::new(vault.default_vault_id()?, category, args.title.clone());

    for spec in &args.fields {
        let Some((label, value)) = spec.split_once('=') else {
            bail!("--field expects LABEL=VALUE, got {spec:?}");
        };
        if label.is_empty() {
            bail!("--field needs a label before the '='");
        }
        item.fields.push(Field::public(label, value));
    }

    for label in &args.secrets {
        let value = input.read(&format!("Value for {label}"))?;
        item.fields.push(Field::concealed(
            label,
            Secret::from_string(value.to_string()),
        ));
    }

    for label in &args.totps {
        let uri = input.read(&format!("otpauth:// URI for {label}"))?;
        // Parsed here and thrown away: storing a URI that cannot produce a code would turn a
        // typo into a failure discovered at the next login, which is exactly the failure
        // ui-spec.md §9 asks the setup flow to prevent.
        let uri = uri.to_string();
        kagisecure_core::totp::Totp::parse_uri(&uri)?;
        item.fields
            .push(Field::totp(label, Secret::from_string(uri)));
    }

    item.tags.clone_from(&args.tags);
    item.urls.clone_from(&args.urls);
    item.notes.clone_from(&args.note);

    let id = item.id;
    let concealed = item.fields.iter().filter(|f| f.value.is_secret()).count();
    let public = item.fields.len() - concealed;
    vault.add_item(item);
    vault.save()?;

    println!("Added {id}");
    println!("  title      {}", args.title);
    println!("  fields     {public} public, {concealed} concealed");
    Ok(())
}

/// List items: titles, categories and field counts. Never a value.
///
/// # Errors
///
/// If the vault cannot be opened.
pub fn list(path: &Path, args: &ListArgs, input: &mut SecretInput) -> Result<()> {
    let vault = open(path, input)?;
    let summaries = vault.item_summaries();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&summaries)?);
        return Ok(());
    }

    if summaries.is_empty() {
        println!("No items yet. Add one with `kagisecure item add --title ... --secret ...`.");
        return Ok(());
    }

    println!(
        "{:<10}  {:<32}  {:<16}  {:>6}  {:<10}",
        "ID", "TITLE", "CATEGORY", "FIELDS", "UPDATED"
    );
    for s in &summaries {
        let id = s.id.to_string();
        println!(
            "{:<10}  {:<32}  {:<16}  {:>6}  {:<10}",
            &id[..8],
            truncate(&s.title, 32),
            truncate(s.category.as_str(), 16),
            s.fields.len(),
            ymd(s.updated_at)
        );
    }
    Ok(())
}

/// Show one item's metadata, and its concealed values only when explicitly asked.
///
/// # Errors
///
/// If the vault cannot be opened or the item does not resolve.
pub fn show(path: &Path, args: &ShowArgs, input: &mut SecretInput) -> Result<()> {
    let vault = open(path, input)?;
    let item = vault.find_item(&args.item)?;

    if args.json {
        // Metadata only, whatever `--reveal` says: a machine-readable format is exactly the kind
        // of thing that ends up in a log or a pipe by accident.
        println!("{}", serde_json::to_string_pretty(&item.summary())?);
        return Ok(());
    }

    println!("{:<14}{}", "id", item.id);
    println!("{:<14}{}", "title", item.title);
    println!("{:<14}{}", "category", item.category);
    if !item.tags.is_empty() {
        println!("{:<14}{}", "tags", item.tags.join(", "));
    }
    for url in &item.urls {
        println!("{:<14}{url}", "url");
    }
    if let Some(note) = &item.notes {
        println!("{:<14}{note}", "note");
    }
    println!("{:<14}{}", "created", ymd(item.created_at));
    println!("{:<14}{}", "updated", ymd(item.updated_at));
    println!(
        "{:<14}{}",
        "agent visible",
        if item.agent_visible { "yes" } else { "no" }
    );
    println!();
    println!("{:<24}  {:<12}  VALUE", "FIELD", "KIND");
    for field in &item.fields {
        let rendered = match &field.value {
            FieldValue::Public(v) => v.clone(),
            FieldValue::Secret(s) if args.reveal => match s.expose_str() {
                Some(v) => v.to_owned(),
                None => format!("<{} bytes, not text>", s.len()),
            },
            FieldValue::Secret(_) => "<concealed>".to_owned(),
        };
        println!(
            "{:<24}  {:<12}  {}",
            truncate(&field.label, 24),
            field.kind,
            rendered
        );
    }
    if !args.reveal && item.fields.iter().any(|f| f.value.is_secret()) {
        println!();
        println!("Concealed values are hidden. Pass --reveal to print them to this terminal.");
    }
    Ok(())
}

/// Remove an item.
///
/// # Errors
///
/// If the vault cannot be opened or the item does not resolve.
pub fn rm(path: &Path, args: &RmArgs, input: &mut SecretInput) -> Result<()> {
    let mut vault = open(path, input)?;
    let removed = vault.remove_item(&args.item)?;
    let id = removed.id;
    let title = removed.title.clone();
    drop(removed);
    vault.save()?;
    println!("Removed {id} ({title})");
    Ok(())
}

/// Resolve `NAME=item/field` into a variable name and the field it refers to.
///
/// # Errors
///
/// [`Error::FieldNotFound`] if the field does not exist on the item.
pub fn resolve_field<'v>(vault: &'v Vault, item_ref: &str, field_ref: &str) -> Result<&'v Field> {
    let item = vault.find_item(item_ref)?;
    item.field(field_ref).ok_or_else(|| {
        Error::FieldNotFound {
            item: item_ref.to_owned(),
            field: field_ref.to_owned(),
        }
        .into()
    })
}

/// Shorten a display string to `width` characters, with an ellipsis when it does not fit.
///
/// Only ever applied to metadata — titles, names, labels. There is no code path that would hand
/// it a value.
#[must_use]
pub fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn truncation_keeps_short_strings_intact() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("exactlyten", 10), "exactlyten");
        assert_eq!(truncate("a bit too long", 10), "a bit too…");
    }
}
