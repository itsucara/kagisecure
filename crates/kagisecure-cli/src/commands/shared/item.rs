//! `kagisecure shared item add | set | rm | show`.

use std::path::Path;

use anyhow::{Context, Result, bail};
use kagisecure_core::model::{Category, Field, FieldKind, FieldValue, Item, Secret, SecretText};
use kagisecure_core::proto::ItemId;
use kagisecure_shared::merge::{MaterializedItem, materialize_all, materialize_item};
use kagisecure_shared::write;

use crate::cli::{SharedItemAddArgs, SharedItemRmArgs, SharedItemSetArgs, SharedItemShowArgs};
use crate::commands::item::truncate;
use crate::prompt::SecretInput;

use super::{open_personal, resolve_vault, view_of};

/// Resolve an item by id, unique id prefix, or exact title, among a shared vault's merged items —
/// the same convention [`kagisecure_core::Vault::find_item`] uses, reusing its error variants so
/// a shared item reference that does not resolve maps to the same exit code as a personal one.
pub(super) fn resolve_item(items: &[MaterializedItem], reference: &str) -> Result<ItemId> {
    let mut hits = Vec::new();
    for m in items {
        let id_text = m.id.to_string();
        let title_matches = m.item.as_ref().is_some_and(|i| i.title == reference);
        if id_text == reference
            || title_matches
            || (reference.len() >= 4 && id_text.starts_with(reference))
        {
            hits.push(m.id);
        }
    }
    match hits.len() {
        1 => Ok(hits[0]),
        0 => Err(kagisecure_core::Error::ItemNotFound(reference.to_owned()).into()),
        _ => Err(kagisecure_core::Error::AmbiguousItem(reference.to_owned()).into()),
    }
}

fn parse_fields(specs: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for spec in specs {
        let Some((label, value)) = spec.split_once('=') else {
            bail!("--field expects LABEL=VALUE, got {spec:?}");
        };
        if label.is_empty() {
            bail!("--field needs a label before the '='");
        }
        out.push((label.to_owned(), value.to_owned()));
    }
    Ok(out)
}

fn upsert_public(fields: &mut Vec<Field>, label: &str, value: &str) {
    if let Some(f) = fields.iter_mut().find(|f| f.label == label) {
        f.value = FieldValue::Public(value.to_owned());
    } else {
        fields.push(Field::public(label, value));
    }
}

fn upsert_concealed(fields: &mut Vec<Field>, label: &str, value: Secret) {
    if let Some(f) = fields
        .iter_mut()
        .find(|f| f.label == label && f.kind != FieldKind::Totp)
    {
        f.value = FieldValue::Secret(value);
    } else {
        fields.push(Field::concealed(label, value));
    }
}

fn upsert_totp(fields: &mut Vec<Field>, label: &str, value: Secret) {
    if let Some(f) = fields
        .iter_mut()
        .find(|f| f.label == label && f.kind == FieldKind::Totp)
    {
        f.value = FieldValue::Secret(value);
    } else {
        fields.push(Field::totp(label, value));
    }
}

/// Add an item to a shared vault. Concealed values, one-time-password seeds and the note come
/// from a prompt, standard input, or — the note only — a file, never from argv, exactly as
/// `kagisecure item add`.
///
/// # Errors
///
/// If the personal vault cannot be opened, `--vault` does not resolve, a `--field` is malformed,
/// a value cannot be read, or this device may not write to the shared vault.
pub fn add(path: &Path, args: &SharedItemAddArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let mut opened = resolve_vault(path, &personal, &args.shared_vault)?;

    let category: Category = args.category.parse().unwrap_or(Category::Login);
    let mut fields = Vec::new();
    for (label, value) in parse_fields(&args.fields)? {
        fields.push(Field::public(label, value));
    }
    for label in &args.secrets {
        let value = input.read(&format!("Value for {label}"))?;
        fields.push(Field::concealed(
            label,
            Secret::from_string(value.to_string()),
        ));
    }
    for label in &args.totps {
        let uri = input
            .read(&format!("otpauth:// URI for {label}"))?
            .to_string();
        kagisecure_core::totp::Totp::parse_uri(&uri)?;
        fields.push(Field::totp(label, Secret::from_string(uri)));
    }
    let note = if let Some(note_path) = &args.note_file {
        let contents = std::fs::read_to_string(note_path)
            .with_context(|| format!("reading the note from {}", note_path.display()))?;
        Some(contents.trim_end_matches(['\r', '\n']).to_owned())
    } else if args.note {
        Some(input.read("Note")?.to_string())
    } else {
        None
    };

    let mut item = Item::new(*opened.replica.vault_id(), category, args.title.clone());
    item.fields = fields;
    item.tags.clone_from(&args.tags);
    item.urls.clone_from(&args.urls);
    item.notes = note.map(SecretText::new);
    let id = item.id;

    let now = kagisecure_core::unix_now();
    write::put_item(&mut opened.replica, &opened.device, item, now)?;
    println!("Added {id} to shared vault {}", opened.replica.vault_id());
    Ok(())
}

/// Change an item in a shared vault: fetches the current merged item, applies every change given,
/// and writes the whole item back as a new version (last-writer-wins; ADR-0035 addendum,
/// decision 80).
///
/// # Errors
///
/// As [`add`], and [`kagisecure_core::Error::ItemNotFound`] / `AmbiguousItem` if `item` does not
/// resolve to exactly one item.
pub fn set(path: &Path, args: &SharedItemSetArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let mut opened = resolve_vault(path, &personal, &args.shared_vault)?;
    let view = view_of(&opened)?;
    let (items, _) = materialize_all(&view)?;
    let id = resolve_item(&items, &args.item)?;
    let mut item = materialize_item(&view, id)?
        .and_then(|m| m.item)
        .ok_or_else(|| kagisecure_core::Error::ItemNotFound(args.item.clone()))?;

    if let Some(title) = &args.title {
        item.title = title.clone();
    }
    if let Some(category) = &args.category {
        item.category = category.parse().unwrap_or(Category::Login);
    }
    if !args.tags.is_empty() {
        item.tags = args.tags.clone();
    }
    if !args.urls.is_empty() {
        item.urls = args.urls.clone();
    }
    for (label, value) in parse_fields(&args.fields)? {
        upsert_public(&mut item.fields, &label, &value);
    }
    for label in &args.secrets {
        let value = input.read(&format!("Value for {label}"))?;
        upsert_concealed(
            &mut item.fields,
            label,
            Secret::from_string(value.to_string()),
        );
    }
    for label in &args.totps {
        let uri = input
            .read(&format!("otpauth:// URI for {label}"))?
            .to_string();
        kagisecure_core::totp::Totp::parse_uri(&uri)?;
        upsert_totp(&mut item.fields, label, Secret::from_string(uri));
    }
    for reference in &args.rm_fields {
        item.fields
            .retain(|f| f.id.to_string() != *reference && f.label != *reference);
    }
    if let Some(note_path) = &args.note_file {
        let contents = std::fs::read_to_string(note_path)
            .with_context(|| format!("reading the note from {}", note_path.display()))?;
        item.notes = Some(SecretText::new(
            contents.trim_end_matches(['\r', '\n']).to_owned(),
        ));
    } else if args.note {
        item.notes = Some(SecretText::new(input.read("Note")?.to_string()));
    } else if args.clear_note {
        item.notes = None;
    }

    let now = kagisecure_core::unix_now();
    write::put_item(&mut opened.replica, &opened.device, item, now)?;
    println!("Updated {id} in shared vault {}", opened.replica.vault_id());
    Ok(())
}

/// Delete an item. A later edit brings it back (last-writer-wins).
///
/// # Errors
///
/// As [`set`].
pub fn rm(path: &Path, args: &SharedItemRmArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let mut opened = resolve_vault(path, &personal, &args.shared_vault)?;
    let view = view_of(&opened)?;
    let (items, _) = materialize_all(&view)?;
    let id = resolve_item(&items, &args.item)?;

    let now = kagisecure_core::unix_now();
    write::delete_item(&mut opened.replica, &opened.device, id, now)?;
    println!(
        "Removed {id} from shared vault {}",
        opened.replica.vault_id()
    );
    Ok(())
}

/// Show one item's metadata, and its concealed values only when explicitly asked.
///
/// # Errors
///
/// If the personal vault cannot be opened, `--vault` does not resolve, or `item` does not
/// resolve to exactly one item.
pub fn show(path: &Path, args: &SharedItemShowArgs, input: &mut SecretInput) -> Result<()> {
    let personal = open_personal(path, input)?;
    let opened = resolve_vault(path, &personal, &args.shared_vault)?;
    let view = view_of(&opened)?;
    let (items, _) = materialize_all(&view)?;
    let id = resolve_item(&items, &args.item)?;
    let merged = materialize_item(&view, id)?
        .ok_or_else(|| kagisecure_core::Error::ItemNotFound(args.item.clone()))?;

    let Some(item) = merged.item else {
        println!("{id} was deleted.");
        return Ok(());
    };

    if args.json {
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
    let has_notes = item.notes.is_some();
    match (&item.notes, args.reveal) {
        (Some(note), true) => println!("{:<14}{}", "note", note.expose()),
        (Some(_), false) => println!("{:<14}(hidden, use --reveal)", "note"),
        (None, _) => {}
    }
    println!(
        "{:<14}{}",
        "agent visible",
        if opened
            .replica
            .local()
            .agent_visible_items
            .contains(&item.id)
        {
            "yes, on this device"
        } else {
            "no"
        }
    );
    println!();
    println!("{:<24}  {:<12}  VALUE", "FIELD", "KIND");
    let mut any_concealed = false;
    for field in &item.fields {
        let rendered = match &field.value {
            FieldValue::Public(v) => v.clone(),
            FieldValue::Secret(s) if args.reveal => match s.expose_str() {
                Some(v) => v.to_owned(),
                None => format!("<{} bytes, not text>", s.len()),
            },
            FieldValue::Secret(_) => {
                any_concealed = true;
                "<concealed>".to_owned()
            }
        };
        println!(
            "{:<24}  {:<12}  {}",
            truncate(&field.label, 24),
            field.kind,
            rendered
        );
    }
    if !args.reveal && (any_concealed || has_notes) {
        println!();
        println!("Concealed values are hidden. Pass --reveal to print them to this terminal.");
    }
    Ok(())
}
