//! `kagisecure item add | list | show | rm | agent-visible`.

use std::path::Path;

use anyhow::{Context, Result, bail};
use kagisecure_core::Vault;
use kagisecure_core::audit::AuditDraft;
use kagisecure_core::model::{Category, Field, FieldValue, Item, Secret, SecretText};

use kagisecure_core::vault::AgentVisibilityScope;

use crate::cli::{AddArgs, AgentVisibleArgs, ListArgs, RmArgs, ShowArgs};
use crate::commands::{cli_draft, record_audit_best_effort, transact_patiently, ymd};
use crate::prompt::SecretInput;

fn open(path: &Path, input: &mut SecretInput) -> Result<Vault> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    Ok(Vault::open_with_password(path, password.as_bytes())?)
}

/// Add an item. Concealed values, one-time-password seeds and the note all come from a prompt,
/// standard input, or — the note only — a file, never from argv.
///
/// # Errors
///
/// If the vault cannot be opened, a `--field` is malformed, a value cannot be read, or
/// `--note-file` names a path that cannot be read.
pub fn add(path: &Path, args: &AddArgs, input: &mut SecretInput) -> Result<()> {
    // The master password is read first so that the secret, one-time-password and note values
    // follow it on standard input in a predictable order.
    let mut vault = open(path, input)?;

    let category: Category = args.category.parse().unwrap_or(Category::Login);

    let mut fields = Vec::new();
    for spec in &args.fields {
        let Some((label, value)) = spec.split_once('=') else {
            bail!("--field expects LABEL=VALUE, got {spec:?}");
        };
        if label.is_empty() {
            bail!("--field needs a label before the '='");
        }
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
        let uri = input.read(&format!("otpauth:// URI for {label}"))?;
        // Parsed here and thrown away: storing a URI that cannot produce a code would turn a
        // typo into a failure discovered at the next login, which is exactly the failure
        // ui-spec.md §9 asks the setup flow to prevent.
        let uri = uri.to_string();
        kagisecure_core::totp::Totp::parse_uri(&uri)?;
        fields.push(Field::totp(label, Secret::from_string(uri)));
    }

    // The note, if `--note` or `--note-file` asked for one — read (or read from disk) here,
    // alongside every `--secret` and `--totp` value above, and for the same reason: never while a
    // lock is held. `--note` and `--note-file` conflict in the grammar (`cli.rs`), so exactly one
    // of these two arms ever supplies a value.
    let note = if let Some(path) = &args.note_file {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading the note from {}", path.display()))?;
        Some(contents.trim_end_matches(['\r', '\n']).to_owned())
    } else if args.note {
        Some(input.read("Note")?.to_string())
    } else {
        None
    };

    let concealed = fields.iter().filter(|f| f.value.is_secret()).count();
    let public = fields.len() - concealed;

    // Every prompt above ran before any lock was taken (never hold it across one). The only read
    // that has to be fresh is which logical vault the item lands in, so that is the one thing the
    // transaction itself decides.
    let mut fields = Some(fields);
    let id = transact_patiently(&mut vault, |tx| {
        let mut item = Item::new(tx.default_vault_id()?, category.clone(), args.title.clone());
        item.fields = fields.take().expect("the transaction commits at most once");
        item.tags.clone_from(&args.tags);
        item.urls.clone_from(&args.urls);
        item.notes = note.clone().map(SecretText::new);
        let id = item.id;
        // Honours the logical vault's "Show new items to agents" setting.
        tx.add_new_item(item);
        tx.append_audit(AuditDraft {
            item_id: Some(id),
            ..cli_draft("item add")
        });
        Ok(id)
    })?;

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

/// Show one item's metadata, and its concealed values — including its notes, which are secret
/// like any other field (ADR-0038) — only when explicitly asked.
///
/// Every `--reveal` is audited, best-effort: actor `cli`, tool `reveal_field`, the item id and the
/// labels of whatever was actually shown (`"notes"` among them if the note was), detail
/// `MASTER_PASSWORD` — the CLI's presence proof is the master password it already asked for to
/// open the vault at all, unlike the app's per-reveal biometric gate (ADR-0038's "the CLI already
/// asks for the master password on every run, so a presence gate there adds nothing"). This never
/// blocks the value from printing: if the audit save fails, the value is already on the terminal
/// and only a warning goes to stderr (design doc "transactions-and-audit" part B, user decision 1:
/// "own reveals ... AUDIT them, best-effort, NEVER blocking").
///
/// # Errors
///
/// If the vault cannot be opened or the item does not resolve.
pub fn show(path: &Path, args: &ShowArgs, input: &mut SecretInput) -> Result<()> {
    let mut vault = open(path, input)?;
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
    let has_notes = item.notes.is_some();
    match (&item.notes, args.reveal) {
        (Some(note), true) => println!("{:<14}{}", "note", note.expose()),
        (Some(_), false) => println!("{:<14}(hidden, use --reveal)", "note"),
        (None, _) => {}
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
    let mut revealed_fields = Vec::new();
    let mut any_concealed = false;
    for field in &item.fields {
        let rendered = match &field.value {
            FieldValue::Public(v) => v.clone(),
            FieldValue::Secret(s) if args.reveal => {
                revealed_fields.push(field.label.clone());
                match s.expose_str() {
                    Some(v) => v.to_owned(),
                    None => format!("<{} bytes, not text>", s.len()),
                }
            }
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

    let item_id = item.id;

    // Everything above is done reading `item`, so the vault can be borrowed mutably from here —
    // never before the value has already been printed: a failed audit save must not cost the user
    // the thing they asked to see.
    if args.reveal {
        let mut shown = revealed_fields;
        if has_notes {
            shown.push("notes".to_owned());
        }
        record_audit_best_effort(
            &mut vault,
            AuditDraft {
                item_id: Some(item_id),
                variables: shown,
                detail: Some("MASTER_PASSWORD".to_owned()),
                ..cli_draft("reveal_field")
            },
        );
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
    let (id, title) = transact_patiently(&mut vault, |tx| {
        let removed = tx.remove_item(&args.item)?;
        let id = removed.id;
        let title = removed.title.clone();
        drop(removed);
        tx.append_audit(AuditDraft {
            item_id: Some(id),
            ..cli_draft("item rm")
        });
        Ok((id, title))
    })?;
    println!("Removed {id} ({title})");
    Ok(())
}

/// Show items to agents, or hide them, in bulk (ADR-0007 amendment 2026-10-04): one
/// transaction, one audit entry carrying the scope kind and counts, never a tag or a title.
///
/// # Errors
///
/// If the vault cannot be opened or a named `--item` does not resolve (nothing changes then).
pub fn agent_visible(path: &Path, args: &AgentVisibleArgs, input: &mut SecretInput) -> Result<()> {
    let mut vault = open(path, input)?;
    let visible = args.state.is_on();
    let result = transact_patiently(&mut vault, |tx| {
        let scope = if let Some(tag) = &args.tag {
            AgentVisibilityScope::Tag(tag.clone())
        } else if let Some(category) = &args.category {
            let Ok(category) = category.parse::<Category>();
            AgentVisibilityScope::Category(category)
        } else if args.all {
            AgentVisibilityScope::All
        } else {
            let mut ids = Vec::with_capacity(args.items.len());
            for reference in &args.items {
                ids.push(tx.find_item(reference)?.id);
            }
            AgentVisibilityScope::Items(ids)
        };
        Ok(tx.set_agent_visible_bulk(&scope, visible, "cli"))
    })?;
    println!(
        "{} {} item(s) to agents ({} changed)",
        if visible { "Showed" } else { "Hid" },
        result.matched,
        result.changed
    );
    Ok(())
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
