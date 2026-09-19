//! `kagisecure import`.
//!
//! Everything printed here — the summary, the JSON, the Markdown report — comes from
//! [`kagisecure_import::ImportReport`] or [`kagisecure_import::ImportOutcome`], neither of which
//! can hold a value: see `kagisecure-import`'s module docs for why that is a compile-time
//! property rather than a convention this file has to honour by hand.
//!
//! Parsing happens before anything is written (`kagisecure_import::parse` only ever reads the
//! source), so a malformed export fails with the vault untouched — which is also exactly what
//! `--dry-run` is: a run that stops right after the report is built and printed.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use kagisecure_core::Vault;
use kagisecure_import::{DuplicatePolicy, ImportReport, ItemAction, SourceKind, TargetVault};

use crate::cli::{ImportArgs, UsageError};
use crate::prompt::SecretInput;

/// A source of more than this many items asks for confirmation before it is committed.
const CONFIRM_THRESHOLD: usize = 100;

fn open(path: &Path, input: &mut SecretInput) -> Result<Vault> {
    crate::commands::ensure_exists(path)?;
    let password = input.read("Master password")?;
    Ok(Vault::open_with_password(path, password.as_bytes())?)
}

/// Parse `--format`, if given, into a [`SourceKind`].
///
/// A bad value is a usage error (exit 2), not an import failure (exit 7): nothing has been read
/// yet.
fn parse_format(format: &Option<String>) -> Result<Option<SourceKind>> {
    match format {
        None => Ok(None),
        Some(name) => SourceKind::parse_name(name).map(Some).ok_or_else(|| {
            let names: Vec<&str> = SourceKind::ALL.iter().map(|k| k.as_str()).collect();
            UsageError(format!(
                "unknown --format {name:?}; try one of: {}",
                names.join(", ")
            ))
            .into()
        }),
    }
}

/// Parse `--on-duplicate` into a [`DuplicatePolicy`]. Same usage-error reasoning as
/// [`parse_format`].
fn parse_policy(name: &str) -> Result<DuplicatePolicy> {
    DuplicatePolicy::parse_name(name).ok_or_else(|| {
        let names: Vec<&str> = DuplicatePolicy::ALL.iter().map(|p| p.as_str()).collect();
        UsageError(format!(
            "unknown --on-duplicate {name:?}; try one of: {}",
            names.join(", ")
        ))
        .into()
    })
}

/// Import items from `args.source` into the vault at `path`.
///
/// # Errors
///
/// If the vault cannot be opened, `--format` or `--on-duplicate` name something this build does
/// not know, the source cannot be read or parsed ([`kagisecure_import::ImportError`], mapped to
/// exit 7 in `main::exit_code_for`), the confirmation for a large import is declined, or the save
/// fails.
pub fn import(path: &Path, args: &ImportArgs, input: &mut SecretInput) -> Result<()> {
    // Validated before the vault is even opened, so a typo in a flag does not also cost the user
    // a master-password prompt.
    let format = parse_format(&args.format)?;
    let policy = parse_policy(&args.on_duplicate)?;

    let mut vault = open(path, input)?;

    // `kagisecure_import::parse` — the frozen, format-sniffing entry point (plan §8) — takes no
    // options argument, so it has no way to carry `--include-trashed` through. The 1PUX parser
    // itself does, via `onepux::parse_with`, so an explicit `--format 1pux` goes there directly;
    // anything else (a named CSV dialect, or auto-detection) still goes through `parse`, and the
    // flag is recorded as a no-op there rather than silently dropped — a user relying on it
    // should see why nothing changed instead of wondering whether their trashed items were
    // skipped without a trace.
    let mut plan = if format == Some(SourceKind::OnePux) {
        let options =
            kagisecure_import::onepux::Options::default().include_trashed(args.include_trashed);
        kagisecure_import::onepux::parse_with(&args.source, &options)?
    } else {
        kagisecure_import::parse(&args.source, format)?
    };
    if format != Some(SourceKind::OnePux) && args.include_trashed {
        plan.note(
            "include-trashed-not-wired",
            "--include-trashed only takes effect with --format 1pux in this build; a CSV \
             source or an auto-detected one ignored it",
        );
    }

    if let Some(name) = &args.logical_vault {
        plan.retarget_all(&TargetVault::Named(name.clone()));
    }

    let report = plan.report_against(&vault, policy);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_summary(&report);
    }

    if let Some(report_path) = &args.report {
        write_report(report_path, &report.to_markdown())?;
    }

    if args.dry_run {
        return Ok(());
    }

    if plan.len() > CONFIRM_THRESHOLD && !args.yes {
        confirm_large_import(&args.source, plan.len())?;
    }

    let outcome = kagisecure_import::commit(&mut vault, plan, policy)?;
    vault.save()?;

    if args.json {
        // The JSON stream is the report printed above and nothing else; a plain-text line after
        // it would not be valid JSON on its own and would not belong to the document either.
    } else {
        println!("{}", outcome.headline());
    }

    if args.shred_source {
        let shred = kagisecure_import::shred_file(&args.source)?;
        if args.json {
            eprintln!("{}", shred.caveat());
        } else {
            println!("{}", shred.caveat());
        }
    }

    Ok(())
}

/// The plain-text summary: counts per category, duplicates by resolution, drops by reason, then
/// the one-line headline.
///
/// Every field this prints comes from [`ImportReport`], which cannot hold a value.
fn print_summary(report: &ImportReport) {
    if !report.by_category.is_empty() {
        println!("By category:");
        for (category, count) in &report.by_category {
            println!("  {category:<20} {count:>6}");
        }
        println!();
    }

    if !report.by_action.is_empty() {
        println!("Duplicates:");
        for action in [
            ItemAction::Create,
            ItemAction::Update,
            ItemAction::Skip,
            ItemAction::KeepBoth,
        ] {
            let count = report.action_count(action);
            if count > 0 {
                println!("  {:<20} {count:>6}", action.as_str());
            }
        }
        println!();
    }

    if report.totals.history_entries > 0 {
        println!(
            "History: {} retired value{} will be imported",
            report.totals.history_entries,
            if report.totals.history_entries == 1 {
                ""
            } else {
                "s"
            }
        );
        println!();
    }

    if !report.dropped.is_empty() {
        println!("Not imported:");
        for note in &report.dropped {
            println!(
                "  {:<24} {:>6}  {}",
                note.what.as_str(),
                note.count,
                note.what.explanation()
            );
        }
        println!();
    }

    for decision in &report.decisions {
        println!("Note: {}", decision.detail);
    }

    println!("{}", report.headline());
}

/// Ask before committing a source of more than [`CONFIRM_THRESHOLD`] items.
///
/// # Errors
///
/// If the answer is not `y`/`yes`, or standard input cannot be read.
fn confirm_large_import(source: &Path, count: usize) -> Result<()> {
    print!(
        "This will import {count} items from {}. Continue? [y/N] ",
        source.display()
    );
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading the confirmation")?;
    match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(()),
        _ => bail!("import cancelled"),
    }
}

/// Write `markdown` to `path`, mode `0600`.
///
/// The report holds no values (`ImportReport` cannot), but it is still a complete inventory of
/// which accounts a person has, which is worth protecting in its own right.
fn write_report(path: &Path, markdown: &str) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("writing the report to {}", path.display()))?;
    file.write_all(markdown.as_bytes())?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `create` + `mode` already did this; re-asserting costs nothing and covers a
        // pre-existing target file whose permissions were something else.
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use kagisecure_core::model::{Category, FieldKind};
    use kagisecure_import::{DropKind, ImportPlan, ImportedField, ImportedItem};

    use super::*;

    fn sample_report() -> ImportReport {
        let mut item = ImportedItem::new("Acme", Category::Login);
        item.push_field(ImportedField::public("username", FieldKind::Text, "ada"));
        item.report.note_dropped(DropKind::Attachment);
        let mut plan = ImportPlan::new(SourceKind::OnePux, "export.1pux");
        plan.push(item);
        plan.report()
    }

    #[test]
    fn format_and_policy_names_round_trip_or_fail_as_usage_errors() {
        assert!(parse_format(&None).unwrap().is_none());
        assert_eq!(
            parse_format(&Some("1pux".to_owned())).unwrap(),
            Some(SourceKind::OnePux)
        );
        let err = parse_format(&Some("lastpass".to_owned())).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());

        assert_eq!(parse_policy("update").unwrap(), DuplicatePolicy::Update);
        let err = parse_policy("interactive").unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    #[test]
    fn a_report_can_be_rendered_as_json_and_as_a_0600_file() {
        let report = sample_report();
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"attachment\""));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.md");
        write_report(&path, &report.to_markdown()).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("Acme"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        }
    }

    #[test]
    fn the_summary_never_panics_on_an_empty_report() {
        let plan = ImportPlan::new(SourceKind::AppleCsv, "empty.csv");
        print_summary(&plan.report());
    }
}
