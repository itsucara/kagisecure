//! Importing a vault exported from another password manager (import.md §8).
//!
//! # This adds no new secret crossing
//!
//! [ADR-0008](../../../docs/decisions/0008-ffi-secret-crossings.md) enumerates every place a
//! plaintext value crosses this boundary. Import adds none of them, and the type system is what
//! says so rather than a promise:
//!
//! * [`VaultSession::import_preview`] returns an [`ImportPlanHandle`] — a
//!   [`uniffi::Object`], which means Swift holds a *pointer* to a Rust-side object and can call
//!   its methods. The parsed values sit inside it, in the Rust heap, and the only projection of
//!   that object Swift can ask for is [`ImportPlanHandle::report`].
//! * A report is [`kagisecure_import::ImportReport`] converted field by field into the records
//!   below. Every one of them holds a name, a kind, a count or a timestamp.
//!   `kagisecure_import::ir::ImportedValue` and [`kagisecure_core::Secret`] are not `Serialize`
//!   and have no conversion into anything here; adding a value column to
//!   [`ImportItemRow`] would mean writing a conversion that does not exist.
//! * [`VaultSession::import_commit`] returns counts. Even password history — which *is* imported
//!   (import.md §2.7) — is a number here and nothing else: no value, no label, no timestamp.
//!
//! So the preview the app renders is the report, the plan never leaves Rust, and the app's screen
//! cannot show a value because it is never given one.
//!
//! # Why the plan is an object and not a record
//!
//! A record would be copied into Swift, values and all. The object keeps the parse on this side
//! of the boundary, which also makes "the plan is spent" enforceable: [`commit`] consumes the
//! [`kagisecure_import::ImportPlan`] by value, so the handle takes it out of its `Mutex` and
//! leaves `None` behind. A second commit of the same handle fails instead of importing twice.
//!
//! # Shredding
//!
//! [`shred_source_file`] is a free function rather than a session method because it is not a
//! vault operation: an export sitting in `~/Downloads` is a plaintext copy of someone's entire
//! password manager, and deleting it is worth offering whether or not a vault happens to be open
//! (import.md §9). [`shred_caveat`] is the sentence the prompt must show *before* the user
//! agrees, so the UI cannot offer this as "secure erase".

use std::path::Path;
use std::sync::{Arc, Mutex};

use kagisecure_core::Vault;
use kagisecure_import::dedupe::{DuplicatePolicy, ItemAction};
use kagisecure_import::error::ImportError;
use kagisecure_import::ir::{DropKind, DropNote, ImportPlan, SourceKind, TargetVault};
use kagisecure_import::report::{ImportReport, ItemRow};
use kagisecure_import::{commit, parse, shred};

use crate::{FfiError, FfiResult};

/// Which export format a file is, as `--format` names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ImportFormat {
    /// 1Password's own archive, the highest-fidelity path.
    OnePux,
    /// Apple Passwords / iCloud Keychain CSV.
    AppleCsv,
    /// Chrome, Edge or another Chromium browser's CSV.
    ChromiumCsv,
    /// Firefox's CSV.
    FirefoxCsv,
    /// 1Password's CSV, which carries less than its `.1pux`.
    OnePasswordCsv,
}

impl ImportFormat {
    fn from_core(kind: SourceKind) -> Self {
        match kind {
            SourceKind::OnePux => Self::OnePux,
            SourceKind::AppleCsv => Self::AppleCsv,
            SourceKind::ChromiumCsv => Self::ChromiumCsv,
            SourceKind::FirefoxCsv => Self::FirefoxCsv,
            SourceKind::OnePasswordCsv => Self::OnePasswordCsv,
        }
    }

    fn to_core(self) -> SourceKind {
        match self {
            Self::OnePux => SourceKind::OnePux,
            Self::AppleCsv => SourceKind::AppleCsv,
            Self::ChromiumCsv => SourceKind::ChromiumCsv,
            Self::FirefoxCsv => SourceKind::FirefoxCsv,
            Self::OnePasswordCsv => SourceKind::OnePasswordCsv,
        }
    }
}

/// One row of the sheet's format picker.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportFormatInfo {
    /// The format itself.
    pub format: ImportFormat,
    /// Its canonical name, as the CLI's `--format` takes it.
    pub id: String,
    /// What the picker shows.
    pub display_name: String,
}

/// Every format this build can read, in the order the CLI lists them.
///
/// The app's picker is built from this rather than from a list written a second time in Swift, so
/// a format added to `kagisecure-import` appears in the app without an edit there.
#[uniffi::export]
#[must_use]
pub fn import_formats() -> Vec<ImportFormatInfo> {
    SourceKind::ALL
        .iter()
        .map(|&kind| ImportFormatInfo {
            format: ImportFormat::from_core(kind),
            id: kind.as_str().to_owned(),
            display_name: display_name(kind).to_owned(),
        })
        .collect()
}

/// What the picker calls a format. The canonical names (`1pux`, `apple-csv`) are for a command
/// line; a menu wants the name of the app the file came out of.
fn display_name(kind: SourceKind) -> &'static str {
    match kind {
        SourceKind::OnePux => "1Password archive (.1pux)",
        SourceKind::AppleCsv => "Apple Passwords (.csv)",
        SourceKind::ChromiumCsv => "Chrome or Edge (.csv)",
        SourceKind::FirefoxCsv => "Firefox (.csv)",
        SourceKind::OnePasswordCsv => "1Password export (.csv)",
    }
}

/// What to do with an item the vault already has (import.md §5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Enum)]
pub enum DuplicatePolicyView {
    /// Leave the existing item alone. The default.
    #[default]
    Skip,
    /// Overwrite what the source carries and keep what only this vault knows.
    Update,
    /// Import it as a second item, with a dated title.
    KeepBoth,
}

impl DuplicatePolicyView {
    fn to_core(self) -> DuplicatePolicy {
        match self {
            Self::Skip => DuplicatePolicy::Skip,
            Self::Update => DuplicatePolicy::Update,
            Self::KeepBoth => DuplicatePolicy::KeepBoth,
        }
    }
}

/// What committing would do, or did, to one item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ImportItemActionView {
    /// Add it; the vault has nothing like it.
    Create,
    /// Overwrite the matching item's source-carried parts.
    Update,
    /// Leave the matching item alone.
    Skip,
    /// Add it beside the matching item.
    KeepBoth,
}

impl ImportItemActionView {
    fn from_core(action: ItemAction) -> Self {
        match action {
            ItemAction::Create => Self::Create,
            ItemAction::Update => Self::Update,
            ItemAction::Skip => Self::Skip,
            ItemAction::KeepBoth => Self::KeepBoth,
        }
    }

    /// Whether this action means the vault already had the item.
    fn is_duplicate(self) -> bool {
        !matches!(self, Self::Create)
    }
}

/// A kind of thing the import cannot bring across (import.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ImportDropKindView {
    /// A file attached to an item.
    Attachment,
    /// A passkey / WebAuthn credential.
    Passkey,
    /// A password-history entry the parser could not read. History itself **is** imported.
    PasswordHistory,
    /// A Watchtower / breach-report flag.
    WatchtowerFlag,
    /// A form field the source carried with nothing in it.
    EmptyFormField,
    /// Something this build does not recognize.
    UnknownEntry,
}

impl ImportDropKindView {
    fn from_core(kind: DropKind) -> Self {
        match kind {
            DropKind::Attachment => Self::Attachment,
            DropKind::Passkey => Self::Passkey,
            DropKind::PasswordHistory => Self::PasswordHistory,
            DropKind::WatchtowerFlag => Self::WatchtowerFlag,
            DropKind::EmptyFormField => Self::EmptyFormField,
            DropKind::UnknownEntry => Self::UnknownEntry,
        }
    }
}

/// How many of one kind were left behind, and why.
#[derive(Clone, Debug, uniffi::Record)]
pub struct DropNoteView {
    /// What was dropped.
    pub kind: ImportDropKindView,
    /// Its short name, for a label.
    pub name: String,
    /// How many.
    pub count: u32,
    /// The one line the sheet puts beside the counter, so "17 dropped" is not a mystery.
    pub explanation: String,
}

impl DropNoteView {
    fn from_core(note: &DropNote) -> Self {
        Self {
            kind: ImportDropKindView::from_core(note.what),
            name: note.what.as_str().to_owned(),
            count: count(note.count),
            explanation: note.what.explanation().to_owned(),
        }
    }
}

/// Run-level counts.
#[derive(Clone, Copy, Debug, uniffi::Record)]
pub struct ImportTotals {
    /// Items in the plan.
    pub items: u32,
    /// Fields that will become typed fields.
    pub fields_mapped: u32,
    /// Things kept only as metadata.
    pub fields_preserved: u32,
    /// Things left behind, across every kind.
    pub fields_dropped: u32,
    /// Retired values that will be imported. A count, deliberately and only.
    pub history_entries: u32,
}

/// Items of one category.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportCategoryCount {
    /// The category's canonical name, e.g. `"credit-card"`.
    pub category: String,
    /// How many items.
    pub items: u32,
}

/// Items that would be handled one way.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportActionCount {
    /// What would happen to them.
    pub action: ImportItemActionView,
    /// How many.
    pub items: u32,
}

/// A note the parser made about the run as a whole.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportDecisionView {
    /// A stable machine-readable code.
    pub code: String,
    /// One sentence for a person. Metadata, like everything else here.
    pub detail: String,
}

/// One row of the sheet's per-item table.
///
/// There is no value column. See this module's header for why there cannot be one.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportItemRow {
    /// The item's title.
    pub title: String,
    /// Its category's canonical name.
    pub category: String,
    /// Whether the category was guessed rather than stated by the source.
    pub category_was_guessed: bool,
    /// The logical vault it is headed for.
    pub vault: String,
    /// How many fields it brings.
    pub fields: u32,
    /// How many retired values it brings. A count, deliberately and only.
    pub history_entries: u32,
    /// What is being left behind for this item.
    pub dropped: Vec<DropNoteView>,
    /// What committing would do to it. `None` when the report was built without a vault.
    pub action: Option<ImportItemActionView>,
}

impl ImportItemRow {
    fn from_core(row: &ItemRow) -> Self {
        Self {
            title: row.title.clone(),
            category: row.category.clone(),
            category_was_guessed: row.category_was_guessed,
            vault: row.vault.clone(),
            fields: count(row.fields),
            history_entries: count(row.history_entries),
            dropped: row.dropped.iter().map(DropNoteView::from_core).collect(),
            action: row.action.map(ImportItemActionView::from_core),
        }
    }
}

/// The preview: what an import would do, in names and counts.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportReportView {
    /// The format that was read.
    pub source: ImportFormat,
    /// The source file's *name*. Never the directory it lived in.
    pub source_name: String,
    /// One line summarising the run, for the top of the sheet.
    pub headline: String,
    /// Run-level counts.
    pub totals: ImportTotals,
    /// Item counts by category, sorted by name.
    pub by_category: Vec<ImportCategoryCount>,
    /// Everything left behind, across the whole run.
    pub dropped: Vec<DropNoteView>,
    /// Run-level notes from the parser.
    pub decisions: Vec<ImportDecisionView>,
    /// Counts by what committing would do. Empty when the report was built without a vault.
    pub by_action: Vec<ImportActionCount>,
    /// How many items the vault already has. `0` when the report was built without a vault, which
    /// is not the same as "no duplicates" — [`ImportReportView::vault_aware`] distinguishes them.
    pub duplicates: u32,
    /// Whether this report was built against the open vault, and so knows about duplicates.
    pub vault_aware: bool,
    /// One row per item.
    pub items: Vec<ImportItemRow>,
}

impl ImportReportView {
    fn from_core(report: &ImportReport, vault_aware: bool) -> Self {
        let items: Vec<ImportItemRow> = report.items.iter().map(ImportItemRow::from_core).collect();
        let duplicates = items
            .iter()
            .filter(|row| row.action.is_some_and(ImportItemActionView::is_duplicate))
            .count();
        Self {
            source: ImportFormat::from_core(report.source),
            source_name: report.source_file.clone(),
            headline: report.headline(),
            totals: ImportTotals {
                items: count(report.totals.items),
                fields_mapped: count(report.totals.fields_mapped),
                fields_preserved: count(report.totals.fields_preserved),
                fields_dropped: count(report.totals.fields_dropped),
                history_entries: count(report.totals.history_entries),
            },
            by_category: report
                .by_category
                .iter()
                .map(|(category, items)| ImportCategoryCount {
                    category: category.clone(),
                    items: count(*items),
                })
                .collect(),
            dropped: report.dropped.iter().map(DropNoteView::from_core).collect(),
            decisions: report
                .decisions
                .iter()
                .map(|d| ImportDecisionView {
                    code: d.code.clone(),
                    detail: d.detail.clone(),
                })
                .collect(),
            by_action: [
                ItemAction::Create,
                ItemAction::Update,
                ItemAction::Skip,
                ItemAction::KeepBoth,
            ]
            .into_iter()
            .filter_map(|action| {
                let items = report.action_count(action);
                (items > 0).then(|| ImportActionCount {
                    action: ImportItemActionView::from_core(action),
                    items: count(items),
                })
            })
            .collect(),
            duplicates: count(duplicates),
            vault_aware,
            items,
        }
    }
}

/// What an import actually did.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportOutcomeView {
    /// Items added.
    pub created: u32,
    /// Items overwritten in place.
    pub updated: u32,
    /// Items left alone because the vault already had them.
    pub skipped: u32,
    /// Items added beside an existing one under `keep-both`.
    pub kept_both: u32,
    /// Retired values added to items' password history. A count, deliberately and only.
    pub history_added: u32,
    /// Names of the logical vaults that had to be created.
    pub vaults_created: Vec<String>,
    /// One line for the result pane.
    pub headline: String,
    /// The preview, as it stood when the decision was made.
    pub report: ImportReportView,
}

/// How far [`shred_source_file`] got, and what the UI must still say about it.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ShredOutcomeView {
    /// The file's bytes were overwritten and the write reached the device.
    pub overwritten: bool,
    /// The directory entry is gone.
    pub removed: bool,
    /// The sentence to show underneath. Never says "securely erased", because it is not.
    pub caveat: String,
}

/// A parsed import, held on the Rust side.
///
/// Swift holds a reference to this and can ask it for a [`ImportReportView`]. It cannot ask it
/// for anything else, which is the whole design: the values the parse produced stay here until
/// they are written into the vault, or dropped when the sheet closes.
#[derive(uniffi::Object)]
pub struct ImportPlanHandle {
    /// `None` once the plan has been committed. [`commit`] takes the plan by value, so a handle
    /// can be spent exactly once and a double-press of Import cannot import twice.
    plan: Mutex<Option<ImportPlan>>,
    /// Kept beside the plan so the sheet can still show what it was reading after the commit has
    /// consumed it. The full path, because this is the string the shred prompt needs.
    source_path: String,
}

impl ImportPlanHandle {
    fn new(plan: ImportPlan) -> Arc<Self> {
        Arc::new(Self {
            source_path: plan.source_path.display().to_string(),
            plan: Mutex::new(Some(plan)),
        })
    }

    /// The plan, for as long as it is still there.
    ///
    /// A poisoned lock means another thread panicked holding it; recovering the guard is right
    /// here, because the plan is either present and whole or absent, with no half state a panic
    /// could have left behind.
    fn guard(&self) -> std::sync::MutexGuard<'_, Option<ImportPlan>> {
        self.plan.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn spent() -> FfiError {
        FfiError::invalid("this import has already been applied; choose the file again")
    }

    /// The report for this plan against `vault` under `policy`. Reads the vault, writes nothing.
    pub(crate) fn report_against(
        &self,
        vault: &Vault,
        policy: DuplicatePolicyView,
    ) -> FfiResult<ImportReportView> {
        let guard = self.guard();
        let plan = guard.as_ref().ok_or_else(Self::spent)?;
        Ok(ImportReportView::from_core(
            &plan.report_against(vault, policy.to_core()),
            true,
        ))
    }

    /// Apply this plan to `vault`, consuming it.
    ///
    /// The caller saves. Nothing here touches the disk, so a save that fails leaves the file as
    /// it was — the same discipline `kagisecure_import::commit` documents.
    pub(crate) fn commit_into(
        &self,
        vault: &mut Vault,
        policy: DuplicatePolicyView,
        target_vault: Option<String>,
    ) -> FfiResult<ImportOutcomeView> {
        let mut plan = self.guard().take().ok_or_else(Self::spent)?;
        if let Some(name) = target_vault {
            if name.trim().is_empty() {
                return Err(FfiError::invalid("a target vault name cannot be blank"));
            }
            plan.retarget_all(&TargetVault::Named(name));
        }
        let outcome = commit(vault, plan, policy.to_core())?;
        Ok(ImportOutcomeView {
            created: count(outcome.created),
            updated: count(outcome.updated),
            skipped: count(outcome.skipped),
            kept_both: count(outcome.kept_both),
            history_added: count(outcome.history_added),
            vaults_created: outcome.vaults_created.clone(),
            headline: outcome.headline(),
            report: ImportReportView::from_core(&outcome.report, true),
        })
    }
}

#[uniffi::export]
impl ImportPlanHandle {
    /// The preview, with no vault in sight: every row's `action` is `None` and `duplicates` is
    /// `0`, because without a vault there is no way to know what is already in it. The sheet
    /// shows this first and replaces it with `VaultSession::import_preview_against` as soon as a
    /// duplicate policy is chosen.
    ///
    /// # Errors
    ///
    /// [`FfiError::Invalid`] if this plan has already been committed.
    pub fn report(&self) -> FfiResult<ImportReportView> {
        let guard = self.guard();
        let plan = guard.as_ref().ok_or_else(Self::spent)?;
        Ok(ImportReportView::from_core(&plan.report(), false))
    }

    /// The file this plan was parsed from, in full. The *name* alone is on the report; this is
    /// the path the shred prompt needs.
    #[must_use]
    pub fn source_path(&self) -> String {
        self.source_path.clone()
    }

    /// Whether this plan has been committed and can no longer be used.
    #[must_use]
    pub fn is_spent(&self) -> bool {
        self.guard().is_none()
    }
}

/// Parse `path` into a plan.
///
/// `format` overrides detection, the way `--format` does; with `None` the parser is chosen from
/// the file itself and a CSV dialect from its header row.
pub(crate) fn preview(
    path: &str,
    format: Option<ImportFormat>,
) -> FfiResult<Arc<ImportPlanHandle>> {
    let plan = parse(Path::new(path), format.map(ImportFormat::to_core))?;
    Ok(ImportPlanHandle::new(plan))
}

/// Overwrite, truncate and remove the file an import was read from (import.md §9).
///
/// Not a vault operation and not implicit: an export is a full plaintext copy of a password
/// manager, and the app asks before calling this. **Best effort, not secure erase** — see
/// [`shred_caveat`], which is the text the prompt must show first.
///
/// # Errors
///
/// [`FfiError::NotFound`] if there is no file there, [`FfiError::Io`] if it cannot be opened for
/// writing. A failure *after* the file was opened comes back in the outcome instead, so a caller
/// that is told `removed: false` knows the file is still there.
#[uniffi::export]
pub fn shred_source_file(path: String) -> FfiResult<ShredOutcomeView> {
    let outcome = shred::shred_file(Path::new(&path))?;
    Ok(ShredOutcomeView {
        overwritten: outcome.overwritten,
        removed: outcome.removed,
        caveat: outcome.caveat().to_owned(),
    })
}

/// What the "Delete the source file?" prompt has to say before the user agrees.
///
/// A separate function from [`ShredOutcomeView::caveat`], which reports what happened: this one
/// is the warning that has to be on screen *beforehand*, so the offer is never made as though it
/// were a secure erase.
#[uniffi::export]
#[must_use]
pub fn shred_caveat() -> String {
    "Deleting this file is best effort. It may survive in a Time Machine or local snapshot, in a \
     backup, in a Spotlight index or in unallocated SSD blocks. The reliable step is not leaving \
     an export anywhere it can be backed up."
        .to_owned()
}

/// `usize` counts, as the boundary's `u32`.
///
/// Saturating rather than wrapping: a plan is capped at 100 000 items by the parser's own limits,
/// so this cannot be reached in practice, and a count that is too large should read as "very
/// many" rather than as a small number.
fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

impl From<ImportError> for FfiError {
    fn from(e: ImportError) -> Self {
        match e {
            ImportError::Io(io) => Self::Io {
                message: io.to_string(),
            },
            ImportError::Vault(core) => core.into(),
            ImportError::SourceNotFound(path) => Self::NotFound {
                path: path.display().to_string(),
            },
            ImportError::TargetVaultNotFound(name) => Self::missing("vault", name),
            // Everything else is the file being wrong in some way the user can act on: a format
            // that could not be told apart, a column that is missing, an encoding this build does
            // not read, a limit that was hit. `Display` for each of those is already written to
            // name the problem and never the contents (`kagisecure_import::error`), so the
            // rendered message is what the app shows.
            other => Self::invalid(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use kagisecure_core::model::{Category, FieldKind};
    use kagisecure_import::ir::{ImportedField, ImportedItem, ImportedRevision};

    use super::*;
    use crate::VaultSession;

    /// The error a preview failed with.
    ///
    /// Written out rather than `unwrap_err`, which would need `ImportPlanHandle: Debug` — and the
    /// handle is deliberately not printable: a `Debug` on it would be a rendering of a parsed
    /// vault, values included, one `dbg!` away from a log file.
    fn failure(result: FfiResult<Arc<ImportPlanHandle>>) -> FfiError {
        match result {
            Ok(_) => panic!("expected the preview to fail"),
            Err(e) => e,
        }
    }

    /// An unlocked vault at cheap KDF parameters, the way `session.rs`'s own tests make one.
    fn session() -> (tempfile::TempDir, Arc<VaultSession>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kagivault").display().to_string();
        let session = VaultSession::create(
            path,
            "pw".to_owned(),
            "Personal".to_owned(),
            Some(8),
            Some(1),
        )
        .expect("create");
        (dir, session)
    }

    /// A two-item plan with a secret, a retired value and a dropped attachment. Stands in for a
    /// parser, which is still a stub in this work package.
    fn plan(source_path: &str) -> ImportPlan {
        let mut plan = ImportPlan::new(SourceKind::OnePux, source_path);
        plan.note("format-given", "the format was named by the caller");

        let mut login = ImportedItem::new("Acme", Category::Login);
        login.push_field(ImportedField::public("username", FieldKind::Text, "deploy"));
        login.push_field(ImportedField::secret(
            "password",
            FieldKind::Concealed,
            "hunter2".to_owned(),
        ));
        login.push_revision(ImportedRevision::secret("older-one".to_owned(), Some(10)));
        login.report.note_dropped(DropKind::Attachment);
        plan.push(login);

        let mut note = ImportedItem::new("Router", Category::SecureNote);
        note.report.note_dropped(DropKind::Passkey);
        plan.push(note);
        plan
    }

    #[test]
    fn a_missing_source_file_is_a_not_found_naming_the_path() {
        let dir = tempfile::tempdir().unwrap();
        // A name the sniffer does not recognize as an archive, so the missing file is noticed
        // here rather than inside a parser: `kagisecure_import::parse` hands a `*.1pux` name
        // straight to the 1PUX parser, which is the one that reports on it.
        let path = dir.path().join("nothing-here.csv").display().to_string();
        match failure(preview(&path, None)) {
            FfiError::NotFound { path: reported } => assert_eq!(reported, path),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    /// A file the importer will not read has to arrive as something the sheet can put on screen.
    ///
    /// Deliberately not a *valid* header with no rows: that is a file the CSV parser is entitled
    /// to accept, and a test that depends on it being refused would break the day it does.
    #[test]
    fn a_file_no_parser_recognizes_arrives_as_an_invalid_with_a_readable_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-an-export.csv");
        std::fs::write(&path, b"nonsense\n").unwrap();
        match failure(preview(&path.display().to_string(), None)) {
            FfiError::Invalid { message } => assert!(!message.is_empty(), "{message}"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn every_format_survives_the_trip_through_the_boundary_enum() {
        for info in import_formats() {
            assert_eq!(
                ImportFormat::from_core(info.format.to_core()),
                info.format,
                "{} did not round-trip",
                info.id
            );
            assert!(!info.display_name.is_empty());
        }
        assert_eq!(import_formats().len(), SourceKind::ALL.len());
    }

    #[test]
    fn the_caveat_never_calls_itself_a_secure_erase() {
        let caveat = shred_caveat().to_lowercase();
        assert!(caveat.contains("best effort"), "{caveat}");
        assert!(!caveat.contains("secure erase"), "{caveat}");
        assert!(!caveat.contains("permanently"), "{caveat}");
    }

    #[test]
    fn shredding_a_file_that_is_not_there_names_it_rather_than_reporting_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gone.csv").display().to_string();
        assert!(matches!(
            shred_source_file(path).unwrap_err(),
            FfiError::NotFound { .. }
        ));
    }

    #[test]
    fn the_plan_only_projection_is_a_report_of_names_and_counts() {
        let handle = ImportPlanHandle::new(plan("/home/ada/private/export.1pux"));
        let report = handle.report().unwrap();

        assert_eq!(report.totals.items, 2);
        assert_eq!(report.totals.history_entries, 1);
        assert_eq!(report.source_name, "export.1pux");
        assert!(!report.vault_aware);
        assert_eq!(report.duplicates, 0);
        assert!(report.items.iter().all(|row| row.action.is_none()));
        assert!(report.by_action.is_empty());

        // The three counters the sheet shows, each with its sentence.
        let attachments = report
            .dropped
            .iter()
            .find(|d| d.kind == ImportDropKindView::Attachment)
            .expect("an attachment was dropped");
        assert_eq!(attachments.count, 1);
        assert!(!attachments.explanation.is_empty());

        // Nothing about a value, anywhere in the rendering the app gets.
        let rendered = format!("{report:?}");
        for value in ["hunter2", "older-one", "deploy", "private"] {
            assert!(
                !rendered.contains(value),
                "{value} reached the boundary: {rendered}"
            );
        }
        // …and the full path is available only where the shred prompt needs it.
        assert_eq!(handle.source_path(), "/home/ada/private/export.1pux");
    }

    #[test]
    fn committing_writes_the_items_and_spends_the_handle() {
        let (dir, session) = session();
        let handle =
            ImportPlanHandle::new(plan(&dir.path().join("export.1pux").display().to_string()));

        let previewed = session
            .import_preview_against(Arc::clone(&handle), DuplicatePolicyView::Skip)
            .unwrap();
        assert!(previewed.vault_aware);
        assert_eq!(previewed.duplicates, 0);

        let outcome = session
            .import_commit(
                Arc::clone(&handle),
                DuplicatePolicyView::Skip,
                Some("Imported".to_owned()),
            )
            .unwrap();
        assert_eq!(outcome.created, 2);
        assert_eq!(outcome.history_added, 1);
        assert_eq!(outcome.vaults_created, vec!["Imported".to_owned()]);
        assert!(!outcome.headline.is_empty());

        // The vault has them, and the save already happened — a reopen sees the same two items.
        assert_eq!(session.sidebar_counts().all, 2);
        assert!(handle.is_spent());

        // A second press of Import is refused rather than doubling the vault.
        assert!(matches!(
            session.import_commit(handle, DuplicatePolicyView::Skip, None),
            Err(FfiError::Invalid { .. })
        ));
    }

    #[test]
    fn a_re_import_under_skip_previews_every_item_as_a_duplicate() {
        let (dir, session) = session();
        let source = dir.path().join("export.1pux").display().to_string();
        session
            .import_commit(
                ImportPlanHandle::new(plan(&source)),
                DuplicatePolicyView::Skip,
                None,
            )
            .unwrap();

        let again = ImportPlanHandle::new(plan(&source));
        let report = session
            .import_preview_against(again, DuplicatePolicyView::Skip)
            .unwrap();
        assert_eq!(report.duplicates, 2);
        assert_eq!(
            report
                .by_action
                .iter()
                .find(|c| c.action == ImportItemActionView::Skip)
                .map(|c| c.items),
            Some(2)
        );
    }

    #[test]
    fn an_imported_item_is_never_agent_visible() {
        let (dir, session) = session();
        session
            .import_commit(
                ImportPlanHandle::new(plan(&dir.path().join("e.1pux").display().to_string())),
                DuplicatePolicyView::Skip,
                None,
            )
            .unwrap();
        assert!(
            session
                .list_items(crate::ItemFilter::All, None, crate::ItemSort::Title)
                .iter()
                .all(|item| !item.agent_visible),
            "threat-model M-9: an import must not opt items into agent visibility"
        );
    }

    #[test]
    fn shredding_removes_the_file_and_reports_the_caveat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        std::fs::write(&path, b"title,url,username,password\nx,y,z,hunter2\n").unwrap();

        let outcome = shred_source_file(path.display().to_string()).unwrap();
        assert!(outcome.removed);
        assert!(outcome.overwritten);
        assert!(!path.exists());
        assert!(outcome.caveat.to_lowercase().contains("best effort"));
    }
}
