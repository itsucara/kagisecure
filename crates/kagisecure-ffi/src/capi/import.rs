//! Importing another password manager's export (import.md §8). No new secret crossing: the plan
//! stays behind [`KgsImportPlan`], and what comes out is names and counts.

use std::sync::Arc;

use super::{
    KgsBuffer, KgsBufferArray, KgsDuplicatePolicy, KgsImportDropKind, KgsImportFormat,
    KgsImportItemAction, KgsImportPlan, KgsOptSlice, KgsOptU32, KgsSession, KgsSlice, KgsStatus,
    Release, call, free, plan as live_plan, session as live, slot,
};
use crate::{
    DropNoteView, ImportFormatInfo, ImportItemRow, ImportOutcomeView, ImportReportView,
    ShredOutcomeView,
};

// -------------------------------------------------------------------------------------------
// Records
// -------------------------------------------------------------------------------------------

/// [`ImportFormatInfo`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsImportFormatInfo {
    /// A [`KgsImportFormat`] tag.
    pub format: u32,
    /// Its canonical name, as the CLI's `--format` takes it.
    pub id: KgsBuffer,
    /// What the picker shows.
    pub display_name: KgsBuffer,
}

impl KgsImportFormatInfo {
    fn new(f: ImportFormatInfo) -> Self {
        Self {
            format: KgsImportFormat::tag(f.format),
            id: KgsBuffer::from_string(f.id),
            display_name: KgsBuffer::from_string(f.display_name),
        }
    }
}

impl Release for KgsImportFormatInfo {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.id.release();
            self.display_name.release();
        }
    }
}

/// A list of [`KgsImportFormatInfo`]. Free with [`kgs_import_format_info_array_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsImportFormatInfoArray {
    /// First element.
    pub ptr: *mut KgsImportFormatInfo,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsImportFormatInfoArray, KgsImportFormatInfo);

/// [`DropNoteView`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsDropNote {
    /// A [`KgsImportDropKind`] tag.
    pub kind: u32,
    /// Its short name.
    pub name: KgsBuffer,
    /// How many.
    pub count: u32,
    /// The one-line explanation.
    pub explanation: KgsBuffer,
}

impl KgsDropNote {
    fn new(n: DropNoteView) -> Self {
        Self {
            kind: KgsImportDropKind::tag(n.kind),
            name: KgsBuffer::from_string(n.name),
            count: n.count,
            explanation: KgsBuffer::from_string(n.explanation),
        }
    }
}

impl Release for KgsDropNote {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.name.release();
            self.explanation.release();
        }
    }
}

/// A list of [`KgsDropNote`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsDropNoteArray {
    /// First element.
    pub ptr: *mut KgsDropNote,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsDropNoteArray, KgsDropNote);

/// [`crate::ImportTotals`]. Plain data.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsImportTotals {
    /// Items in the plan.
    pub items: u32,
    /// Fields that will become typed fields.
    pub fields_mapped: u32,
    /// Things kept only as metadata.
    pub fields_preserved: u32,
    /// Things left behind.
    pub fields_dropped: u32,
    /// Retired values that will be imported. A count.
    pub history_entries: u32,
}

/// [`crate::ImportCategoryCount`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsImportCategoryCount {
    /// The category's canonical name.
    pub category: KgsBuffer,
    /// How many items.
    pub items: u32,
}

impl Release for KgsImportCategoryCount {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe { self.category.release() };
    }
}

/// A list of [`KgsImportCategoryCount`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsImportCategoryCountArray {
    /// First element.
    pub ptr: *mut KgsImportCategoryCount,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsImportCategoryCountArray, KgsImportCategoryCount);

/// [`crate::ImportActionCount`]. Plain data.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KgsImportActionCount {
    /// A [`KgsImportItemAction`] tag.
    pub action: u32,
    /// How many.
    pub items: u32,
}

impl Release for KgsImportActionCount {
    unsafe fn release(&mut self) {}
}

/// A list of [`KgsImportActionCount`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsImportActionCountArray {
    /// First element.
    pub ptr: *mut KgsImportActionCount,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsImportActionCountArray, KgsImportActionCount);

/// [`crate::ImportDecisionView`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsImportDecision {
    /// A stable machine-readable code.
    pub code: KgsBuffer,
    /// One sentence for a person.
    pub detail: KgsBuffer,
}

impl Release for KgsImportDecision {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.code.release();
            self.detail.release();
        }
    }
}

/// A list of [`KgsImportDecision`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsImportDecisionArray {
    /// First element.
    pub ptr: *mut KgsImportDecision,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsImportDecisionArray, KgsImportDecision);

/// [`ImportItemRow`]. There is no value column.
#[repr(C)]
#[derive(Debug)]
pub struct KgsImportItemRow {
    /// The item's title.
    pub title: KgsBuffer,
    /// Its category's canonical name.
    pub category: KgsBuffer,
    /// 0 or 1: the category was guessed.
    pub category_was_guessed: u8,
    /// The logical vault it is headed for.
    pub vault: KgsBuffer,
    /// How many fields it brings.
    pub fields: u32,
    /// How many retired values it brings. A count.
    pub history_entries: u32,
    /// What is being left behind for this item.
    pub dropped: KgsDropNoteArray,
    /// A [`KgsImportItemAction`] tag; absent when the report was built without a vault.
    pub action: KgsOptU32,
}

impl KgsImportItemRow {
    fn new(r: ImportItemRow) -> Self {
        Self {
            title: KgsBuffer::from_string(r.title),
            category: KgsBuffer::from_string(r.category),
            category_was_guessed: u8::from(r.category_was_guessed),
            vault: KgsBuffer::from_string(r.vault),
            fields: r.fields,
            history_entries: r.history_entries,
            dropped: KgsDropNoteArray::collect(r.dropped, KgsDropNote::new),
            action: KgsOptU32::from_option(r.action.map(KgsImportItemAction::tag)),
        }
    }
}

impl Release for KgsImportItemRow {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.title.release();
            self.category.release();
            self.vault.release();
            self.dropped.release();
        }
    }
}

/// A list of [`KgsImportItemRow`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsImportItemRowArray {
    /// First element.
    pub ptr: *mut KgsImportItemRow,
    /// How many.
    pub len: usize,
    /// Opaque to the caller.
    pub cap: usize,
}
array!(KgsImportItemRowArray, KgsImportItemRow);

/// [`ImportReportView`]. Free with [`kgs_import_report_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsImportReport {
    /// A [`KgsImportFormat`] tag: the format that was read.
    pub source: u32,
    /// The source file's name. Never its directory.
    pub source_name: KgsBuffer,
    /// One line summarising the run.
    pub headline: KgsBuffer,
    /// Run-level counts.
    pub totals: KgsImportTotals,
    /// Item counts by category.
    pub by_category: KgsImportCategoryCountArray,
    /// Everything left behind.
    pub dropped: KgsDropNoteArray,
    /// Run-level notes from the parser.
    pub decisions: KgsImportDecisionArray,
    /// Counts by what committing would do.
    pub by_action: KgsImportActionCountArray,
    /// How many items the vault already has.
    pub duplicates: u32,
    /// 0 or 1: built against the open vault.
    pub vault_aware: u8,
    /// One row per item.
    pub items: KgsImportItemRowArray,
}

impl KgsImportReport {
    fn new(r: ImportReportView) -> Self {
        Self {
            source: KgsImportFormat::tag(r.source),
            source_name: KgsBuffer::from_string(r.source_name),
            headline: KgsBuffer::from_string(r.headline),
            totals: KgsImportTotals {
                items: r.totals.items,
                fields_mapped: r.totals.fields_mapped,
                fields_preserved: r.totals.fields_preserved,
                fields_dropped: r.totals.fields_dropped,
                history_entries: r.totals.history_entries,
            },
            by_category: KgsImportCategoryCountArray::collect(r.by_category, |c| {
                KgsImportCategoryCount {
                    category: KgsBuffer::from_string(c.category),
                    items: c.items,
                }
            }),
            dropped: KgsDropNoteArray::collect(r.dropped, KgsDropNote::new),
            decisions: KgsImportDecisionArray::collect(r.decisions, |d| KgsImportDecision {
                code: KgsBuffer::from_string(d.code),
                detail: KgsBuffer::from_string(d.detail),
            }),
            by_action: KgsImportActionCountArray::collect(r.by_action, |a| KgsImportActionCount {
                action: KgsImportItemAction::tag(a.action),
                items: a.items,
            }),
            duplicates: r.duplicates,
            vault_aware: u8::from(r.vault_aware),
            items: KgsImportItemRowArray::collect(r.items, KgsImportItemRow::new),
        }
    }
}

impl Release for KgsImportReport {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.source_name.release();
            self.headline.release();
            self.by_category.release();
            self.dropped.release();
            self.decisions.release();
            self.by_action.release();
            self.items.release();
        }
    }
}

/// [`ImportOutcomeView`]. Free with [`kgs_import_outcome_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsImportOutcome {
    /// Items added.
    pub created: u32,
    /// Items overwritten in place.
    pub updated: u32,
    /// Items left alone.
    pub skipped: u32,
    /// Items added beside an existing one.
    pub kept_both: u32,
    /// Retired values added. A count.
    pub history_added: u32,
    /// Names of the logical vaults that had to be created.
    pub vaults_created: KgsBufferArray,
    /// One line for the result pane.
    pub headline: KgsBuffer,
    /// The preview, as it stood when the decision was made.
    pub report: KgsImportReport,
}

impl KgsImportOutcome {
    fn new(o: ImportOutcomeView) -> Self {
        Self {
            created: o.created,
            updated: o.updated,
            skipped: o.skipped,
            kept_both: o.kept_both,
            history_added: o.history_added,
            vaults_created: KgsBufferArray::strings(o.vaults_created),
            headline: KgsBuffer::from_string(o.headline),
            report: KgsImportReport::new(o.report),
        }
    }
}

impl Release for KgsImportOutcome {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe {
            self.vaults_created.release();
            self.headline.release();
            self.report.release();
        }
    }
}

/// [`ShredOutcomeView`]. Free with [`kgs_shred_outcome_free`].
#[repr(C)]
#[derive(Debug)]
pub struct KgsShredOutcome {
    /// 0 or 1: the bytes were overwritten and the write reached the device.
    pub overwritten: u8,
    /// 0 or 1: the directory entry is gone.
    pub removed: u8,
    /// The sentence to show underneath.
    pub caveat: KgsBuffer,
}

impl KgsShredOutcome {
    fn new(o: ShredOutcomeView) -> Self {
        Self {
            overwritten: u8::from(o.overwritten),
            removed: u8::from(o.removed),
            caveat: KgsBuffer::from_string(o.caveat),
        }
    }
}

impl Release for KgsShredOutcome {
    unsafe fn release(&mut self) {
        // SAFETY: forwarded to the caller.
        unsafe { self.caveat.release() };
    }
}

// -------------------------------------------------------------------------------------------
// Free functions
// -------------------------------------------------------------------------------------------

/// [`crate::import_formats`].
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_import_formats(
    out: *mut KgsImportFormatInfoArray,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsImportFormatInfoArray::collect(
                crate::import_formats(),
                KgsImportFormatInfo::new,
            ));
            Ok(())
        })
    }
}

/// [`crate::shred_source_file`]. Best effort, not secure erase: show [`kgs_shred_caveat`] first.
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_shred_source_file(
    path: KgsSlice,
    out: *mut KgsShredOutcome,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsShredOutcome::new(crate::shred_source_file(
                path.string()?,
            )?));
            Ok(())
        })
    }
}

/// [`crate::shred_caveat`].
///
/// # Safety
///
/// Module rules.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_shred_caveat(out: *mut KgsBuffer, error: *mut KgsBuffer) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsBuffer::from_string(crate::shred_caveat()));
            Ok(())
        })
    }
}

// -------------------------------------------------------------------------------------------
// The session's import methods
// -------------------------------------------------------------------------------------------

/// [`crate::VaultSession::import_preview`]: parse `path` into a plan and hand back a handle to
/// it. `format` is an optional [`KgsImportFormat`] tag; absent lets the parser be chosen from the
/// file. Free the handle with [`kgs_import_plan_free`].
///
/// # Safety
///
/// Module rules; `session` a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_import_preview(
    session: *const KgsSession,
    path: KgsSlice,
    format: KgsOptU32,
    out: *mut *mut KgsImportPlan,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let format = format.option().map(KgsImportFormat::parse).transpose()?;
            let plan = live(session)?.import_preview(path.string()?, format)?;
            out.write(Box::into_raw(Box::new(KgsImportPlan { plan })));
            Ok(())
        })
    }
}

/// [`crate::VaultSession::import_preview_against`], under a [`KgsDuplicatePolicy`] tag.
///
/// # Safety
///
/// Module rules; `session` and `plan` live handles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_import_preview_against(
    session: *const KgsSession,
    plan: *const KgsImportPlan,
    policy: u32,
    out: *mut KgsImportReport,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let plan = Arc::clone(live_plan(plan)?);
            let report =
                live(session)?.import_preview_against(plan, KgsDuplicatePolicy::parse(policy)?)?;
            out.write(KgsImportReport::new(report));
            Ok(())
        })
    }
}

/// [`crate::VaultSession::import_commit`]. Spends the plan; the handle stays valid (and must
/// still be freed) but every later use of it is [`KgsStatus::Invalid`].
///
/// # Safety
///
/// Module rules; `session` and `plan` live handles.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_session_import_commit(
    session: *const KgsSession,
    plan: *const KgsImportPlan,
    policy: u32,
    target_vault: KgsOptSlice,
    out: *mut KgsImportOutcome,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            let plan = Arc::clone(live_plan(plan)?);
            let outcome = live(session)?.import_commit(
                plan,
                KgsDuplicatePolicy::parse(policy)?,
                target_vault.string()?,
            )?;
            out.write(KgsImportOutcome::new(outcome));
            Ok(())
        })
    }
}

// -------------------------------------------------------------------------------------------
// The plan handle
// -------------------------------------------------------------------------------------------

/// [`crate::ImportPlanHandle::report`]: the vault-less preview.
///
/// # Safety
///
/// Module rules; `plan` a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_import_plan_report(
    plan: *const KgsImportPlan,
    out: *mut KgsImportReport,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsImportReport::new(live_plan(plan)?.report()?));
            Ok(())
        })
    }
}

/// [`crate::ImportPlanHandle::source_path`].
///
/// # Safety
///
/// Module rules; `plan` a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_import_plan_source_path(
    plan: *const KgsImportPlan,
    out: *mut KgsBuffer,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(KgsBuffer::from_string(live_plan(plan)?.source_path()));
            Ok(())
        })
    }
}

/// [`crate::ImportPlanHandle::is_spent`]. `out` is 0 or 1.
///
/// # Safety
///
/// Module rules; `plan` a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_import_plan_is_spent(
    plan: *const KgsImportPlan,
    out: *mut u8,
    error: *mut KgsBuffer,
) -> KgsStatus {
    // SAFETY: every pointer is used within this call, per the caller's promise.
    unsafe {
        call(error, || {
            let out = slot(out)?;
            out.write(u8::from(live_plan(plan)?.is_spent()));
            Ok(())
        })
    }
}

/// Release the caller's reference to a plan. The parsed values die with the last one.
///
/// # Safety
///
/// `plan` must be null or a pointer from [`kgs_session_import_preview`] that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_import_plan_free(plan: *mut KgsImportPlan) {
    if !plan.is_null() {
        // SAFETY: a pointer `kgs_session_import_preview` boxed, freed exactly once — the caller's
        // promise.
        drop(unsafe { Box::from_raw(plan) });
    }
}

// -------------------------------------------------------------------------------------------
// Frees
// -------------------------------------------------------------------------------------------

/// Free a [`KgsImportFormatInfoArray`].
///
/// # Safety
///
/// `list` must be null, or point to a record this library wrote (or a zeroed one), not modified
/// since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_import_format_info_array_free(list: *mut KgsImportFormatInfoArray) {
    // SAFETY: forwarded to the caller.
    unsafe { free(list) }
}

/// Free a [`KgsImportReport`] and everything in it.
///
/// # Safety
///
/// As [`kgs_import_format_info_array_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_import_report_free(report: *mut KgsImportReport) {
    // SAFETY: forwarded to the caller.
    unsafe { free(report) }
}

/// Free a [`KgsImportOutcome`] and everything in it.
///
/// # Safety
///
/// As [`kgs_import_format_info_array_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_import_outcome_free(outcome: *mut KgsImportOutcome) {
    // SAFETY: forwarded to the caller.
    unsafe { free(outcome) }
}

/// Free a [`KgsShredOutcome`].
///
/// # Safety
///
/// As [`kgs_import_format_info_array_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kgs_shred_outcome_free(outcome: *mut KgsShredOutcome) {
    // SAFETY: forwarded to the caller.
    unsafe { free(outcome) }
}
