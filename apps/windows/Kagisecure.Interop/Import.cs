using System;
using System.Collections.Generic;
using Kagisecure.Interop.Native;
using static Kagisecure.Interop.Native.Marshalling;

namespace Kagisecure.Interop;

/// <summary>Which export format a file is, as <c>--format</c> names them.</summary>
public enum ImportFormat : uint
{
    /// <summary>1Password's own archive.</summary>
    OnePux = (uint)KgsImportFormat.OnePux,

    /// <summary>Apple Passwords / iCloud Keychain CSV.</summary>
    AppleCsv = (uint)KgsImportFormat.AppleCsv,

    /// <summary>Chrome, Edge or another Chromium browser's CSV.</summary>
    ChromiumCsv = (uint)KgsImportFormat.ChromiumCsv,

    /// <summary>Firefox's CSV.</summary>
    FirefoxCsv = (uint)KgsImportFormat.FirefoxCsv,

    /// <summary>1Password's CSV.</summary>
    OnePasswordCsv = (uint)KgsImportFormat.OnePasswordCsv,
}

/// <summary>What to do with an item the vault already has.</summary>
public enum DuplicatePolicy : uint
{
    /// <summary>Leave the existing item alone. The default.</summary>
    Skip = (uint)KgsDuplicatePolicy.Skip,

    /// <summary>Overwrite what the source carries and keep what only this vault knows.</summary>
    Update = (uint)KgsDuplicatePolicy.Update,

    /// <summary>Import it as a second item, with a dated title.</summary>
    KeepBoth = (uint)KgsDuplicatePolicy.KeepBoth,
}

/// <summary>What committing would do, or did, to one item.</summary>
public enum ImportItemAction : uint
{
    /// <summary>Add it.</summary>
    Create = (uint)KgsImportItemAction.Create,

    /// <summary>Overwrite the matching item's source-carried parts.</summary>
    Update = (uint)KgsImportItemAction.Update,

    /// <summary>Leave the matching item alone.</summary>
    Skip = (uint)KgsImportItemAction.Skip,

    /// <summary>Add it beside the matching item.</summary>
    KeepBoth = (uint)KgsImportItemAction.KeepBoth,
}

/// <summary>A kind of thing the import cannot bring across.</summary>
public enum ImportDropKind : uint
{
    /// <summary>A file attachment.</summary>
    Attachment = (uint)KgsImportDropKind.Attachment,

    /// <summary>A passkey.</summary>
    Passkey = (uint)KgsImportDropKind.Passkey,

    /// <summary>A password-history entry the parser could not read.</summary>
    PasswordHistory = (uint)KgsImportDropKind.PasswordHistory,

    /// <summary>A Watchtower / breach-report flag.</summary>
    WatchtowerFlag = (uint)KgsImportDropKind.WatchtowerFlag,

    /// <summary>A form field the source carried with nothing in it.</summary>
    EmptyFormField = (uint)KgsImportDropKind.EmptyFormField,

    /// <summary>Something this build does not recognize.</summary>
    UnknownEntry = (uint)KgsImportDropKind.UnknownEntry,
}

/// <summary>One row of the format picker.</summary>
/// <param name="Format">The format.</param>
/// <param name="Id">Its canonical name, as the CLI's <c>--format</c> takes it.</param>
/// <param name="DisplayName">What the picker shows.</param>
public sealed record ImportFormatInfo(ImportFormat Format, string Id, string DisplayName)
{
    internal static ImportFormatInfo From(in KgsImportFormatInfo n) =>
        new((ImportFormat)n.format, Str(n.id), Str(n.display_name));
}

/// <summary>How many of one kind were left behind, and why.</summary>
/// <param name="Kind">What was dropped.</param>
/// <param name="Name">Its short name.</param>
/// <param name="Count">How many.</param>
/// <param name="Explanation">The one line the sheet puts beside the counter.</param>
public sealed record DropNote(ImportDropKind Kind, string Name, uint Count, string Explanation)
{
    internal static DropNote From(in KgsDropNote n) =>
        new((ImportDropKind)n.kind, Str(n.name), n.count, Str(n.explanation));
}

/// <summary>Run-level counts.</summary>
/// <param name="Items">Items in the plan.</param>
/// <param name="FieldsMapped">Fields that will become typed fields.</param>
/// <param name="FieldsPreserved">Things kept only as metadata.</param>
/// <param name="FieldsDropped">Things left behind.</param>
/// <param name="HistoryEntries">Retired values that will be imported. A count, only.</param>
public sealed record ImportTotals(uint Items, uint FieldsMapped, uint FieldsPreserved, uint FieldsDropped, uint HistoryEntries);

/// <summary>Items of one category.</summary>
/// <param name="Category">The category's canonical name.</param>
/// <param name="Items">How many.</param>
public sealed record ImportCategoryCount(string Category, uint Items);

/// <summary>Items that would be handled one way.</summary>
/// <param name="Action">What would happen to them.</param>
/// <param name="Items">How many.</param>
public sealed record ImportActionCount(ImportItemAction Action, uint Items);

/// <summary>A note the parser made about the run as a whole.</summary>
/// <param name="Code">A stable machine-readable code.</param>
/// <param name="Detail">One sentence for a person.</param>
public sealed record ImportDecision(string Code, string Detail);

/// <summary>One row of the per-item table. There is no value column.</summary>
/// <param name="Title">The item's title.</param>
/// <param name="Category">Its category's canonical name.</param>
/// <param name="CategoryWasGuessed">The category was guessed rather than stated by the source.</param>
/// <param name="Vault">The logical vault it is headed for.</param>
/// <param name="Fields">How many fields it brings.</param>
/// <param name="HistoryEntries">How many retired values it brings. A count, only.</param>
/// <param name="Dropped">What is being left behind for this item.</param>
/// <param name="Action">What committing would do; <c>null</c> in a report built without a vault.</param>
public sealed record ImportItemRow(
    string Title,
    string Category,
    bool CategoryWasGuessed,
    string Vault,
    uint Fields,
    uint HistoryEntries,
    ValueList<DropNote> Dropped,
    ImportItemAction? Action)
{
    internal static unsafe ImportItemRow From(in KgsImportItemRow n) => new(
        Str(n.title),
        Str(n.category),
        n.category_was_guessed != 0,
        Str(n.vault),
        n.fields,
        n.history_entries,
        List<KgsDropNote, DropNote>(n.dropped.ptr, n.dropped.len, DropNote.From),
        (ImportItemAction?)n.action.ToNullable());
}

/// <summary>The preview: what an import would do, in names and counts.</summary>
/// <param name="Source">The format that was read.</param>
/// <param name="SourceName">The source file's name — never its directory.</param>
/// <param name="Headline">One line summarising the run.</param>
/// <param name="Totals">Run-level counts.</param>
/// <param name="ByCategory">Item counts by category.</param>
/// <param name="Dropped">Everything left behind.</param>
/// <param name="Decisions">Run-level notes from the parser.</param>
/// <param name="ByAction">Counts by what committing would do; empty without a vault.</param>
/// <param name="Duplicates">How many items the vault already has; see <paramref name="VaultAware"/>.</param>
/// <param name="VaultAware">Whether this report was built against the open vault.</param>
/// <param name="Items">One row per item.</param>
public sealed record ImportReport(
    ImportFormat Source,
    string SourceName,
    string Headline,
    ImportTotals Totals,
    ValueList<ImportCategoryCount> ByCategory,
    ValueList<DropNote> Dropped,
    ValueList<ImportDecision> Decisions,
    ValueList<ImportActionCount> ByAction,
    uint Duplicates,
    bool VaultAware,
    ValueList<ImportItemRow> Items)
{
    internal static unsafe ImportReport From(in KgsImportReport n) => new(
        (ImportFormat)n.source,
        Str(n.source_name),
        Str(n.headline),
        new ImportTotals(
            n.totals.items, n.totals.fields_mapped, n.totals.fields_preserved, n.totals.fields_dropped, n.totals.history_entries),
        List(n.by_category.ptr, n.by_category.len, (in KgsImportCategoryCount c) => new ImportCategoryCount(Str(c.category), c.items)),
        List<KgsDropNote, DropNote>(n.dropped.ptr, n.dropped.len, DropNote.From),
        List(n.decisions.ptr, n.decisions.len, (in KgsImportDecision d) => new ImportDecision(Str(d.code), Str(d.detail))),
        List(n.by_action.ptr, n.by_action.len, (in KgsImportActionCount a) => new ImportActionCount((ImportItemAction)a.action, a.items)),
        n.duplicates,
        n.vault_aware != 0,
        List<KgsImportItemRow, ImportItemRow>(n.items.ptr, n.items.len, ImportItemRow.From));
}

/// <summary>What an import actually did.</summary>
/// <param name="Created">Items added.</param>
/// <param name="Updated">Items overwritten in place.</param>
/// <param name="Skipped">Items left alone because the vault already had them.</param>
/// <param name="KeptBoth">Items added beside an existing one.</param>
/// <param name="HistoryAdded">Retired values added. A count, only.</param>
/// <param name="VaultsCreated">Names of the logical vaults that had to be created.</param>
/// <param name="Headline">One line for the result pane.</param>
/// <param name="Report">The preview, as it stood when the decision was made.</param>
public sealed record ImportOutcome(
    uint Created,
    uint Updated,
    uint Skipped,
    uint KeptBoth,
    uint HistoryAdded,
    ValueList<string> VaultsCreated,
    string Headline,
    ImportReport Report)
{
    internal static ImportOutcome From(in KgsImportOutcome n) => new(
        n.created,
        n.updated,
        n.skipped,
        n.kept_both,
        n.history_added,
        Strings(n.vaults_created),
        Str(n.headline),
        ImportReport.From(n.report));
}

/// <summary>How far <see cref="Importer.ShredSourceFile"/> got, and what must still be said.</summary>
/// <param name="Overwritten">The bytes were overwritten and the write reached the device.</param>
/// <param name="Removed">The directory entry is gone.</param>
/// <param name="Caveat">The sentence to show underneath. Never "securely erased".</param>
public sealed record ShredOutcome(bool Overwritten, bool Removed, string Caveat);

/// <summary>
/// A parsed import, held on the Rust side: the only projection of it C# can ask for is a
/// <see cref="ImportReport"/>, so no imported value ever reaches the managed heap. Dispose it when
/// the sheet closes; the parsed values die with it.
/// </summary>
public sealed unsafe class ImportPlan : IDisposable
{
    internal ImportPlan(ImportPlanHandle handle)
    {
        Handle = handle;
    }

    internal ImportPlanHandle Handle { get; }

    /// <summary>The preview with no vault in sight: every row's action is <c>null</c>.</summary>
    /// <exception cref="KagisecureException.Invalid">The plan has been committed.</exception>
    public ImportReport Report()
    {
        using var p = Handle.Borrow();
        KgsImportReport output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_import_plan_report(p.Ptr, &output, &error), ref error);
            return ImportReport.From(output);
        }
        finally
        {
            NativeMethods.kgs_import_report_free(&output);
        }
    }

    /// <summary>The file this plan was parsed from, in full — what the shred prompt needs.</summary>
    public string SourcePath
    {
        get
        {
            using var p = Handle.Borrow();
            KgsBuffer output = default;
            KgsBuffer error = default;
            Check(NativeMethods.kgs_import_plan_source_path(p.Ptr, &output, &error), ref error);
            return TakeString(ref output);
        }
    }

    /// <summary>Whether this plan has been committed and can no longer be used.</summary>
    public bool IsSpent
    {
        get
        {
            using var p = Handle.Borrow();
            byte output = 0;
            KgsBuffer error = default;
            Check(NativeMethods.kgs_import_plan_is_spent(p.Ptr, &output, &error), ref error);
            return output != 0;
        }
    }

    /// <summary>Release this reference to the plan.</summary>
    public void Dispose() => Handle.Dispose();
}

/// <summary>The parts of import that need no vault.</summary>
public static class Importer
{
    /// <summary>Every format this build can read, in the order the CLI lists them.</summary>
    public static unsafe IReadOnlyList<ImportFormatInfo> Formats()
    {
        EnsureAbi();
        KgsImportFormatInfoArray output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_import_formats(&output, &error), ref error);
            return List<KgsImportFormatInfo, ImportFormatInfo>(output.ptr, output.len, ImportFormatInfo.From);
        }
        finally
        {
            NativeMethods.kgs_import_format_info_array_free(&output);
        }
    }

    /// <summary>
    /// Overwrite, truncate and remove the file an import was read from. Best effort, not secure
    /// erase: show <see cref="ShredCaveat"/> before offering it.
    /// </summary>
    /// <exception cref="KagisecureException.NotFound">No file there.</exception>
    public static unsafe ShredOutcome ShredSourceFile(string path)
    {
        EnsureAbi();
        using var p = new PinnedUtf8(path);
        KgsShredOutcome output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_shred_source_file(p.Slice, &output, &error), ref error);
            return new ShredOutcome(output.overwritten != 0, output.removed != 0, Str(output.caveat));
        }
        finally
        {
            NativeMethods.kgs_shred_outcome_free(&output);
        }
    }

    /// <summary>What the "Delete the source file?" prompt must say before the user agrees.</summary>
    public static unsafe string ShredCaveat()
    {
        EnsureAbi();
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_shred_caveat(&output, &error), ref error);
        return TakeString(ref output);
    }
}
