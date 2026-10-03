using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>The import wizard's phase, mirroring the macOS <c>ImportModel.phase</c> state machine.</summary>
public enum ImportPhase
{
    PickFile,
    Loading,
    Previewing,
    Committing,
    Done,
    ShredPrompt,
    Finished,
    Failed,
}

/// <summary>One row of the format picker. <see cref="Format"/> <c>null</c> means "detect automatically".</summary>
public sealed record FormatPickerOption(ImportFormat? Format, string DisplayName);

/// <summary>
/// Import wizard (import.md, ui-spec.md §15 <c>ks.import.*</c>): pick a file, preview what would
/// happen (counts, drops, duplicates), choose a duplicate policy and target vault, commit, then
/// offer to shred the source with the honest caveat text — never "securely erased".
/// </summary>
public sealed partial class ImportViewModel : ObservableObject
{
    /// <summary>
    /// Shown under the per-item table: the FFI has no way to change or exclude one item's action
    /// before commit (<c>ImportPlanHandle</c> exposes only <c>report()</c>, <c>source_path()</c>
    /// and <c>is_spent()</c> — see <c>Kagisecure.Interop/Import.cs</c>), so the table is read-only
    /// and says so rather than implying a control that is not there.
    /// </summary>
    public const string ItemDetailNote =
        "This lists exactly what committing will do to every item, decided by the duplicate " +
        "policy above. Individual items cannot be changed or excluded here.";

    /// <summary>Instance-bindable form of <see cref="ItemDetailNote"/>, for x:Bind.</summary>
    public string ItemDetailNoteText => ItemDetailNote;

    private readonly IVaultService vaultService;
    private string? planToken;

    public ImportViewModel(IVaultService vaultService)
    {
        this.vaultService = vaultService;
        Formats = vaultService.ImportFormats();
        FormatOptions = new[] { new FormatPickerOption(null, "Detect automatically") }
            .Concat(Formats.Select(f => new FormatPickerOption(f.Format, f.DisplayName)))
            .ToArray();
        Items = new ObservableCollection<ImportItemRow>();
    }

    public IReadOnlyList<ImportFormatInfo> Formats { get; }

    /// <summary>The format picker's rows: "Detect automatically" first, then every format the build reads.</summary>
    public IReadOnlyList<FormatPickerOption> FormatOptions { get; }

    /// <summary>The option matching <see cref="FormatOverride"/>, for the picker's selection.</summary>
    public FormatPickerOption SelectedFormatOption =>
        FormatOptions.FirstOrDefault(o => o.Format == FormatOverride) ?? FormatOptions[0];

    /// <summary>What the parser actually read the file as, once there is a report — shown next to the picker whether or not it was overridden.</summary>
    public string? DetectedFormatText => Report is { } r
        ? $"Read as {FormatOptions.FirstOrDefault(o => o.Format == r.Source)?.DisplayName ?? r.Source.ToString()}"
        : null;

    [ObservableProperty]
    private ImportPhase phase = ImportPhase.PickFile;

    [ObservableProperty]
    private string? sourcePath;

    [ObservableProperty]
    private ImportFormat? formatOverride;

    [ObservableProperty]
    private ImportReport? report;

    [ObservableProperty]
    private DuplicatePolicy policy = DuplicatePolicy.Skip;

    [ObservableProperty]
    private IReadOnlyList<LogicalVault> vaults = Array.Empty<LogicalVault>();

    /// <summary><c>null</c> follows the source (macOS/ui-spec.md default).</summary>
    [ObservableProperty]
    private string? targetVault;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private ImportOutcome? outcome;

    [ObservableProperty]
    private string shredWarning = string.Empty;

    [ObservableProperty]
    private string? finishedSentence;

    /// <summary>Which action the per-item table shows: "all", "create", "update", "skip" or "keepboth" — mirrors <see cref="Interop.ImportItemAction"/>.</summary>
    [ObservableProperty]
    private string actionFilter = "all";

    /// <summary>The per-item table, filtered by <see cref="ActionFilter"/>. Names, categories and counts only — see <see cref="ItemDetailNote"/>.</summary>
    public ObservableCollection<ImportItemRow> Items { get; }

    public string PolicyExplanation => Policy switch
    {
        DuplicatePolicy.Skip => "Existing items are left exactly as they are. Nothing is overwritten.",
        DuplicatePolicy.Update => "Existing items take the source's fields and keep what only this vault knows — tags, agent visibility. History is merged, not replaced.",
        DuplicatePolicy.KeepBoth => "Existing items are left alone and the imported ones are added beside them, with today's date in the title.",
        _ => string.Empty,
    };

    public bool CanImport => Phase == ImportPhase.Previewing && Report is not null;

    /// <summary>Whether the format picker may be used right now — once a file is loaded and nothing is in flight.</summary>
    public bool CanChangeFormat => SourcePath is not null && Phase is ImportPhase.Previewing or ImportPhase.Failed;

    partial void OnPolicyChanged(DuplicatePolicy value)
    {
        OnPropertyChanged(nameof(PolicyExplanation));
        if (Phase == ImportPhase.Previewing)
        {
            _ = RefreshReportAsync();
        }
    }

    partial void OnPhaseChanged(ImportPhase value) => OnPropertyChanged(nameof(CanChangeFormat));

    partial void OnFormatOverrideChanged(ImportFormat? value) => OnPropertyChanged(nameof(SelectedFormatOption));

    partial void OnActionFilterChanged(string value) => ApplyItemFilter();

    /// <summary>Called by the page once a file has been picked (a file picker is a UI concern, kept out of the view model).</summary>
    public async Task LoadAsync(string path, ImportFormat? format)
    {
        DisposePlan(); // a re-parse (e.g. a format override) must not leak the plan it replaces
        SourcePath = path;
        FormatOverride = format;
        Phase = ImportPhase.Loading;
        ErrorMessage = null;
        try
        {
            (string token, ImportReport initialReport) = await vaultService.ImportPreviewAsync(path, format).ConfigureAwait(true);
            planToken = token;
            Report = initialReport;
            Vaults = await vaultService.VaultsAsync().ConfigureAwait(true);
            await RefreshReportAsync().ConfigureAwait(true);
            ShredWarning = vaultService.ImportShredCaveat();
        }
        catch (KagisecureException ex)
        {
            ErrorMessage = ex.Message;
            Phase = ImportPhase.Failed;
            Report = null; // otherwise the "Read as …" caption keeps describing the last successful parse
        }
    }

    /// <summary>
    /// Re-parse the already-chosen file under a different format — the manual override (import.md
    /// §3, mirroring the macOS sheet's format picker). A no-op with no file chosen yet, or when the
    /// format did not actually change.
    /// </summary>
    public Task ChangeFormatAsync(ImportFormat? format) =>
        SourcePath is null || format == FormatOverride ? Task.CompletedTask : LoadAsync(SourcePath, format);

    private async Task RefreshReportAsync()
    {
        if (planToken is null)
        {
            return;
        }

        try
        {
            Report = await vaultService.ImportPreviewAgainstAsync(planToken, Policy).ConfigureAwait(true);
            Phase = ImportPhase.Previewing;
        }
        catch (KagisecureException ex)
        {
            ErrorMessage = ex.Message;
            Phase = ImportPhase.Failed;
        }

        CommitCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand(CanExecute = nameof(CanImport))]
    private async Task CommitAsync()
    {
        if (planToken is null)
        {
            return;
        }

        Phase = ImportPhase.Committing;
        ErrorMessage = null;
        try
        {
            Outcome = await vaultService.ImportCommitAsync(planToken, Policy, TargetVault).ConfigureAwait(true);
            planToken = null; // ImportCommitAsync spends and disposes the plan either way.
            Phase = ImportPhase.ShredPrompt;
        }
        catch (KagisecureException ex)
        {
            ErrorMessage = ex.Message;
            Phase = ImportPhase.Failed;
        }
    }

    [RelayCommand]
    private async Task ShredSourceAsync()
    {
        if (SourcePath is null)
        {
            return;
        }

        try
        {
            ShredOutcome shredded = await vaultService.ImportShredSourceFileAsync(SourcePath).ConfigureAwait(true);
            FinishedSentence = shredded.Caveat;
        }
        catch (KagisecureException ex)
        {
            FinishedSentence = $"Could not remove the source file: {ex.Message}";
        }
        finally
        {
            Phase = ImportPhase.Finished;
        }
    }

    [RelayCommand]
    private void KeepSource()
    {
        FinishedSentence = "The source file was left where it was.";
        Phase = ImportPhase.Finished;
    }

    [RelayCommand]
    private void Retry()
    {
        DisposePlan();
        Phase = ImportPhase.PickFile;
        Report = null;
        ErrorMessage = null;
    }

    public string DuplicateSentence => Report is not { } r
        ? "Checking this vault for items it already has…"
        : r.Duplicates == 0
            ? "No duplicates — this vault has none of these items yet."
            : $"{r.Duplicates} of these are already in this vault.";

    partial void OnReportChanged(ImportReport? value)
    {
        OnPropertyChanged(nameof(DuplicateSentence));
        OnPropertyChanged(nameof(DetectedFormatText));
        ApplyItemFilter();
    }

    private void ApplyItemFilter()
    {
        Items.Clear();
        if (Report is { } r)
        {
            foreach (ImportItemRow row in FilterItems(r.Items, ActionFilter))
            {
                Items.Add(row);
            }
        }
    }

    /// <summary>
    /// The per-item table's filter logic, free of the view model so it is directly testable
    /// (mirrors <see cref="AuditViewModel.FilterRows"/>). <paramref name="actionFilter"/> is
    /// "all", or the lowercase name of an <see cref="Interop.ImportItemAction"/>; a row whose
    /// action is <c>null</c> (a report built with no vault) never matches a specific filter.
    /// </summary>
    public static IEnumerable<ImportItemRow> FilterItems(IReadOnlyList<ImportItemRow> rows, string actionFilter) =>
        actionFilter == "all" ? rows : rows.Where(row => ActionTag(row.Action) == actionFilter);

    private static string ActionTag(ImportItemAction? action) => action switch
    {
        ImportItemAction.Create => "create",
        ImportItemAction.Update => "update",
        ImportItemAction.Skip => "skip",
        ImportItemAction.KeepBoth => "keepboth",
        _ => string.Empty,
    };

    /// <summary>Release a plan that was never committed. Called when the wizard closes early.</summary>
    public void DisposePlan()
    {
        if (planToken is { } token)
        {
            vaultService.DisposeImportPlan(token);
            planToken = null;
        }
    }
}
