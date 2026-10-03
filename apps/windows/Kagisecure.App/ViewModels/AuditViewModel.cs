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

/// <summary>
/// The audit viewer (mcp-server.md §6, ui-spec.md §10.4 <c>ks.audit.*</c>): every recorded call,
/// newest first, filterable by outcome/actor/tool and a free-text query. Denials are kept in the
/// default filter deliberately — a burst of them is the only evidence a user gets that something
/// tried an exfiltration.
/// </summary>
public sealed partial class AuditViewModel : ObservableObject
{
    private const uint PageSize = 500;

    /// <summary>mcp-server.md's two M6 tool kinds, called out by name in the Tool filter rather than left to free text.</summary>
    public const string FillCredentialTool = "fill_credential";
    public const string TotpCodeTool = "totp_code";

    private readonly IVaultService vaultService;
    private IReadOnlyList<AuditRow> allRows = Array.Empty<AuditRow>();

    public AuditViewModel(IVaultService vaultService)
    {
        this.vaultService = vaultService;
        Rows = new ObservableCollection<AuditRow>();
        _ = RefreshAsync();
    }

    public ObservableCollection<AuditRow> Rows { get; }

    [ObservableProperty]
    private string outcomeFilter = "all";

    [ObservableProperty]
    private string actorFilter = "all";

    [ObservableProperty]
    private string toolFilter = "all";

    [ObservableProperty]
    private string query = string.Empty;

    [ObservableProperty]
    private bool auditIntact = true;

    [ObservableProperty]
    private uint total;

    [ObservableProperty]
    private uint unsavedEntries;

    [ObservableProperty]
    private string? saveError;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool isLoading;

    public bool IsEmpty => Rows.Count == 0;

    public string ChainStateText => AuditIntact
        ? $"Hash chain intact — {Total} entries, names only, never values."
        : "The hash chain does not verify. Entries may have been dropped or reordered.";

    public string? SaveWarningText
    {
        get
        {
            if (UnsavedEntries == 0)
            {
                return null;
            }

            string subject = UnsavedEntries == 1 ? "1 audit entry is" : $"{UnsavedEntries} audit entries are";
            return SaveError is { } reason
                ? $"{subject} not saved to disk yet — the last save failed: {reason}"
                : $"{subject} not saved to disk yet.";
        }
    }

    partial void OnOutcomeFilterChanged(string value) => ApplyFilter();

    partial void OnActorFilterChanged(string value) => ApplyFilter();

    partial void OnToolFilterChanged(string value) => ApplyFilter();

    partial void OnQueryChanged(string value) => ApplyFilter();

    [RelayCommand]
    private async Task RefreshAsync()
    {
        IsLoading = true;
        ErrorMessage = null;
        try
        {
            allRows = await vaultService.AuditPageAsync(PageSize, 0).ConfigureAwait(true);
            Total = await vaultService.AuditCountAsync().ConfigureAwait(true);
            AuditIntact = await vaultService.AuditIntactAsync().ConfigureAwait(true);
            AuditDurability durability = await vaultService.AuditDurabilityAsync().ConfigureAwait(true);
            UnsavedEntries = durability.UnsavedEntries;
            SaveError = durability.LastError;
            ApplyFilter();
        }
        catch (KagisecureException ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsLoading = false;
        }

        OnPropertyChanged(nameof(ChainStateText));
        OnPropertyChanged(nameof(SaveWarningText));
    }

    private void ApplyFilter()
    {
        Rows.Clear();
        foreach (AuditRow row in FilterRows(allRows, OutcomeFilter, ActorFilter, ToolFilter, Query))
        {
            Rows.Add(row);
        }

        OnPropertyChanged(nameof(IsEmpty));
    }

    /// <summary>The filter logic itself, free of the view model so it is directly testable (mirrors the macOS app's <c>AuditView.filteredRows</c>).</summary>
    public static IEnumerable<AuditRow> FilterRows(
        IReadOnlyList<AuditRow> rows, string outcome, string actor, string tool, string query)
    {
        string needle = query.Trim().ToLowerInvariant();
        return rows.Where(row =>
            (outcome == "all" || string.Equals(row.Outcome, outcome, StringComparison.OrdinalIgnoreCase)) &&
            (actor == "all" || ActorMatches(row.Actor, actor)) &&
            (tool == "all" || (tool == "other" ? row.Tool != FillCredentialTool && row.Tool != TotpCodeTool : row.Tool == tool)) &&
            (needle.Length == 0 || Matches(row, needle)));
    }

    /// <summary>
    /// Whether an audit row's actor belongs under the caller filter <paramref name="actor"/>.
    /// Agents are a prefix match: every agent actor starts with <c>mcp</c>, and an agent fill's
    /// carries the agent's name, pid and browser after it (ADR-0036, implementation decision 7).
    /// Every other filter is exact.
    /// </summary>
    public static bool ActorMatches(string rowActor, string actor) =>
        actor == "mcp"
            ? rowActor.StartsWith("mcp", StringComparison.OrdinalIgnoreCase)
            : string.Equals(rowActor, actor, StringComparison.OrdinalIgnoreCase);

    private static bool Matches(AuditRow row, string needle) =>
        row.Tool.ToLowerInvariant().Contains(needle) ||
        row.Variables.Any(v => v.ToLowerInvariant().Contains(needle)) ||
        (row.TargetPath?.ToLowerInvariant().Contains(needle) ?? false) ||
        (row.Detail?.ToLowerInvariant().Contains(needle) ?? false);
}
