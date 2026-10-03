using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// Settings (ui-spec.md §6.2/§6.3/§7, <c>ks.settings.*</c>): auto-lock timeout, lock on minimize,
/// clipboard clear timeout, and the vault pane's audit-durability warning
/// (<see cref="IVaultService.AuditDurabilityAsync"/>) — kept minimal (no tabs, no Touch-ID/Quick-
/// Access sections, which are out of this Windows pass's scope) but every value here is real and
/// persisted, not a placeholder.
/// </summary>
public sealed partial class SettingsViewModel : ObservableObject
{
    /// <summary>ui-spec.md §6.2's auto-lock picker choices, 0 meaning "never".</summary>
    public static readonly IReadOnlyList<int> AutoLockChoices = new[] { 1, 5, 10, 30, 60, 0 };

    /// <summary>Matches the macOS app's clipboard-clear choices (ADR-0017), 0 meaning "never".</summary>
    public static readonly IReadOnlyList<int> ClipboardChoices = new[] { 15, 30, 60, 120, 300, 0 };

    private readonly IVaultService vaultService;
    private readonly IClipboardService clipboardService;
    private readonly ISettingsService settingsService;

    public SettingsViewModel(IVaultService vaultService, IClipboardService clipboardService, ISettingsService settingsService)
    {
        this.vaultService = vaultService;
        this.clipboardService = clipboardService;
        this.settingsService = settingsService;

        autoLockIdleMinutes = settingsService.AutoLockIdleMinutes;
        lockOnMinimize = settingsService.LockOnMinimize;
        clipboardClearSeconds = settingsService.ClipboardClearSeconds;
        vaultPath = vaultService.VaultFilePath;

        _ = LoadAuditStateAsync();
    }

    public IReadOnlyList<int> AutoLockOptions => AutoLockChoices;

    public IReadOnlyList<int> ClipboardOptions => ClipboardChoices;

    [ObservableProperty]
    private int autoLockIdleMinutes;

    [ObservableProperty]
    private bool lockOnMinimize;

    [ObservableProperty]
    private int clipboardClearSeconds;

    [ObservableProperty]
    private string vaultPath;

    [ObservableProperty]
    private string auditStateText = string.Empty;

    /// <summary>Shown only when a save has been failing (ui-spec.md's <c>ks.audit.saveState</c> — the same rule, surfaced here too since Settings is where a user checks vault health).</summary>
    [ObservableProperty]
    private string? auditSaveWarning;

    [ObservableProperty]
    private string wordlistText = "EFF long list";

    partial void OnAutoLockIdleMinutesChanged(int value) => settingsService.AutoLockIdleMinutes = value;

    partial void OnLockOnMinimizeChanged(bool value) => settingsService.LockOnMinimize = value;

    partial void OnClipboardClearSecondsChanged(int value)
    {
        settingsService.ClipboardClearSeconds = value;
        clipboardService.ClearAfterSeconds = value;
    }

    [RelayCommand]
    private async Task RefreshAuditStateAsync() => await LoadAuditStateAsync().ConfigureAwait(true);

    private async Task LoadAuditStateAsync()
    {
        try
        {
            bool intact = await vaultService.AuditIntactAsync().ConfigureAwait(true);
            AuditDurability durability = await vaultService.AuditDurabilityAsync().ConfigureAwait(true);
            AuditStateText = intact ? "Chain intact" : "Chain broken";
            if (durability.UnsavedEntries > 0)
            {
                string subject = durability.UnsavedEntries == 1 ? "1 audit entry is" : $"{durability.UnsavedEntries} audit entries are";
                AuditSaveWarning = durability.LastError is { } reason
                    ? $"{subject} not saved to disk yet — the last save failed: {reason}"
                    : $"{subject} not saved to disk yet.";
            }
            else
            {
                AuditSaveWarning = null;
            }

            WordlistText = $"EFF long list — {vaultService.GeneratorLimits().WordlistSize} words";
        }
        catch (KagisecureException)
        {
            AuditStateText = "Locked";
            AuditSaveWarning = null;
        }
    }
}
