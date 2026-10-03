using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// The "write this down" interstitial after vault creation (ui-spec.md §12,
/// accessibility ids <c>ks.recoveryCode.*</c>): the code is shown exactly once — the core never
/// hands it back again (<see cref="VaultSession.TakeRecoveryCode"/> on the Interop side) — so this
/// screen requires an explicit acknowledgement before the shell is reachable.
/// </summary>
public sealed partial class RecoveryCodeViewModel : ObservableObject
{
    private readonly IClipboardService clipboardService;

    public RecoveryCodeViewModel(IClipboardService clipboardService, string recoveryCode)
    {
        this.clipboardService = clipboardService;
        RecoveryCode = recoveryCode;
    }

    public string RecoveryCode { get; }

    [ObservableProperty]
    private bool acknowledged;

    [ObservableProperty]
    private string? copiedNotice;

    /// <summary>Whether "Done" may be pressed. A plain pass-through of <see cref="Acknowledged"/>, kept as its own
    /// property (rather than binding <see cref="Acknowledged"/> directly in XAML) so the "what enables Done" rule
    /// has one place to grow if it ever needs more than the checkbox.</summary>
    public bool CanContinue => Acknowledged;

    partial void OnAcknowledgedChanged(bool value) => OnPropertyChanged(nameof(CanContinue));

    [RelayCommand]
    private void Copy()
    {
        clipboardService.CopySecret(RecoveryCode, "Recovery code");
        CopiedNotice = $"Copied — clears in {clipboardService.ClearAfterSeconds}s";
    }
}
