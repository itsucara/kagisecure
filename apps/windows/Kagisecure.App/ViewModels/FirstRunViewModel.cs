using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// First-run: create a vault (ui-spec.md's macOS flow has no direct equivalent — this is
/// Windows-only setup, adapted from the "create a vault" shape 1Password 8's own first run uses).
/// </summary>
public sealed partial class FirstRunViewModel : ObservableObject
{
    private readonly IVaultService vaultService;

    public FirstRunViewModel(IVaultService vaultService)
    {
        this.vaultService = vaultService;
        VaultPath = vaultService.DefaultVaultPath;
    }

    [ObservableProperty]
    private string vaultPath;

    [ObservableProperty]
    private string vaultName = "Personal";

    [ObservableProperty]
    private string masterPassword = string.Empty;

    [ObservableProperty]
    private string confirmPassword = string.Empty;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool isBusy;

    /// <summary>
    /// The one-time recovery code the core hands back exactly once, right after creation.
    /// <see cref="IVaultService.TakePendingRecoveryCode"/> is what actually drives the "write this
    /// down" interstitial (<see cref="Views.RecoveryCodePage"/>, ui-spec.md §12) — <c>MainWindow</c>
    /// checks it before navigating past <see cref="VaultCreated"/>'s <c>Unlocked</c> event — this
    /// property just keeps the value around for any view that wants it directly.
    /// </summary>
    [ObservableProperty]
    private string? recoveryCode;

    /// <summary>Raised once the vault has been created and unlocked; the shell listens via <see cref="IVaultService.Unlocked"/> instead, but views can use this for one-shot UI feedback.</summary>
    public event EventHandler? VaultCreated;

    partial void OnMasterPasswordChanged(string value) => OnPropertyChanged(nameof(StrengthLabel));

    /// <summary>The master password's strength, from the core's own estimator (never a local guess).</summary>
    public string StrengthLabel =>
        MasterPassword.Length == 0 ? string.Empty : vaultService.PasswordStrength(MasterPassword).Label;

    public bool CanCreate =>
        !IsBusy &&
        !string.IsNullOrWhiteSpace(VaultPath) &&
        !string.IsNullOrWhiteSpace(VaultName) &&
        MasterPassword.Length > 0 &&
        MasterPassword == ConfirmPassword;

    [RelayCommand(CanExecute = nameof(CanCreate))]
    private async Task CreateAsync()
    {
        if (MasterPassword != ConfirmPassword)
        {
            ErrorMessage = "Passwords don't match.";
            return;
        }

        IsBusy = true;
        ErrorMessage = null;
        try
        {
            RecoveryCode = await vaultService.CreateVaultAsync(VaultPath, MasterPassword, VaultName).ConfigureAwait(true);
            VaultCreated?.Invoke(this, EventArgs.Empty);
        }
        catch (KagisecureException.AlreadyExists)
        {
            ErrorMessage = $"There is already a vault at {VaultPath}.";
        }
        catch (KagisecureException ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    partial void OnIsBusyChanged(bool value) => CreateCommand.NotifyCanExecuteChanged();

    partial void OnVaultPathChanged(string value) => CreateCommand.NotifyCanExecuteChanged();

    partial void OnVaultNameChanged(string value) => CreateCommand.NotifyCanExecuteChanged();

    partial void OnConfirmPasswordChanged(string value) => CreateCommand.NotifyCanExecuteChanged();
}
