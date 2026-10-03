using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// Forces a new master password right after a recovery-code unlock (ui-spec.md §6.1: "After
/// unlocking this way you will be asked to set a new master password"), before the shell is
/// reachable — <see cref="IVaultService.RequiresMasterPasswordChange"/> is the core's own rule
/// (<c>VaultSession.UnlockedBy == RecoveryCode</c>), not a Windows-only addition.
/// </summary>
public sealed partial class ForceChangePasswordViewModel : ObservableObject
{
    private readonly IVaultService vaultService;

    public ForceChangePasswordViewModel(IVaultService vaultService)
    {
        this.vaultService = vaultService;
    }

    [ObservableProperty]
    private string newPassword = string.Empty;

    [ObservableProperty]
    private string confirmPassword = string.Empty;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool isBusy;

    public event EventHandler? PasswordChanged;

    public bool CanSave => !IsBusy && NewPassword.Length > 0 && NewPassword == ConfirmPassword;

    [RelayCommand(CanExecute = nameof(CanSave))]
    private async Task SaveAsync()
    {
        if (NewPassword != ConfirmPassword)
        {
            ErrorMessage = "Passwords don't match.";
            return;
        }

        IsBusy = true;
        ErrorMessage = null;
        try
        {
            await vaultService.ChangeMasterPasswordAsync(NewPassword).ConfigureAwait(true);
            NewPassword = string.Empty;
            ConfirmPassword = string.Empty;
            PasswordChanged?.Invoke(this, EventArgs.Empty);
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

    partial void OnIsBusyChanged(bool value) => SaveCommand.NotifyCanExecuteChanged();

    partial void OnNewPasswordChanged(string value) => SaveCommand.NotifyCanExecuteChanged();

    partial void OnConfirmPasswordChanged(string value) => SaveCommand.NotifyCanExecuteChanged();
}
