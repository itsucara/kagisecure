using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>Lock screen: master-password unlock (ui-spec.md §6.1, minus the Touch-ID-specific parts).</summary>
public sealed partial class LockViewModel : ObservableObject
{
    private readonly IVaultService vaultService;

    public LockViewModel(IVaultService vaultService)
    {
        this.vaultService = vaultService;
        VaultPath = vaultService.DefaultVaultPath;
    }

    [ObservableProperty]
    private string vaultPath;

    [ObservableProperty]
    private string masterPassword = string.Empty;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool isBusy;

    public event EventHandler? Unlocked;

    public bool CanUnlock => !IsBusy && MasterPassword.Length > 0;

    [RelayCommand(CanExecute = nameof(CanUnlock))]
    private async Task UnlockAsync()
    {
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            await vaultService.UnlockAsync(VaultPath, MasterPassword).ConfigureAwait(true);
            MasterPassword = string.Empty;
            Unlocked?.Invoke(this, EventArgs.Empty);
        }
        catch (KagisecureException.WrongCredential)
        {
            ErrorMessage = "Wrong password.";
        }
        catch (KagisecureException.NotFound)
        {
            ErrorMessage = $"No vault found at {VaultPath}.";
        }
        catch (KagisecureException ex)
        {
            ErrorMessage = ex.Message;
        }
        catch (VaultLockedDuringUnlockException ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    partial void OnIsBusyChanged(bool value)
    {
        UnlockCommand.NotifyCanExecuteChanged();
        UnlockWithRecoveryCommand.NotifyCanExecuteChanged();
        // All three unlock paths share IsBusy; a Hello button left enabled while a password unlock
        // runs would start a second, concurrent unlock (LockViewModel.WindowsHello.cs).
        UnlockWithHelloCommand.NotifyCanExecuteChanged();
    }

    partial void OnMasterPasswordChanged(string value) => UnlockCommand.NotifyCanExecuteChanged();

    // ---------------------------------------------------------------------------------------
    // Recovery code (ui-spec.md §6.1's "Use recovery code instead" disclosure)
    // ---------------------------------------------------------------------------------------

    [ObservableProperty]
    private bool showRecoveryCode;

    [ObservableProperty]
    private string recoveryCode = string.Empty;

    public bool CanUnlockWithRecovery => !IsBusy && RecoveryCode.Length > 0;

    [RelayCommand]
    private void ToggleRecoveryCode() => ShowRecoveryCode = !ShowRecoveryCode;

    [RelayCommand(CanExecute = nameof(CanUnlockWithRecovery))]
    private async Task UnlockWithRecoveryAsync()
    {
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            await vaultService.UnlockWithRecoveryCodeAsync(VaultPath, RecoveryCode).ConfigureAwait(true);
            RecoveryCode = string.Empty;
            // MainWindow's Unlocked handler checks IVaultService.RequiresMasterPasswordChange and
            // routes to the forced-password-change page before the shell, same as this event.
            Unlocked?.Invoke(this, EventArgs.Empty);
        }
        catch (KagisecureException.Invalid)
        {
            ErrorMessage = "That recovery code isn't valid.";
        }
        catch (KagisecureException.WrongCredential)
        {
            ErrorMessage = "That recovery code doesn't open this vault.";
        }
        catch (KagisecureException ex)
        {
            ErrorMessage = ex.Message;
        }
        catch (VaultLockedDuringUnlockException ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    partial void OnRecoveryCodeChanged(string value) => UnlockWithRecoveryCommand.NotifyCanExecuteChanged();
}
