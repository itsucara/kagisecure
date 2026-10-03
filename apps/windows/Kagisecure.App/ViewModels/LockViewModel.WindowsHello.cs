using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// The lock screen's Windows Hello half (ui-spec.md §6.1, ADR-0004, ADR-0033): an "Unlock with
/// Windows Hello" button when this vault has a Windows Hello slot, beside the password field that
/// is always there.
/// </summary>
public sealed partial class LockViewModel
{
    /// <summary>After this many Hello failures (not cancellations) the button gives way to the password, as Touch ID does after three.</summary>
    public const int MaxHelloFailures = 3;

    private WindowsHelloService? hello;
    private int helloFailures;
    private bool showHelloButton;
    private bool helloButtonEnabled;
    private string? helloNote;

    /// <summary>The lock screen with Windows Hello offered when the vault is enrolled.</summary>
    public LockViewModel(IVaultService vaultService, WindowsHelloService hello)
        : this(vaultService)
    {
        this.hello = hello;
        RefreshHelloState();
    }

    /// <summary>Whether to show "Unlock with Windows Hello" at all: the vault has a Windows Hello slot.</summary>
    public bool ShowHelloButton
    {
        get => showHelloButton;
        private set => SetProperty(ref showHelloButton, value);
    }

    /// <summary>Whether the button can be pressed: Hello is available and has not failed three times.</summary>
    public bool HelloButtonEnabled
    {
        get => helloButtonEnabled;
        private set
        {
            if (SetProperty(ref helloButtonEnabled, value))
            {
                UnlockWithHelloCommand.NotifyCanExecuteChanged();
            }
        }
    }

    /// <summary>Why Hello is not offered or not pressable, in a sentence; <c>null</c> when it is fine.</summary>
    public string? HelloNote
    {
        get => helloNote;
        private set => SetProperty(ref helloNote, value);
    }

    /// <summary>The W-1 notice, for the lock screen's help text.</summary>
    public string HelloScopeNotice => WindowsHelloService.ScopeNotice;

    private bool CanUnlockWithHello => HelloButtonEnabled && !IsBusy;

    /// <summary>Re-read whether the vault is enrolled and whether Hello is available. Never prompts.</summary>
    public async Task RefreshHelloStateAsync()
    {
        if (hello is null)
        {
            return;
        }

        RefreshHelloState();
        if (!ShowHelloButton)
        {
            return;
        }

        HelloAvailability availability = await hello.RefreshAvailabilityAsync().ConfigureAwait(true);
        HelloButtonEnabled = availability.Available && helloFailures < MaxHelloFailures;
        HelloNote = availability.Available ? null : availability.Reason;
    }

    private void RefreshHelloState()
    {
        ShowHelloButton = hello is not null && VaultPath is { Length: > 0 } && hello.IsEnrolledAt(VaultPath);
        HelloButtonEnabled = ShowHelloButton && helloFailures < MaxHelloFailures;
    }

    // No automatic prompt, unlike Touch ID on the Mac (ADR-0033 §5). A Windows Hello prompt that
    // appears by itself trains the user to approve prompts they did not ask for — and a program
    // running as the user can raise a prompt for this app's Hello key and time it to coincide. The
    // only Hello prompt this app shows for unlocking is the one the user just clicked for.

    [RelayCommand(CanExecute = nameof(CanUnlockWithHello))]
    private async Task UnlockWithHelloAsync()
    {
        if (hello is null || IsBusy)
        {
            return;
        }

        IsBusy = true;
        ErrorMessage = null;
        try
        {
            HelloResult result = await hello.UnlockAsync(VaultPath).ConfigureAwait(true);
            switch (result.Status)
            {
                case HelloUnlockStatus.Unlocked:
                    helloFailures = 0;
                    MasterPassword = string.Empty;
                    RaiseUnlocked();
                    break;
                case HelloUnlockStatus.Cancelled:
                    // Not an error: the password field is right there.
                    break;
                case HelloUnlockStatus.NotEnrolled:
                    ShowHelloButton = false;
                    break;
                case HelloUnlockStatus.LockedMeanwhile:
                    // Not a Hello failure: the screen locked or the PC slept while it ran.
                    ErrorMessage = result.Message;
                    break;
                case HelloUnlockStatus.Unavailable:
                    HelloButtonEnabled = false;
                    HelloNote = result.Message ?? "Windows Hello is unavailable. Unlock with your master password.";
                    break;
                case HelloUnlockStatus.NeedsReEnroll:
                    // The slot is dead (key deleted or replaced, secret gone): stop offering an unlock
                    // it cannot perform, and say how to get it back.
                    HelloButtonEnabled = false;
                    ShowHelloButton = false;
                    ErrorMessage = result.Message;
                    break;
                default:
                    helloFailures++;
                    ErrorMessage = result.Message ?? "Windows Hello did not unlock the vault.";
                    if (helloFailures >= MaxHelloFailures)
                    {
                        HelloButtonEnabled = false;
                        HelloNote = "Windows Hello failed three times. Unlock with your master password.";
                    }

                    break;
            }
        }
        finally
        {
            IsBusy = false;
            UnlockWithHelloCommand.NotifyCanExecuteChanged();
        }
    }

    private void RaiseUnlocked() => Unlocked?.Invoke(this, EventArgs.Empty);
}
