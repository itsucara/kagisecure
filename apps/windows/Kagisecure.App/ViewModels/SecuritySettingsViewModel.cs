using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// Security › Windows Hello (the macOS Settings › Touch ID section): turn Windows Hello unlock on
/// or off for the unlocked vault, say plainly what it is and is not (W-1), and show the state of
/// the two listeners — which, as on macOS, always run while the vault is unlocked; there is no
/// switch for them.
/// </summary>
public sealed partial class SecuritySettingsViewModel : ObservableObject
{
    private readonly WindowsHelloService hello;
    private readonly AgentHostService host;
    private bool isBusy;
    private string? message;
    private bool isHelloEnabled;
    private string? otherSlotWarning;

    public SecuritySettingsViewModel(WindowsHelloService hello, AgentHostService host)
    {
        this.hello = hello;
        this.host = host;
        hello.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(WindowsHelloService.Availability))
            {
                OnPropertyChanged(nameof(IsHelloAvailable));
                OnPropertyChanged(nameof(AvailabilityText));
                SetHelloCommand.NotifyCanExecuteChanged();
            }
            else if (e.PropertyName is nameof(WindowsHelloService.NeedsReEnroll))
            {
                OnPropertyChanged(nameof(NeedsReEnroll));
            }
        };
        host.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(AgentHostService.AgentStatus) or nameof(AgentHostService.ExtensionStatus)
                or nameof(AgentHostService.StartupError) or nameof(AgentHostService.ExtensionStartupError))
            {
                OnPropertyChanged(nameof(AgentListenerText));
                OnPropertyChanged(nameof(ExtensionListenerText));
            }
        };
        ReadState();
    }

    /// <summary>The W-1 notice, verbatim.</summary>
    public string ScopeNotice => WindowsHelloService.ScopeNotice;

    public bool IsHelloAvailable => hello.Availability.Available;

    public string AvailabilityText => hello.Availability switch
    {
        { Available: true } => "Windows Hello is set up on this PC, with a TPM.",
        { Reason: { } why } => $"Windows Hello is unavailable: {why}",
        _ => "Checking Windows Hello…",
    };

    /// <summary>Whether this vault unlocks with Windows Hello. Shown on the switch; changed only through <see cref="SetHelloCommand"/>.</summary>
    public bool IsHelloEnabled
    {
        get => isHelloEnabled;
        private set => SetProperty(ref isHelloEnabled, value);
    }

    /// <summary>An unlock that stopped working and wants enrolling again.</summary>
    public bool NeedsReEnroll => hello.NeedsReEnroll;

    /// <summary>
    /// When the vault already has a platform slot that is not this PC's Windows Hello (a Mac's
    /// Touch ID, say): turning Hello on replaces it — v1 keeps one platform slot per vault.
    /// </summary>
    public string? OtherSlotWarning
    {
        get => otherSlotWarning;
        private set => SetProperty(ref otherSlotWarning, value);
    }

    public bool IsBusy
    {
        get => isBusy;
        private set
        {
            if (SetProperty(ref isBusy, value))
            {
                SetHelloCommand.NotifyCanExecuteChanged();
                ReEnrollCommand.NotifyCanExecuteChanged();
            }
        }
    }

    /// <summary>The last result, in a sentence.</summary>
    public string? Message
    {
        get => message;
        private set => SetProperty(ref message, value);
    }

    public string AgentListenerText => host.StartupError is { } error
        ? $"Agents cannot reach this app: {error}"
        : host.AgentStatus.Running ? $"Serving agents on {host.AgentStatus.Endpoint}" : "Not serving agents (the vault is locked).";

    public string ExtensionListenerText => host.ExtensionStartupError is { } error
        ? $"The browser extension cannot reach this app: {error}"
        : host.ExtensionStatus.Running ? $"Listening for browsers on {host.ExtensionStatus.Endpoint}" : "Not listening for browsers (the vault is locked).";

    /// <summary>Check availability and read the vault's slot. Never prompts.</summary>
    [RelayCommand]
    private async Task RefreshAsync()
    {
        await hello.RefreshAvailabilityAsync().ConfigureAwait(true);
        ReadState();
    }

    private bool CanSetHello => !IsBusy;

    /// <summary>Turn Windows Hello on (two Hello prompts: create the key, then sign) or off.</summary>
    [RelayCommand(CanExecute = nameof(CanSetHello))]
    private async Task SetHelloAsync(bool enable)
    {
        if (enable && ReplacementNeedsConfirmation && !ReplacementConfirmed)
        {
            // The page asks first (a dialog naming what would be replaced) and sets
            // ReplacementConfirmed; without that, overwriting another device's unlock is refused.
            Message = "Confirm replacing the other device's unlock first.";
            OnPropertyChanged(nameof(IsHelloEnabled));
            return;
        }

        IsBusy = true;
        Message = null;
        try
        {
            HelloResult result = enable ? await hello.EnableAsync().ConfigureAwait(true) : await hello.DisableAsync().ConfigureAwait(true);
            Message = result.Status switch
            {
                HelloUnlockStatus.Unlocked => "Windows Hello now unlocks this vault on this PC.",
                HelloUnlockStatus.NotEnrolled => "Windows Hello no longer unlocks this vault. Its key and secret were deleted from this PC.",
                HelloUnlockStatus.Cancelled => "Cancelled. Nothing changed.",
                _ => result.Message ?? "That did not work. Nothing changed.",
            };
        }
        finally
        {
            ReplacementConfirmed = false;
            ReadState();
            // Push the real state back to the switch even when nothing changed, so a switch the user
            // flipped does not stay flipped after a cancel.
            OnPropertyChanged(nameof(IsHelloEnabled));
            IsBusy = false;
        }
    }

    private bool CanReEnroll => !IsBusy;

    [RelayCommand(CanExecute = nameof(CanReEnroll))]
    private Task ReEnrollAsync() => SetHelloAsync(true);

    /// <summary>What the vault's platform slot is now, as far as this PC can tell.</summary>
    public PlatformSlotKind SlotKind { get; private set; }

    /// <summary>
    /// Turning Hello on would overwrite another device's unlock (a Mac's Touch ID, Windows Hello on
    /// another PC or profile, or one this app does not recognise): the page must ask first.
    /// </summary>
    public bool ReplacementNeedsConfirmation => SlotKind is PlatformSlotKind.MacTouchId or PlatformSlotKind.OtherWindowsHello or PlatformSlotKind.Unknown;

    /// <summary>Set by the page once the user has confirmed the replacement; consumed by the next enable.</summary>
    public bool ReplacementConfirmed { get; set; }

    /// <summary>A line describing the vault's current device unlock, for the page.</summary>
    public string SlotDescription => SlotKind switch
    {
        PlatformSlotKind.None => "This vault has no device unlock. Only the master password (and the recovery code) open it.",
        PlatformSlotKind.ThisPc => "This vault unlocks with Windows Hello on this PC.",
        PlatformSlotKind.OtherWindowsHello => "This vault has a Windows Hello unlock from another PC or Windows profile (or an older version of this app). It cannot be used here.",
        PlatformSlotKind.MacTouchId => "This vault has a Touch ID unlock from a Mac.",
        _ => "This vault has a device unlock this app does not recognise.",
    };

    private void ReadState()
    {
        string? slot = hello.CurrentSlotId();
        SlotKind = hello.Classify(slot);
        IsHelloEnabled = SlotKind == PlatformSlotKind.ThisPc;
        OtherSlotWarning = ReplacementNeedsConfirmation
            ? $"{SlotDescription} A vault keeps one device unlock, so turning Windows Hello on here replaces it; that device then needs the master password."
            : null;
        OnPropertyChanged(nameof(SlotKind));
        OnPropertyChanged(nameof(SlotDescription));
        OnPropertyChanged(nameof(ReplacementNeedsConfirmation));
        OnPropertyChanged(nameof(NeedsReEnroll));
    }
}
