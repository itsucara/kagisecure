using System;
using Kagisecure.App.Services;
using Kagisecure.App.Views;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;

namespace Kagisecure.App;

/// <summary>
/// The single top-level window. Owns navigation between first-run, lock, and the main shell —
/// there is no separate "app shell" abstraction because a WinUI <see cref="Frame"/> already is
/// one. Theme (light/dark) is left at its default, which follows the system setting
/// (<see cref="FrameworkElement.RequestedTheme"/> unset means "inherit"), matching ui-spec.md's
/// "light/dark theme follow system." Pages pull their services from <see cref="App.Instance"/>
/// rather than a navigation parameter (see the doc comment there for why), so <c>Navigate</c> is
/// called with no parameter throughout.
/// </summary>
public sealed partial class MainWindow : Window
{
    private readonly IVaultService vaultService;

    public MainWindow(IVaultService vaultService, IClipboardService clipboardService)
    {
        InitializeComponent();
        Title = "kagisecure";

        // Mica needs DWM composition support, which isn't guaranteed on every host (e.g. some
        // remote-desktop/VM sessions) — MicaController.IsSupported() is the documented guard
        // (Microsoft's own WinUI 3 samples check this before assigning SystemBackdrop).
        if (MicaController.IsSupported())
        {
            SystemBackdrop = new MicaBackdrop();
        }

        this.vaultService = vaultService;

        vaultService.Unlocked += OnVaultUnlocked;
        vaultService.Locked += OnVaultLocked;

        NavigateToInitialPage();
    }

    private void NavigateToInitialPage()
    {
        if (vaultService.VaultFileExists(vaultService.DefaultVaultPath))
        {
            RootFrame.Navigate(typeof(LockPage));
        }
        else
        {
            RootFrame.Navigate(typeof(FirstRunPage));
        }
    }

    private void OnVaultUnlocked(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(() =>
        {
            // ui-spec.md §12's recovery-code interstitial ("write this down") comes first, right
            // after vault creation, before the shell is ever shown. A recovery-code *unlock*
            // (lock screen) instead requires a new master password before the shell — the core's
            // own rule (VaultSession.UnlockedBy == RecoveryCode), not a Windows-only one.
            if (vaultService.TakePendingRecoveryCode() is { } code)
            {
                RootFrame.Navigate(typeof(RecoveryCodePage), code);
            }
            else if (vaultService.RequiresMasterPasswordChange)
            {
                RootFrame.Navigate(typeof(ForceChangePasswordPage));
            }
            else
            {
                RootFrame.Navigate(typeof(ShellPage));
            }
        });

    private void OnVaultLocked(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(() => RootFrame.Navigate(typeof(LockPage)));

    private void OnLockAccelerator(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        vaultService.Lock();
        args.Handled = true;
    }
}
