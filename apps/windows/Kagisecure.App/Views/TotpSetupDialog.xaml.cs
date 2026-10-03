using System;
using Kagisecure.App.Services;
using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml.Controls;
using WinRT.Interop;

namespace Kagisecure.App.Views;

/// <summary>
/// The TOTP setup dialog (ui-spec.md §9), opened from a <c>FieldDraftRowViewModel</c> row in the
/// item editor when its kind is <see cref="Kagisecure.Interop.FieldKind.Totp"/> — see
/// <c>ShellPage.xaml.cs</c>'s <c>OnTotpSetupClicked</c>. Real services (<see cref="ZXingQrCodeReader"/>,
/// <see cref="FileOpenPickerImageSource"/> parented to the app's window, <see cref="ClipboardImageSource"/>)
/// are wired here rather than injected, matching how <c>GeneratorView</c>/<c>ImportPage</c> build
/// their own view models — <c>Kagisecure.App.Tests</c> exercises <see cref="TotpSetupViewModel"/>
/// directly, against fakes, and never constructs this dialog.
/// </summary>
public sealed partial class TotpSetupDialog : ContentDialog
{
    public TotpSetupViewModel ViewModel { get; }

    public TotpSetupDialog(IVaultService vaultService, string existingUri = "")
    {
        IntPtr hwnd = WindowNative.GetWindowHandle(App.CurrentWindow);
        ViewModel = new TotpSetupViewModel(
            vaultService,
            new ZXingQrCodeReader(),
            new FileOpenPickerImageSource(hwnd),
            new ClipboardImageSource(),
            existingUri);
        InitializeComponent();
    }
}
