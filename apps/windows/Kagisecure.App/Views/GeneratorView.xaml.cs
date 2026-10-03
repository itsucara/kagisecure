using Kagisecure.App.Services;
using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml.Controls;

namespace Kagisecure.App.Views;

/// <summary>
/// The password generator sheet (ui-spec.md §8), hosted in a <see cref="Flyout"/> from
/// <see cref="ShellPage"/>'s toolbar rather than a full page — closer to 1Password 8's generator
/// panel than a navigation destination.
/// </summary>
public sealed partial class GeneratorView : UserControl
{
    public GeneratorViewModel ViewModel { get; }

    public GeneratorView(IVaultService vaultService, IClipboardService clipboardService)
    {
        ViewModel = new GeneratorViewModel(vaultService, clipboardService);
        InitializeComponent();
    }
}
