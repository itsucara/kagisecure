using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml.Controls;

namespace Kagisecure.App.Views;

/// <summary>Settings (ui-spec.md §6.2/§6.3/§7): auto-lock, clipboard, vault/audit summary.</summary>
public sealed partial class SettingsPage : Page
{
    public SettingsViewModel ViewModel { get; }

    public SettingsPage()
    {
        ViewModel = new SettingsViewModel(App.Instance.VaultService, App.Instance.ClipboardService, App.Instance.SettingsService);
        InitializeComponent();
    }

    private void OnBackClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) =>
        Frame.Navigate(typeof(ShellPage));

    private void OnAuditClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) =>
        Frame.Navigate(typeof(AuditPage));
}
