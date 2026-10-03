using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Kagisecure.App.Views;

/// <summary>
/// The recovery-code "write this down" interstitial (ui-spec.md §12), shown once right after a
/// vault is created — see <see cref="MainWindow"/>'s navigation for how this is reached instead
/// of going straight to <see cref="ShellPage"/>.
/// </summary>
public sealed partial class RecoveryCodePage : Page
{
    public RecoveryCodeViewModel ViewModel { get; private set; } = null!;

    public RecoveryCodePage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        string code = e.Parameter as string ?? string.Empty;
        ViewModel = new RecoveryCodeViewModel(App.Instance.ClipboardService, code);
        Bindings.Update();
    }

    private void OnDoneClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) =>
        Frame.Navigate(typeof(ShellPage));
}
