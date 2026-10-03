using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Kagisecure.App.Views;

/// <summary>Agent access › Browser extension. See <see cref="BrowserExtensionViewModel"/>.</summary>
public sealed partial class BrowserExtensionPage : Page
{
    public BrowserExtensionViewModel ViewModel { get; }

    public string Intro => BrowserExtensionViewModel.Intro;

    public string HostMissingText => BrowserExtensionViewModel.HostMissingText;

    public string ExtensionIdHelp => BrowserExtensionViewModel.ExtensionIdHelp;

    public BrowserExtensionPage()
    {
        ViewModel = new BrowserExtensionViewModel(App.Instance.AgentRuntime, App.Instance.AgentHost, SetupClipboard.Copy);
        InitializeComponent();
        Unloaded += (_, _) => ViewModel.Dispose();
    }

    public InfoBarSeverity ListenerSeverity(bool hasError) => hasError ? InfoBarSeverity.Error : InfoBarSeverity.Informational;

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = ViewModel.RefreshAsync();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        base.OnNavigatedFrom(e);
        ViewModel.Dispose();
    }
}
