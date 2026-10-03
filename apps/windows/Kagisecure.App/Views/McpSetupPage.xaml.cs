using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;

namespace Kagisecure.App.Views;

/// <summary>Agent access › Set up your agent (mcp-server.md §9). See <see cref="McpSetupViewModel"/>.</summary>
public sealed partial class McpSetupPage : Page
{
    public McpSetupViewModel ViewModel { get; }

    public string Intro => McpSetupViewModel.Intro;

    public string Footer => McpSetupViewModel.Footer;

    public string SidecarMissingText => McpSetupViewModel.SidecarMissingText;

    public McpSetupPage()
    {
        ViewModel = new McpSetupViewModel(App.Instance.AgentRuntime, App.Instance.AgentHost, SetupClipboard.Copy);
        InitializeComponent();
        Unloaded += (_, _) => ViewModel.Dispose();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = ViewModel.LoadAsync();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        base.OnNavigatedFrom(e);
        ViewModel.Dispose();
    }
}

/// <summary>
/// Copies setup text — paths, snippets, the extension id — straight to the clipboard. Not the
/// secret path (<c>IClipboardService.CopySecret</c>): none of this is secret, and clearing it after
/// a minute would break the paste the user is about to do.
/// </summary>
internal static class SetupClipboard
{
    public static void Copy(string text)
    {
        var package = new DataPackage();
        package.SetText(text);
        Clipboard.SetContent(package);
    }
}
