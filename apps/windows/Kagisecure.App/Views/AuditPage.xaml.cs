using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml.Controls;

namespace Kagisecure.App.Views;

/// <summary>The audit viewer (mcp-server.md §6, ui-spec.md §10.4).</summary>
public sealed partial class AuditPage : Page
{
    public AuditViewModel ViewModel { get; }

    public AuditPage()
    {
        ViewModel = new AuditViewModel(App.Instance.VaultService);
        InitializeComponent();
    }

    private void OnBackClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) =>
        Frame.Navigate(typeof(ShellPage));

    private void OnOutcomeChanged(object sender, SelectionChangedEventArgs e) => SetFilter(sender, v => ViewModel.OutcomeFilter = v);

    private void OnActorChanged(object sender, SelectionChangedEventArgs e) => SetFilter(sender, v => ViewModel.ActorFilter = v);

    private void OnToolChanged(object sender, SelectionChangedEventArgs e) => SetFilter(sender, v => ViewModel.ToolFilter = v);

    private static void SetFilter(object sender, System.Action<string> apply)
    {
        if (sender is ComboBox { SelectedItem: ComboBoxItem { Tag: string tag } })
        {
            apply(tag);
        }
    }
}
