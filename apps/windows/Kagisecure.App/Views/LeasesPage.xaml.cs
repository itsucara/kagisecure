using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Kagisecure.App.Views;

/// <summary>Agent access › Leases (ui-spec.md §10.4). See <see cref="LeasesViewModel"/>.</summary>
public sealed partial class LeasesPage : Page
{
    public LeasesViewModel ViewModel { get; }

    public string EmptyMessage => LeasesViewModel.EmptyMessage;

    public LeasesPage()
    {
        ViewModel = new LeasesViewModel(App.Instance.AgentHost);
        InitializeComponent();
        Unloaded += (_, _) => ViewModel.Dispose();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        App.Instance.AgentHost.Refresh();
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        base.OnNavigatedFrom(e);
        ViewModel.Dispose();
    }
}
