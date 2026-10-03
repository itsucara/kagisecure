using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Kagisecure.App.Views;

/// <summary>
/// Lock screen (ui-spec.md §6.1): master-password unlock, and "Unlock with Windows Hello" when
/// this PC has a Windows Hello slot for the vault (ADR-0004, ADR-0033). Never prompted
/// automatically, unlike Touch ID on the Mac: see ADR-0033 §5 on why an unrequested Hello prompt is
/// a risk here.
/// </summary>
public sealed partial class LockPage : Page
{
    public LockViewModel ViewModel { get; }

    public LockPage()
    {
        // Built before InitializeComponent, same as GeneratorView, so every x:Bind below resolves
        // on first layout — no Bindings.Update() needed.
        ViewModel = new LockViewModel(App.Instance.VaultService, App.Instance.WindowsHello);
        InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = ViewModel.RefreshHelloStateAsync();
    }
}
