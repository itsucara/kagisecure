using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml.Controls;

namespace Kagisecure.App.Views;

/// <summary>Forced master-password change after a recovery-code unlock (ui-spec.md §6.1).</summary>
public sealed partial class ForceChangePasswordPage : Page
{
    public ForceChangePasswordViewModel ViewModel { get; }

    public ForceChangePasswordPage()
    {
        ViewModel = new ForceChangePasswordViewModel(App.Instance.VaultService);
        ViewModel.PasswordChanged += (_, _) => Frame.Navigate(typeof(ShellPage));
        InitializeComponent();
    }
}
