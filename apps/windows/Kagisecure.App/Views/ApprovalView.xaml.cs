using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace Kagisecure.App.Views;

/// <summary>The approval sheet's content (ui-spec.md §10). One per request; the window swaps it when the head of the queue changes.</summary>
public sealed partial class ApprovalView : UserControl
{
    public ApprovalViewModel ViewModel { get; }

    public ApprovalView(ApprovalViewModel viewModel)
    {
        ViewModel = viewModel;
        InitializeComponent();
    }

    /// <summary>Green when verified, red when not, informational while the check runs.</summary>
    public InfoBarSeverity Severity(bool verified, bool checking) =>
        checking ? InfoBarSeverity.Informational : verified ? InfoBarSeverity.Success : InfoBarSeverity.Error;

    private void OnEscape(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        if (ViewModel.DenyCommand.CanExecute(null))
        {
            ViewModel.DenyCommand.Execute(null);
        }

        args.Handled = true;
    }
}
