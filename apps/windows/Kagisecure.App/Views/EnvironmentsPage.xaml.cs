using System;
using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Kagisecure.App.Views;

/// <summary>Agent access › Environments (ui-spec.md §10.4). See <see cref="EnvironmentsViewModel"/>.</summary>
public sealed partial class EnvironmentsPage : Page
{
    public EnvironmentsViewModel ViewModel { get; }

    public string EmptyMessage => EnvironmentsViewModel.EmptyMessage;

    public string NewEnvironmentNote => EnvironmentsViewModel.NewEnvironmentNote;

    public EnvironmentsPage()
    {
        ViewModel = new EnvironmentsViewModel(App.Instance.AgentVault, App.Instance.AgentHost);
        InitializeComponent();
        Unloaded += (_, _) => ViewModel.Dispose();
    }

    public string EmptyTitle(bool isEmpty) => isEmpty ? "No environments yet" : "Select an environment";

    public double ListenerOpacity(bool running) => running ? 1.0 : 0.4;

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

    private async void OnDeleteClicked(object sender, RoutedEventArgs e)
    {
        if (ViewModel.Selected is not { } env)
        {
            return;
        }

        var confirm = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = $"Delete “{env.Name}”?",
            Content = "Its variables and the values stored here are deleted from the vault. Agents that used it will no longer find it.",
            PrimaryButtonText = "Delete",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };
        try
        {
            if (await confirm.ShowAsync() == ContentDialogResult.Primary)
            {
                await ViewModel.DeleteCommand.ExecuteAsync(null);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException)
        {
            // Another dialog is already open on this window; nothing was deleted.
        }
    }
}
