using System;
using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Kagisecure.App.Views;

/// <summary>
/// Security: Windows Hello unlock and the listeners' state. A page of its own rather than a
/// section of Settings, so the item-side Settings page is not touched by the agent side. See
/// <see cref="SecuritySettingsViewModel"/>.
/// </summary>
public sealed partial class SecuritySettingsPage : Page
{
    public SecuritySettingsViewModel ViewModel { get; }

    public SecuritySettingsPage()
    {
        ViewModel = new SecuritySettingsViewModel(App.Instance.WindowsHello, App.Instance.AgentHost);
        InitializeComponent();
    }

    /// <summary>Turning Hello on needs Hello; turning it off never does.</summary>
    public bool SwitchEnabled(bool available, bool busy, bool enabled) => !busy && (available || enabled);

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = ViewModel.RefreshCommand.ExecuteAsync(null);
    }

    private async void OnHelloToggled(object sender, RoutedEventArgs e)
    {
        // Toggled also fires when the binding pushes the real state back; only a change the user
        // made (the switch now disagrees with the vault) is an instruction.
        bool enable = HelloSwitch.IsOn;
        if (enable == ViewModel.IsHelloEnabled || !ViewModel.SetHelloCommand.CanExecute(enable))
        {
            return;
        }

        if (enable && ViewModel.ReplacementNeedsConfirmation)
        {
            var confirm = new ContentDialog
            {
                XamlRoot = XamlRoot,
                Title = "Replace this vault's other device unlock?",
                Content = ViewModel.SlotDescription
                    + " A vault keeps one device unlock. Turning on Windows Hello here removes that one, and that device will need the master password.",
                PrimaryButtonText = "Replace it",
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Close,
            };
            ContentDialogResult answer;
            try
            {
                answer = await confirm.ShowAsync();
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException)
            {
                answer = ContentDialogResult.None; // another dialog was open: nothing is replaced
            }

            if (answer != ContentDialogResult.Primary)
            {
                HelloSwitch.IsOn = false;
                return;
            }

            ViewModel.ReplacementConfirmed = true;
        }

        await ViewModel.SetHelloCommand.ExecuteAsync(enable);
    }
}
