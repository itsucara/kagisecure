using System;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Kagisecure.App.Views;

/// <summary>The import wizard page (import.md, ui-spec.md §15's <c>ks.import.*</c>).</summary>
public sealed partial class ImportPage : Page
{
    public ImportViewModel ViewModel { get; }

    public ImportPage()
    {
        ViewModel = new ImportViewModel(App.Instance.VaultService);
        InitializeComponent();
    }

    private async void OnPickFileClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.Downloads };
        picker.FileTypeFilter.Add(".1pux");
        picker.FileTypeFilter.Add(".csv");
        picker.FileTypeFilter.Add("*");

        var hwnd = WindowNative.GetWindowHandle(App.CurrentWindow);
        InitializeWithWindow.Initialize(picker, hwnd);

        Windows.Storage.StorageFile? file = await picker.PickSingleFileAsync();
        if (file is not null)
        {
            await ViewModel.LoadAsync(file.Path, null);
        }
    }

    private void OnPolicySelectionChanged(object sender, SelectionChangedEventArgs e) =>
        ViewModel.Policy = (DuplicatePolicy)PolicyRadios.SelectedIndex;

    private void OnTargetVaultChanged(object sender, SelectionChangedEventArgs e) =>
        ViewModel.TargetVault = (TargetVaultCombo.SelectedItem as LogicalVault)?.Id;

    private async void OnFormatSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FormatCombo.SelectedItem is FormatPickerOption option)
        {
            await ViewModel.ChangeFormatAsync(option.Format);
        }
    }

    private void OnActionFilterChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is ComboBox { SelectedItem: ComboBoxItem { Tag: string tag } })
        {
            ViewModel.ActionFilter = tag;
        }
    }

    private void OnBackClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        if (ViewModel.Phase is ImportPhase.Previewing or ImportPhase.PickFile or ImportPhase.Failed)
        {
            ViewModel.DisposePlan();
        }

        Frame.Navigate(typeof(ShellPage));
    }
}
