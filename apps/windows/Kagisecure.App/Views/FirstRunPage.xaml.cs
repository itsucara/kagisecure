using System;
using System.IO;
using Kagisecure.App.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace Kagisecure.App.Views;

/// <summary>First-run: create a vault (see docs/windows-port.md — Windows has no macOS first-run equivalent to follow).</summary>
public sealed partial class FirstRunPage : Page
{
    public FirstRunViewModel ViewModel { get; }

    public FirstRunPage()
    {
        // Built before InitializeComponent, same as GeneratorView, so every x:Bind below resolves
        // on first layout — no Bindings.Update() needed.
        ViewModel = new FirstRunViewModel(App.Instance.VaultService);
        InitializeComponent();
    }

    private async void OnBrowseClicked(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
    {
        // A folder picker, not FileSavePicker: FileSavePicker creates an empty placeholder file
        // at the chosen path as soon as the user picks it (needed for its CompleteUpdatesAsync
        // pattern), which would collide with VaultSession.Create's own "must not already exist"
        // check. Picking a folder and appending the file name avoids that entirely.
        var picker = new FolderPicker
        {
            SuggestedStartLocation = PickerLocationId.Downloads,
        };
        picker.FileTypeFilter.Add("*");

        var hwnd = WindowNative.GetWindowHandle(App.CurrentWindow);
        InitializeWithWindow.Initialize(picker, hwnd);

        Windows.Storage.StorageFolder? folder = await picker.PickSingleFolderAsync();
        if (folder is not null)
        {
            string fileName = Path.GetFileName(ViewModel.VaultPath);
            if (string.IsNullOrEmpty(fileName))
            {
                fileName = "default.kagivault";
            }

            ViewModel.VaultPath = Path.Combine(folder.Path, fileName);
        }
    }
}
