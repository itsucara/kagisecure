using System;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.Storage.Streams;
using WinRT.Interop;

namespace Kagisecure.App.Services;

/// <summary>The real <see cref="IImageFilePicker"/>: a <see cref="FileOpenPicker"/> parented to the app's window, same pattern as <c>ImportPage</c>'s and <c>FirstRunPage</c>'s file pickers.</summary>
public sealed class FileOpenPickerImageSource : IImageFilePicker
{
    private readonly IntPtr windowHandle;

    public FileOpenPickerImageSource(IntPtr windowHandle) => this.windowHandle = windowHandle;

    public async Task<IRandomAccessStream?> PickImageAsync()
    {
        var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.PicturesLibrary };
        picker.FileTypeFilter.Add(".png");
        picker.FileTypeFilter.Add(".jpg");
        picker.FileTypeFilter.Add(".jpeg");
        picker.FileTypeFilter.Add(".bmp");
        picker.FileTypeFilter.Add(".gif");
        InitializeWithWindow.Initialize(picker, windowHandle);

        StorageFile? file = await picker.PickSingleFileAsync();
        return file is null ? null : await file.OpenReadAsync();
    }
}
