using System.Threading.Tasks;
using Windows.Storage.Streams;

namespace Kagisecure.App.Services;

/// <summary>
/// Picks an image file for TOTP QR import (ui-spec.md §9). A thin seam over
/// <see cref="Windows.Storage.Pickers.FileOpenPicker"/> — which needs a window handle to show at
/// all (<c>WinRT.Interop.InitializeWithWindow</c>, same as <c>ImportPage</c>'s file picker) — so
/// <c>TotpSetupViewModel</c> stays constructible, and testable, without a live <c>Window</c>.
/// </summary>
public interface IImageFilePicker
{
    /// <summary>The picked file, opened for read, or <c>null</c> if the user cancelled.</summary>
    Task<IRandomAccessStream?> PickImageAsync();
}
