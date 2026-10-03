using System.Threading.Tasks;
using Windows.Storage.Streams;

namespace Kagisecure.App.Services;

/// <summary>
/// The clipboard's current image, if any — abstracted, like <see cref="IClipboardService"/>, so a
/// unit test never touches the real clipboard (ui-spec.md §9's QR import "from the clipboard").
/// </summary>
public interface IClipboardImageSource
{
    /// <summary>The clipboard's image, opened for read, or <c>null</c> if the clipboard holds no image right now.</summary>
    Task<IRandomAccessStream?> GetImageAsync();
}
