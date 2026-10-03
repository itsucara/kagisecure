using System;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage.Streams;

namespace Kagisecure.App.Services;

/// <summary>The real <see cref="IClipboardImageSource"/>, over <see cref="Clipboard.GetContent"/> — the same clipboard API <see cref="ClipboardService"/> writes to, read instead of written.</summary>
public sealed class ClipboardImageSource : IClipboardImageSource
{
    public async Task<IRandomAccessStream?> GetImageAsync()
    {
        DataPackageView content = Clipboard.GetContent();
        if (!content.Contains(StandardDataFormats.Bitmap))
        {
            return null;
        }

        RandomAccessStreamReference reference = await content.GetBitmapAsync();
        return await reference.OpenReadAsync();
    }
}
