using System;
using System.Threading.Tasks;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;
using ZXing;
using ZXing.Common;

namespace Kagisecure.App.Services;

/// <summary>
/// The real <see cref="IQrCodeReader"/>. <see cref="BitmapDecoder"/> (built into Windows, no extra
/// dependency) turns whatever image container the file or clipboard handed over into raw pixels,
/// and ZXing.Net reads the QR code out of those pixels — see the "why this dependency" note next to
/// its <c>PackageReference</c> in Kagisecure.App.csproj.
///
/// No unsafe code: pixel data crosses from <see cref="SoftwareBitmap"/> to ZXing through
/// <see cref="Windows.Storage.Streams.Buffer"/> and <see cref="DataReader"/> rather than the
/// <c>IMemoryBufferByteAccess</c> COM interface real-world samples usually reach for — that needs
/// <c>AllowUnsafeBlocks</c>, which this project turns off on purpose (Kagisecure.App.csproj).
/// </summary>
public sealed class ZXingQrCodeReader : IQrCodeReader
{
    public async Task<string?> DecodeAsync(IRandomAccessStream imageStream)
    {
        ArgumentNullException.ThrowIfNull(imageStream);

        SoftwareBitmap bitmap;
        try
        {
            BitmapDecoder decoder = await BitmapDecoder.CreateAsync(imageStream).AsTask().ConfigureAwait(false);
            bitmap = await decoder.GetSoftwareBitmapAsync(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Straight).AsTask().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Not a decodable image at all (corrupt file, a non-image file the user picked
            // anyway, ...) — reported identically to "found no code" rather than as an error.
            return null;
        }

        using (bitmap)
        {
            return Decode(bitmap);
        }
    }

    private static string? Decode(SoftwareBitmap bitmap)
    {
        int width = bitmap.PixelWidth;
        int height = bitmap.PixelHeight;
        var pixelBuffer = new Windows.Storage.Streams.Buffer((uint)(width * height * 4));
        bitmap.CopyToBuffer(pixelBuffer);

        var pixels = new byte[pixelBuffer.Length];
        using (DataReader reader = DataReader.FromBuffer(pixelBuffer))
        {
            reader.ReadBytes(pixels);
        }

        var source = new RGBLuminanceSource(pixels, width, height, RGBLuminanceSource.BitmapFormat.BGRA32);
        var barcodeReader = new BarcodeReaderGeneric
        {
            AutoRotate = true,
            Options = new DecodingOptions
            {
                TryHarder = true,
                PossibleFormats = new[] { BarcodeFormat.QR_CODE },
            },
        };

        Result? result = barcodeReader.Decode(source);
        return result?.Text;
    }
}
