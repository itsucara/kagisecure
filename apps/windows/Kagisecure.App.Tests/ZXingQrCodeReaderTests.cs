using System;
using System.Threading.Tasks;
using Kagisecure.App.Services;
using Windows.Graphics.Imaging;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;
using Xunit;
using ZXing;
using ZXing.Common;
using ZXing.QrCode;

namespace Kagisecure.App.Tests;

/// <summary>
/// Exercises the real <see cref="ZXingQrCodeReader"/> end to end: a QR code is encoded with
/// ZXing.Net's own writer (the "ZXing can encode" the task brief points at), rasterized by hand
/// into a BGRA32 pixel buffer, and turned into an actual PNG with Windows' own
/// <see cref="BitmapEncoder"/> — the same file format a screenshot or a saved QR image would be.
/// Fully offline: no network, no real file, no real clipboard, no System.Drawing.
/// </summary>
public class ZXingQrCodeReaderTests
{
    [Fact]
    public async Task DecodeAsync_ReadsTheOtpauthUri_FromAQrCodePngGeneratedInTheTest()
    {
        const string uri = "otpauth://totp/Kagisecure:ada%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Kagisecure";
        byte[] png = await EncodeUriAsQrPngAsync(uri);

        var reader = new ZXingQrCodeReader();
        using IRandomAccessStream stream = await ToStreamAsync(png);

        string? decoded = await reader.DecodeAsync(stream);

        Assert.Equal(uri, decoded);
    }

    [Fact]
    public async Task DecodeAsync_OnAnImageWithNoQrCode_ReturnsNullRatherThanThrowing()
    {
        byte[] blankPixels = new byte[64 * 64 * 4];
        for (int i = 0; i < blankPixels.Length; i++)
        {
            blankPixels[i] = 255; // opaque white
        }

        byte[] png = await EncodeBgraPixelsAsPngAsync(blankPixels, 64, 64);

        var reader = new ZXingQrCodeReader();
        using IRandomAccessStream stream = await ToStreamAsync(png);

        string? decoded = await reader.DecodeAsync(stream);

        Assert.Null(decoded);
    }

    [Fact]
    public async Task DecodeAsync_OnBytesThatArentAnImageAtAll_ReturnsNullRatherThanThrowing()
    {
        var reader = new ZXingQrCodeReader();
        using IRandomAccessStream stream = await ToStreamAsync(new byte[] { 1, 2, 3, 4, 5 });

        string? decoded = await reader.DecodeAsync(stream);

        Assert.Null(decoded);
    }

    /// <summary>ZXing.Net encodes the QR code's module grid (<see cref="BitMatrix"/>); this rasterizes it into a PNG the same way a real QR image file would arrive.</summary>
    private static async Task<byte[]> EncodeUriAsQrPngAsync(string uri)
    {
        var writer = new QRCodeWriter();
        BitMatrix matrix = writer.encode(uri, BarcodeFormat.QR_CODE, 240, 240);

        int width = matrix.Width;
        int height = matrix.Height;
        var pixels = new byte[width * height * 4];
        int i = 0;
        for (int y = 0; y < height; y++)
        {
            for (int x = 0; x < width; x++)
            {
                byte value = matrix[x, y] ? (byte)0 : (byte)255; // BitMatrix: true == black.
                pixels[i++] = value; // B
                pixels[i++] = value; // G
                pixels[i++] = value; // R
                pixels[i++] = 255; // A
            }
        }

        return await EncodeBgraPixelsAsPngAsync(pixels, width, height);
    }

    private static async Task<byte[]> EncodeBgraPixelsAsPngAsync(byte[] bgraPixels, int width, int height)
    {
        IBuffer buffer = CryptographicBuffer.CreateFromByteArray(bgraPixels);
        SoftwareBitmap bitmap = SoftwareBitmap.CreateCopyFromBuffer(buffer, BitmapPixelFormat.Bgra8, width, height, BitmapAlphaMode.Straight);

        using var stream = new InMemoryRandomAccessStream();
        BitmapEncoder encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
        encoder.SetSoftwareBitmap(bitmap);
        await encoder.FlushAsync();

        var bytes = new byte[stream.Size];
        using var reader = new DataReader(stream.GetInputStreamAt(0));
        await reader.LoadAsync((uint)stream.Size);
        reader.ReadBytes(bytes);
        return bytes;
    }

    private static async Task<IRandomAccessStream> ToStreamAsync(byte[] bytes)
    {
        var stream = new InMemoryRandomAccessStream();
        using (var writer = new DataWriter(stream))
        {
            writer.WriteBytes(bytes);
            await writer.StoreAsync();
            await writer.FlushAsync();
            writer.DetachStream();
        }

        stream.Seek(0);
        return stream;
    }
}
