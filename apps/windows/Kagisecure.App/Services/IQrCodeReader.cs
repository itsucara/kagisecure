using System.Threading.Tasks;
using Windows.Storage.Streams;

namespace Kagisecure.App.Services;

/// <summary>
/// Decodes a QR code out of an image (whatever container <c>BitmapDecoder</c> understands — PNG,
/// JPEG, BMP, GIF, ...) into the text it encodes. Used for TOTP setup's QR import (ui-spec.md §9):
/// an image file, or an image pasted from the clipboard. macOS has no QR import at all yet
/// (<c>TotpSetupSheet</c>'s own comment: "QR scanning is not here; see the roadmap's M5 notes"), so
/// this is a Windows-only addition built straight from ui-spec.md §9's brief rather than a port.
/// </summary>
public interface IQrCodeReader
{
    /// <summary>
    /// The decoded text, or <c>null</c> if the image holds no readable QR code (including "not
    /// actually a decodable image at all"). Never throws for that — only lets an out-of-memory
    /// condition propagate. The caller (<see cref="Kagisecure.App.ViewModels.TotpSetupViewModel"/>)
    /// checks the result is an <c>otpauth://</c> URI before accepting it; this type doesn't care
    /// what the QR code says.
    /// </summary>
    Task<string?> DecodeAsync(IRandomAccessStream imageStream);
}
