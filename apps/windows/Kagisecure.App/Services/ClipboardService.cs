using System;
using System.Threading;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;

namespace Kagisecure.App.Services;

/// <summary>
/// The real <see cref="IClipboardService"/>, over <c>Windows.ApplicationModel.DataTransfer</c>.
/// </summary>
/// <remarks>
/// Mirrors the macOS app's <c>PasteboardService</c> (ADR-0017) as closely as the two clipboard
/// APIs allow:
/// <list type="bullet">
/// <item><description>
/// <c>ClipboardContentOptions { IsAllowedInHistory = false, IsRoamable = false }</c> is the
/// Windows equivalent of macOS's <c>org.nspasteboard.ConcealedType</c> convention — it keeps the
/// value out of Clipboard History (Win+V) and out of Cloud Clipboard sync.
/// </description></item>
/// <item><description>
/// The clear is conditional on nothing else having claimed the clipboard since, exactly like the
/// macOS timer's <c>changeCount</c> comparison. Windows has no exposed change counter, so this
/// stamps a random per-copy token onto the <see cref="DataPackage"/> as a second clipboard
/// format and, when the timer fires, only clears if that token is still the one on the
/// clipboard — same idea, different mechanism.
/// </description></item>
/// </list>
/// </remarks>
public sealed class ClipboardService : IClipboardService
{
    private const string TokenFormat = "application/x-kagisecure-copy-token";

    /// <summary>The default delay, in seconds, matching the macOS app's default (ADR-0017 <c>PasteboardService.defaultClearSeconds</c>).</summary>
    public const int DefaultClearAfterSeconds = 60;

    /// <inheritdoc />
    public int ClearAfterSeconds { get; set; } = DefaultClearAfterSeconds;

    /// <inheritdoc />
    public void CopySecret(string value, string label)
    {
        string token = Guid.NewGuid().ToString("N");

        var package = new DataPackage { RequestedOperation = DataPackageOperation.Copy };
        package.SetText(value);
        package.SetData(TokenFormat, token);

        var options = new ClipboardContentOptions
        {
            IsAllowedInHistory = false,
            IsRoamable = false,
        };

        try
        {
            Clipboard.SetContentWithOptions(package, options);
        }
        catch (Exception)
        {
            // The clipboard can be transiently locked by another process (common on Windows,
            // e.g. a clipboard manager mid-read). Nothing useful to do beyond not crashing the
            // caller — the user can just copy again.
            return;
        }

        if (ClearAfterSeconds <= 0)
        {
            return;
        }

        _ = ClearAfterDelayAsync(token, ClearAfterSeconds);
    }

    private static async Task ClearAfterDelayAsync(string token, int seconds)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(seconds)).ConfigureAwait(false);
        }
        catch (Exception)
        {
            return;
        }

        await ClearIfStillOursAsync(token).ConfigureAwait(false);
    }

    /// <summary>
    /// Clear the clipboard, but only if it still carries the token this copy stamped on it.
    /// Internal rather than private so a UI-thread test can drive it directly without waiting out
    /// the real delay.
    /// </summary>
    internal static async Task<bool> ClearIfStillOursAsync(string token)
    {
        DataPackageView view;
        try
        {
            view = Clipboard.GetContent();
        }
        catch (Exception)
        {
            return false;
        }

        if (!view.Contains(TokenFormat))
        {
            return false;
        }

        string? current;
        try
        {
            current = await view.GetDataAsync(TokenFormat) as string;
        }
        catch (Exception)
        {
            return false;
        }

        if (!string.Equals(current, token, StringComparison.Ordinal))
        {
            return false;
        }

        Clipboard.Clear();
        return true;
    }
}
