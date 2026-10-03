namespace Kagisecure.App.Services;

/// <summary>
/// The one place anything in this app reaches the Windows clipboard, mirroring the macOS app's
/// <c>PasteboardService</c> (ADR-0017): every copy of secret material is excluded from clipboard
/// history/roaming and cleared after a timeout, unless something else has written to the
/// clipboard in the meantime.
/// </summary>
public interface IClipboardService
{
    /// <summary>
    /// Put <paramref name="value"/> on the clipboard, excluded from clipboard history and
    /// roaming, and schedule its removal after <see cref="ClearAfterSeconds"/> seconds (0
    /// disables the clear). <paramref name="label"/> is metadata only (e.g. a field name) for a
    /// transient confirmation — never the secret itself.
    /// </summary>
    void CopySecret(string value, string label);

    /// <summary>
    /// The delay, in seconds, before a copied secret is cleared. Matches the macOS app's default
    /// (ADR-0017); settable so the Settings page (ui-spec.md §6.2 <c>ks.settings.clipboardInterval</c>)
    /// can change it live — a copy already in flight keeps the delay it was scheduled with.
    /// </summary>
    int ClearAfterSeconds { get; set; }
}
