namespace Kagisecure.App.ViewModels;

/// <summary>How the TOTP setup dialog's field is being filled (ui-spec.md §9).</summary>
public enum TotpSetupMode
{
    /// <summary>Type the Base32 secret, issuer, account, and (advanced) algorithm/digits/period. The default — most services no longer show a raw URI at all.</summary>
    Manual,

    /// <summary>Import an <c>otpauth://</c> URI from a QR code — a file, or the clipboard.</summary>
    Qr,

    /// <summary>
    /// Paste or view the raw <c>otpauth://</c> URI directly — kept as the "advanced" option macOS's
    /// <c>TotpSetupSheet</c> has (there it is the default and only non-manual path; here it is
    /// where a decoded QR code's URI lands too, since that is also "the URI", just discovered a
    /// different way).
    /// </summary>
    Uri,
}
