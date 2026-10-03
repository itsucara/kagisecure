using System;
using Kagisecure.Interop.Native;
using static Kagisecure.Interop.Native.Marshalling;

namespace Kagisecure.Interop;

/// <summary>Which HMAC a TOTP field uses.</summary>
public enum TotpAlgorithm : uint
{
    /// <summary>HMAC-SHA-1, the near-universal default.</summary>
    Sha1 = (uint)KgsTotpAlgorithm.Sha1,

    /// <summary>HMAC-SHA-256.</summary>
    Sha256 = (uint)KgsTotpAlgorithm.Sha256,

    /// <summary>HMAC-SHA-512.</summary>
    Sha512 = (uint)KgsTotpAlgorithm.Sha512,
}

/// <summary>A TOTP field's parameters. Metadata: no seed, no code.</summary>
/// <param name="Algorithm">Which HMAC.</param>
/// <param name="Digits">6, 7 or 8.</param>
/// <param name="Period">Seconds per code.</param>
/// <param name="Issuer">The service, if the URI named one.</param>
/// <param name="Account">The account at that service, if the URI named one.</param>
/// <param name="Caption"><c>"GitHub · ada@example.com"</c>, for the line under the code. Ignored going in.</param>
public sealed record TotpParams(
    TotpAlgorithm Algorithm,
    byte Digits,
    uint Period,
    string? Issuer,
    string? Account,
    string? Caption)
{
    internal static TotpParams From(in KgsTotpParams n) =>
        new((TotpAlgorithm)n.algorithm, n.digits, n.period, Str(n.issuer), Str(n.account), Str(n.caption));
}

/// <summary>
/// A live code and everything the countdown ring needs. <see cref="Code"/> is ADR-0008 crossing 5,
/// outbound: a managed string, recomputed each second rather than cached.
/// </summary>
/// <param name="Code">The code.</param>
/// <param name="SecondsRemaining">Seconds left in this code's window, in <c>1..=period</c>.</param>
/// <param name="Params">The field's parameters.</param>
public sealed record TotpCode(string Code, uint SecondsRemaining, TotpParams Params)
{
    internal static TotpCode From(in KgsTotpCode n) =>
        new(Str(n.code), n.seconds_remaining, TotpParams.From(n.@params));

    /// <summary>Copy the native code out and zeroize-free it, whatever happens.</summary>
    internal static unsafe TotpCode Take(ref KgsTotpCode native)
    {
        try
        {
            return From(native);
        }
        finally
        {
            fixed (KgsTotpCode* p = &native)
            {
                NativeMethods.kgs_totp_code_free(p);
            }
        }
    }
}

/// <summary>
/// One-time passwords that are not yet stored in a field: the setup sheet's validation and live
/// preview. Every <c>otpauth://</c> URI carries its seed, so each is taken as a span.
/// </summary>
public static class Totp
{
    /// <summary>Parse a URI and report its parameters, without producing a code.</summary>
    /// <exception cref="KagisecureException.Invalid">It is not a usable <c>otpauth://</c> URI. The message never quotes it.</exception>
    public static unsafe TotpParams Describe(ReadOnlySpan<char> uri)
    {
        EnsureAbi();
        using var u = new PinnedUtf8(uri);
        KgsTotpParams output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_totp_describe(u.Slice, &output, &error), ref error);
            return TotpParams.From(output);
        }
        finally
        {
            NativeMethods.kgs_totp_params_free(&output);
        }
    }

    /// <summary>The code a not-yet-saved setup would produce at Unix time <paramref name="at"/>.</summary>
    /// <exception cref="KagisecureException.Invalid">As <see cref="Describe"/>.</exception>
    public static unsafe TotpCode Preview(ReadOnlySpan<char> uri, ulong at)
    {
        EnsureAbi();
        using var u = new PinnedUtf8(uri);
        KgsTotpCode output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_totp_preview(u.Slice, at, &output, &error), ref error);
        return TotpCode.Take(ref output);
    }

    /// <summary>
    /// Build an <c>otpauth://</c> URI from a hand-typed Base32 seed. The result carries the seed and
    /// is what gets stored in the field.
    /// </summary>
    /// <exception cref="KagisecureException.Invalid">The seed is not Base32, or a parameter is out of range.</exception>
    public static unsafe string UriFromParts(ReadOnlySpan<char> secretBase32, TotpParams parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        EnsureAbi();
        using var secret = new PinnedUtf8(secretBase32);
        using var issuer = PinnedUtf8.Optional(parameters.Issuer);
        using var account = PinnedUtf8.Optional(parameters.Account);
        using var caption = PinnedUtf8.Optional(parameters.Caption);
        var native = new KgsTotpParamsRef
        {
            algorithm = (uint)parameters.Algorithm,
            digits = parameters.Digits,
            period = parameters.Period,
            issuer = issuer.OptSlice,
            account = account.OptSlice,
            caption = caption.OptSlice,
        };
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_totp_uri_from_parts(secret.Slice, &native, &output, &error), ref error);
        return TakeString(ref output);
    }

    /// <summary>Whether a string is a usable <c>otpauth://</c> URI — for enabling a Save button.</summary>
    public static unsafe bool UriIsValid(ReadOnlySpan<char> uri)
    {
        EnsureAbi();
        using var u = new PinnedUtf8(uri);
        byte output = 0;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_totp_uri_is_valid(u.Slice, &output, &error), ref error);
        return output != 0;
    }
}
