using System;
using System.Threading.Tasks;
using Windows.Security.Credentials.UI;

namespace Kagisecure.App.Services;

/// <summary>What asking the person at the keyboard produced.</summary>
public enum ConsentStatus
{
    /// <summary>Windows Hello verified the user.</summary>
    Verified,

    /// <summary>
    /// The user cancelled. <b>Not</b> a denial: ui-spec.md §10.3 — a fumbled fingerprint returns
    /// to the approval sheet rather than being mistaken for a policy decision. Nothing is granted.
    /// </summary>
    Cancelled,

    /// <summary>
    /// Windows Hello is not set up, not present, or disabled by policy. The sheet then offers the
    /// master-password fallback (ADR-0004) — never a silent approval.
    /// </summary>
    Unavailable,

    /// <summary>Hello ran and did not verify (retries exhausted, device busy). Nothing is granted.</summary>
    Failed,
}

/// <summary>The outcome, with a sentence for the sheet when it is not <see cref="ConsentStatus.Verified"/>.</summary>
public sealed record ConsentOutcome(ConsentStatus Status, string? Message = null)
{
    /// <summary>Verified.</summary>
    public static ConsentOutcome Verified { get; } = new(ConsentStatus.Verified);
}

/// <summary>
/// Whatever asks the human before an approval is granted — the macOS <c>BiometricGate</c>. A seam
/// for the same reason: the approval logic (what a cancel means, what a refusal means, when the
/// password fallback appears) is untestable if the only way to reach it is a system dialog.
/// </summary>
public interface IConsentGate
{
    /// <summary>Ask, with <paramref name="reason"/> as the prompt's text. Never throws.</summary>
    Task<ConsentOutcome> RequestAsync(string reason);
}

/// <summary>
/// The real gate: <see cref="UserConsentVerifier"/> (ADR-0004, Windows). Like macOS's
/// <c>LAContext.evaluatePolicy</c> it hands back no key material — it answers a yes/no about the
/// person at the keyboard, which is exactly what an approval is. Windows Hello's own PIN is the
/// in-dialog fallback for a finger or face that will not read.
/// </summary>
/// <remarks>
/// <para>
/// W-1, stated plainly: a Windows Hello verification is scoped to the user and the device, not to
/// this app. Another process running as the same user can raise the same prompt. What it cannot
/// do is make <i>this</i> app's sheet resolve: the prompt only matters because this process asked
/// for it, in its own window, after showing the request.
/// </para>
/// <para>
/// The dialog is parented to the approval window (<c>IUserConsentVerifierInterop</c>) so it comes
/// up in front of it rather than behind — an unpackaged desktop app has no CoreWindow for the
/// plain <see cref="UserConsentVerifier.RequestVerificationAsync"/> to attach to.
/// </para>
/// </remarks>
public sealed class WindowsHelloConsentGate : IConsentGate
{
    private readonly Func<IntPtr> ownerWindow;

    /// <param name="ownerWindow">The HWND the Hello dialog is parented to — the approval window.</param>
    public WindowsHelloConsentGate(Func<IntPtr> ownerWindow)
    {
        this.ownerWindow = ownerWindow;
    }

    /// <inheritdoc />
    public async Task<ConsentOutcome> RequestAsync(string reason)
    {
        try
        {
            UserConsentVerifierAvailability availability = await UserConsentVerifier.CheckAvailabilityAsync();
            if (availability != UserConsentVerifierAvailability.Available)
            {
                return FromAvailability(availability);
            }

            IntPtr hwnd = ownerWindow();
            UserConsentVerificationResult result = hwnd != IntPtr.Zero
                ? await UserConsentVerifierInterop.RequestVerificationForWindowAsync(hwnd, reason)
                : await UserConsentVerifier.RequestVerificationAsync(reason);
            return FromResult(result);
        }
        catch (Exception ex)
        {
            // Fail closed, with a reason. Never an approval.
            return new ConsentOutcome(ConsentStatus.Failed, $"Windows Hello could not be asked: {ex.Message}");
        }
    }

    /// <summary>What an availability that is not <c>Available</c> means for the sheet.</summary>
    public static ConsentOutcome FromAvailability(UserConsentVerifierAvailability availability) => availability switch
    {
        UserConsentVerifierAvailability.Available => ConsentOutcome.Verified,
        UserConsentVerifierAvailability.DeviceBusy =>
            new(ConsentStatus.Failed, "Windows Hello is busy. Try again in a moment."),
        UserConsentVerifierAvailability.DeviceNotPresent =>
            new(ConsentStatus.Unavailable, "This PC has no Windows Hello device."),
        UserConsentVerifierAvailability.NotConfiguredForUser =>
            new(ConsentStatus.Unavailable, "Windows Hello is not set up for this account."),
        UserConsentVerifierAvailability.DisabledByPolicy =>
            new(ConsentStatus.Unavailable, "Windows Hello is disabled by policy on this PC."),
        // A value this build does not know is not evidence that Hello is absent, so it must not
        // open the master-password fallback: fail closed.
        _ => new(ConsentStatus.Failed, $"Windows Hello reported a state this app does not recognise ({availability})."),
    };

    /// <summary>What a verification result means for the sheet.</summary>
    public static ConsentOutcome FromResult(UserConsentVerificationResult result) => result switch
    {
        UserConsentVerificationResult.Verified => ConsentOutcome.Verified,
        UserConsentVerificationResult.Canceled => new(ConsentStatus.Cancelled),
        UserConsentVerificationResult.RetriesExhausted =>
            new(ConsentStatus.Failed, "Windows Hello could not verify you (too many attempts)."),
        UserConsentVerificationResult.DeviceBusy =>
            new(ConsentStatus.Failed, "Windows Hello is busy. Try again in a moment."),
        UserConsentVerificationResult.DeviceNotPresent =>
            new(ConsentStatus.Unavailable, "This PC has no Windows Hello device."),
        UserConsentVerificationResult.NotConfiguredForUser =>
            new(ConsentStatus.Unavailable, "Windows Hello is not set up for this account."),
        UserConsentVerificationResult.DisabledByPolicy =>
            new(ConsentStatus.Unavailable, "Windows Hello is disabled by policy on this PC."),
        _ => new(ConsentStatus.Failed, $"Windows Hello did not verify you ({result})."),
    };
}
