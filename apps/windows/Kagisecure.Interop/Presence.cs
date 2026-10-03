using System;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Kagisecure.Interop.Native;
using static Kagisecure.Interop.Native.Marshalling;

namespace Kagisecure.Interop;

/// <summary>What a presence check answered (ADR-0038).</summary>
public enum PresenceOutcome : uint
{
    /// <summary>A person proved presence. The one answer that releases anything.</summary>
    Confirmed = (uint)KgsPresenceOutcome.Confirmed,

    /// <summary>The person dismissed the prompt, or the check failed.</summary>
    Cancelled = (uint)KgsPresenceOutcome.Cancelled,

    /// <summary>No presence check can run on this PC right now.</summary>
    Unavailable = (uint)KgsPresenceOutcome.Unavailable,

    /// <summary>Another prompt is already up; this one was refused rather than queued.</summary>
    Busy = (uint)KgsPresenceOutcome.Busy,
}

/// <summary>Why the app is asking for a value: decides the prompt's wording, the audit entry, and what the release may do afterwards.</summary>
public enum ReleasePurpose : uint
{
    /// <summary>Show the value. It can be read again until the release ends, and copied once more with no new touch.</summary>
    Reveal = (uint)KgsReleasePurpose.Reveal,

    /// <summary>Copy the value without showing it. One use.</summary>
    Copy = (uint)KgsReleasePurpose.Copy,

    /// <summary>Copy from a quick-access surface. One use.</summary>
    QuickAccessCopy = (uint)KgsReleasePurpose.QuickAccessCopy,

    /// <summary>Show one concealed value inside the edit sheet, which never prefills.</summary>
    EditReveal = (uint)KgsReleasePurpose.EditReveal,
}

/// <summary>What <see cref="VaultSession.VerifyMasterPassword"/> answered.</summary>
public enum MasterPasswordCheckKind : uint
{
    /// <summary>The password is this vault's master password.</summary>
    Verified = (uint)KgsMasterPasswordCheckTag.Verified,

    /// <summary>It is not. The next attempt waits <see cref="MasterPasswordCheck.RetryAfter"/>.</summary>
    Wrong = (uint)KgsMasterPasswordCheckTag.Wrong,

    /// <summary>Not checked at all: an earlier failure's back-off has not run out, or another check is running.</summary>
    Throttled = (uint)KgsMasterPasswordCheckTag.Throttled,
}

/// <summary>
/// The master-password check's answer. Rate limited per session in Rust: one second after the
/// first wrong password, doubling up to five minutes; a right one resets it.
/// </summary>
/// <param name="Kind">Verified, wrong, or not checked.</param>
/// <param name="RetryAfter">For <see cref="MasterPasswordCheckKind.Wrong"/> and <see cref="MasterPasswordCheckKind.Throttled"/>, how long until an attempt is checked.</param>
public sealed record MasterPasswordCheck(MasterPasswordCheckKind Kind, TimeSpan RetryAfter)
{
    /// <summary>Whether the password was checked and is right.</summary>
    public bool Verified => Kind == MasterPasswordCheckKind.Verified;

    internal static MasterPasswordCheck From(in KgsMasterPasswordCheck n) =>
        new((MasterPasswordCheckKind)n.tag, TimeSpan.FromMilliseconds(n.retry_after_ms));
}

/// <summary>
/// The app's presence check — the Windows counterpart of the Swift app's
/// <c>LocalAuthenticationGate</c> (ADR-0038). Installed once per session with
/// <see cref="VaultSession.SetPresenceGate"/>; until one is, every release fails closed.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Confirm"/> is called <b>synchronously, on the thread that called</b>
/// <see cref="VaultSession.ReleaseField"/> (or the TOTP or notes release) — a background thread —
/// and must block until the person has answered. If showing the prompt needs the UI thread, hand
/// it there and wait; never wait on the calling thread from the UI thread.
/// </para>
/// <para>
/// The contract, the same one the Swift gate keeps: a fresh Windows Hello check every call with no
/// reuse of an earlier verification; <see cref="PresenceOutcome.Confirmed"/> only for a verification
/// that completed (or, only when Hello cannot run at all, a master password that
/// <see cref="VaultSession.VerifyMasterPassword"/> verified on the same session while this call
/// waited); <see cref="PresenceOutcome.Busy"/> rather than waiting when another prompt is up. It
/// must not throw — an exception is answered as <see cref="PresenceOutcome.Cancelled"/> anyway.
/// </para>
/// <para>
/// The <c>reason</c> is built and sanitised by Rust from vault facts; show it as it is.
/// </para>
/// </remarks>
public interface IPresenceGate
{
    /// <summary>Ask a person to prove they are present and meant <paramref name="reason"/>.</summary>
    PresenceOutcome Confirm(string reason);
}

/// <summary>
/// The one native entry point Rust calls back through, and the table it finds each session's gate
/// in. A table rather than a <see cref="GCHandle"/> per gate: a release racing a lock can still be
/// on its way to the callback after the session is disposed, and a stale key finds nothing and is
/// answered <see cref="PresenceOutcome.Cancelled"/>, where a freed handle would be undefined.
/// </summary>
internal static unsafe class PresenceBridge
{
    private static readonly ConcurrentDictionary<nint, IPresenceGate> Gates = new();
    private static long nextKey;

    internal static nint Register(IPresenceGate gate)
    {
        nint key = (nint)Interlocked.Increment(ref nextKey);
        Gates[key] = gate;
        return key;
    }

    internal static void Unregister(nint key) => Gates.TryRemove(key, out _);

    internal static delegate* unmanaged[Cdecl]<void*, KgsSlice, uint> Confirm => &ConfirmThunk;

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static uint ConfirmThunk(void* context, KgsSlice reason)
    {
        try
        {
            if (!Gates.TryGetValue((nint)context, out IPresenceGate? gate))
            {
                return (uint)PresenceOutcome.Cancelled;
            }

            string text = reason.len == 0
                ? string.Empty
                : Encoding.UTF8.GetString(reason.ptr, checked((int)reason.len));
            PresenceOutcome outcome = gate.Confirm(text);
            return Enum.IsDefined(outcome) ? (uint)outcome : (uint)PresenceOutcome.Cancelled;
        }
        catch
        {
            // Nothing may unwind into Rust, and nothing that went wrong may release a value.
            return (uint)PresenceOutcome.Cancelled;
        }
    }
}

/// <summary>A released concealed field (<see cref="FieldRelease"/>), as the app's view models hold it.</summary>
public interface IFieldRelease : IDisposable
{
    /// <summary>The item it is bound to.</summary>
    string ItemId { get; }

    /// <summary>The field it is bound to.</summary>
    string FieldId { get; }

    /// <summary>The value as it is in the vault now.</summary>
    string Value();

    /// <summary>The value as UTF-8 bytes the caller clears.</summary>
    byte[] ValueUtf8();

    /// <summary>The shown value again, for the clipboard, with no new touch; bytes the caller clears.</summary>
    byte[] CopyShownValueUtf8();

    /// <summary>End it now. Idempotent.</summary>
    void Close();

    /// <summary>Whether it is still live, how long it has left, and what it was for.</summary>
    ReleaseState State();
}

/// <summary>A released one-time code (<see cref="TotpRelease"/>), as the app's view models hold it.</summary>
public interface ITotpRelease : IDisposable
{
    /// <summary>The item it is bound to.</summary>
    string ItemId { get; }

    /// <summary>The code at Unix time <paramref name="at"/>.</summary>
    TotpCode CodeAt(ulong at);

    /// <summary>The shown code again, for the clipboard, with no new touch.</summary>
    TotpCode CopyShownCodeAt(ulong at);

    /// <summary>End it now. Idempotent.</summary>
    void Close();

    /// <summary>Whether it is still live, how long it has left, and what it was for.</summary>
    ReleaseState State();
}

/// <summary>Released notes (<see cref="NotesRelease"/>), as the app's view models hold them.</summary>
public interface INotesRelease : IDisposable
{
    /// <summary>The item it is bound to.</summary>
    string ItemId { get; }

    /// <summary>The notes as they are in the vault now.</summary>
    string Text();

    /// <summary>The shown notes again, for the clipboard, with no new touch; bytes the caller clears.</summary>
    byte[] CopyShownTextUtf8();

    /// <summary>End it now. Idempotent.</summary>
    void Close();

    /// <summary>Whether it is still live, how long it has left, and what it was for.</summary>
    ReleaseState State();
}

/// <summary>A release's lifecycle, read in one call.</summary>
/// <param name="IsLive">Whether a use would still be allowed.</param>
/// <param name="SecondsRemaining">Seconds before the five-minute cap ends it.</param>
/// <param name="Purpose">What it was granted for.</param>
public sealed record ReleaseState(bool IsLive, uint SecondsRemaining, ReleasePurpose Purpose)
{
    internal static ReleaseState From(in KgsReleaseState n) =>
        new(n.is_live != 0, n.seconds_remaining, (ReleasePurpose)n.purpose);
}

/// <summary>
/// One concealed field's value, released by one presence check (<see cref="VaultSession.ReleaseField"/>).
/// Holds no value: every read goes back to the vault, and fails once the vault is locked, after five
/// minutes, after <see cref="Close"/> — and for a copy, after its one use. Dispose it when done.
/// </summary>
public sealed unsafe class FieldRelease : IFieldRelease
{
    private readonly FieldReleaseHandle handle;

    internal FieldRelease(KgsFieldRelease* pointer, string itemId, string fieldId)
    {
        handle = new FieldReleaseHandle(pointer);
        ItemId = itemId;
        FieldId = fieldId;
    }

    /// <summary>The item it is bound to.</summary>
    public string ItemId { get; }

    /// <summary>The field it is bound to.</summary>
    public string FieldId { get; }

    /// <summary>The field's value as it is in the vault now. ADR-0008 crossing 2, outbound.</summary>
    /// <exception cref="KagisecureException.ReleaseEnded">The release has ended.</exception>
    /// <exception cref="KagisecureException.VaultLocked">The vault locked.</exception>
    public string Value()
    {
        using var h = handle.Borrow();
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_field_release_value(h.Ptr, &output, &error), ref error);
        return TakeString(ref output);
    }

    /// <summary>
    /// The value as UTF-8 bytes the caller owns and must clear with
    /// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory"/> — for anything
    /// that does not render it.
    /// </summary>
    public byte[] ValueUtf8()
    {
        using var h = handle.Borrow();
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_field_release_value(h.Ptr, &output, &error), ref error);
        return TakeBytes(ref output);
    }

    /// <summary>
    /// The shown value again, for the clipboard, with no new touch (ADR-0038 user decision 1).
    /// Refused for a release that was never shown: a second copy is a second touch.
    /// </summary>
    public byte[] CopyShownValueUtf8()
    {
        using var h = handle.Borrow();
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_field_release_copy_shown_value(h.Ptr, &output, &error), ref error);
        return TakeBytes(ref output);
    }

    /// <summary>End the release now — on hide, deselect, or leaving the edit sheet. Idempotent.</summary>
    public void Close()
    {
        if (handle.IsClosed)
        {
            return;
        }

        using var h = handle.Borrow();
        KgsBuffer error = default;
        Check(NativeMethods.kgs_field_release_close(h.Ptr, &error), ref error);
    }

    /// <summary>Whether it is still live, how long it has left, and what it was for.</summary>
    public ReleaseState State()
    {
        using var h = handle.Borrow();
        KgsReleaseState output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_field_release_state(h.Ptr, &output, &error), ref error);
        return ReleaseState.From(output);
    }

    /// <summary>End the release and drop this reference to it.</summary>
    public void Dispose()
    {
        try
        {
            Close();
        }
        catch (Exception ex) when (ex is KagisecureException or ObjectDisposedException)
        {
            // Already ended, one way or another.
        }

        handle.Dispose();
    }
}

/// <summary>
/// One item's one-time code, released by one presence check (<see cref="VaultSession.ReleaseTotp"/>).
/// <see cref="CodeAt"/> derives the code for the caller's clock, so the digits and the countdown stay
/// drawn from one instant. Ends as <see cref="FieldRelease"/> does. Dispose it when done.
/// </summary>
public sealed unsafe class TotpRelease : ITotpRelease
{
    private readonly TotpReleaseHandle handle;

    internal TotpRelease(KgsTotpRelease* pointer, string itemId)
    {
        handle = new TotpReleaseHandle(pointer);
        ItemId = itemId;
    }

    /// <summary>The item it is bound to.</summary>
    public string ItemId { get; }

    /// <summary>The code at Unix time <paramref name="at"/>. ADR-0008 crossing 5, outbound.</summary>
    public TotpCode CodeAt(ulong at)
    {
        using var h = handle.Borrow();
        KgsTotpCode output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_totp_release_code_at(h.Ptr, at, &output, &error), ref error);
        return TotpCode.Take(ref output);
    }

    /// <summary>The shown code at <paramref name="at"/> again, for the clipboard, with no new touch.</summary>
    public TotpCode CopyShownCodeAt(ulong at)
    {
        using var h = handle.Borrow();
        KgsTotpCode output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_totp_release_copy_shown_code_at(h.Ptr, at, &output, &error), ref error);
        return TotpCode.Take(ref output);
    }

    /// <summary>End the release now. Idempotent.</summary>
    public void Close()
    {
        if (handle.IsClosed)
        {
            return;
        }

        using var h = handle.Borrow();
        KgsBuffer error = default;
        Check(NativeMethods.kgs_totp_release_close(h.Ptr, &error), ref error);
    }

    /// <summary>Whether it is still live, how long it has left, and what it was for.</summary>
    public ReleaseState State()
    {
        using var h = handle.Borrow();
        KgsReleaseState output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_totp_release_state(h.Ptr, &output, &error), ref error);
        return ReleaseState.From(output);
    }

    /// <summary>End the release and drop this reference to it.</summary>
    public void Dispose()
    {
        try
        {
            Close();
        }
        catch (Exception ex) when (ex is KagisecureException or ObjectDisposedException)
        {
            // Already ended, one way or another.
        }

        handle.Dispose();
    }
}

/// <summary>
/// One item's notes, released by one presence check (<see cref="VaultSession.ReleaseNotes"/>).
/// Ends as <see cref="FieldRelease"/> does. Dispose it when done.
/// </summary>
public sealed unsafe class NotesRelease : INotesRelease
{
    private readonly NotesReleaseHandle handle;

    internal NotesRelease(KgsNotesRelease* pointer, string itemId)
    {
        handle = new NotesReleaseHandle(pointer);
        ItemId = itemId;
    }

    /// <summary>The item it is bound to.</summary>
    public string ItemId { get; }

    /// <summary>The notes as they are in the vault now.</summary>
    public string Text()
    {
        using var h = handle.Borrow();
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_notes_release_text(h.Ptr, &output, &error), ref error);
        return TakeString(ref output);
    }

    /// <summary>The shown notes again, for the clipboard, with no new touch; bytes the caller clears.</summary>
    public byte[] CopyShownTextUtf8()
    {
        using var h = handle.Borrow();
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_notes_release_copy_shown_text(h.Ptr, &output, &error), ref error);
        return TakeBytes(ref output);
    }

    /// <summary>End the release now. Idempotent.</summary>
    public void Close()
    {
        if (handle.IsClosed)
        {
            return;
        }

        using var h = handle.Borrow();
        KgsBuffer error = default;
        Check(NativeMethods.kgs_notes_release_close(h.Ptr, &error), ref error);
    }

    /// <summary>Whether it is still live, how long it has left, and what it was for.</summary>
    public ReleaseState State()
    {
        using var h = handle.Borrow();
        KgsReleaseState output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_notes_release_state(h.Ptr, &output, &error), ref error);
        return ReleaseState.From(output);
    }

    /// <summary>End the release and drop this reference to it.</summary>
    public void Dispose()
    {
        try
        {
            Close();
        }
        catch (Exception ex) when (ex is KagisecureException or ObjectDisposedException)
        {
            // Already ended, one way or another.
        }

        handle.Dispose();
    }
}
