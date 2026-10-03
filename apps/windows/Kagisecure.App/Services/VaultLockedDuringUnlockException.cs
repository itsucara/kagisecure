using System;

namespace Kagisecure.App.Services;

/// <summary>
/// An unlock finished its key derivation after the vault was told to lock (the screen locked, the
/// PC went to sleep, <c>kagisecure lock</c>) while it ran. The lock wins: the new session was
/// disposed without ever being served, and the vault is locked. Not a wrong password.
/// </summary>
public sealed class VaultLockedDuringUnlockException : InvalidOperationException
{
    public const string DefaultMessage =
        "The vault locked again while it was being unlocked (the screen locked or the PC went to sleep). Unlock again.";

    public VaultLockedDuringUnlockException()
        : base(DefaultMessage)
    {
    }
}
