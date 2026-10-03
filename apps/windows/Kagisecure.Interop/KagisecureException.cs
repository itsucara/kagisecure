using System;
using Kagisecure.Interop.Native;

namespace Kagisecure.Interop;

/// <summary>
/// Everything that can go wrong on the way down into the core: the C# face of Rust's
/// <c>FfiError</c>, one nested type per variant, carrying the same message the Swift app gets.
/// </summary>
/// <remarks>
/// Deliberately as coarse as <c>FfiError</c>: a wrong password and a tampered file both arrive as
/// <see cref="WrongCredential"/>, because the core does not tell them apart (threat-model M-8).
/// </remarks>
public abstract class KagisecureException : Exception
{
    private KagisecureException(string message)
        : base(message)
    {
    }

    internal static KagisecureException From(KgsStatus status, string message) => status switch
    {
        KgsStatus.NotFound => new NotFound(message),
        KgsStatus.AlreadyExists => new AlreadyExists(message),
        KgsStatus.WrongCredential => new WrongCredential(message),
        KgsStatus.NoSuchSlot => new NoSuchSlot(message),
        KgsStatus.NotPresent => new NotPresent(message),
        KgsStatus.Invalid => new Invalid(message),
        KgsStatus.Io => new Io(message),
        KgsStatus.Busy => new Busy(message),
        KgsStatus.Diverged => new Diverged(message),
        KgsStatus.ItemChangedElsewhere => new ItemChangedElsewhere(message),
        KgsStatus.VaultLocked => new VaultLocked(message),
        KgsStatus.NoPresenceGate => new NoPresenceGate(message),
        KgsStatus.PresenceCancelled => new PresenceCancelled(message),
        KgsStatus.PresenceUnavailable => new PresenceUnavailable(message),
        KgsStatus.PresenceBusy => new PresenceBusy(message),
        KgsStatus.ReleaseEnded => new ReleaseEnded(message),
        KgsStatus.Panic => new Panic(message),
        _ => new Panic($"unknown status {(int)status}: {message}"),
    };

    /// <summary>There is no vault file at that path.</summary>
    public sealed class NotFound : KagisecureException
    {
        internal NotFound(string message) : base(message) { }
    }

    /// <summary>There is already a vault file at that path.</summary>
    public sealed class AlreadyExists : KagisecureException
    {
        internal AlreadyExists(string message) : base(message) { }
    }

    /// <summary>The credential does not open this vault — or the file was tampered with.</summary>
    public sealed class WrongCredential : KagisecureException
    {
        internal WrongCredential(string message) : base(message) { }
    }

    /// <summary>The vault has no slot of the kind that was asked for.</summary>
    public sealed class NoSuchSlot : KagisecureException
    {
        internal NoSuchSlot(string message) : base(message) { }
    }

    /// <summary>No item, field, environment or logical vault with that identifier.</summary>
    public sealed class NotPresent : KagisecureException
    {
        internal NotPresent(string message) : base(message) { }
    }

    /// <summary>The argument was not of a shape the core accepts.</summary>
    public sealed class Invalid : KagisecureException
    {
        internal Invalid(string message) : base(message) { }
    }

    /// <summary>Reading or writing the vault file failed.</summary>
    public sealed class Io : KagisecureException
    {
        internal Io(string message) : base(message) { }
    }

    /// <summary>
    /// Another kagisecure process (the CLI, the MCP daemon) held the vault's lock past the wait.
    /// Nothing was written; retrying shortly is safe.
    /// </summary>
    public sealed class Busy : KagisecureException
    {
        internal Busy(string message) : base(message) { }
    }

    /// <summary>
    /// The vault file on disk is no longer the one this session builds on — an older copy was
    /// restored over it, another vault replaced it, or it is gone. Nothing was written (ADR-0039).
    /// </summary>
    public sealed class Diverged : KagisecureException
    {
        internal Diverged(string message) : base(message) { }
    }

    /// <summary>
    /// The item changed since the edit sheet or the Trash row read it (another window or process
    /// saved it first). Nothing was written; reload the item.
    /// </summary>
    public sealed class ItemChangedElsewhere : KagisecureException
    {
        internal ItemChangedElsewhere(string message) : base(message) { }
    }

    /// <summary>The vault is locked. Nothing was read or released.</summary>
    public sealed class VaultLocked : KagisecureException
    {
        internal VaultLocked(string message) : base(message) { }
    }

    /// <summary>
    /// No presence gate is installed on this session, so nothing was released (ADR-0038: with no
    /// gate, every release fails closed).
    /// </summary>
    public sealed class NoPresenceGate : KagisecureException
    {
        internal NoPresenceGate(string message) : base(message) { }
    }

    /// <summary>The person dismissed the Windows Hello prompt, or it failed. Nothing was released.</summary>
    public sealed class PresenceCancelled : KagisecureException
    {
        internal PresenceCancelled(string message) : base(message) { }
    }

    /// <summary>
    /// No presence check could run and the master-password fallback was not completed. Nothing was
    /// released.
    /// </summary>
    public sealed class PresenceUnavailable : KagisecureException
    {
        internal PresenceUnavailable(string message) : base(message) { }
    }

    /// <summary>Another confirmation prompt is already up; this one was refused, not queued.</summary>
    public sealed class PresenceBusy : KagisecureException
    {
        internal PresenceBusy(string message) : base(message) { }
    }

    /// <summary>
    /// A release is no longer live — closed, past its five-minute cap, or a copy already used. Ask
    /// again, which means another prompt.
    /// </summary>
    public sealed class ReleaseEnded : KagisecureException
    {
        internal ReleaseEnded(string message) : base(message) { }
    }

    /// <summary>The Rust side panicked. Always a bug in kagisecure, never in the caller.</summary>
    public sealed class Panic : KagisecureException
    {
        internal Panic(string message) : base(message) { }
    }
}
