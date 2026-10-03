using System;
using System.Runtime.InteropServices;

namespace Kagisecure.Interop.Native;

/// <summary>
/// One strong reference to a Rust object behind an opaque pointer — a <c>*mut KgsSession</c> or a
/// <c>*mut KgsImportPlan</c>.
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="SafeHandle"/> rather than a raw pointer because it gives the three lifetime
/// guarantees ADR-0003 C4 asks for without hand-written reference counting:
/// </para>
/// <list type="bullet">
/// <item><see cref="IDisposable.Dispose"/> releases the reference deterministically — for a session
/// that is the lock: the vault key is zeroized when the last reference goes.</item>
/// <item><see cref="Borrow"/> add-refs the handle for the duration of every call, so a
/// <c>Dispose</c> racing a call on another thread defers the free until that call returns rather
/// than freeing memory Rust is still using; and a call after <c>Dispose</c> throws
/// <see cref="ObjectDisposedException"/> instead of passing a dangling pointer. (The generated
/// declarations take the raw pointer, so this is what the marshaller did for the hand-written
/// proof's <c>SafeHandle</c> parameters, done explicitly.)</item>
/// <item><see cref="SafeHandle.ReleaseHandle"/> runs at most once, so there is no double free.</item>
/// </list>
/// <para>
/// A forgotten <c>Dispose</c> is still caught by the critical finalizer, but that is a backstop,
/// not the design: a vault that stays unlocked until the GC gets round to it is the thing C4
/// exists to prevent. Callers hold these in <c>using</c>.
/// </para>
/// </remarks>
/// <typeparam name="T">The opaque native type the pointer points to.</typeparam>
internal abstract unsafe class NativeHandle<T> : SafeHandle
    where T : unmanaged
{
    protected NativeHandle(T* pointer)
        : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle((IntPtr)pointer);
    }

    /// <inheritdoc />
    public override bool IsInvalid => handle == IntPtr.Zero;

    /// <summary>
    /// Keep the object alive for one call. Throws <see cref="ObjectDisposedException"/> once the
    /// handle has been disposed.
    /// </summary>
    internal Borrowed Borrow()
    {
        bool added = false;
        DangerousAddRef(ref added);
        return new Borrowed(this, (T*)DangerousGetHandle());
    }

    /// <summary>A pointer that stays valid until <see cref="Dispose"/>.</summary>
    internal readonly ref struct Borrowed
    {
        private readonly NativeHandle<T> owner;

        internal Borrowed(NativeHandle<T> owner, T* pointer)
        {
            this.owner = owner;
            Ptr = pointer;
        }

        /// <summary>The live pointer.</summary>
        internal T* Ptr { get; }

        /// <summary>Release the call's reference.</summary>
        public void Dispose() => owner.DangerousRelease();
    }
}

/// <summary>One strong reference to a Rust <c>VaultSession</c>.</summary>
internal sealed unsafe class SessionHandle : NativeHandle<KgsSession>
{
    internal SessionHandle(KgsSession* pointer)
        : base(pointer)
    {
    }

    /// <inheritdoc />
    protected override bool ReleaseHandle()
    {
        NativeMethods.kgs_session_free((KgsSession*)handle);
        return true;
    }
}

/// <summary>One strong reference to a Rust <c>ImportPlanHandle</c>.</summary>
internal sealed unsafe class ImportPlanHandle : NativeHandle<KgsImportPlan>
{
    internal ImportPlanHandle(KgsImportPlan* pointer)
        : base(pointer)
    {
    }

    /// <inheritdoc />
    protected override bool ReleaseHandle()
    {
        NativeMethods.kgs_import_plan_free((KgsImportPlan*)handle);
        return true;
    }
}

/// <summary>One strong reference to a Rust <c>FieldRelease</c>.</summary>
internal sealed unsafe class FieldReleaseHandle : NativeHandle<KgsFieldRelease>
{
    internal FieldReleaseHandle(KgsFieldRelease* pointer)
        : base(pointer)
    {
    }

    /// <inheritdoc />
    protected override bool ReleaseHandle()
    {
        NativeMethods.kgs_field_release_free((KgsFieldRelease*)handle);
        return true;
    }
}

/// <summary>One strong reference to a Rust <c>TotpRelease</c>.</summary>
internal sealed unsafe class TotpReleaseHandle : NativeHandle<KgsTotpRelease>
{
    internal TotpReleaseHandle(KgsTotpRelease* pointer)
        : base(pointer)
    {
    }

    /// <inheritdoc />
    protected override bool ReleaseHandle()
    {
        NativeMethods.kgs_totp_release_free((KgsTotpRelease*)handle);
        return true;
    }
}

/// <summary>One strong reference to a Rust <c>NotesRelease</c>.</summary>
internal sealed unsafe class NotesReleaseHandle : NativeHandle<KgsNotesRelease>
{
    internal NotesReleaseHandle(KgsNotesRelease* pointer)
        : base(pointer)
    {
    }

    /// <inheritdoc />
    protected override bool ReleaseHandle()
    {
        NativeMethods.kgs_notes_release_free((KgsNotesRelease*)handle);
        return true;
    }
}
