using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Kagisecure.Interop.Native;

/// <summary>Converts one native element of an array to its managed record.</summary>
internal delegate T FromNative<TNative, T>(in TNative native)
    where TNative : unmanaged;

/// <summary>The handful of conversions every call in this assembly goes through.</summary>
/// <remarks>
/// The pattern every wrapper follows: pin the arguments, call, <see cref="Check"/> the status,
/// copy the native result into managed records, and hand the native result back to its
/// <c>kgs_*_free</c> in a <c>finally</c>. The frees accept a zeroed record, so the <c>finally</c> is
/// safe whether or not the call succeeded.
/// </remarks>
internal static unsafe class Marshalling
{
    private static readonly Lazy<bool> abiChecked = new(() =>
    {
        uint native = NativeMethods.kgs_abi_version();
        if (native != NativeMethods.KGS_ABI_VERSION)
        {
            throw new InvalidOperationException(
                $"kagisecure_ffi.dll speaks C ABI version {native}, but Kagisecure.Interop was " +
                $"generated against version {NativeMethods.KGS_ABI_VERSION}. Rebuild the DLL with " +
                "`cargo xtask bindgen-cs` from the same checkout.");
        }
        return true;
    });

    /// <summary>
    /// Refuse to make any call into a DLL whose ABI this assembly was not generated for. The same
    /// job UniFFI's contract-version check does for the Swift bindings.
    /// </summary>
    internal static void EnsureAbi() => _ = abiChecked.Value;

    /// <summary>Throw the typed exception for a failed call, consuming its message buffer.</summary>
    internal static void Check(KgsStatus status, ref KgsBuffer error)
    {
        if (status == KgsStatus.Ok)
        {
            return;
        }
        string message = TakeString(ref error);
        throw KagisecureException.From(status, message);
    }

    /// <summary>A Rust-owned string, copied. The buffer stays Rust's: free it with its record.</summary>
    internal static string Str(in KgsBuffer buffer) =>
        buffer.ptr == null || buffer.len == 0
            ? string.Empty
            : Encoding.UTF8.GetString(buffer.ptr, checked((int)buffer.len));

    /// <summary>A Rust-owned optional string, copied.</summary>
    internal static string? Str(in KgsOptBuffer buffer) =>
        buffer.present != 0 ? Str(buffer.value) : null;

    /// <summary>A Rust-owned list of strings, copied.</summary>
    internal static ValueList<string> Strings(in KgsBufferArray list)
    {
        var items = new string[checked((int)list.len)];
        for (int i = 0; i < items.Length; i++)
        {
            items[i] = Str(list.ptr[i]);
        }
        return new ValueList<string>(items);
    }

    /// <summary>A Rust-owned list of records, each converted by <paramref name="convert"/>.</summary>
    internal static ValueList<T> List<TNative, T>(TNative* ptr, nuint len, FromNative<TNative, T> convert)
        where TNative : unmanaged
    {
        var items = new T[checked((int)len)];
        for (int i = 0; i < items.Length; i++)
        {
            items[i] = convert(in ptr[i]);
        }
        return new ValueList<T>(items);
    }

    /// <summary>Copy a Rust-owned string out, then hand the buffer back to be zeroized and freed.</summary>
    internal static string TakeString(ref KgsBuffer buffer)
    {
        try
        {
            return Str(buffer);
        }
        finally
        {
            fixed (KgsBuffer* p = &buffer)
            {
                NativeMethods.kgs_buffer_free(p);
            }
        }
    }

    /// <summary>
    /// Copy Rust-owned bytes out, then hand the buffer back. Never decoded as text (ADR-0003 C3):
    /// the copy is a <c>byte[]</c>, and the caller owns — and must clear — it.
    /// </summary>
    internal static byte[] TakeBytes(ref KgsBuffer buffer)
    {
        try
        {
            return buffer.ptr == null
                ? Array.Empty<byte>()
                : new ReadOnlySpan<byte>(buffer.ptr, checked((int)buffer.len)).ToArray();
        }
        finally
        {
            fixed (KgsBuffer* p = &buffer)
            {
                NativeMethods.kgs_buffer_free(p);
            }
        }
    }

    /// <summary>As <see cref="TakeString(ref KgsBuffer)"/>, for an optional string.</summary>
    internal static string? TakeString(ref KgsOptBuffer buffer)
    {
        bool present = buffer.present != 0;
        string text = TakeString(ref buffer.value);
        return present ? text : null;
    }

    /// <summary>As <see cref="TakeBytes(ref KgsBuffer)"/>, for optional bytes.</summary>
    internal static byte[]? TakeBytes(ref KgsOptBuffer buffer)
    {
        bool present = buffer.present != 0;
        byte[] bytes = TakeBytes(ref buffer.value);
        return present ? bytes : null;
    }

    /// <summary>A 0/1 byte from a boolean.</summary>
    internal static byte Byte(bool value) => value ? (byte)1 : (byte)0;

    /// <summary>A <see cref="TimeSpan"/> as whole milliseconds, clamped to <c>u32</c>.</summary>
    internal static uint Milliseconds(TimeSpan timeout) =>
        (uint)Math.Clamp(timeout.TotalMilliseconds, 0, uint.MaxValue);
}

/// <summary>
/// A string encoded as UTF-8 into a pinned array that is zeroed on dispose, lent to Rust as a
/// <see cref="KgsSlice"/>.
/// </summary>
/// <remarks>
/// Used for every string argument, secret or not, so there is one path and it is the careful one
/// (ADR-0003 rule 5): the UTF-8 copy lives on the pinned object heap, so the GC never moves it and
/// leaves a stale copy behind, and it is cleared the moment the call returns. What this cannot fix
/// is the caller's own <see cref="string"/>; that is why the secret-taking APIs accept
/// <see cref="ReadOnlySpan{T}"/> of <see cref="char"/>, so a caller holding the secret in a
/// clearable <c>char[]</c> never has to make a <see cref="string"/> of it.
/// </remarks>
internal readonly unsafe struct PinnedUtf8 : IDisposable
{
    private readonly byte[] bytes;
    private readonly bool present;

    internal PinnedUtf8(ReadOnlySpan<char> text)
    {
        bytes = GC.AllocateUninitializedArray<byte>(Encoding.UTF8.GetByteCount(text), pinned: true);
        Encoding.UTF8.GetBytes(text, bytes);
        present = true;
    }

    private PinnedUtf8(bool absent)
    {
        bytes = Array.Empty<byte>();
        present = !absent;
    }

    /// <summary>A present string for non-null <paramref name="text"/>, an absent one for null.</summary>
    internal static PinnedUtf8 Optional(string? text) => text is null ? new PinnedUtf8(absent: true) : new PinnedUtf8(text);

    internal KgsSlice Slice =>
        new((byte*)Unsafe.AsPointer(ref MemoryMarshal.GetArrayDataReference(bytes)), bytes.Length);

    internal KgsOptSlice OptSlice => present ? KgsOptSlice.Some(Slice) : KgsOptSlice.None;

    public void Dispose() => CryptographicOperations.ZeroMemory(bytes);
}

/// <summary>
/// A list of strings lent to Rust as a <see cref="KgsSliceList"/>: each one a
/// <see cref="PinnedUtf8"/>, and the slice array itself on the pinned heap.
/// </summary>
internal sealed unsafe class PinnedUtf8List : IDisposable
{
    private readonly PinnedUtf8[] strings;
    private readonly KgsSlice[] slices;

    internal PinnedUtf8List(IReadOnlyList<string> items)
    {
        strings = new PinnedUtf8[items.Count];
        slices = GC.AllocateArray<KgsSlice>(items.Count, pinned: true);
        for (int i = 0; i < items.Count; i++)
        {
            strings[i] = new PinnedUtf8(items[i] ?? throw new ArgumentNullException(nameof(items)));
            slices[i] = strings[i].Slice;
        }
    }

    internal KgsSliceList List => new()
    {
        ptr = slices.Length == 0 ? null : (KgsSlice*)Unsafe.AsPointer(ref MemoryMarshal.GetArrayDataReference(slices)),
        len = (nuint)slices.Length,
    };

    public void Dispose()
    {
        foreach (PinnedUtf8 s in strings)
        {
            s.Dispose();
        }
    }
}
