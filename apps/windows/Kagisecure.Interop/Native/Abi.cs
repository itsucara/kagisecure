// The hand-written half of the native layer. The declarations themselves are generated into
// NativeMethods.g.cs by `cargo xtask bindgen-cs` from crates/kagisecure-ffi/src/capi/ and must not
// be edited; this file holds only what csbindgen does not emit.
//
// The whole assembly runs with runtime marshalling disabled, so every type crossing the boundary
// is blittable and passed exactly as laid out: a generated signature can only disagree with the
// Rust if the generated file is stale, and xtask's `generated_csharp_is_up_to_date` test fails
// when it is. At run time, kgs_abi_version is checked once, before the first call, against the
// generated KGS_ABI_VERSION.

using System.Runtime.CompilerServices;

[assembly: DisableRuntimeMarshalling]
[assembly: InternalsVisibleTo("Kagisecure.Interop.Tests")]

namespace Kagisecure.Interop.Native;

/// <summary>A borrowed <c>{ptr, len}</c> of UTF-8 or raw bytes.</summary>
internal unsafe partial struct KgsSlice
{
    /// <summary>Lend <paramref name="length"/> bytes at <paramref name="start"/>; null when empty.</summary>
    public KgsSlice(byte* start, int length)
    {
        ptr = length == 0 ? null : start;
        len = (nuint)length;
    }
}

/// <summary>An optional <see cref="KgsSlice"/>.</summary>
internal partial struct KgsOptSlice
{
    /// <summary>Absent: <c>value</c> is never read.</summary>
    public static KgsOptSlice None => default;

    /// <summary>Present, holding <paramref name="slice"/>.</summary>
    public static KgsOptSlice Some(KgsSlice slice) => new() { present = 1, value = slice };
}

/// <summary>An optional <c>u32</c>.</summary>
internal partial struct KgsOptU32
{
    /// <summary>From a nullable.</summary>
    public static KgsOptU32 From(uint? value) =>
        value is uint v ? new KgsOptU32 { present = 1, value = v } : default;

    /// <summary>To a nullable.</summary>
    public readonly uint? ToNullable() => present != 0 ? value : null;
}

/// <summary>An optional boolean.</summary>
internal partial struct KgsOptBool
{
    /// <summary>To a nullable.</summary>
    public readonly bool? ToNullable() => present != 0 ? value != 0 : null;
}
