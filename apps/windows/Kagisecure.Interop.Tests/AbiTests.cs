using System;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using Kagisecure.Interop.Native;
using Xunit;

namespace Kagisecure.Interop.Tests;

/// <summary>
/// The C# half of the drift check. xtask's <c>generated_csharp_is_up_to_date</c> proves the
/// checked-in declarations match the Rust sources; these prove the DLL on disk matches the
/// declarations, which is the drift a stale <c>cargo xtask bindgen-cs</c> run would leave behind.
/// </summary>
public class AbiTests
{
    [Fact]
    public void The_dll_speaks_the_abi_version_the_declarations_were_generated_for()
    {
        Assert.Equal(NativeMethods.KGS_ABI_VERSION, NativeMethods.kgs_abi_version());
    }

    [Fact]
    public void Every_declared_entry_point_is_exported_by_the_dll()
    {
        var entryPoints = typeof(NativeMethods)
            .GetMethods(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)
            .Select(m => m.GetCustomAttribute<DllImportAttribute>())
            .Where(a => a is not null)
            .Select(a => a!.EntryPoint!)
            .ToList();
        Assert.True(entryPoints.Count > 100, $"only {entryPoints.Count} declarations found");
        Assert.All(entryPoints, name => Assert.StartsWith("kgs_", name));

        IntPtr library = NativeLibrary.Load("kagisecure_ffi", typeof(VaultSession).Assembly, null);
        var missing = entryPoints.Where(name => !NativeLibrary.TryGetExport(library, name, out _)).ToList();
        Assert.True(missing.Count == 0, "declared but not exported: " + string.Join(", ", missing));
    }

    [Fact]
    public void Value_lists_compare_by_content()
    {
        var a = new ValueList<string>(new[] { "x", "y" });
        var b = new ValueList<string>(new[] { "x", "y" });
        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.NotEqual(a, new ValueList<string>(new[] { "y", "x" }));
        Assert.Empty(ValueList<int>.Empty);
    }
}
