using System;
using System.IO;

namespace Kagisecure.Interop.Tests;

/// <summary>A scratch directory holding one vault path, deleted when the test is done.</summary>
internal sealed class TempVault : IDisposable
{
    /// <summary>The cheapest Argon2id cost the core accepts, so a vault takes milliseconds.</summary>
    internal const uint KdfMKib = 64;
    internal const uint KdfT = 1;

    internal const string Password = "correct horse battery staple";

    internal TempVault()
    {
        Directory = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "kagisecure-interop-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(Directory);
        Path = System.IO.Path.Combine(Directory, "test.kagivault");
    }

    /// <summary>The scratch directory, for anything else a test needs to write.</summary>
    internal string Directory { get; }

    internal string Path { get; }

    internal VaultSession Create() =>
        VaultSession.Create(Path, Password, "Personal", KdfMKib, KdfT);

    public void Dispose()
    {
        try
        {
            System.IO.Directory.Delete(Directory, recursive: true);
        }
        catch (IOException)
        {
            // A handle still open on Windows; the OS temp cleaner will get it.
        }
        catch (UnauthorizedAccessException)
        {
            // As above.
        }
    }
}
