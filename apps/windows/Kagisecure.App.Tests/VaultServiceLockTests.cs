using System;
using System.IO;
using System.Threading.Tasks;
using Kagisecure.App.Services;
using Kagisecure.Interop;
using Xunit;

namespace Kagisecure.App.Tests;

/// <summary>
/// The real <see cref="VaultService"/>'s lock ordering, against the real FFI and a vault in a temp
/// directory (security review #1 and #2). These are the orderings the agent host relies on.
/// </summary>
public sealed class VaultServiceLockTests : IDisposable
{
    private const string Password = "correct horse battery staple";
    private readonly string directory;
    private readonly string path;
    private readonly VaultService service = new();

    public VaultServiceLockTests()
    {
        directory = Path.Combine(Path.GetTempPath(), "kagisecure-app-lock-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        path = Path.Combine(directory, "v.kagivault");
    }

    public void Dispose()
    {
        service.Dispose();
        try
        {
            Directory.Delete(directory, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    /// <summary>A vault at the cheapest KDF cost, so an unlock takes milliseconds.</summary>
    private void CreateCheapVault()
    {
        using VaultSession created = VaultSession.Create(path, Password, "Personal", 64, 1);
    }

    [Fact]
    public async Task Locking_IsRaisedAfterTheSessionIsTakenOut_SoNothingCanBindItAnyMore()
    {
        CreateCheapVault();
        await service.UnlockAsync(path, Password);
        int before = service.SessionGeneration;
        bool unlockedDuringLocking = true;
        VaultSession? sessionDuringLocking = null;
        int generationDuringLocking = before;
        service.Locking += (_, _) =>
        {
            unlockedDuringLocking = service.IsUnlocked;
            sessionDuringLocking = service.SessionForListeners;
            generationDuringLocking = service.SessionGeneration;
        };

        service.Lock();

        Assert.False(unlockedDuringLocking);
        Assert.Null(sessionDuringLocking);
        Assert.NotEqual(before, generationDuringLocking);
    }

    [Fact]
    public void Lock_RaisesLocking_EvenWithNoSession_SoARacingStartIsStillStopped()
    {
        int lockings = 0;
        service.Locking += (_, _) => lockings++;

        service.Lock();

        Assert.Equal(1, lockings);
    }

    [Fact]
    public async Task ALockDuringTheKdf_Wins_AndTheUnlockedSessionIsNeverAdopted()
    {
        // The default (desktop) KDF cost, so the unlock is still running when Lock() arrives.
        using (VaultSession.Create(path, Password, "Personal"))
        {
        }

        int unlockedEvents = 0;
        int lockedEvents = 0;
        service.Unlocked += (_, _) => unlockedEvents++;
        service.Locked += (_, _) => lockedEvents++;

        Task unlocking = service.UnlockAsync(path, Password);
        await Task.Delay(50);
        Assert.False(unlocking.IsCompleted, "the KDF is still running");
        service.Lock(); // the screen locked

        await Assert.ThrowsAsync<VaultLockedDuringUnlockException>(() => unlocking);
        Assert.False(service.IsUnlocked);
        Assert.Null(service.SessionForListeners);
        Assert.Equal(0, unlockedEvents);
        Assert.Equal(1, lockedEvents);
    }

    [Fact]
    public async Task ReplacingAnOpenSession_GoesThroughLocking()
    {
        CreateCheapVault();
        await service.UnlockAsync(path, Password);
        int lockings = 0;
        service.Locking += (_, _) => lockings++;

        await service.UnlockAsync(path, Password);

        Assert.Equal(1, lockings);
        Assert.True(service.IsUnlocked);
    }

    [Fact]
    public async Task VerifyMasterPassword_UsesTheSessionInMemory()
    {
        CreateCheapVault();
        await service.UnlockAsync(path, Password);
        string other = Path.Combine(directory, "other.kagivault");
        using (VaultSession.Create(other, "known to the attacker", "Personal", 64, 1))
        {
        }

        File.Copy(other, path, overwrite: true);

        MasterPasswordCheck wrong = await service.VerifyMasterPasswordAsync("known to the attacker");
        Assert.Equal(MasterPasswordCheckKind.Wrong, wrong.Kind);
        // Rate limited in Rust: the right password is not even checked until the back-off passes.
        await Task.Delay(wrong.RetryAfter + TimeSpan.FromMilliseconds(200));
        Assert.True((await service.VerifyMasterPasswordAsync(Password)).Verified);
    }
}
