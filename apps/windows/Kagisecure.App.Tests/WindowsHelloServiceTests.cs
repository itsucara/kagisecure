using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Kagisecure.App.Services;
using Kagisecure.App.ViewModels;
using Xunit;

namespace Kagisecure.App.Tests;

public sealed class WindowsHelloServiceTests : IDisposable
{
    private const string Path = @"C:\fake\default.kagivault";

    private readonly FakeHelloKeys keys = new();
    private readonly FakeHelloSecrets secrets = new();
    private readonly FakeHelloVault vault = new();
    private readonly List<string> log = new();
    private readonly WindowsHelloService hello;

    public WindowsHelloServiceTests()
    {
        hello = new WindowsHelloService(keys, secrets, vault, log.Add);
    }

    public void Dispose() => keys.Dispose();

    private async Task<string> EnrolAsync()
    {
        HelloResult enrolled = await hello.EnableAsync();
        Assert.Equal(HelloUnlockStatus.Unlocked, enrolled.Status);
        vault.Unlocked = false;
        return vault.SlotId!;
    }

    private static bool AllZero(byte[] bytes) => bytes.All(b => b == 0);

    [Fact]
    public async Task Enrol_ThenUnlock_HandsTheVaultTheExactVaultKey_AndClearsEveryBuffer()
    {
        string slot = await EnrolAsync();

        Assert.True(WindowsHelloCrypto.IsWindowsHelloSlot(slot));
        Assert.StartsWith("Windows Hello on ", vault.Label);
        Assert.Equal(WindowsHelloCrypto.BlobLength, vault.Blob!.Length);
        Assert.True(hello.IsEnrolledAt(Path));

        HelloResult unlocked = await hello.UnlockAsync(Path);

        Assert.Equal(HelloUnlockStatus.Unlocked, unlocked.Status);
        Assert.Equal(1, vault.Unlocks);
        Assert.Equal(vault.VaultKey, vault.KeysOffered.Single());

        // byte[] buffers are cleared after use: the exported vault key, the unwrapped vault key,
        // every Hello signature and every copy of the app secret.
        Assert.All(vault.ArraysHandedOut, a => Assert.True(AllZero(a)));
        Assert.All(keys.SignaturesHandedOut, s => Assert.True(AllZero(s)));
        Assert.All(secrets.HandedOut, s => Assert.True(AllZero(s)));
    }

    [Fact]
    public async Task HelloConsentAlone_IsNotEnough_TheDpapiSecretIsTheOtherHalf()
    {
        string slot = await EnrolAsync();
        secrets.LoseBehindTheAppsBack(slot);

        HelloResult result = await hello.UnlockAsync(Path);

        Assert.Equal(HelloUnlockStatus.NeedsReEnroll, result.Status);
        Assert.Equal(0, vault.Unlocks);
        Assert.True(hello.NeedsReEnroll);
    }

    [Fact]
    public async Task CredentialDeleted_FallsBackToThePassword_AndAsksForReEnrolment()
    {
        string slot = await EnrolAsync();
        keys.DeleteBehindTheAppsBack(WindowsHelloCrypto.CredentialName(slot));

        HelloResult result = await hello.UnlockAsync(Path);

        Assert.Equal(HelloUnlockStatus.NeedsReEnroll, result.Status);
        Assert.Contains("master password", result.Message);
        Assert.Contains("Windows Hello back on", result.Message);
        Assert.Equal(0, vault.Unlocks);
    }

    [Fact]
    public async Task CredentialReplaced_UnwrapFails_AndFallsBackToThePassword()
    {
        string slot = await EnrolAsync();
        keys.ReplaceBehindTheAppsBack(WindowsHelloCrypto.CredentialName(slot));

        HelloResult result = await hello.UnlockAsync(Path);

        Assert.Equal(HelloUnlockStatus.NeedsReEnroll, result.Status);
        Assert.Equal(0, vault.Unlocks);
        Assert.Empty(vault.KeysOffered);
    }

    [Fact]
    public async Task Cancelled_IsNotAnError_AndUnlocksNothing()
    {
        await EnrolAsync();
        keys.NextStatus = HelloKeyStatus.Cancelled;

        HelloResult result = await hello.UnlockAsync(Path);

        Assert.Equal(HelloUnlockStatus.Cancelled, result.Status);
        Assert.Null(result.Message);
        Assert.False(hello.NeedsReEnroll);
        Assert.Equal(0, vault.Unlocks);
    }

    [Fact]
    public async Task Unavailable_SaysWhy_AndNeverPrompts()
    {
        await EnrolAsync();
        int prompts = keys.Prompts;
        keys.Availability = new HelloAvailability(false, "This PC has no TPM.");

        HelloResult result = await hello.UnlockAsync(Path);

        Assert.Equal(HelloUnlockStatus.Unavailable, result.Status);
        Assert.Equal("This PC has no TPM.", result.Message);
        Assert.Equal(prompts, keys.Prompts);
    }

    [Fact]
    public async Task NotEnrolled_WhenTheSlotIsSomeoneElses()
    {
        vault.SlotId = "macos-secure-enclave";
        vault.Blob = new byte[] { 1, 2, 3 };

        Assert.False(hello.IsEnrolledAt(Path));
        HelloResult result = await hello.UnlockAsync(Path);

        Assert.Equal(HelloUnlockStatus.NotEnrolled, result.Status);
        Assert.Equal(0, keys.Prompts);
        Assert.Equal(PlatformSlotKind.MacTouchId, hello.Classify(vault.SlotId));
    }

    [Fact]
    public async Task ASlotEnrolledOnAnotherPc_IsNotOffered_AndIsShownAsSuch()
    {
        string slot = await EnrolAsync();
        secrets.LoseBehindTheAppsBack(slot); // what this PC looks like to a slot enrolled elsewhere

        Assert.False(hello.IsEnrolledAt(Path));
        Assert.Equal(PlatformSlotKind.OtherWindowsHello, hello.Classify(slot));
        Assert.Equal(PlatformSlotKind.OtherWindowsHello, hello.Classify("windows-hello-v1-0011"));
        secrets.Plant(slot);
        Assert.Equal(PlatformSlotKind.ThisPc, hello.Classify(slot));
    }

    [Fact]
    public async Task Unlock_ReadsTheHeaderOnce()
    {
        await EnrolAsync();
        int before = vault.HeaderReads;

        await hello.UnlockAsync(Path);

        Assert.Equal(1, vault.HeaderReads - before);
        Assert.Equal(1, vault.Unlocks);
    }

    [Fact]
    public async Task ABlobCopiedIntoAnotherVaultFile_DoesNotUnwrap()
    {
        await EnrolAsync();
        vault.VaultId = RandomNumberGenerator.GetBytes(16); // same slot and blob, a different vault file

        HelloResult result = await hello.UnlockAsync(Path);

        Assert.Equal(HelloUnlockStatus.NeedsReEnroll, result.Status);
        Assert.Empty(vault.KeysOffered);
    }

    [Fact]
    public async Task ALockDuringTheUnlock_IsReportedAsSuch_NotAsAHelloFailure()
    {
        await EnrolAsync();
        vault.LockArrivesDuringUnlock = true;

        HelloResult result = await hello.UnlockAsync(Path);

        Assert.Equal(HelloUnlockStatus.LockedMeanwhile, result.Status);
        Assert.False(hello.NeedsReEnroll);
        Assert.All(vault.ArraysHandedOut, a => Assert.True(AllZero(a)));
    }

    [Fact]
    public async Task EnrolmentWithoutTpmAttestation_IsRefused_AndLeavesNothingBehind()
    {
        keys.NextStatus = HelloKeyStatus.NotHardwareBacked;

        HelloResult result = await hello.EnableAsync();

        Assert.Equal(HelloUnlockStatus.Unavailable, result.Status);
        Assert.Null(vault.SlotId);
        Assert.Single(secrets.Deleted);
    }

    [Fact]
    public void TheHelloDialog_IsOnlyForegroundedWhenItIsTheSystemBroker()
    {
        const string root = @"C:\Windows";
        Assert.True(HelloDialogFocus.IsSystemCredentialBroker(@"C:\Windows\System32\CredentialUIBroker.exe", root));
        Assert.True(HelloDialogFocus.IsSystemCredentialBroker(@"c:\windows\system32\credentialuibroker.exe", root));
        Assert.False(HelloDialogFocus.IsSystemCredentialBroker(@"C:\Users\x\AppData\Local\Temp\CredentialUIBroker.exe", root));
        Assert.False(HelloDialogFocus.IsSystemCredentialBroker(@"C:\Windows\System32\evil\CredentialUIBroker.exe", root));
        Assert.False(HelloDialogFocus.IsSystemCredentialBroker(@"C:\Windows\SysWOW64\CredentialUIBroker.exe", root));
        Assert.False(HelloDialogFocus.IsSystemCredentialBroker(null, root));
        Assert.False(HelloDialogFocus.IsSystemCredentialBroker(@"C:\Windows\System32\notepad.exe", root));
    }

    [Fact]
    public async Task WrappedKeyAndEveryOtherSecret_NeverReachTheLogOrAMessage()
    {
        string slot = await EnrolAsync();
        await hello.UnlockAsync(Path);
        byte[] blob = vault.Blob!;
        byte[] secret = secrets.Peek(slot);

        // Every failure path, so every log line and message is produced at least once.
        var messages = new List<string?>();
        keys.ReplaceBehindTheAppsBack(WindowsHelloCrypto.CredentialName(slot));
        messages.Add((await hello.UnlockAsync(Path)).Message);
        vault.Blob = blob.Select(b => (byte)(b ^ 0xFF)).ToArray();
        messages.Add((await hello.UnlockAsync(Path)).Message);
        keys.NextStatus = HelloKeyStatus.Failed;
        messages.Add((await hello.UnlockAsync(Path)).Message);

        var forbidden = new List<string>();
        foreach (byte[] value in new[] { blob, secret, vault.VaultKey })
        {
            forbidden.Add(Convert.ToHexString(value));
            forbidden.Add(Convert.ToHexString(value).ToLowerInvariant());
            forbidden.Add(Convert.ToBase64String(value));
            forbidden.Add(BitConverter.ToString(value));
        }

        IEnumerable<string> said = log.Concat(messages.Where(m => m is not null)!)!;
        Assert.NotEmpty(log);
        foreach (string line in said)
        {
            foreach (string f in forbidden)
            {
                Assert.DoesNotContain(f, line, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    [Fact]
    public async Task Disable_RemovesTheSlot_AndDeletesTheHelloKeyAndTheSecret()
    {
        await hello.EnableAsync();
        string slot = vault.SlotId!;

        HelloResult result = await hello.DisableAsync();

        Assert.Equal(HelloUnlockStatus.NotEnrolled, result.Status);
        Assert.Null(vault.SlotId);
        Assert.False(keys.Has(WindowsHelloCrypto.CredentialName(slot)));
        Assert.False(secrets.Has(slot));
    }

    [Fact]
    public async Task ReEnrolling_ReplacesTheSlot_AndForgetsTheOldKey()
    {
        await hello.EnableAsync();
        string first = vault.SlotId!;

        await hello.EnableAsync();
        string second = vault.SlotId!;

        Assert.NotEqual(first, second);
        Assert.False(keys.Has(WindowsHelloCrypto.CredentialName(first)));
        Assert.False(secrets.Has(first));
        Assert.True(keys.Has(WindowsHelloCrypto.CredentialName(second)));
    }

    [Fact]
    public async Task EnrolmentCancelled_LeavesNothingBehind()
    {
        keys.NextStatus = HelloKeyStatus.Cancelled;

        HelloResult result = await hello.EnableAsync();

        Assert.Equal(HelloUnlockStatus.Cancelled, result.Status);
        Assert.Null(vault.SlotId);
        Assert.Empty(vault.ArraysHandedOut);
    }

    [Fact]
    public void Crypto_RoundTrips_AndFailsClosed()
    {
        string slot = WindowsHelloCrypto.NewSlotId();
        byte[] vk = RandomNumberGenerator.GetBytes(32);
        byte[] sig = RandomNumberGenerator.GetBytes(256);
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        byte[] vaultId = RandomNumberGenerator.GetBytes(16);
        byte[] kek = WindowsHelloCrypto.DeriveKek(sig, secret, slot);
        byte[] blob = WindowsHelloCrypto.Wrap(kek, vk, slot, vaultId);

        Assert.Equal(vk, WindowsHelloCrypto.Unwrap(kek, blob, slot, vaultId));

        // Either input alone is not the key.
        byte[] otherSecret = RandomNumberGenerator.GetBytes(32);
        Assert.Null(WindowsHelloCrypto.Unwrap(WindowsHelloCrypto.DeriveKek(sig, otherSecret, slot), blob, slot, vaultId));
        byte[] otherSig = RandomNumberGenerator.GetBytes(256);
        Assert.Null(WindowsHelloCrypto.Unwrap(WindowsHelloCrypto.DeriveKek(otherSig, secret, slot), blob, slot, vaultId));

        // Bound to its slot id, to its vault file, and to its bytes.
        Assert.Null(WindowsHelloCrypto.Unwrap(kek, blob, WindowsHelloCrypto.NewSlotId(), vaultId));
        Assert.Null(WindowsHelloCrypto.Unwrap(kek, blob, slot, RandomNumberGenerator.GetBytes(16)));
        byte[] tampered = (byte[])blob.Clone();
        tampered[^1] ^= 1;
        Assert.Null(WindowsHelloCrypto.Unwrap(kek, tampered, slot, vaultId));
        Assert.Null(WindowsHelloCrypto.Unwrap(kek, blob.AsSpan(0, 10), slot, vaultId));
        Assert.Equal((byte)'2', blob[3]); // "KGH2": the vault-id-bound version

        // Secrets live on the pinned heap (generation 2 in the GC's accounting, and never moved).
        Assert.Equal(GC.MaxGeneration, GC.GetGeneration(kek));

        // The per-slot challenge is fixed (so a deterministic signature is reproducible) and per slot.
        Assert.Equal(WindowsHelloCrypto.Challenge(slot), WindowsHelloCrypto.Challenge(slot));
        Assert.NotEqual(WindowsHelloCrypto.Challenge(slot), WindowsHelloCrypto.Challenge(WindowsHelloCrypto.NewSlotId()));
    }

    [Fact]
    public void Dpapi_SecretStore_RoundTrips_AndIsBoundToItsSlot()
    {
        string dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "kagisecure-hello-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new DpapiWindowsHelloSecretStore(dir);
            string slot = WindowsHelloCrypto.NewSlotId();
            byte[] created = store.Create(slot);
            byte[] loaded = store.Load(slot)!;
            Assert.Equal(created, loaded);

            // The file on disk is DPAPI output, not the secret.
            byte[] onDisk = File.ReadAllBytes(System.IO.Path.Combine(dir, slot + ".dpapi"));
            Assert.False(onDisk.AsSpan().IndexOf(created) >= 0);

            // Copied over another slot's file, it does not unprotect (the entropy names the slot).
            string other = WindowsHelloCrypto.NewSlotId();
            File.Copy(System.IO.Path.Combine(dir, slot + ".dpapi"), System.IO.Path.Combine(dir, other + ".dpapi"));
            Assert.Null(store.Load(other));

            store.Delete(slot);
            Assert.Null(store.Load(slot));
            Assert.Throws<ArgumentException>(() => store.Load(@"..\evil"));
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    [Fact]
    public void ScopeNotice_SaysPlainlyWhatEnrollingCosts()
    {
        // ADR-0033 §5: what the protection drops to, why (the PIN, not invalidated by new
        // fingerprints, keys belong to the account), that one approved prompt is enough, and that
        // it is weaker than the Mac.
        Assert.Contains("anyone who can sign in to this Windows account", WindowsHelloService.ScopeNotice);
        Assert.Contains("always accepts your Windows PIN", WindowsHelloService.ScopeNotice);
        Assert.Contains("adding a fingerprint does not reset it", WindowsHelloService.ScopeNotice);
        Assert.Contains("belong to your account, not to kagisecure", WindowsHelloService.ScopeNotice);
        Assert.Contains("one approved prompt is enough", WindowsHelloService.ScopeNotice);
        Assert.Contains("weaker than Touch ID", WindowsHelloService.ScopeNotice);
    }
}

public sealed class LockViewModelWindowsHelloTests : IDisposable
{
    private readonly FakeVaultService vaultService = new();
    private readonly FakeHelloKeys keys = new();
    private readonly FakeHelloSecrets secrets = new();
    private readonly FakeHelloVault helloVault = new();
    private readonly WindowsHelloService hello;

    public LockViewModelWindowsHelloTests()
    {
        hello = new WindowsHelloService(keys, secrets, helloVault);
    }

    public void Dispose() => keys.Dispose();

    private async Task<LockViewModel> EnrolledLockScreenAsync()
    {
        await hello.EnableAsync();
        helloVault.Unlocked = false;
        var vm = new LockViewModel(vaultService, hello);
        await vm.RefreshHelloStateAsync();
        return vm;
    }

    [Fact]
    public void NotEnrolled_NoHelloButton()
    {
        var vm = new LockViewModel(vaultService, hello);
        Assert.False(vm.ShowHelloButton);
    }

    [Fact]
    public async Task Enrolled_OffersHello_AndUnlocks()
    {
        LockViewModel vm = await EnrolledLockScreenAsync();
        bool unlocked = false;
        vm.Unlocked += (_, _) => unlocked = true;

        Assert.True(vm.ShowHelloButton);
        Assert.True(vm.HelloButtonEnabled);
        await vm.UnlockWithHelloCommand.ExecuteAsync(null);

        Assert.True(unlocked);
        Assert.Null(vm.ErrorMessage);
        Assert.Equal(1, helloVault.Unlocks);
    }

    [Fact]
    public async Task HelloUnwrapFailure_FallsBackToThePassword()
    {
        LockViewModel vm = await EnrolledLockScreenAsync();
        keys.ReplaceBehindTheAppsBack(WindowsHelloCrypto.CredentialName(helloVault.SlotId!));
        bool unlocked = false;
        vm.Unlocked += (_, _) => unlocked = true;

        await vm.UnlockWithHelloCommand.ExecuteAsync(null);

        Assert.False(unlocked);
        Assert.False(vm.ShowHelloButton); // stops offering an unlock it cannot perform
        Assert.Contains("master password", vm.ErrorMessage);

        // The password path is untouched.
        vm.MasterPassword = "correct horse battery staple";
        await vm.UnlockCommand.ExecuteAsync(null);
        Assert.True(unlocked);
        Assert.True(vaultService.IsUnlocked);
    }

    [Fact]
    public async Task Cancel_IsSilent()
    {
        LockViewModel vm = await EnrolledLockScreenAsync();
        keys.NextStatus = HelloKeyStatus.Cancelled;

        await vm.UnlockWithHelloCommand.ExecuteAsync(null);

        Assert.Null(vm.ErrorMessage);
        Assert.True(vm.HelloButtonEnabled);
    }

    [Fact]
    public async Task ThreeFailures_LeaveOnlyThePassword()
    {
        LockViewModel vm = await EnrolledLockScreenAsync();
        for (int i = 0; i < LockViewModel.MaxHelloFailures; i++)
        {
            keys.NextStatus = HelloKeyStatus.Failed;
            await vm.UnlockWithHelloCommand.ExecuteAsync(null);
        }

        Assert.False(vm.HelloButtonEnabled);
        Assert.NotNull(vm.HelloNote);
        Assert.Equal(0, helloVault.Unlocks);
    }

    [Fact]
    public async Task Unavailable_DisablesTheButton_WithTheReason()
    {
        await hello.EnableAsync();
        helloVault.Unlocked = false;
        keys.Availability = new HelloAvailability(false, "Windows Hello is not set up for this account.");
        var vm = new LockViewModel(vaultService, hello);

        await vm.RefreshHelloStateAsync();

        Assert.True(vm.ShowHelloButton);
        Assert.False(vm.HelloButtonEnabled);
        Assert.Equal("Windows Hello is not set up for this account.", vm.HelloNote);
    }

    [Fact]
    public async Task APasswordUnlockInFlight_DisablesTheHelloButton_SoTwoUnlocksCannotRace()
    {
        LockViewModel vm = await EnrolledLockScreenAsync();
        bool notified = false;
        vm.UnlockWithHelloCommand.CanExecuteChanged += (_, _) => notified = true;
        vaultService.UnlockGate = new TaskCompletionSource();
        vm.MasterPassword = "pw";

        Task unlocking = vm.UnlockCommand.ExecuteAsync(null);

        Assert.True(vm.IsBusy);
        Assert.True(notified, "the Hello command is told when IsBusy changes");
        Assert.False(vm.UnlockWithHelloCommand.CanExecute(null));
        vaultService.UnlockGate.SetResult();
        await unlocking;
        Assert.Equal(0, helloVault.Unlocks);
    }

    [Fact]
    public async Task ALockDuringTheUnlock_ShowsWhyTheVaultIsStillLocked()
    {
        LockViewModel vm = await EnrolledLockScreenAsync();
        vaultService.UnlockThrows = new VaultLockedDuringUnlockException();
        vm.MasterPassword = "pw";

        await vm.UnlockCommand.ExecuteAsync(null);

        Assert.Equal(VaultLockedDuringUnlockException.DefaultMessage, vm.ErrorMessage);
        Assert.False(vaultService.IsUnlocked);
    }
}
