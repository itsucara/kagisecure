using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.Tests;

/// <summary>
/// Windows Hello without Windows Hello: one RSA key per credential name, signing with
/// RSASSA-PKCS1-v1_5 exactly as a Hello key does (so signatures are deterministic), and a switch
/// for each way the real thing can refuse.
/// </summary>
internal sealed class FakeHelloKeys : IWindowsHelloKeys, IDisposable
{
    private readonly Dictionary<string, RSA> keys = new();

    public HelloAvailability Availability { get; set; } = new(true, null);

    /// <summary>The next sign/create returns this instead of signing.</summary>
    public HelloKeyStatus? NextStatus { get; set; }

    public List<string> Deleted { get; } = new();

    public List<byte[]> SignaturesHandedOut { get; } = new();

    public int Prompts { get; private set; }

    public bool Has(string name) => keys.ContainsKey(name);

    /// <summary>Somebody deleted the credential behind the app's back (Windows Settings, a reset).</summary>
    public void DeleteBehindTheAppsBack(string name) => keys.Remove(name);

    /// <summary>Somebody created a new credential under the same name: same name, different key.</summary>
    public void ReplaceBehindTheAppsBack(string name)
    {
        keys[name].Dispose();
        keys[name] = RSA.Create(2048);
    }

    public Task<HelloAvailability> AvailabilityAsync() => Task.FromResult(Availability);

    public Task<HelloSignResult> CreateAndSignAsync(string credentialName, byte[] challenge)
    {
        Prompts++;
        if (Refusal() is { } refused)
        {
            return Task.FromResult(refused);
        }

        keys[credentialName] = RSA.Create(2048);
        Prompts++;
        return Task.FromResult(Sign(credentialName, challenge));
    }

    public Task<HelloSignResult> SignAsync(string credentialName, byte[] challenge)
    {
        if (!keys.ContainsKey(credentialName))
        {
            return Task.FromResult(new HelloSignResult(HelloKeyStatus.NotFound, Message: "The Windows Hello key for this vault no longer exists."));
        }

        Prompts++;
        if (Refusal() is { } refused)
        {
            return Task.FromResult(refused);
        }

        return Task.FromResult(Sign(credentialName, challenge));
    }

    public Task DeleteAsync(string credentialName)
    {
        Deleted.Add(credentialName);
        if (keys.Remove(credentialName, out RSA? key))
        {
            key.Dispose();
        }

        return Task.CompletedTask;
    }

    private HelloSignResult? Refusal()
    {
        if (NextStatus is { } status)
        {
            NextStatus = null;
            return new HelloSignResult(status, Message: status == HelloKeyStatus.Cancelled ? null : $"refused: {status}");
        }

        return null;
    }

    private HelloSignResult Sign(string name, byte[] challenge)
    {
        byte[] signature = keys[name].SignData(challenge, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        SignaturesHandedOut.Add(signature);
        return new HelloSignResult(HelloKeyStatus.Success, signature);
    }

    public void Dispose()
    {
        foreach (RSA key in keys.Values)
        {
            key.Dispose();
        }
    }
}

/// <summary>DPAPI without DPAPI: an in-memory map standing in for the protected files.</summary>
internal sealed class FakeHelloSecrets : IWindowsHelloSecretStore
{
    private readonly Dictionary<string, byte[]> stored = new();

    public List<byte[]> HandedOut { get; } = new();

    public List<string> Deleted { get; } = new();

    public bool Has(string slotId) => stored.ContainsKey(slotId);

    public byte[] Peek(string slotId) => (byte[])stored[slotId].Clone();

    public void LoseBehindTheAppsBack(string slotId) => stored.Remove(slotId);

    public byte[] Create(string slotId)
    {
        byte[] secret = RandomNumberGenerator.GetBytes(WindowsHelloCrypto.AppSecretLength);
        stored[slotId] = (byte[])secret.Clone();
        HandedOut.Add(secret);
        return secret;
    }

    public byte[]? Load(string slotId)
    {
        if (!stored.TryGetValue(slotId, out byte[]? secret))
        {
            return null;
        }

        byte[] copy = (byte[])secret.Clone();
        HandedOut.Add(copy);
        return copy;
    }

    public bool Exists(string slotId) => stored.ContainsKey(slotId);

    /// <summary>Plant a secret as if this profile had enrolled the slot (for "this PC" states).</summary>
    public void Plant(string slotId) => stored[slotId] = RandomNumberGenerator.GetBytes(WindowsHelloCrypto.AppSecretLength);

    public void Delete(string slotId)
    {
        Deleted.Add(slotId);
        stored.Remove(slotId);
    }
}

/// <summary>The vault's platform slot, in memory, with a real 32-byte vault key.</summary>
internal sealed class FakeHelloVault : IWindowsHelloVault
{
    public byte[] VaultKey { get; } = RandomNumberGenerator.GetBytes(32);

    public string? SlotId { get; set; }

    public byte[]? Blob { get; set; }

    public string? Label { get; private set; }

    public bool Unlocked { get; set; } = true;

    /// <summary>Copies of every key handed to <see cref="UnlockWithVaultKeyAsync"/>, taken at call time.</summary>
    public List<byte[]> KeysOffered { get; } = new();

    /// <summary>The arrays handed to callers — so a test can check they were cleared afterwards.</summary>
    public List<byte[]> ArraysHandedOut { get; } = new();

    public int Unlocks { get; private set; }

    /// <summary>The header's vault-file id.</summary>
    public byte[] VaultId { get; set; } = RandomNumberGenerator.GetBytes(16);

    /// <summary>How many times the header was read — the unlock reads it once.</summary>
    public int HeaderReads { get; private set; }

    /// <summary>Set to make the next unlock report that a lock arrived while it ran.</summary>
    public bool LockArrivesDuringUnlock { get; set; }

    public PlatformSlotInfo PlatformSlotInfoOf(string path)
    {
        HeaderReads++;
        return new PlatformSlotInfo((byte[])VaultId.Clone(), SlotId, Blob is null ? null : (byte[])Blob.Clone());
    }

    public byte[] CurrentVaultFileId() =>
        Unlocked ? (byte[])VaultId.Clone() : throw new InvalidOperationException("The vault is locked.");

    public Task UnlockWithVaultKeyAsync(string path, byte[] vaultKey, CancellationToken cancellationToken = default)
    {
        KeysOffered.Add((byte[])vaultKey.Clone());
        ArraysHandedOut.Add(vaultKey);
        if (LockArrivesDuringUnlock)
        {
            LockArrivesDuringUnlock = false;
            return Task.FromException(new VaultLockedDuringUnlockException());
        }

        if (!CryptographicOperations.FixedTimeEquals(vaultKey, VaultKey))
        {
            return Task.FromException(KagisecureExceptionFactory.Create<KagisecureException.WrongCredential>("wrong key"));
        }

        Unlocks++;
        Unlocked = true;
        return Task.CompletedTask;
    }

    public string? CurrentPlatformSlotId() =>
        Unlocked ? SlotId : throw new InvalidOperationException("The vault is locked.");

    public Task<byte[]> ExportVaultKeyForPlatformWrappingAsync(CancellationToken cancellationToken = default)
    {
        byte[] copy = (byte[])VaultKey.Clone();
        ArraysHandedOut.Add(copy);
        return Task.FromResult(copy);
    }

    public Task InstallPlatformSlotAsync(string slotId, string label, byte[] wrappedKey, CancellationToken cancellationToken = default)
    {
        SlotId = slotId;
        Label = label;
        Blob = (byte[])wrappedKey.Clone();
        return Task.CompletedTask;
    }

    public Task<bool> RemovePlatformSlotAsync(CancellationToken cancellationToken = default)
    {
        bool had = SlotId is not null;
        SlotId = null;
        Blob = null;
        return Task.FromResult(had);
    }
}
