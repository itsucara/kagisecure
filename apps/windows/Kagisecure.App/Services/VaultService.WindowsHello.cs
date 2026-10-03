using System;
using System.Threading;
using System.Threading.Tasks;
using Kagisecure.Interop;

namespace Kagisecure.App.Services;

/// <summary>The platform-slot side of <see cref="VaultService"/>: see <see cref="IWindowsHelloVault"/>.</summary>
public sealed partial class VaultService : IWindowsHelloVault
{
    /// <inheritdoc />
    public PlatformSlotInfo PlatformSlotInfoOf(string path) => VaultSession.PlatformSlotInfoOf(path);

    /// <inheritdoc />
    public byte[] CurrentVaultFileId() => RequireSession().VaultFileId();

    /// <inheritdoc />
    public async Task UnlockWithVaultKeyAsync(string path, byte[] vaultKey, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        int startedAt = CurrentLockGeneration();
        // The key crosses as a span over the caller's array: the interop layer pins it and hands
        // Rust a pointer, Rust copies it once into a buffer it wipes before returning (ADR-0008
        // crossing 4), and the caller clears its own array when this returns. No other copy is
        // made on this side.
        VaultSession unlocked = await Task.Run(
            () => VaultSession.UnlockWithVaultKey(path, vaultKey), cancellationToken).ConfigureAwait(false);
        AdoptOrThrow(unlocked, startedAt, requiresPasswordChange: false);
    }

    /// <inheritdoc />
    public string? CurrentPlatformSlotId() => RequireSession().PlatformSlotId();

    /// <inheritdoc />
    public Task<byte[]> ExportVaultKeyForPlatformWrappingAsync(CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return Task.Run(
            () =>
            {
                // Moved onto the pinned heap before it crosses an await, and the interop layer's
                // own (movable) copy cleared at once, so the GC cannot leave a stray copy behind.
                byte[] raw = current.ExportVaultKeyForPlatformWrapping();
                try
                {
                    return WindowsHelloCrypto.PinnedCopy(raw);
                }
                finally
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(raw);
                }
            },
            cancellationToken);
    }

    /// <inheritdoc />
    public Task InstallPlatformSlotAsync(string slotId, string label, byte[] wrappedKey, CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return Task.Run(() => current.InstallPlatformSlot(slotId, label, wrappedKey), cancellationToken);
    }

    /// <inheritdoc />
    public Task<bool> RemovePlatformSlotAsync(CancellationToken cancellationToken = default)
    {
        VaultSession current = RequireSession();
        return Task.Run(() => current.RemovePlatformSlot(), cancellationToken);
    }
}
