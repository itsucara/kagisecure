using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Kagisecure.Interop;

namespace Kagisecure.App.Services;

/// <summary>
/// What the agent host and the Agent-access pages need from the vault, beyond
/// <see cref="IVaultService"/>: a lock hook that runs <i>before</i> the session is released, the
/// session itself for the two listeners to take their own reference to, the environments
/// (ui-spec.md §10.4), the vault-level "Share this vault" gate, and a master-password check for the
/// approval sheet's fallback when Windows Hello is not available (ADR-0004: "falls back to a
/// password prompt per injection").
/// </summary>
/// <remarks>
/// A separate interface rather than more members on <see cref="IVaultService"/> so that the item
/// side of the app, and its fake, are not touched by the agent side. <see cref="VaultService"/>
/// implements both.
/// </remarks>
public interface IAgentVaultAccess
{
    /// <summary>
    /// Raised by <see cref="IVaultService.Lock"/> <b>before</b> the session is disposed, on
    /// whatever thread called it. The agent host stops both listeners here, so there is no
    /// interval in which a locked vault is still being served (ADR-0014, ADR-0020).
    /// </summary>
    event EventHandler? Locking;

    /// <summary>Whether a vault is unlocked (the same answer as <see cref="IVaultService.IsUnlocked"/>).</summary>
    bool IsUnlocked { get; }

    /// <summary>
    /// Changes whenever the session does — on every lock (including one with nothing to lock) and
    /// every adopted unlock. The agent host reads it before binding the listeners and again after:
    /// if it moved, the session they were bound to is gone or going, and it stops them itself.
    /// </summary>
    int SessionGeneration { get; }

    /// <summary>
    /// The unlocked session, for <see cref="AgentRuntime"/> to hand to <see cref="Agent.Start"/>
    /// and <see cref="BrowserExtension.Start"/>; <c>null</c> while locked. Nothing else may hold it.
    /// </summary>
    VaultSession? SessionForListeners { get; }

    /// <summary>Every environment: names and bindings, never values.</summary>
    Task<IReadOnlyList<VaultEnvironment>> EnvironmentsAsync(CancellationToken cancellationToken = default);

    /// <summary>Create an empty environment, hidden from agents until the user shares it.</summary>
    Task<VaultEnvironment> CreateEnvironmentAsync(string name, string? description, CancellationToken cancellationToken = default);

    /// <summary>Share an environment with agents, or stop sharing it.</summary>
    Task<VaultEnvironment> SetEnvironmentAgentVisibleAsync(string environmentId, bool visible, CancellationToken cancellationToken = default);

    /// <summary>Set (or add) a literal variable. The value goes straight into the vault.</summary>
    Task<VaultEnvironment> SetVariableValueAsync(string environmentId, string name, string value, CancellationToken cancellationToken = default);

    /// <summary>Remove one variable.</summary>
    Task<VaultEnvironment> RemoveVariableAsync(string environmentId, string name, CancellationToken cancellationToken = default);

    /// <summary>Delete an environment.</summary>
    Task DeleteEnvironmentAsync(string environmentId, CancellationToken cancellationToken = default);

    /// <summary>Whether the default logical vault is shared with agents — the outermost of the three gates (threat-model M-9).</summary>
    Task<bool> VaultAgentVisibleAsync(CancellationToken cancellationToken = default);

    /// <summary>Share the default logical vault with agents, or stop.</summary>
    Task SetVaultAgentVisibleAsync(bool visible, CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether <paramref name="masterPassword"/> opens the vault that is unlocked right now —
    /// checked against the session in memory (<see cref="VaultSession.VerifyMasterPassword"/>),
    /// never against the file on disk, which a same-user process could have swapped for one with a
    /// password it knows or a KDF cost that stalls the app. Runs the KDF off the UI thread. Rate
    /// limited in Rust: after a wrong password the next attempt is not checked until
    /// <see cref="MasterPasswordCheck.RetryAfter"/> has passed.
    /// </summary>
    Task<MasterPasswordCheck> VerifyMasterPasswordAsync(string masterPassword, CancellationToken cancellationToken = default);
}

/// <summary>
/// The vault half of Windows Hello unlock (ADR-0004, ADR-0033): the platform slot in the vault
/// header, and unlocking with a vault key the Hello path unwrapped.
/// </summary>
public interface IWindowsHelloVault
{
    /// <summary>
    /// The vault-file id and the platform slot (id and opaque wrapped key), from one read of the
    /// header, without unlocking.
    /// </summary>
    PlatformSlotInfo PlatformSlotInfoOf(string path);

    /// <summary>The unlocked vault's file id, from the header in memory. Requires an unlocked vault.</summary>
    byte[] CurrentVaultFileId();

    /// <summary>
    /// Unlock with a vault key the Hello path unwrapped (ADR-0008 crossing 4) and adopt the session,
    /// exactly as a password unlock does. The caller clears <paramref name="vaultKey"/> afterwards.
    /// </summary>
    /// <exception cref="KagisecureException.WrongCredential">The key does not open this vault.</exception>
    /// <exception cref="VaultLockedDuringUnlockException">A lock arrived while the unlock ran; the vault stays locked.</exception>
    Task UnlockWithVaultKeyAsync(string path, byte[] vaultKey, CancellationToken cancellationToken = default);

    /// <summary>The unlocked vault's platform slot id, or <c>null</c>. Requires an unlocked vault.</summary>
    string? CurrentPlatformSlotId();

    /// <summary>
    /// The raw vault key, for wrapping (ADR-0008 crossing 3). The caller must clear the array with
    /// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory"/>.
    /// </summary>
    Task<byte[]> ExportVaultKeyForPlatformWrappingAsync(CancellationToken cancellationToken = default);

    /// <summary>Store the wrapped vault key as the platform slot, replacing any, and save.</summary>
    Task InstallPlatformSlotAsync(string slotId, string label, byte[] wrappedKey, CancellationToken cancellationToken = default);

    /// <summary>Remove the platform slot and save. Returns whether there was one.</summary>
    Task<bool> RemovePlatformSlotAsync(CancellationToken cancellationToken = default);
}
