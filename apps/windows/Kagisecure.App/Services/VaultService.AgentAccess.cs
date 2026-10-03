using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kagisecure.Interop;

namespace Kagisecure.App.Services;

/// <summary>The agent side of <see cref="VaultService"/>: see <see cref="IAgentVaultAccess"/>.</summary>
public sealed partial class VaultService : IAgentVaultAccess
{
    /// <inheritdoc />
    public event EventHandler? Locking;

    /// <inheritdoc />
    public VaultSession? SessionForListeners
    {
        get
        {
            lock (gate)
            {
                return session is { IsDisposed: false } s ? s : null;
            }
        }
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<VaultEnvironment>> EnvironmentsAsync(CancellationToken cancellationToken = default) =>
        OnSession(s => s.Environments(), cancellationToken);

    /// <inheritdoc />
    public Task<VaultEnvironment> CreateEnvironmentAsync(string name, string? description, CancellationToken cancellationToken = default) =>
        OnSession(s => s.CreateEnvironment(name, description), cancellationToken);

    /// <inheritdoc />
    public Task<VaultEnvironment> SetEnvironmentAgentVisibleAsync(string environmentId, bool visible, CancellationToken cancellationToken = default) =>
        OnSession(s => s.SetEnvironmentAgentVisible(environmentId, visible), cancellationToken);

    /// <inheritdoc />
    public Task<VaultEnvironment> SetVariableValueAsync(string environmentId, string name, string value, CancellationToken cancellationToken = default) =>
        OnSession(s => s.SetVariableValue(environmentId, name, value), cancellationToken);

    /// <inheritdoc />
    public Task<VaultEnvironment> RemoveVariableAsync(string environmentId, string name, CancellationToken cancellationToken = default) =>
        OnSession(s => s.RemoveVariable(environmentId, name), cancellationToken);

    /// <inheritdoc />
    public Task DeleteEnvironmentAsync(string environmentId, CancellationToken cancellationToken = default) =>
        OnSession(
            s =>
            {
                s.DeleteEnvironment(environmentId);
                return true;
            },
            cancellationToken);

    /// <inheritdoc />
    public Task<bool> VaultAgentVisibleAsync(CancellationToken cancellationToken = default) =>
        OnSession(
            s =>
            {
                string id = s.DefaultVaultId();
                return s.Vaults().FirstOrDefault(v => v.Id == id)?.AgentVisible ?? false;
            },
            cancellationToken);

    /// <inheritdoc />
    public Task SetVaultAgentVisibleAsync(bool visible, CancellationToken cancellationToken = default) =>
        OnSession(s => s.SetVaultAgentVisible(s.DefaultVaultId(), visible), cancellationToken);

    /// <inheritdoc />
    public Task<MasterPasswordCheck> VerifyMasterPasswordAsync(string masterPassword, CancellationToken cancellationToken = default) =>
        // In memory, against this session's own header and key — never the file on disk, which a
        // same-user process could have replaced (threat-model T-3).
        OnSession(s => s.VerifyMasterPassword(masterPassword), cancellationToken);

    /// <inheritdoc />
    public int SessionGeneration
    {
        get
        {
            lock (gate)
            {
                return sessionGeneration;
            }
        }
    }

    private void RaiseLocking() => Locking?.Invoke(this, EventArgs.Empty);

    private Task<T> OnSession<T>(Func<VaultSession, T> body, CancellationToken cancellationToken)
    {
        VaultSession current = RequireSession();
        return Task.Run(() => body(current), cancellationToken);
    }
}
