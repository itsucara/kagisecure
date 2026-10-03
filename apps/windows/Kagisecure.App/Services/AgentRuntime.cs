using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Kagisecure.Interop;

namespace Kagisecure.App.Services;

/// <summary>
/// Everything <see cref="AgentHostService"/> and the Agent-access pages need from the two
/// process-global listeners (<see cref="Agent"/> and <see cref="BrowserExtension"/>): a seam, so
/// the host's logic — the one-sheet-at-a-time queue, the verdict cache, the timeout sweep, the
/// lock ordering — can be driven by a fake queue in <c>Kagisecure.App.Tests</c> without the real
/// FFI. Mirrors what the macOS <c>AgentService</c>/<c>ExtensionService</c> call.
/// </summary>
public interface IAgentRuntime
{
    /// <summary>
    /// Bind the MCP endpoint and start serving from the vault that is unlocked right now.
    /// <paramref name="endpoint"/> is <c>KAGISECURE_SOCKET</c> or <c>null</c> for the per-user default.
    /// </summary>
    /// <exception cref="KagisecureException">The endpoint is taken (the CLI daemon, another app instance) or unusable.</exception>
    /// <exception cref="InvalidOperationException">No vault is unlocked.</exception>
    string StartAgent(string? endpoint);

    /// <summary>Bind the browser-extension endpoint (<c>KAGISECURE_EXTENSION_SOCKET</c> or the default).</summary>
    string StartExtension(string? endpoint);

    /// <summary>Stop the MCP listener: denies every waiting approval and drops every lease. Idempotent.</summary>
    void StopAgent();

    /// <summary>Stop the extension listener and drop every fill lease. Idempotent.</summary>
    void StopExtension();

    /// <summary>
    /// <see cref="Agent.NextRequestAsync"/>: park a dedicated thread in Rust, one poll interval at
    /// a time, until a request arrives or <paramref name="cancellationToken"/> is cancelled.
    /// </summary>
    Task<ApprovalRequest> NextRequestAsync(TimeSpan pollInterval, CancellationToken cancellationToken);

    /// <summary><see cref="Agent.Resolve"/>.</summary>
    bool Resolve(string requestId, ApprovalDecision decision, ClientVerification verification);

    /// <summary><see cref="Agent.VerifyPeerCodeSignature"/>. Reads and hashes a whole file: never on the UI thread.</summary>
    ClientVerification VerifyPeer(uint pid, string executable, PeerRequirement requirement);

    /// <summary><see cref="Agent.TakeLockRequest"/>.</summary>
    bool TakeLockRequest();

    /// <summary><see cref="Agent.Status"/>.</summary>
    AgentStatus AgentStatus();

    /// <summary><see cref="BrowserExtension.Status"/>.</summary>
    ExtensionStatus ExtensionStatus();

    /// <summary><see cref="Agent.Leases"/>.</summary>
    IReadOnlyList<Lease> Leases();

    /// <summary><see cref="Agent.RevokeLease"/>.</summary>
    bool RevokeLease(string leaseId);

    /// <summary><see cref="Agent.RevokeAllLeases"/>.</summary>
    void RevokeAllLeases();

    /// <summary><see cref="BrowserExtension.FillLeases"/>.</summary>
    IReadOnlyList<FillLease> FillLeases();

    /// <summary><see cref="BrowserExtension.RevokeFillLease"/>.</summary>
    bool RevokeFillLease(string origin, string itemId);

    /// <summary><see cref="BrowserExtension.RevokeAllFillLeases"/>.</summary>
    void RevokeAllFillLeases();

    /// <summary><see cref="Agent.McpSetup"/>, looking for the sidecar next to this app first.</summary>
    McpSetup McpSetup();

    /// <summary><see cref="BrowserExtension.Setup"/>, looking for the native host next to this app first.</summary>
    ExtensionSetup ExtensionSetup();

    /// <summary>
    /// <see cref="BrowserExtension.InstallManifest"/>: writes the manifest file and the
    /// <c>HKEY_CURRENT_USER</c> registry value that points the browser at it.
    /// </summary>
    void InstallManifest(BrowserManifest manifest);

    /// <summary><see cref="BrowserExtension.UninstallManifest"/>.</summary>
    void UninstallManifest(BrowserManifest manifest);
}

/// <summary>The real <see cref="IAgentRuntime"/>: a pass-through to <c>Kagisecure.Interop</c>.</summary>
public sealed class AgentRuntime : IAgentRuntime
{
    private readonly Func<VaultSession?> currentSession;

    /// <param name="currentSession">
    /// The session the listeners serve from — <see cref="IAgentVaultAccess.SessionForListeners"/>.
    /// Each listener takes its own reference, which is why the host stops them before the app's
    /// reference is disposed.
    /// </param>
    public AgentRuntime(Func<VaultSession?> currentSession)
    {
        this.currentSession = currentSession;
    }

    /// <summary>
    /// Where this app looks for <c>kagisecure-mcp.exe</c> and <c>kagisecure-nmhost.exe</c>: its own
    /// directory. The Rust side falls back to <c>PATH</c> and the <c>KAGISECURE_MCP</c> /
    /// <c>KAGISECURE_NMHOST</c> overrides.
    /// </summary>
    public static string HelpersDirectory => AppContext.BaseDirectory;

    /// <inheritdoc />
    public string StartAgent(string? endpoint) => Agent.Start(RequireSession(), endpoint);

    /// <inheritdoc />
    public string StartExtension(string? endpoint) => BrowserExtension.Start(RequireSession(), endpoint);

    /// <inheritdoc />
    public void StopAgent() => Agent.Stop();

    /// <inheritdoc />
    public void StopExtension() => BrowserExtension.Stop();

    /// <inheritdoc />
    public Task<ApprovalRequest> NextRequestAsync(TimeSpan pollInterval, CancellationToken cancellationToken) =>
        Agent.NextRequestAsync(pollInterval, cancellationToken);

    /// <inheritdoc />
    public bool Resolve(string requestId, ApprovalDecision decision, ClientVerification verification) =>
        Agent.Resolve(requestId, decision, verification);

    /// <inheritdoc />
    public ClientVerification VerifyPeer(uint pid, string executable, PeerRequirement requirement) =>
        Agent.VerifyPeerCodeSignature(pid, executable, requirement);

    /// <inheritdoc />
    public bool TakeLockRequest() => Agent.TakeLockRequest();

    /// <inheritdoc />
    public AgentStatus AgentStatus() => Agent.Status();

    /// <inheritdoc />
    public ExtensionStatus ExtensionStatus() => BrowserExtension.Status();

    /// <inheritdoc />
    public IReadOnlyList<Lease> Leases() => Agent.Leases();

    /// <inheritdoc />
    public bool RevokeLease(string leaseId) => Agent.RevokeLease(leaseId);

    /// <inheritdoc />
    public void RevokeAllLeases() => Agent.RevokeAllLeases();

    /// <inheritdoc />
    public IReadOnlyList<FillLease> FillLeases() => BrowserExtension.FillLeases();

    /// <inheritdoc />
    public bool RevokeFillLease(string origin, string itemId) => BrowserExtension.RevokeFillLease(origin, itemId);

    /// <inheritdoc />
    public void RevokeAllFillLeases() => BrowserExtension.RevokeAllFillLeases();

    /// <inheritdoc />
    public McpSetup McpSetup() => Agent.McpSetup(HelpersDirectory);

    /// <inheritdoc />
    public ExtensionSetup ExtensionSetup() => BrowserExtension.Setup(HelpersDirectory);

    /// <inheritdoc />
    public void InstallManifest(BrowserManifest manifest) => BrowserExtension.InstallManifest(manifest);

    /// <inheritdoc />
    public void UninstallManifest(BrowserManifest manifest) => BrowserExtension.UninstallManifest(manifest);

    private VaultSession RequireSession() =>
        currentSession() ?? throw new InvalidOperationException("The vault is locked.");
}
