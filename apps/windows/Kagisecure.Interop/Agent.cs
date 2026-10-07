using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Kagisecure.Interop.Native;
using static Kagisecure.Interop.Native.Marshalling;

namespace Kagisecure.Interop;

/// <summary>What kind of request the approval sheet is about.</summary>
public enum ApprovalAction : uint
{
    /// <summary><c>create_environment</c>.</summary>
    CreateEnvironment = (uint)KgsApprovalAction.CreateEnvironment,

    /// <summary><c>add_variables</c>.</summary>
    AddVariables = (uint)KgsApprovalAction.AddVariables,

    /// <summary><c>write_env_file</c>.</summary>
    WriteEnvFile = (uint)KgsApprovalAction.WriteEnvFile,

    /// <summary><c>run_with_env</c>.</summary>
    RunWithEnv = (uint)KgsApprovalAction.RunWithEnv,

    /// <summary>A browser extension wants to fill a credential into a page.</summary>
    FillCredential = (uint)KgsApprovalAction.FillCredential,

    /// <summary>
    /// An agent asks for a login to be typed into a browser tab (ADR-0036). Windows never offers
    /// agent fills, so this arrives only if something is wrong; the app denies it unseen.
    /// </summary>
    AgentFill = (uint)KgsApprovalAction.AgentFill,

    /// <summary>
    /// An agent asks to create a test login (ADR-0048). Windows never offers agent test logins,
    /// so this arrives only if something is wrong; the app denies it unseen.
    /// </summary>
    CreateTestLogin = (uint)KgsApprovalAction.CreateTestLogin,
}

/// <summary>
/// One question waiting for a human. Metadata only: there is no value, no length, and no way to
/// add one without editing ADR-0008. Render <see cref="ClientName"/> as a quotation, never a label.
/// </summary>
/// <param name="Id">Quote this back to <see cref="Agent.Resolve"/>.</param>
/// <param name="Action">What is being asked for.</param>
/// <param name="MintsLease">Whether granting mints a lease, so the sheet shows the TTL control.</param>
/// <param name="ClientName">The caller's self-reported name.</param>
/// <param name="ClientPid">The peer's process id.</param>
/// <param name="ClientPidFromKernel">Whether that pid came from the kernel.</param>
/// <param name="ClientExecutable">The executable behind that pid — what the app checks the signature of.</param>
/// <param name="ClientCwd">The directory the sidecar was started in. Self-reported.</param>
/// <param name="EnvironmentId">The environment involved.</param>
/// <param name="EnvironmentName">Its display name.</param>
/// <param name="Directory">The canonical target directory.</param>
/// <param name="TargetPath">The exact file that would be written.</param>
/// <param name="Variables">Variable names.</param>
/// <param name="Command">The resolved argv, for <c>run_with_env</c>.</param>
/// <param name="Gitignored"><c>false</c> is the red "not gitignored" callout; <c>null</c> outside a work tree.</param>
/// <param name="OverwriteRequested">The caller asked to replace an existing file.</param>
/// <param name="TargetExists">Whether a file is already at the target; <c>null</c> when not a file write.</param>
/// <param name="TargetWrittenByUs">Whether kagisecure wrote that file this session; <c>false</c> is the destructive case.</param>
/// <param name="RequestedTtlSeconds">The TTL asked for. The user may shorten it, never lengthen it.</param>
/// <param name="RequestedUses">The use count the lease would carry.</param>
/// <param name="MaxTtlSeconds">The ceiling the TTL control must respect.</param>
/// <param name="CreatedAt">Unix seconds the request arrived.</param>
/// <param name="ExpiresAt">Unix seconds it self-denies, for the countdown bar.</param>
/// <param name="Origin">The fill origin.</param>
/// <param name="TopOrigin">The top-level page's origin when it differs; may be the literal <c>"null"</c>.</param>
/// <param name="TopOriginUnknown">The embedder could not be established: say "an unknown site".</param>
/// <param name="ItemId">The item that would be filled.</param>
/// <param name="ItemTitle">Its title.</param>
/// <param name="FillFields">Which fields would be written. Names.</param>
/// <param name="Browser">The browser.</param>
/// <param name="BrowserPid">That browser's pid.</param>
/// <param name="BrowserExecutable">That browser's executable path.</param>
/// <param name="BrowserIsAppExtension">Whether the peer is an app extension we ship (Safari only).</param>
/// <param name="ExtensionId">The extension's self-reported id.</param>
/// <param name="PresenceOnly">
/// Ask only for a fresh presence check (Windows Hello), not the sheet: a fill the person already
/// reviewed in full this session (ADR-0037). The check itself is never skipped, and a cancelled or
/// unavailable one is a denial. Showing the full sheet instead is always safe.
/// </param>
public sealed record ApprovalRequest(
    string Id,
    ApprovalAction Action,
    bool MintsLease,
    string ClientName,
    uint? ClientPid,
    bool ClientPidFromKernel,
    string? ClientExecutable,
    string? ClientCwd,
    string? EnvironmentId,
    string? EnvironmentName,
    string? Directory,
    string? TargetPath,
    ValueList<string> Variables,
    ValueList<string> Command,
    bool? Gitignored,
    bool OverwriteRequested,
    bool? TargetExists,
    bool? TargetWrittenByUs,
    ulong RequestedTtlSeconds,
    uint RequestedUses,
    ulong MaxTtlSeconds,
    ulong CreatedAt,
    ulong ExpiresAt,
    string? Origin,
    string? TopOrigin,
    bool TopOriginUnknown,
    string? ItemId,
    string? ItemTitle,
    ValueList<string> FillFields,
    string? Browser,
    uint? BrowserPid,
    string? BrowserExecutable,
    bool BrowserIsAppExtension,
    string? ExtensionId,
    bool PresenceOnly = false)
{
    internal static ApprovalRequest From(in KgsApprovalRequest n) => new(
        Str(n.id),
        (ApprovalAction)n.action,
        n.mints_lease != 0,
        Str(n.client_name),
        n.client_pid.ToNullable(),
        n.client_pid_from_kernel != 0,
        Str(n.client_executable),
        Str(n.client_cwd),
        Str(n.environment_id),
        Str(n.environment_name),
        Str(n.directory),
        Str(n.target_path),
        Strings(n.variables),
        Strings(n.command),
        n.gitignored.ToNullable(),
        n.overwrite_requested != 0,
        n.target_exists.ToNullable(),
        n.target_written_by_us.ToNullable(),
        n.requested_ttl_seconds,
        n.requested_uses,
        n.max_ttl_seconds,
        n.created_at,
        n.expires_at,
        Str(n.origin),
        Str(n.top_origin),
        n.top_origin_unknown != 0,
        Str(n.item_id),
        Str(n.item_title),
        Strings(n.fill_fields),
        Str(n.browser),
        n.browser_pid.ToNullable(),
        Str(n.browser_executable),
        n.browser_is_app_extension != 0,
        Str(n.extension_id),
        n.presence_only != 0);
}

/// <summary>
/// The three buttons on the sheet — Rust's <c>ApprovalDecision</c>, an enum with data. There is no
/// "always allow". A closed hierarchy.
/// </summary>
public abstract record ApprovalDecision
{
    private ApprovalDecision()
    {
    }

    /// <summary>Mint a single-use lease; the next identical request asks again.</summary>
    public sealed record AllowOnce : ApprovalDecision;

    /// <summary>Mint a lease for the TTL and uses the user agreed to, clamped to what was requested.</summary>
    /// <param name="TtlSeconds">Seconds.</param>
    /// <param name="Uses">Uses.</param>
    public sealed record AllowSession(ulong TtlSeconds, uint Uses) : ApprovalDecision;

    /// <summary>Refuse. The agent gets <c>USER_DENIED</c>.</summary>
    public sealed record Deny : ApprovalDecision;

    internal KgsApprovalDecision ToNative() => this switch
    {
        AllowOnce => new KgsApprovalDecision { tag = (uint)KgsApprovalDecisionTag.AllowOnce },
        AllowSession s => new KgsApprovalDecision
        {
            tag = (uint)KgsApprovalDecisionTag.AllowSession,
            ttl_seconds = s.TtlSeconds,
            uses = s.Uses,
        },
        Deny => new KgsApprovalDecision { tag = (uint)KgsApprovalDecisionTag.Deny },
        _ => throw new InvalidOperationException("unreachable: ApprovalDecision is closed"),
    };
}

/// <summary>What the app's code-signature check concluded about the caller.</summary>
/// <param name="Verified">Whether the peer's signature satisfied the app's requirement.</param>
/// <param name="Evidence">One line of evidence: a signer, or why the check failed.</param>
public sealed record ClientVerification(bool Verified, string Evidence)
{
    /// <summary>No check was made.</summary>
    public static ClientVerification Unchecked { get; } = new(false, string.Empty);
}

/// <summary>Which signer a peer's Authenticode signature must name (ADR-0032).</summary>
public enum PeerRequirement : uint
{
    /// <summary>One of our own helpers: signed with the same key as this build. Never met by an unsigned build.</summary>
    OwnHelper = (uint)KgsPeerRequirementKind.OwnHelper,

    /// <summary>A browser: signed by the publisher its executable name maps to.</summary>
    Browser = (uint)KgsPeerRequirementKind.Browser,
}

/// <summary>One live lease, for the Leases table.</summary>
/// <param name="Id">Identifier, for Revoke.</param>
/// <param name="EnvironmentId">The environment it is scoped to.</param>
/// <param name="Directory">The canonical directory it is scoped to. Exact match, never a prefix.</param>
/// <param name="Variables">The variable names it covers.</param>
/// <param name="Kind"><c>"env-file"</c> or <c>"run-command"</c>.</param>
/// <param name="ClientIdentity">The caller it was minted for.</param>
/// <param name="ExpiresAt">Unix seconds it dies at.</param>
/// <param name="UsesRemaining">Uses left.</param>
public sealed record Lease(
    string Id,
    string EnvironmentId,
    string Directory,
    ValueList<string> Variables,
    string Kind,
    string ClientIdentity,
    ulong ExpiresAt,
    uint UsesRemaining)
{
    internal static Lease From(in KgsLease n) => new(
        Str(n.id),
        Str(n.environment_id),
        Str(n.directory),
        Strings(n.variables),
        Str(n.kind),
        Str(n.client_identity),
        n.expires_at,
        n.uses_remaining);
}

/// <summary>The listener's state.</summary>
/// <param name="Running">Whether the endpoint is bound and being accepted on.</param>
/// <param name="Endpoint">Where it is listening; empty when it is not.</param>
/// <param name="PendingApprovals">Approvals waiting for a human.</param>
/// <param name="ActiveLeases">Live leases.</param>
/// <param name="VaultUnlocked">Whether the vault behind it is still unlocked.</param>
public sealed record AgentStatus(bool Running, string Endpoint, uint PendingApprovals, uint ActiveLeases, bool VaultUnlocked);

/// <summary>One MCP client's setup snippet.</summary>
/// <param name="Title">Display name, e.g. <c>"Claude Code"</c>.</param>
/// <param name="Language"><c>"shell"</c>, <c>"json"</c> or <c>"toml"</c>.</param>
/// <param name="Body">The text the copy button copies.</param>
/// <param name="ConfigPath">Where it goes; <c>null</c> for a client that keeps its own registry.</param>
public sealed record McpSnippet(string Title, string Language, string Body, string? ConfigPath)
{
    internal static McpSnippet From(in KgsMcpSnippet n) =>
        new(Str(n.title), Str(n.language), Str(n.body), Str(n.config_path));
}

/// <summary>Where the sidecar is and what to paste into each client.</summary>
/// <param name="SidecarPath">The absolute path to <c>kagisecure-mcp</c>, or <c>null</c> if not found.</param>
/// <param name="Snippets">One entry per client.</param>
public sealed record McpSetup(string? SidecarPath, ValueList<McpSnippet> Snippets);

/// <summary>
/// The agent: an IPC listener serving MCP sidecars from an unlocked vault, and the approval queue
/// the app answers (ADR-0014). A process global — one per process — so a static class.
/// </summary>
/// <remarks>
/// <para>
/// <b>Threading.</b> <see cref="NextRequest"/> blocks the calling thread for up to its timeout.
/// Run exactly one loop, on a dedicated background thread (<see cref="NextRequestAsync"/> does
/// this), never on the UI thread, and marshal each request to the UI with the dispatcher. Every
/// other member returns promptly and may be called from any thread, including while a poll is
/// parked. There is no way to interrupt a parked poll, and none is needed: cancellation takes
/// effect between polls, so its latency is bounded by the poll interval — exactly the Swift app's
/// <c>Task.detached</c> loop with a 500 ms timeout.
/// </para>
/// <para>
/// <b>Locking.</b> Call <see cref="Stop"/> before disposing the <see cref="VaultSession"/>: the
/// agent holds its own reference to the session, so disposing the app's reference alone does not
/// lock while the agent runs.
/// </para>
/// </remarks>
public static unsafe class Agent
{
    /// <summary>The poll interval the Swift app uses.</summary>
    public static readonly TimeSpan DefaultPollInterval = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// Bind the endpoint and start serving agents from <paramref name="session"/>'s vault. On
    /// Windows <paramref name="socketPath"/> is a named-pipe name (<c>kagisecure-mine.sock</c> or
    /// <c>\\.\pipe\kagisecure-mine.sock</c>); <c>null</c> is the per-user default. Returns the
    /// endpoint it bound, for the setup screen.
    /// </summary>
    /// <exception cref="KagisecureException.Invalid">Another kagisecure holds the endpoint, the name is not usable here, or this process already runs an agent. The message is written for a human.</exception>
    public static string Start(VaultSession session, string? socketPath = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        EnsureAbi();
        using var s = session.Handle.Borrow();
        using var p = PinnedUtf8.Optional(socketPath);
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_agent_start(s.Ptr, p.OptSlice, &output, &error), ref error);
        return TakeString(ref output);
    }

    /// <summary>Stop serving, deny every waiting approval, and drop every lease. Idempotent.</summary>
    public static void Stop()
    {
        EnsureAbi();
        KgsBuffer error = default;
        Check(NativeMethods.kgs_agent_stop(&error), ref error);
    }

    /// <summary>Whether the listener is running, and what it is holding.</summary>
    public static AgentStatus Status()
    {
        EnsureAbi();
        KgsAgentStatus output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_agent_status(&output, &error), ref error);
            return new AgentStatus(
                output.running != 0, Str(output.endpoint), output.pending_approvals, output.active_leases, output.vault_unlocked != 0);
        }
        finally
        {
            NativeMethods.kgs_agent_status_free(&output);
        }
    }

    /// <summary>
    /// Wait up to <paramref name="timeout"/> for something to ask the user, and take it off the
    /// queue; <c>null</c> when nothing arrived. <b>Blocks</b> — see the remarks on <see cref="Agent"/>.
    /// Browser-extension fills arrive here too.
    /// </summary>
    public static ApprovalRequest? NextRequest(TimeSpan timeout)
    {
        EnsureAbi();
        KgsOptApprovalRequest output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_agent_next_request(Milliseconds(timeout), &output, &error), ref error);
            return output.present != 0 ? ApprovalRequest.From(output.value) : null;
        }
        finally
        {
            NativeMethods.kgs_approval_request_free(&output.value);
        }
    }

    /// <summary>
    /// Poll <see cref="NextRequest"/> on a dedicated background thread until a request arrives.
    /// Cancellation is checked between polls, so it takes effect within
    /// <paramref name="pollInterval"/>; a request already taken off the queue when cancellation
    /// arrives is still returned rather than dropped, because a dropped request would leave the
    /// agent waiting out its full timeout.
    /// </summary>
    /// <exception cref="OperationCanceledException">Cancelled before a request arrived.</exception>
    public static Task<ApprovalRequest> NextRequestAsync(TimeSpan pollInterval, CancellationToken cancellationToken = default) =>
        Task.Factory.StartNew(
            () =>
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (NextRequest(pollInterval) is ApprovalRequest request)
                    {
                        return request;
                    }
                }
            },
            cancellationToken,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);

    /// <summary>Everything still outstanding, delivered or not.</summary>
    public static IReadOnlyList<ApprovalRequest> PendingRequests()
    {
        EnsureAbi();
        KgsApprovalRequestArray output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_agent_pending_requests(&output, &error), ref error);
            return List<KgsApprovalRequest, ApprovalRequest>(output.ptr, output.len, ApprovalRequest.From);
        }
        finally
        {
            NativeMethods.kgs_approval_request_array_free(&output);
        }
    }

    /// <summary>
    /// Answer one request. <c>false</c> when the id is no longer live — normally the 60-second
    /// window closed while the user was deciding. Not an error: dismiss the sheet.
    /// </summary>
    public static bool Resolve(string requestId, ApprovalDecision decision, ClientVerification verification)
    {
        ArgumentNullException.ThrowIfNull(decision);
        ArgumentNullException.ThrowIfNull(verification);
        EnsureAbi();
        using var id = new PinnedUtf8(requestId);
        using var evidence = new PinnedUtf8(verification.Evidence);
        KgsApprovalDecision nativeDecision = decision.ToNative();
        var nativeVerification = new KgsClientVerification { verified = Byte(verification.Verified), evidence = evidence.Slice };
        byte output = 0;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_agent_resolve(id.Slice, &nativeDecision, &nativeVerification, &output, &error), ref error);
        return output != 0;
    }

    /// <summary>
    /// Check the process behind <paramref name="pid"/> with Authenticode (ADR-0032), for the approval
    /// sheet, and hand the result back unchanged to <see cref="Resolve"/>. Pass the request's client
    /// pid and executable with <see cref="PeerRequirement.OwnHelper"/>, or its browser pid and
    /// executable with <see cref="PeerRequirement.Browser"/>. It reads and hashes the whole file, so
    /// call it off the UI thread. The check verifies a file, not the running process, and is weaker
    /// than the macOS one: show its evidence as a warning, never treat it as a gate.
    /// </summary>
    public static ClientVerification VerifyPeerCodeSignature(uint pid, string executable, PeerRequirement requirement)
    {
        EnsureAbi();
        using var path = new PinnedUtf8(executable);
        KgsClientVerificationOut output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_verify_peer_code_signature(pid, path.Slice, (uint)requirement, &output, &error), ref error);
            return new ClientVerification(output.verified != 0, Str(output.evidence));
        }
        finally
        {
            NativeMethods.kgs_client_verification_free(&output);
        }
    }

    /// <summary>Live leases, for the Leases table.</summary>
    public static IReadOnlyList<Lease> Leases()
    {
        EnsureAbi();
        KgsLeaseArray output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_agent_leases(&output, &error), ref error);
            return List<KgsLease, Lease>(output.ptr, output.len, Lease.From);
        }
        finally
        {
            NativeMethods.kgs_lease_array_free(&output);
        }
    }

    /// <summary>Revoke one lease and shred anything written under it. Returns whether it was live.</summary>
    /// <exception cref="KagisecureException.Invalid"><paramref name="leaseId"/> is not a lease id at all.</exception>
    public static bool RevokeLease(string leaseId)
    {
        EnsureAbi();
        using var id = new PinnedUtf8(leaseId);
        byte output = 0;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_agent_revoke_lease(id.Slice, &output, &error), ref error);
        return output != 0;
    }

    /// <summary>Revoke every lease at once.</summary>
    public static void RevokeAllLeases()
    {
        EnsureAbi();
        KgsBuffer error = default;
        Check(NativeMethods.kgs_agent_revoke_all_leases(&error), ref error);
    }

    /// <summary>
    /// Whether something asked the vault to lock over IPC (<c>kagisecure lock</c>), clearing the
    /// flag. Poll it beside <see cref="NextRequest"/> and lock the app when it is set.
    /// </summary>
    public static bool TakeLockRequest()
    {
        EnsureAbi();
        byte output = 0;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_agent_take_lock_request(&output, &error), ref error);
        return output != 0;
    }

    /// <summary>
    /// Where the sidecar is, and the snippet for each MCP client. <paramref name="helpersDirectory"/>
    /// is the directory the app installed <c>kagisecure-mcp.exe</c> into.
    /// </summary>
    public static McpSetup McpSetup(string? helpersDirectory = null)
    {
        EnsureAbi();
        using var dir = PinnedUtf8.Optional(helpersDirectory);
        KgsMcpSetup output = default;
        KgsBuffer error = default;
        try
        {
            Check(NativeMethods.kgs_mcp_setup(dir.OptSlice, &output, &error), ref error);
            return new McpSetup(
                Str(output.sidecar_path),
                List<KgsMcpSnippet, McpSnippet>(output.snippets.ptr, output.snippets.len, McpSnippet.From));
        }
        finally
        {
            NativeMethods.kgs_mcp_setup_free(&output);
        }
    }
}
