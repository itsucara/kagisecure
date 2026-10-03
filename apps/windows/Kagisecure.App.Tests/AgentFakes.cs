using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.Tests;

/// <summary>A scriptable approval queue and listener pair: no FFI, no pipes, no registry.</summary>
internal sealed class FakeAgentRuntime : IAgentRuntime
{
    private readonly ConcurrentQueue<ApprovalRequest> incoming = new();

    public List<string?> AgentStarts { get; } = new();

    public List<string?> ExtensionStarts { get; } = new();

    public int AgentStops;

    public int ExtensionStops;

    public int NextRequestCalls;

    public Exception? StartAgentThrows { get; set; }

    public ConcurrentQueue<(string Id, ApprovalDecision Decision, ClientVerification Verification)> Resolutions { get; } = new();

    public List<(uint Pid, string Executable, PeerRequirement Requirement)> Verifications { get; } = new();

    public Func<uint, string, PeerRequirement, ClientVerification> Verify { get; set; } =
        (_, _, _) => new ClientVerification(false, "Authenticode: not signed (test)");

    /// <summary>Ids <see cref="Resolve"/> reports as no longer live (the Rust side already timed them out).</summary>
    public HashSet<string> DeadIds { get; } = new();

    public bool LockRequested { get; set; }

    public List<Lease> LiveLeases { get; } = new();

    public List<FillLease> LiveFillLeases { get; } = new();

    public List<string> RevokedLeases { get; } = new();

    public List<BrowserManifest> Installed { get; } = new();

    public List<BrowserManifest> Uninstalled { get; } = new();

    public ExtensionSetup SetupToReturn { get; set; } = new(
        @"C:\fake\kagisecure-nmhost.exe", "abcdefghijklmnop", "com.kagisecure.test",
        new ValueList<BrowserManifest>(new[]
        {
            // RegistryKey deliberately null: tests never name a real browser's registry key.
            new BrowserManifest("Google Chrome", @"C:\fake\chrome.json", "{}", true, false, null),
        }));

    public McpSetup McpSetupToReturn { get; set; } = new(
        @"C:\fake\kagisecure-mcp.exe",
        new ValueList<McpSnippet>(new[] { new McpSnippet("Claude Code", "shell", "claude mcp add kagisecure", null) }));

    public bool Running { get; private set; }

    public void Enqueue(ApprovalRequest request) => incoming.Enqueue(request);

    /// <summary>Whether something enqueued has not been taken by the poll loop yet.</summary>
    public bool HasUndelivered => !incoming.IsEmpty;

    /// <summary>Runs inside <see cref="StartAgent"/>, after the listener is "bound" — for racing a lock against it.</summary>
    public Action? DuringStartAgent { get; set; }

    /// <summary>Runs inside <see cref="StartExtension"/>, after the listener is "bound".</summary>
    public Action? DuringStartExtension { get; set; }

    /// <summary>Whether the extension listener is bound.</summary>
    public bool ExtensionRunning { get; private set; }

    public string StartAgent(string? endpoint)
    {
        AgentStarts.Add(endpoint);
        if (StartAgentThrows is { } ex)
        {
            throw ex;
        }

        Running = true;
        DuringStartAgent?.Invoke();
        return endpoint ?? @"\\.\pipe\fake";
    }

    public string StartExtension(string? endpoint)
    {
        ExtensionStarts.Add(endpoint);
        ExtensionRunning = true;
        DuringStartExtension?.Invoke();
        return endpoint ?? @"\\.\pipe\fake-ext";
    }

    public void StopAgent()
    {
        Interlocked.Increment(ref AgentStops);
        Running = false;
    }

    public void StopExtension()
    {
        Interlocked.Increment(ref ExtensionStops);
        ExtensionRunning = false;
    }

    public Task<ApprovalRequest> NextRequestAsync(TimeSpan pollInterval, CancellationToken cancellationToken) =>
        Task.Factory.StartNew(
            () =>
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Interlocked.Increment(ref NextRequestCalls);
                    if (incoming.TryDequeue(out ApprovalRequest? request))
                    {
                        return request;
                    }

                    Thread.Sleep(5);
                }
            },
            cancellationToken,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);

    public bool Resolve(string requestId, ApprovalDecision decision, ClientVerification verification)
    {
        Resolutions.Enqueue((requestId, decision, verification));
        return !DeadIds.Contains(requestId);
    }

    public ClientVerification VerifyPeer(uint pid, string executable, PeerRequirement requirement)
    {
        lock (Verifications)
        {
            Verifications.Add((pid, executable, requirement));
        }

        return Verify(pid, executable, requirement);
    }

    public bool TakeLockRequest()
    {
        bool value = LockRequested;
        LockRequested = false;
        return value;
    }

    public AgentStatus AgentStatus() => new(Running, Running ? @"\\.\pipe\fake" : string.Empty, 0, (uint)LiveLeases.Count, Running);

    public ExtensionStatus ExtensionStatus() => new(Running, Running ? @"\\.\pipe\fake-ext" : string.Empty, 0, (uint)LiveFillLeases.Count, Running);

    public IReadOnlyList<Lease> Leases() => LiveLeases.ToList();

    public bool RevokeLease(string leaseId)
    {
        RevokedLeases.Add(leaseId);
        return LiveLeases.RemoveAll(l => l.Id == leaseId) > 0;
    }

    public void RevokeAllLeases() => LiveLeases.Clear();

    public IReadOnlyList<FillLease> FillLeases() => LiveFillLeases.ToList();

    public bool RevokeFillLease(string origin, string itemId) =>
        LiveFillLeases.RemoveAll(l => l.Origin == origin && l.ItemId == itemId) > 0;

    public void RevokeAllFillLeases() => LiveFillLeases.Clear();

    public McpSetup McpSetup() => McpSetupToReturn;

    public ExtensionSetup ExtensionSetup() => SetupToReturn;

    public void InstallManifest(BrowserManifest manifest) => Installed.Add(manifest);

    public void UninstallManifest(BrowserManifest manifest) => Uninstalled.Add(manifest);
}

/// <summary>A consent gate that answers what the test says, and counts how often it was asked.</summary>
internal sealed class FakeConsentGate : IConsentGate
{
    public ConsentOutcome Next { get; set; } = ConsentOutcome.Verified;

    public List<string> Reasons { get; } = new();

    /// <summary>When set, the prompt "stays up" until the test completes it.</summary>
    public TaskCompletionSource<ConsentOutcome>? Pending { get; set; }

    public Task<ConsentOutcome> RequestAsync(string reason)
    {
        Reasons.Add(reason);
        return Pending?.Task ?? Task.FromResult(Next);
    }
}

/// <summary>Runs nothing until the test pumps: the test thread is the "UI thread".</summary>
internal sealed class FakeDispatcher : IAgentDispatcher
{
    private readonly ConcurrentQueue<Action> actions = new();

    public int TimersStarted;

    public void Post(Action action) => actions.Enqueue(action);

    public IDisposable StartTimer(TimeSpan interval, Action tick)
    {
        TimersStarted++;
        return new Nothing();
    }

    public void Pump()
    {
        while (actions.TryDequeue(out Action? action))
        {
            action();
        }
    }

    /// <summary>Pump until <paramref name="condition"/> holds, or fail after a few seconds.</summary>
    public void PumpUntil(Func<bool> condition, string what)
    {
        DateTime deadline = DateTime.UtcNow.AddSeconds(20);
        while (DateTime.UtcNow < deadline)
        {
            Pump();
            if (condition())
            {
                return;
            }

            Thread.Sleep(5);
        }

        throw new TimeoutException($"timed out waiting for {what}");
    }

    private sealed class Nothing : IDisposable
    {
        public void Dispose()
        {
        }
    }
}

/// <summary>The agent-facing vault: a Locking hook the test fires, environments in memory, and a password check.</summary>
internal sealed class FakeAgentVault : IAgentVaultAccess
{
    public bool Unlocked { get; set; } = true;

    public string MasterPassword { get; set; } = "correct horse";

    public List<string> PasswordAttempts { get; } = new();

    public List<VaultEnvironment> Stored { get; } = new();

    public bool Shared { get; set; }

    public List<(string Env, string Name, string Value)> ValuesSet { get; } = new();

    public event EventHandler? Locking;

    /// <summary>The fake has no real session; the host only checks <see cref="IsUnlocked"/>.</summary>
    public VaultSession? SessionForListeners => null;

    public bool IsUnlocked => Unlocked;

    public int SessionGeneration { get; private set; }

    /// <summary>
    /// A lock, in the order the real <see cref="VaultService.Lock"/> does it: the session goes and
    /// the generation moves first, then Locking is raised (which stops the host).
    /// </summary>
    public void RaiseLocking()
    {
        Unlocked = false;
        SessionGeneration++;
        Locking?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>The first half of a lock only — the session gone — as another thread would be mid-Lock.</summary>
    public void TakeSessionAway()
    {
        Unlocked = false;
        SessionGeneration++;
    }

    public Task<IReadOnlyList<VaultEnvironment>> EnvironmentsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<VaultEnvironment>>(Stored.ToList());

    public Task<VaultEnvironment> CreateEnvironmentAsync(string name, string? description, CancellationToken cancellationToken = default)
    {
        var env = new VaultEnvironment($"env-{Stored.Count + 1}", name, description, ValueList<string>.Empty, ValueList<EnvironmentVariable>.Empty, 0, false);
        Stored.Add(env);
        return Task.FromResult(env);
    }

    public Task<VaultEnvironment> SetEnvironmentAgentVisibleAsync(string environmentId, bool visible, CancellationToken cancellationToken = default) =>
        Task.FromResult(Replace(environmentId, e => e with { AgentVisible = visible }));

    public Task<VaultEnvironment> SetVariableValueAsync(string environmentId, string name, string value, CancellationToken cancellationToken = default)
    {
        ValuesSet.Add((environmentId, name, value));
        return Task.FromResult(Replace(environmentId, e =>
        {
            List<EnvironmentVariable> vars = e.Variables.Where(v => v.Name != name).ToList();
            vars.Add(new EnvironmentVariable(name, VarBinding.Literal, null, null, true, null));
            return e with
            {
                Variables = new ValueList<EnvironmentVariable>(vars),
                VariableNames = new ValueList<string>(vars.Select(v => v.Name)),
                PendingCount = (uint)vars.Count(v => v.Binding == VarBinding.Pending),
            };
        }));
    }

    public Task<VaultEnvironment> RemoveVariableAsync(string environmentId, string name, CancellationToken cancellationToken = default) =>
        Task.FromResult(Replace(environmentId, e =>
        {
            List<EnvironmentVariable> vars = e.Variables.Where(v => v.Name != name).ToList();
            return e with { Variables = new ValueList<EnvironmentVariable>(vars), VariableNames = new ValueList<string>(vars.Select(v => v.Name)) };
        }));

    public Task DeleteEnvironmentAsync(string environmentId, CancellationToken cancellationToken = default)
    {
        Stored.RemoveAll(e => e.Id == environmentId);
        return Task.CompletedTask;
    }

    public Task<bool> VaultAgentVisibleAsync(CancellationToken cancellationToken = default) => Task.FromResult(Shared);

    public Task SetVaultAgentVisibleAsync(bool visible, CancellationToken cancellationToken = default)
    {
        Shared = visible;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Right or wrong, with no back-off: the real rate limit is Rust's, and is tested there and in
    /// Kagisecure.Interop.Tests.
    /// </summary>
    public Task<MasterPasswordCheck> VerifyMasterPasswordAsync(string masterPassword, CancellationToken cancellationToken = default)
    {
        PasswordAttempts.Add(masterPassword);
        return Task.FromResult(masterPassword == MasterPassword
            ? new MasterPasswordCheck(MasterPasswordCheckKind.Verified, TimeSpan.Zero)
            : new MasterPasswordCheck(MasterPasswordCheckKind.Wrong, TimeSpan.FromSeconds(1)));
    }

    private VaultEnvironment Replace(string id, Func<VaultEnvironment, VaultEnvironment> change)
    {
        int index = Stored.FindIndex(e => e.Id == id);
        VaultEnvironment updated = change(Stored[index]);
        Stored[index] = updated;
        return updated;
    }
}

/// <summary>Builds approval requests with sensible defaults.</summary>
internal static class Requests
{
    public static ApprovalRequest Env(
        string id = "req-1",
        ApprovalAction action = ApprovalAction.WriteEnvFile,
        ulong createdAt = 1_000,
        ulong expiresAt = 1_060,
        string clientName = "Claude Code",
        uint? pid = 4242,
        string? exe = @"C:\tools\kagisecure-mcp.exe",
        bool mintsLease = true,
        string[]? variables = null,
        string[]? command = null,
        bool? gitignored = true) => new(
            id, action, mintsLease, clientName, pid, true, exe, @"C:\code\acme", "env-1", "staging",
            @"C:\code\acme", @"C:\code\acme\.env",
            new ValueList<string>(variables ?? new[] { "DATABASE_URL", "STRIPE_SECRET_KEY" }),
            new ValueList<string>(command ?? Array.Empty<string>()),
            gitignored, false, false, null, 900, 10, 900, createdAt, expiresAt,
            null, null, false, null, null, ValueList<string>.Empty, null, null, null, false, null);

    public static ApprovalRequest Fill(
        string id = "fill-1",
        ulong createdAt = 1_000,
        ulong expiresAt = 1_060,
        uint? browserPid = 777,
        string? browserExe = @"C:\Program Files\Google\Chrome\Application\chrome.exe") => new(
            id, ApprovalAction.FillCredential, false, "kagisecure-nmhost", 5151, true, @"C:\tools\kagisecure-nmhost.exe", null, null, null,
            null, null, ValueList<string>.Empty, ValueList<string>.Empty, null, false, null, null, 300, 0, 900, createdAt, expiresAt,
            "https://example.com", null, false, "item-1", "Example account", new ValueList<string>(new[] { "password" }),
            "Google Chrome", browserPid, browserExe, false, "abcdefghijklmnop");
}
