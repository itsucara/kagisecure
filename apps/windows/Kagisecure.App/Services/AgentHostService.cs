using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;

namespace Kagisecure.App.Services;

/// <summary>
/// What the app concluded about who is asking: one verdict for an agent request, and for a
/// browser fill the helper's and the browser's separately plus the combined one that travels back
/// into Rust (ADR-0020 §5: <c>host.verified &amp;&amp; browser.verified</c>, so the record never
/// flatters the weaker half).
/// </summary>
/// <param name="Combined">What goes to <see cref="Agent.Resolve"/>, the lease and the audit entry.</param>
/// <param name="Helper">For a fill: the native messaging helper's verdict.</param>
/// <param name="Browser">For a fill: the browser's verdict.</param>
public sealed record PeerVerdict(ClientVerification Combined, ClientVerification? Helper = null, ClientVerification? Browser = null);

/// <summary>
/// The app's half of the approval flow (ui-spec.md §10, ADR-0014, ADR-0020): the Windows port of
/// the macOS <c>AgentService</c>, plus the lifecycle half of <c>ExtensionService</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Lifecycle.</b> <see cref="Start"/> runs when the vault unlocks: it binds the MCP endpoint
/// and the browser-extension endpoint (both always, as on macOS — there is no setting that turns
/// either off; <c>KAGISECURE_SOCKET</c> / <c>KAGISECURE_EXTENSION_SOCKET</c> move them) and starts
/// one poll loop on <see cref="Agent.NextRequestAsync"/>. <see cref="Stop"/> runs from
/// <see cref="IAgentVaultAccess.Locking"/>, <i>before</i> the session is disposed: it cancels the
/// loop, waits (bounded) for it to be gone so it cannot take a request off the process-global
/// queue after this host has stopped (ADR-0020 §1), then stops both listeners, which denies every
/// waiting approval and drops every lease.
/// </para>
/// <para>
/// <b>One sheet at a time.</b> Requests queue in arrival order; <see cref="Current"/> is the head.
/// Each runs out its own 60-second window, enforced in Rust; the one-second <see cref="Tick"/>
/// retires anything whose window closed, answering it <c>Deny</c> on the way out, which is what
/// dismisses its sheet.
/// </para>
/// <para>
/// <b>Verdicts.</b> <see cref="Agent.VerifyPeerCodeSignature"/> reads and hashes a whole file, so
/// it runs on the thread pool as soon as a request arrives, and its verdict is remembered by
/// request id: the verdict that travels back with a decision is the one computed for <i>that</i>
/// request. It is shown as a warning and never gates anything (ADR-0015, ADR-0032).
/// </para>
/// <para>
/// <b>Threading.</b> Everything observable here belongs to the UI thread. <see cref="Stop"/> may
/// be called from any thread (auto-lock arrives on a system-events thread); the part that must be
/// synchronous — stopping the listeners before the session is released — runs on the caller's
/// thread, and the observable state is cleared through the dispatcher.
/// </para>
/// </remarks>
public sealed partial class AgentHostService : ObservableObject, IDisposable
{
    /// <summary>
    /// How long each poll parks in Rust — the macOS app's 250 ms. Also the unit <see cref="Stop"/>
    /// bounds its wait by.
    /// </summary>
    public static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(250);

    /// <summary>Evidence recorded for a request nobody saw because the vault locked first.</summary>
    public const string LockedBeforeSeenEvidence = "the vault locked before the request reached a human";

    /// <summary>Evidence for a caller whose pid did not come from the kernel: no signature check is attempted.</summary>
    public const string SelfReportedPidEvidence =
        "code signature not checked: the caller's process id is self-reported, not from the kernel";

    /// <summary>
    /// Evidence recorded for an agent-fill request (ADR-0036), which Windows never offers: denied
    /// on arrival, never shown, never granted. Rust answers <c>request_fill</c> with
    /// <c>FILL_UNAVAILABLE</c> on Windows before anything is asked, so this is defence in depth.
    /// </summary>
    public const string AgentFillUnsupportedEvidence =
        "agent-requested browser fills are not offered on Windows";

    /// <summary>Evidence recorded for a request retired because its window closed.</summary>
    public const string ExpiredEvidence = "the request expired before it was answered";

    private readonly IAgentRuntime runtime;
    private readonly IConsentGate gate;
    private readonly IAgentVaultAccess vault;
    private readonly IAgentDispatcher dispatcher;
    private readonly Func<DateTimeOffset> clock;
    private readonly Func<string, string?> environment;

    private readonly object lifecycle = new();

    /// <summary>Held for the whole of <see cref="Start"/> and <see cref="Stop"/>, so the two never interleave.</summary>
    private readonly object startStop = new();
    private CancellationTokenSource? loopCancellation;
    private Task? loopTask;
    private IDisposable? ticker;
    private int generation;
    private bool running;

    private readonly Dictionary<string, Task<PeerVerdict>> verdicts = new();

    /// <summary>Requests whose Windows Hello consent came back <see cref="ConsentStatus.Unavailable"/>: only these may be approved with the master password.</summary>
    private readonly HashSet<string> passwordFallbackOffered = new();

    public AgentHostService(
        IAgentRuntime runtime,
        IConsentGate gate,
        IAgentVaultAccess vault,
        IAgentDispatcher dispatcher,
        Func<DateTimeOffset>? clock = null,
        Func<string, string?>? environment = null)
    {
        this.runtime = runtime;
        this.gate = gate;
        this.vault = vault;
        this.dispatcher = dispatcher;
        this.clock = clock ?? (() => DateTimeOffset.UtcNow);
        this.environment = environment ?? Environment.GetEnvironmentVariable;
        now = this.clock();
    }

    /// <summary>Approvals waiting for the user, oldest first. The head is on screen.</summary>
    public ObservableCollection<ApprovalRequest> Queue { get; } = new();

    /// <summary>The request on screen, if any.</summary>
    public ApprovalRequest? Current => Queue.Count > 0 ? Queue[0] : null;

    /// <summary>Live leases, refreshed on the tick.</summary>
    public ObservableCollection<Lease> Leases { get; } = new();

    /// <summary>Live fill leases, refreshed on the tick.</summary>
    public ObservableCollection<FillLease> FillLeases { get; } = new();

    /// <summary>Raised on the UI thread when <see cref="Current"/> changes — the presenter opens, swaps or closes the sheet.</summary>
    public event EventHandler? CurrentChanged;

    /// <summary>Raised on the UI thread when a request arrives: flash the taskbar, bring the sheet forward.</summary>
    public event EventHandler? AttentionRequested;

    /// <summary>Raised on the UI thread when something asked the vault to lock over IPC (<c>kagisecure lock</c>).</summary>
    public event EventHandler? LockRequested;

    /// <summary>Raised on the UI thread when a verdict for <see cref="Current"/> becomes known.</summary>
    public event EventHandler? VerdictChanged;

    /// <summary>Whether the host is serving (the vault is unlocked and <see cref="Start"/> ran).</summary>
    public bool IsRunning
    {
        get
        {
            lock (lifecycle)
            {
                return running;
            }
        }
    }

    // Hand-written observable properties rather than [ObservableProperty] fields: the field form
    // raises MVVMTK0045 under WinUI, and the partial-property form needs C# 13 (.NET 9 SDK).
    private AgentStatus agentStatus = new(false, string.Empty, 0, 0, false);
    private ExtensionStatus extensionStatus = new(false, string.Empty, 0, 0, false);
    private string? startupError;
    private string? extensionStartupError;
    private DateTimeOffset now;

    /// <summary>The MCP listener's state, refreshed on the tick.</summary>
    public AgentStatus AgentStatus
    {
        get => agentStatus;
        private set => SetProperty(ref agentStatus, value);
    }

    /// <summary>The extension listener's state, refreshed on the tick.</summary>
    public ExtensionStatus ExtensionStatus
    {
        get => extensionStatus;
        private set => SetProperty(ref extensionStatus, value);
    }

    /// <summary>Why the MCP listener could not start — shown verbatim (architecture.md §4.2: "the CLI daemon already owns the socket").</summary>
    public string? StartupError
    {
        get => startupError;
        private set => SetProperty(ref startupError, value);
    }

    /// <summary>Why the extension listener could not start.</summary>
    public string? ExtensionStartupError
    {
        get => extensionStartupError;
        private set => SetProperty(ref extensionStartupError, value);
    }

    /// <summary>Ticks once a second so countdowns are live without a timer in every view.</summary>
    public DateTimeOffset Now
    {
        get => now;
        private set => SetProperty(ref now, value);
    }

    // -------------------------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Wire the host to the vault: start on unlock, stop on lock (before the session goes), and
    /// lock when an IPC client asks. Call once.
    /// </summary>
    public void Bind(IVaultService vaultService)
    {
        vaultService.Unlocked += (_, _) => dispatcher.Post(Start);
        vault.Locking += (_, _) => Stop();
        LockRequested += (_, _) => vaultService.Lock();
        if (vaultService.IsUnlocked)
        {
            dispatcher.Post(Start);
        }
    }

    /// <summary>
    /// Bind both endpoints and start serving. Safe to call when already running, or when the vault
    /// is locked (no-op).
    /// </summary>
    /// <remarks>
    /// Serialized with <see cref="Stop"/>, and checked against the vault's
    /// <see cref="IAgentVaultAccess.SessionGeneration"/> before and after binding. Each listener
    /// takes its own reference to the Rust session, so a Start that bound a session a Lock was
    /// already taking away would keep the vault key alive in the listeners while the window showed
    /// the lock screen. <see cref="VaultService.Lock"/> takes the session out and bumps the
    /// generation <i>before</i> it calls Stop; so either this Start sees the bump and stops what it
    /// bound itself, or it finishes first and that Stop, waiting on the same gate, stops it.
    /// </remarks>
    public void Start()
    {
        int myGeneration;
        lock (startStop)
        {
            lock (lifecycle)
            {
                if (running)
                {
                    return;
                }
            }

            int sessionAt = vault.SessionGeneration;
            if (!vault.IsUnlocked)
            {
                return;
            }

            StartupError = null;
            ExtensionStartupError = null;
            bool agentUp = false;
            bool extensionUp = false;
            try
            {
                runtime.StartAgent(environment("KAGISECURE_SOCKET"));
                agentUp = true;
            }
            catch (Exception ex) when (ex is KagisecureException or InvalidOperationException)
            {
                // Not fatal: the vault still works. Shown in Agent access and the setup page.
                StartupError = ex.Message;
            }

            // After the agent, as on macOS: both listeners ask through the one queue this host's
            // loop drains, and the loop runs whenever either of them is up — a fill that arrived
            // with nobody polling would sit unanswered until it timed out.
            try
            {
                runtime.StartExtension(environment("KAGISECURE_EXTENSION_SOCKET"));
                extensionUp = true;
            }
            catch (Exception ex) when (ex is KagisecureException or InvalidOperationException)
            {
                ExtensionStartupError = ex.Message;
            }

            if (vault.SessionGeneration != sessionAt || !vault.IsUnlocked)
            {
                // The session was locked (or replaced) while the listeners were binding: they hold
                // a session that is on its way out. Stop them here, since the Lock's own Stop may
                // already have come and gone.
                if (agentUp)
                {
                    TryIgnore(runtime.StopAgent);
                }

                if (extensionUp)
                {
                    TryIgnore(runtime.StopExtension);
                }

                StartupError = null;
                ExtensionStartupError = null;
                return;
            }

            CancellationTokenSource cancellation = new();
            lock (lifecycle)
            {
                running = true;
                myGeneration = ++generation;
                loopCancellation = cancellation;
                loopTask = Task.Run(() => PollLoopAsync(myGeneration, cancellation.Token));
                ticker = dispatcher.StartTimer(TimeSpan.FromSeconds(1), Tick);
            }
        }

        Refresh();
    }

    /// <summary>
    /// Stop serving. Denies everything waiting and drops every lease. Any thread; idempotent.
    /// Blocks for at most three poll intervals while the loop drains (ADR-0020's bound), and until
    /// a Start in progress on another thread has finished — so that Start's listeners are stopped
    /// too.
    /// </summary>
    public void Stop()
    {
        lock (startStop)
        {
            Task? loop;
            IDisposable? timer;
            lock (lifecycle)
            {
                if (!running)
                {
                    return;
                }

                running = false;
                generation++;
                loopCancellation?.Cancel();
                loop = loopTask;
                timer = ticker;
                loopTask = null;
                ticker = null;
                loopCancellation = null;
            }

            timer?.Dispose();
            try
            {
                loop?.Wait(PollInterval * 3);
            }
            catch (AggregateException)
            {
                // The loop's own failure is not a reason to leave the listeners running.
            }

            // Stopping each listener denies every waiting approval and drops every lease (Rust side).
            TryIgnore(runtime.StopAgent);
            TryIgnore(runtime.StopExtension);
        }

        dispatcher.Post(ClearState);
    }

    /// <inheritdoc />
    public void Dispose() => Stop();

    private async Task PollLoopAsync(int myGeneration, CancellationToken cancellationToken)
    {
        while (true)
        {
            ApprovalRequest request;
            try
            {
                request = await runtime.NextRequestAsync(PollInterval, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception)
            {
                // An FFI failure in the poll itself. Not fatal to the loop; do not spin on it.
                try
                {
                    await Task.Delay(PollInterval, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                continue;
            }

            if (cancellationToken.IsCancellationRequested)
            {
                // Taken off the queue after the lock began. Answered rather than dropped: USER_DENIED
                // is the truthful outcome for a request nobody will ever see.
                DenyUnseen(request, LockedBeforeSeenEvidence);
                return;
            }

            dispatcher.Post(() => Received(request, myGeneration));
        }
    }

    private void Received(ApprovalRequest request, int fromGeneration)
    {
        bool live;
        lock (lifecycle)
        {
            live = running && generation == fromGeneration;
        }

        if (!live)
        {
            DenyUnseen(request, LockedBeforeSeenEvidence);
            return;
        }

        if (request.Action == ApprovalAction.AgentFill)
        {
            DenyUnseen(request, AgentFillUnsupportedEvidence);
            return;
        }

        Queue.Add(request);
        StartVerification(request);
        if (Queue.Count == 1)
        {
            CurrentChanged?.Invoke(this, EventArgs.Empty);
        }

        AttentionRequested?.Invoke(this, EventArgs.Empty);
        Refresh();
    }

    /// <summary>
    /// The one-second tick: the clock, statuses, both lease tables, the IPC lock flag, and the
    /// timeout sweep. Public so tests drive it; the real timer calls it on the UI thread.
    /// </summary>
    public void Tick()
    {
        Now = clock();
        if (!IsRunning)
        {
            return;
        }

        Refresh();
        bool lockRequested = false;
        try
        {
            lockRequested = runtime.TakeLockRequest();
        }
        catch (KagisecureException)
        {
        }

        DropExpired();
        if (lockRequested)
        {
            LockRequested?.Invoke(this, EventArgs.Empty);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Verdicts
    // -------------------------------------------------------------------------------------------

    /// <summary>The verdict for <paramref name="requestId"/>, if its check has finished.</summary>
    public PeerVerdict? VerdictFor(string requestId) =>
        verdicts.TryGetValue(requestId, out Task<PeerVerdict>? task) && task.IsCompletedSuccessfully ? task.Result : null;

    /// <summary>A task that completes when <paramref name="requestId"/>'s check has finished. For tests and the sheet.</summary>
    public Task<PeerVerdict>? VerificationTask(string requestId) =>
        verdicts.TryGetValue(requestId, out Task<PeerVerdict>? task) ? task : null;

    private void StartVerification(ApprovalRequest request)
    {
        if (verdicts.ContainsKey(request.Id))
        {
            return;
        }

        // Computed once per request and remembered: re-checking a pid that has since exited would
        // turn a verdict into a different verdict just because the head moved.
        Task<PeerVerdict> task = Task.Run(() => ComputeVerdict(request));
        verdicts[request.Id] = task;
        task.ContinueWith(
            _ => dispatcher.Post(() =>
            {
                if (Current?.Id == request.Id)
                {
                    VerdictChanged?.Invoke(this, EventArgs.Empty);
                }
            }),
            TaskScheduler.Default);
    }

    private PeerVerdict ComputeVerdict(ApprovalRequest request)
    {
        // A pid the caller reported about itself is not a process the app can vouch for: checking
        // its file would verify whatever the caller chose to name (a genuinely signed binary, say).
        ClientVerification helper = request.ClientPidFromKernel
            ? Check(request.ClientPid, request.ClientExecutable, PeerRequirement.OwnHelper, "the caller")
            : new ClientVerification(false, SelfReportedPidEvidence);
        if (request.Action != ApprovalAction.FillCredential)
        {
            return new PeerVerdict(helper);
        }

        ClientVerification browser = request.BrowserPid is null || request.BrowserExecutable is null
            ? new ClientVerification(false, "No recognized browser launched the helper.")
            : Check(request.BrowserPid, request.BrowserExecutable, PeerRequirement.Browser, "the browser");
        var combined = new ClientVerification(
            helper.Verified && browser.Verified,
            string.Join("; ", new[] { helper.Evidence, browser.Evidence }.Where(e => !string.IsNullOrEmpty(e))));
        return new PeerVerdict(combined, helper, browser);
    }

    private ClientVerification Check(uint? pid, string? executable, PeerRequirement requirement, string who)
    {
        if (pid is not uint p || string.IsNullOrEmpty(executable))
        {
            return new ClientVerification(false, $"code signature not checked: no process for {who}");
        }

        try
        {
            return runtime.VerifyPeer(p, executable, requirement);
        }
        catch (Exception ex)
        {
            // Fails closed, with the reason.
            return new ClientVerification(false, $"code signature not checked: {ex.Message}");
        }
    }

    private ClientVerification VerificationFrom(Task<PeerVerdict>? task) =>
        task is { IsCompletedSuccessfully: true }
            ? task.Result.Combined
            : new ClientVerification(false, "code signature not checked");

    // -------------------------------------------------------------------------------------------
    // Answering
    // -------------------------------------------------------------------------------------------

    /// <summary>Deny. No consent needed: saying no is always allowed (ui-spec.md §10.3).</summary>
    public void Deny(ApprovalRequest request)
    {
        verdicts.TryGetValue(request.Id, out Task<PeerVerdict>? task);
        TryResolve(request.Id, new ApprovalDecision.Deny(), VerificationFrom(task));
        Advance(request.Id);
    }

    /// <summary>
    /// Allow, after Windows Hello consent. Returns the consent outcome so the sheet can stay up on
    /// anything but <see cref="ConsentStatus.Verified"/> — a cancelled or refused consent grants
    /// nothing and does not answer the request; it stays pending until the user denies, tries
    /// again, or its window closes (which answers <c>Deny</c>).
    /// </summary>
    public async Task<ConsentOutcome> AllowAsync(ApprovalRequest request, ApprovalDecision decision)
    {
        if (decision is ApprovalDecision.Deny)
        {
            throw new ArgumentException("Use Deny to deny.", nameof(decision));
        }

        if (!IsPending(request.Id, out int fromGeneration))
        {
            return new ConsentOutcome(ConsentStatus.Failed, "This request is no longer waiting for an answer.");
        }

        // Captured before the await: the verdict that goes back is the one computed for this
        // request, whatever the head is by the time the prompt returns.
        verdicts.TryGetValue(request.Id, out Task<PeerVerdict>? verdict);
        ConsentOutcome outcome = await gate.RequestAsync(ApprovalText.Reason(request)).ConfigureAwait(true);
        if (outcome.Status == ConsentStatus.Unavailable)
        {
            passwordFallbackOffered.Add(request.Id);
        }

        if (outcome.Status != ConsentStatus.Verified)
        {
            return outcome;
        }

        return Grant(request, decision, verdict, fromGeneration);
    }

    /// <summary>
    /// Whether the master-password fallback may be offered for <paramref name="request"/>: only
    /// after Windows Hello reported itself unavailable for it. Never a way around a Hello that is
    /// available.
    /// </summary>
    public bool PasswordFallbackAllowed(ApprovalRequest request) => passwordFallbackOffered.Contains(request.Id);

    /// <summary>
    /// ADR-0004's fallback for a PC without Windows Hello: approve with the master password,
    /// verified against the vault. Refused unless <see cref="PasswordFallbackAllowed"/>.
    /// </summary>
    public async Task<ConsentOutcome> AllowWithPasswordAsync(ApprovalRequest request, ApprovalDecision decision, string masterPassword)
    {
        if (decision is ApprovalDecision.Deny)
        {
            throw new ArgumentException("Use Deny to deny.", nameof(decision));
        }

        if (!PasswordFallbackAllowed(request))
        {
            return new ConsentOutcome(ConsentStatus.Failed, "Use Windows Hello to approve.");
        }

        if (!IsPending(request.Id, out int fromGeneration))
        {
            return new ConsentOutcome(ConsentStatus.Failed, "This request is no longer waiting for an answer.");
        }

        verdicts.TryGetValue(request.Id, out Task<PeerVerdict>? verdict);
        MasterPasswordCheck check;
        try
        {
            check = await vault.VerifyMasterPasswordAsync(masterPassword).ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is KagisecureException or InvalidOperationException)
        {
            return new ConsentOutcome(ConsentStatus.Failed, ex.Message);
        }

        switch (check.Kind)
        {
            case MasterPasswordCheckKind.Verified:
                break;
            case MasterPasswordCheckKind.Wrong:
                return new ConsentOutcome(
                    ConsentStatus.Failed,
                    $"Wrong password. Nothing has been granted. Try again in {Seconds(check.RetryAfter)}.");
            default:
                // Not checked at all (the back-off after a wrong one, ADR-0038 user decision 7).
                return new ConsentOutcome(
                    ConsentStatus.Failed,
                    $"Too many attempts. Nothing has been granted. Try again in {Seconds(check.RetryAfter)}.");
        }

        return Grant(request, decision, verdict, fromGeneration);
    }

    private static string Seconds(TimeSpan wait)
    {
        int seconds = Math.Max(1, (int)Math.Ceiling(wait.TotalSeconds));
        return seconds == 1 ? "1 second" : $"{seconds} seconds";
    }

    private ConsentOutcome Grant(ApprovalRequest request, ApprovalDecision decision, Task<PeerVerdict>? verdict, int fromGeneration)
    {
        lock (lifecycle)
        {
            if (!running || generation != fromGeneration)
            {
                // The vault locked while the prompt was up. Stopping the listener already denied
                // the request; there is nothing left to grant.
                return new ConsentOutcome(ConsentStatus.Failed, "The vault locked. Nothing has been granted.");
            }
        }

        bool live = TryResolve(request.Id, decision, VerificationFrom(verdict));
        Advance(request.Id);
        return live
            ? ConsentOutcome.Verified
            : new ConsentOutcome(ConsentStatus.Failed, "The request expired before it was approved. Nothing has been granted.");
    }

    private bool IsPending(string requestId, out int currentGeneration)
    {
        lock (lifecycle)
        {
            currentGeneration = generation;
            return running && Queue.Any(r => r.Id == requestId);
        }
    }

    /// <summary>Retire the request that was actually resolved — by id, never "the head".</summary>
    private void Advance(string requestId)
    {
        ApprovalRequest? before = Current;
        for (int i = Queue.Count - 1; i >= 0; i--)
        {
            if (Queue[i].Id == requestId)
            {
                Queue.RemoveAt(i);
            }
        }

        Forget(requestId);
        if (!ReferenceEquals(before, Current))
        {
            CurrentChanged?.Invoke(this, EventArgs.Empty);
        }

        Refresh();
    }

    /// <summary>
    /// How long after <c>expires_at</c> the sheet waits before retiring a request itself.
    /// <c>expires_at</c> is whole Unix seconds while Rust's 60-second wait is measured on a
    /// monotonic clock, so retiring at exactly <c>expires_at</c> can answer Deny up to a second
    /// before Rust answers <c>APPROVAL_TIMEOUT</c> — and the agent is then told the user declined,
    /// which nobody did (observed end to end on Windows). The grace lets Rust's timeout land first;
    /// the Deny that follows is a no-op on the wire.
    /// </summary>
    public const int ExpiryGraceSeconds = 2;

    /// <summary>Retire anything whose 60-second window closed, answering it Deny on the way out — which dismisses its sheet.</summary>
    private void DropExpired()
    {
        ulong cutoff = (ulong)Math.Max(0, Now.ToUnixTimeSeconds() - ExpiryGraceSeconds);
        List<ApprovalRequest> expired = Queue.Where(r => r.ExpiresAt <= cutoff).ToList();
        if (expired.Count == 0)
        {
            return;
        }

        ApprovalRequest? before = Current;
        foreach (ApprovalRequest request in expired)
        {
            // Answered, not merely dropped. The wire side has normally said APPROVAL_TIMEOUT
            // already and this is a no-op there; "denied" is the truthful outcome either way.
            TryResolve(request.Id, new ApprovalDecision.Deny(), new ClientVerification(false, ExpiredEvidence));
            Queue.Remove(request);
            Forget(request.Id);
        }

        if (!ReferenceEquals(before, Current))
        {
            CurrentChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    private void Forget(string requestId)
    {
        verdicts.Remove(requestId);
        passwordFallbackOffered.Remove(requestId);
    }

    private bool TryResolve(string requestId, ApprovalDecision decision, ClientVerification verification)
    {
        try
        {
            return runtime.Resolve(requestId, decision, verification);
        }
        catch (KagisecureException)
        {
            return false;
        }
    }

    private void DenyUnseen(ApprovalRequest request, string evidence) =>
        TryResolve(request.Id, new ApprovalDecision.Deny(), new ClientVerification(false, evidence));

    private void ClearState()
    {
        bool hadCurrent = Current is not null;
        Queue.Clear();
        verdicts.Clear();
        passwordFallbackOffered.Clear();
        Leases.Clear();
        FillLeases.Clear();
        AgentStatus = SafeGet(runtime.AgentStatus, AgentStatus);
        ExtensionStatus = SafeGet(runtime.ExtensionStatus, ExtensionStatus);
        if (hadCurrent)
        {
            CurrentChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    // -------------------------------------------------------------------------------------------
    // Leases
    // -------------------------------------------------------------------------------------------

    /// <summary>Revoke one lease, shredding anything written under it.</summary>
    public void Revoke(Lease lease)
    {
        try
        {
            runtime.RevokeLease(lease.Id);
        }
        catch (KagisecureException)
        {
        }

        Refresh();
    }

    /// <summary>Revoke one fill lease.</summary>
    public void Revoke(FillLease lease)
    {
        try
        {
            runtime.RevokeFillLease(lease.Origin, lease.ItemId);
        }
        catch (KagisecureException)
        {
        }

        Refresh();
    }

    /// <summary>Revoke every lease and every fill lease ("Revoke all" empties both tables).</summary>
    public void RevokeAll()
    {
        TryIgnore(runtime.RevokeAllLeases);
        TryIgnore(runtime.RevokeAllFillLeases);
        Refresh();
    }

    /// <summary>Re-read statuses and both lease tables.</summary>
    public void Refresh()
    {
        AgentStatus = SafeGet(runtime.AgentStatus, AgentStatus);
        ExtensionStatus = SafeGet(runtime.ExtensionStatus, ExtensionStatus);
        if (!IsRunning)
        {
            Leases.Clear();
            FillLeases.Clear();
            return;
        }

        Replace(Leases, SafeGet(runtime.Leases, (IReadOnlyList<Lease>)Array.Empty<Lease>()));
        Replace(FillLeases, SafeGet(runtime.FillLeases, (IReadOnlyList<FillLease>)Array.Empty<FillLease>()));
    }

    private static void Replace<T>(ObservableCollection<T> target, IReadOnlyList<T> source)
    {
        if (target.SequenceEqual(source))
        {
            return;
        }

        target.Clear();
        foreach (T item in source)
        {
            target.Add(item);
        }
    }

    private static T SafeGet<T>(Func<T> read, T fallback)
    {
        try
        {
            return read();
        }
        catch (KagisecureException)
        {
            return fallback;
        }
    }

    private static void TryIgnore(Action action)
    {
        try
        {
            action();
        }
        catch (KagisecureException)
        {
        }
    }
}
