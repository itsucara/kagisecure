using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kagisecure.App.Services;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Xunit;

namespace Kagisecure.App.Tests;

public sealed class AgentHostServiceTests : IDisposable
{
    private readonly FakeAgentRuntime runtime = new();
    private readonly FakeConsentGate gate = new();
    private readonly FakeAgentVault vault = new();
    private readonly FakeDispatcher dispatcher = new();
    private readonly Dictionary<string, string?> env = new();
    private DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(1_000);
    private readonly AgentHostService host;

    public AgentHostServiceTests()
    {
        host = new AgentHostService(runtime, gate, vault, dispatcher, () => now, name => env.TryGetValue(name, out string? v) ? v : null);

        // Wires Locking → Stop, as the app does. The item-side fake starts locked, so this posts no Start.
        host.Bind(new FakeVaultService());
    }

    public void Dispose() => host.Stop();

    private ApprovalRequest Deliver(ApprovalRequest request)
    {
        runtime.Enqueue(request);
        dispatcher.PumpUntil(() => host.Queue.Any(r => r.Id == request.Id), $"request {request.Id} to reach the queue");
        host.VerificationTask(request.Id)!.Wait(TimeSpan.FromSeconds(5));
        dispatcher.Pump();
        return request;
    }

    private List<(string Id, ApprovalDecision Decision, ClientVerification Verification)> Resolutions => runtime.Resolutions.ToList();

    [Fact]
    public void Start_BindsBothListeners_WithTheSocketOverrides_AndStartsOneLoop()
    {
        env["KAGISECURE_SOCKET"] = "kagisecure-test.sock";
        env["KAGISECURE_EXTENSION_SOCKET"] = "kagisecure-test-ext.sock";

        host.Start();
        host.Start(); // idempotent

        Assert.Equal(new string?[] { "kagisecure-test.sock" }, runtime.AgentStarts);
        Assert.Equal(new string?[] { "kagisecure-test-ext.sock" }, runtime.ExtensionStarts);
        Assert.True(host.IsRunning);
        Assert.Equal(1, dispatcher.TimersStarted);
    }

    [Fact]
    public void Start_WhileLocked_DoesNothing()
    {
        vault.Unlocked = false;
        host.Start();
        Assert.Empty(runtime.AgentStarts);
        Assert.False(host.IsRunning);
    }

    [Fact]
    public void Start_RecordsWhyTheAgentCouldNotBind_AndStillServesTheExtension()
    {
        runtime.StartAgentThrows = new InvalidOperationException("the CLI daemon already owns the socket");
        host.Start();
        Assert.Equal("the CLI daemon already owns the socket", host.StartupError);
        Assert.Single(runtime.ExtensionStarts);
        Assert.True(host.IsRunning);
    }

    [Fact]
    public void Request_BecomesCurrent_AndIsVerifiedAsOurOwnHelper()
    {
        host.Start();
        int changed = 0;
        host.CurrentChanged += (_, _) => changed++;

        ApprovalRequest request = Deliver(Requests.Env());

        Assert.Same(request, host.Current);
        Assert.Equal(1, changed);
        Assert.Contains(runtime.Verifications, v => v.Pid == 4242 && v.Executable == @"C:\tools\kagisecure-mcp.exe" && v.Requirement == PeerRequirement.OwnHelper);
        Assert.NotNull(host.VerdictFor(request.Id));
    }

    [Fact]
    public void Fill_ChecksHelperAndBrowser_AndTheCombinedVerdictNeverFlattersTheWeakerHalf()
    {
        runtime.Verify = (_, _, requirement) => requirement == PeerRequirement.Browser
            ? new ClientVerification(true, "Authenticode: signed by 'Google LLC'")
            : new ClientVerification(false, "Authenticode: this build of Kagisecure is unsigned");
        host.Start();

        ApprovalRequest fill = Deliver(Requests.Fill());
        PeerVerdict verdict = host.VerdictFor(fill.Id)!;

        Assert.Contains(runtime.Verifications, v => v.Pid == 777 && v.Requirement == PeerRequirement.Browser);
        Assert.Contains(runtime.Verifications, v => v.Pid == 5151 && v.Requirement == PeerRequirement.OwnHelper);
        Assert.True(verdict.Browser!.Verified);
        Assert.False(verdict.Helper!.Verified);
        Assert.False(verdict.Combined.Verified);
        Assert.Contains("Google LLC", verdict.Combined.Evidence);
        Assert.Contains("unsigned", verdict.Combined.Evidence);
    }

    [Fact]
    public void Fill_WithNoBrowserProcess_IsUnverifiedWithAReason()
    {
        host.Start();
        ApprovalRequest fill = Deliver(Requests.Fill(browserPid: null, browserExe: null));
        PeerVerdict verdict = host.VerdictFor(fill.Id)!;
        Assert.False(verdict.Combined.Verified);
        Assert.Contains("No recognized browser", verdict.Browser!.Evidence);
    }

    [Fact]
    public async Task ConsentVerified_ResolvesWithTheDecision_AndTheVerdictComputedForThatRequest()
    {
        host.Start();
        ApprovalRequest request = Deliver(Requests.Env());

        ConsentOutcome outcome = await host.AllowAsync(request, new ApprovalDecision.AllowSession(600, 10));

        Assert.Equal(ConsentStatus.Verified, outcome.Status);
        var resolution = Assert.Single(Resolutions);
        Assert.Equal(request.Id, resolution.Id);
        Assert.Equal(new ApprovalDecision.AllowSession(600, 10), resolution.Decision);
        Assert.Equal("Authenticode: not signed (test)", resolution.Verification.Evidence);
        Assert.Null(host.Current);
        Assert.Single(gate.Reasons);
        Assert.Equal("approve writing 2 variables to a .env file", gate.Reasons[0]);
    }

    [Theory]
    [InlineData(ConsentStatus.Cancelled)]
    [InlineData(ConsentStatus.Failed)]
    public async Task ConsentRefused_GrantsNothing_AndTheRequestEndsDenied(ConsentStatus refusal)
    {
        host.Start();
        ApprovalRequest request = Deliver(Requests.Env());
        gate.Next = new ConsentOutcome(refusal, "no");

        ConsentOutcome outcome = await host.AllowAsync(request, new ApprovalDecision.AllowOnce());

        Assert.Equal(refusal, outcome.Status);
        Assert.Empty(Resolutions); // not approved; still waiting for a human
        Assert.Same(request, host.Current);

        // The window closes with nobody having approved it: it ends as a Deny, never an Allow.
        now = DateTimeOffset.FromUnixTimeSeconds(1_060 + AgentHostService.ExpiryGraceSeconds);
        host.Tick();

        var resolution = Assert.Single(Resolutions);
        Assert.IsType<ApprovalDecision.Deny>(resolution.Decision);
        Assert.Null(host.Current);
    }

    [Fact]
    public async Task ConsentRefused_ThenDeny_ResolvesDeny()
    {
        host.Start();
        ApprovalRequest request = Deliver(Requests.Env());
        gate.Next = new ConsentOutcome(ConsentStatus.Failed, "retries exhausted");
        await host.AllowAsync(request, new ApprovalDecision.AllowOnce());

        host.Deny(request);

        var resolution = Assert.Single(Resolutions);
        Assert.IsType<ApprovalDecision.Deny>(resolution.Decision);
        Assert.All(Resolutions, r => Assert.IsNotType<ApprovalDecision.AllowOnce>(r.Decision));
    }

    [Fact]
    public async Task HelloUnavailable_OffersThePasswordFallback_WhichMustBeTheRightPassword()
    {
        host.Start();
        ApprovalRequest request = Deliver(Requests.Env());
        gate.Next = new ConsentOutcome(ConsentStatus.Unavailable, "Windows Hello is not set up for this account.");

        ConsentOutcome first = await host.AllowAsync(request, new ApprovalDecision.AllowOnce());
        Assert.Equal(ConsentStatus.Unavailable, first.Status);
        Assert.True(host.PasswordFallbackAllowed(request));
        Assert.Empty(Resolutions);

        ConsentOutcome wrong = await host.AllowWithPasswordAsync(request, new ApprovalDecision.AllowOnce(), "wrong");
        Assert.Equal(ConsentStatus.Failed, wrong.Status);
        Assert.Empty(Resolutions);

        ConsentOutcome right = await host.AllowWithPasswordAsync(request, new ApprovalDecision.AllowOnce(), vault.MasterPassword);
        Assert.Equal(ConsentStatus.Verified, right.Status);
        var resolution = Assert.Single(Resolutions);
        Assert.IsType<ApprovalDecision.AllowOnce>(resolution.Decision);
    }

    [Fact]
    public async Task PasswordFallback_IsRefused_WhileWindowsHelloIsAvailable()
    {
        host.Start();
        ApprovalRequest request = Deliver(Requests.Env());

        ConsentOutcome outcome = await host.AllowWithPasswordAsync(request, new ApprovalDecision.AllowOnce(), vault.MasterPassword);

        Assert.Equal(ConsentStatus.Failed, outcome.Status);
        Assert.Empty(vault.PasswordAttempts);
        Assert.Empty(Resolutions);
    }

    [Fact]
    public void Timeout_RetiresTheRequestAsDeny_AndDismissesTheSheet()
    {
        host.Start();
        ApprovalRequest request = Deliver(Requests.Env(expiresAt: 1_060));
        using var sheet = new ApprovalViewModel(host, request);
        int closes = 0;
        sheet.CloseRequested += (_, _) => closes++;

        now = DateTimeOffset.FromUnixTimeSeconds(1_059);
        host.Tick();
        Assert.Equal(0, closes);
        Assert.Equal(1, (int)sheet.RemainingSeconds);

        // At expires_at the countdown reads 0, but Rust's own APPROVAL_TIMEOUT gets to land first.
        now = DateTimeOffset.FromUnixTimeSeconds(1_060);
        host.Tick();
        Assert.Equal(0, closes);
        Assert.Equal(0, (int)sheet.RemainingSeconds);
        Assert.Empty(Resolutions);

        now = DateTimeOffset.FromUnixTimeSeconds(1_060 + AgentHostService.ExpiryGraceSeconds);
        host.Tick();

        Assert.Equal(1, closes);
        Assert.True(sheet.IsClosed);
        Assert.Null(host.Current);
        var resolution = Assert.Single(Resolutions);
        Assert.IsType<ApprovalDecision.Deny>(resolution.Decision);
        Assert.Equal(AgentHostService.ExpiredEvidence, resolution.Verification.Evidence);
    }

    [Fact]
    public void OneSheetAtATime_TheNextRequestWaitsItsTurn()
    {
        host.Start();
        ApprovalRequest first = Deliver(Requests.Env(id: "a"));
        ApprovalRequest second = Deliver(Requests.Env(id: "b"));

        Assert.Same(first, host.Current);
        host.Deny(first);
        Assert.Same(second, host.Current);
    }

    [Fact]
    public void Lock_StopsBothListeners_DeniesWhatIsWaiting_AndClearsTheSheet()
    {
        var items = new FakeVaultService();
        host.Bind(items);
        host.Start();
        ApprovalRequest request = Deliver(Requests.Env());
        using var sheet = new ApprovalViewModel(host, request);
        bool closed = false;
        sheet.CloseRequested += (_, _) => closed = true;

        vault.RaiseLocking();
        dispatcher.Pump();

        Assert.Equal(1, runtime.AgentStops);
        Assert.Equal(1, runtime.ExtensionStops);
        Assert.False(host.IsRunning);
        Assert.Empty(host.Queue);
        Assert.Null(host.Current);
        Assert.True(closed);

        // The loop is gone: nothing more is taken off the (process-global) queue.
        int calls = Volatile.Read(ref runtime.NextRequestCalls);
        Thread.Sleep(100);
        Assert.Equal(calls, Volatile.Read(ref runtime.NextRequestCalls));
    }

    [Fact]
    public void RequestDeliveredAfterTheLockBegan_IsDeniedUnseen()
    {
        host.Start();
        runtime.Enqueue(Requests.Env(id: "late"));
        // Let the loop take it and post it, but do not pump: the lock happens first.
        Assert.True(SpinWait.SpinUntil(() => !runtime.HasUndelivered, TimeSpan.FromSeconds(5)));
        Thread.Sleep(100);
        Assert.Empty(host.Queue);

        vault.RaiseLocking();
        dispatcher.Pump();

        Assert.Empty(host.Queue);
        Assert.All(Resolutions, r => Assert.IsType<ApprovalDecision.Deny>(r.Decision));
        Assert.Contains(Resolutions, r => r.Id == "late" && r.Verification.Evidence == AgentHostService.LockedBeforeSeenEvidence);
    }

    [Fact]
    public async Task VaultLockingWhileHelloIsUp_GrantsNothing()
    {
        host.Start();
        ApprovalRequest request = Deliver(Requests.Env());
        gate.Pending = new TaskCompletionSource<ConsentOutcome>();

        Task<ConsentOutcome> allowing = host.AllowAsync(request, new ApprovalDecision.AllowOnce());
        vault.RaiseLocking();
        dispatcher.Pump();
        gate.Pending.SetResult(ConsentOutcome.Verified);
        ConsentOutcome outcome = await allowing;

        Assert.Equal(ConsentStatus.Failed, outcome.Status);
        Assert.DoesNotContain(Resolutions, r => r.Decision is ApprovalDecision.AllowOnce);
    }

    [Fact]
    public async Task LockRequestOverIpc_LocksTheVault()
    {
        var items = new FakeVaultService();
        await items.UnlockAsync(items.DefaultVaultPath, "pw");
        host.Bind(items);
        dispatcher.Pump(); // Bind posts a Start because the vault is already unlocked
        Assert.True(host.IsRunning);

        runtime.LockRequested = true;
        host.Tick();

        Assert.Equal(1, items.LockCount);
    }

    [Fact]
    public async Task Unlocking_StartsTheHost()
    {
        var items = new FakeVaultService();
        host.Bind(items);
        Assert.False(host.IsRunning);

        await items.UnlockAsync(items.DefaultVaultPath, "pw");
        dispatcher.Pump();

        Assert.True(host.IsRunning);
    }

    [Fact]
    public void RevokeAll_EmptiesBothTables()
    {
        runtime.LiveLeases.Add(new Lease("l1", "env-1", @"C:\code", new ValueList<string>(new[] { "A" }), "env-file", "Claude Code", 2_000, 3));
        runtime.LiveFillLeases.Add(new FillLease("https://example.com", "item-1", "Example", new ValueList<string>(new[] { "password" }), "Google Chrome", 2_000));
        host.Start();
        Assert.Single(host.Leases);
        Assert.Single(host.FillLeases);

        host.RevokeAll();

        Assert.Empty(host.Leases);
        Assert.Empty(host.FillLeases);
    }

    // -------------------------------------------------------------------------------------------
    // Lock/start races (security review #1)
    // -------------------------------------------------------------------------------------------

    [Fact]
    public void ALockWhoseStopAlreadyRan_WhileTheListenersBind_LeavesNothingServing()
    {
        // The lock took the session away and its Stop found nothing running (Start had not got
        // there yet); then Start bound both listeners to a session on its way out. Start must see
        // that and stop them itself — nothing else ever will.
        runtime.DuringStartExtension = vault.TakeSessionAway;

        host.Start();

        Assert.False(host.IsRunning);
        Assert.False(runtime.Running, "the MCP listener was stopped");
        Assert.False(runtime.ExtensionRunning, "the extension listener was stopped");
        Assert.Equal(0, dispatcher.TimersStarted);
    }

    [Fact]
    public void ALockArrivingWhileTheListenersBind_StopsEverythingStartBound()
    {
        // Locking raised (on this thread, re-entrantly) between the two binds.
        runtime.DuringStartAgent = vault.RaiseLocking;

        host.Start();
        dispatcher.Pump();

        Assert.False(host.IsRunning);
        Assert.False(runtime.Running);
        Assert.False(runtime.ExtensionRunning);
    }

    [Fact]
    public void ALockFromAnotherThreadDuringStart_WaitsForStart_ThenStopsWhatItBound()
    {
        Thread? locker = null;
        using var started = new ManualResetEventSlim();
        runtime.DuringStartAgent = () =>
        {
            locker = new Thread(() =>
            {
                started.Set();
                vault.RaiseLocking(); // blocks in Stop until Start is done
            });
            locker.Start();
            started.Wait();
            Thread.Sleep(50); // let it reach the gate
        };

        host.Start();
        Assert.True(locker!.Join(TimeSpan.FromSeconds(10)));
        dispatcher.Pump();

        Assert.False(host.IsRunning);
        Assert.False(runtime.Running);
        Assert.False(runtime.ExtensionRunning);
    }

    [Fact]
    public async Task StartQueuedByAnUnlock_ThatRunsAfterTheLock_BindsNothing()
    {
        var items = new FakeVaultService();
        host.Bind(items);
        await items.UnlockAsync(items.DefaultVaultPath, "pw"); // posts Start; not pumped yet
        vault.RaiseLocking();                                  // SystemEvents: the screen locked

        dispatcher.Pump();

        Assert.Empty(runtime.AgentStarts);
        Assert.False(host.IsRunning);
    }

    [Fact]
    public void ACallerWithASelfReportedPid_IsNotSignatureChecked()
    {
        host.Start();
        ApprovalRequest request = Requests.Env() with { ClientPidFromKernel = false };

        Deliver(request);

        Assert.Empty(runtime.Verifications);
        PeerVerdict verdict = host.VerdictFor(request.Id)!;
        Assert.False(verdict.Combined.Verified);
        Assert.Equal(AgentHostService.SelfReportedPidEvidence, verdict.Combined.Evidence);
    }
}
