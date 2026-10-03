using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// The approval sheet for one request (ui-spec.md §10.2–§10.5) — the Windows port of the macOS
/// <c>ApprovalSheet</c>. Everything on it is metadata: <see cref="ApprovalRequest"/> has no field a
/// value could be in.
/// </summary>
/// <remarks>
/// Deny needs no consent. Both Allow buttons ask Windows Hello first (<see cref="IConsentGate"/>);
/// a cancelled or refused prompt keeps the sheet up with a message and grants nothing. When Hello
/// reports itself unavailable — not set up, no device, disabled by policy — the sheet offers the
/// master password instead (ADR-0004's fallback, the counterpart of macOS
/// <c>.deviceOwnerAuthentication</c> falling back to the login password); it never approves without
/// one or the other. The sheet closes itself (<see cref="CloseRequested"/>) as soon as its request
/// stops being the one on screen: answered, expired (the 60-second window), or the vault locked.
/// </remarks>
public sealed partial class ApprovalViewModel : ObservableObject, IDisposable
{
    private readonly AgentHostService host;
    private bool closed;

    public ApprovalViewModel(AgentHostService host, ApprovalRequest request)
    {
        this.host = host;
        Request = request;
        ttlSeconds = Math.Max(60, request.RequestedTtlSeconds);
        host.PropertyChanged += OnHostPropertyChanged;
        host.CurrentChanged += OnHostCurrentChanged;
        host.VerdictChanged += OnHostVerdictChanged;
        RefreshVerdict();
    }

    /// <summary>Raised once when this sheet should close: its request is no longer on screen.</summary>
    public event EventHandler? CloseRequested;

    public ApprovalRequest Request { get; }

    public bool IsFill => Request.Action == ApprovalAction.FillCredential;

    public bool IsAgentRequest => !IsFill;

    public string Glyph => ApprovalText.Glyph(Request.Action);

    public string Sentence => ApprovalText.Sentence(Request);

    public string Headline => ApprovalText.Headline(Request);

    // --- Identity (agent request) ---------------------------------------------------------------

    private PeerVerdict? verdict;

    /// <summary>The verdict, once the Authenticode check has finished; <c>null</c> while it runs.</summary>
    public PeerVerdict? Verdict
    {
        get => verdict;
        private set
        {
            if (SetProperty(ref verdict, value))
            {
                foreach (string name in new[]
                {
                    nameof(IsChecking), nameof(IsVerified), nameof(VerdictTitle), nameof(VerdictEvidence),
                    nameof(HelperVerdictTitle), nameof(HelperVerdictEvidence), nameof(HelperVerified),
                    nameof(BrowserVerdictTitle), nameof(BrowserVerdictEvidence), nameof(BrowserVerified),
                })
                {
                    OnPropertyChanged(name);
                }
            }
        }
    }

    public bool IsChecking => Verdict is null;

    public bool IsVerified => Verdict?.Combined.Verified == true;

    /// <summary>Green "Verified", or the red banner. A warning, never a gate (ADR-0015, ADR-0032).</summary>
    public string VerdictTitle => Verdict is null
        ? "Checking the caller's signature…"
        : Verdict.Combined.Verified ? "Verified" : "Unverified — proceed with caution";

    public string VerdictEvidence => Verdict?.Combined.Evidence ?? string.Empty;

    public string ReportedNameLine =>
        $"Reports itself as “{ApprovalText.Safe(Request.ClientName)}”. That name is unverified — it is whatever the caller said.";

    public string? ProcessLine => Request.ClientExecutable is null
        ? null
        : $"{Request.ClientExecutable}  ·  pid {Request.ClientPid?.ToString() ?? "?"}" + (Request.ClientPidFromKernel ? string.Empty : " (self-reported)");

    // --- Identity (fill) ------------------------------------------------------------------------

    public bool HelperVerified => Verdict?.Helper?.Verified == true;

    public string HelperVerdictTitle => Verdict is null ? "Helper: checking…" : HelperVerified ? "Helper: verified" : "Helper: unverified";

    public string HelperVerdictEvidence => Verdict?.Helper?.Evidence ?? (Verdict is null ? string.Empty : "The helper could not be checked.");

    public bool BrowserVerified => Verdict?.Browser?.Verified == true;

    public string BrowserVerdictTitle => Verdict is null ? "Browser: checking…" : BrowserVerified ? "Browser: verified" : "Browser: unverified";

    public string BrowserVerdictEvidence => Verdict?.Browser?.Evidence ?? (Verdict is null ? string.Empty : "No recognized browser launched the helper.");

    public string? ExtensionIdLine => Request.ExtensionId is null
        ? null
        : $"Extension {Request.ExtensionId} — pinned in this app and in the browser's manifest.";

    public string? HelperProcessLine => Request.ClientExecutable is null
        ? null
        : $"{Request.ClientExecutable}  ·  pid {Request.ClientPid?.ToString() ?? "?"}";

    public string? BrowserProcessLine => Request.BrowserExecutable is null
        ? null
        : $"{Request.BrowserExecutable}  ·  pid {Request.BrowserPid?.ToString() ?? "?"}";

    public string FillItem => ApprovalText.Safe(Request.ItemTitle ?? Request.ItemId ?? "unknown", 120);

    public string FillWebsite => Request.Origin ?? "unknown";

    public string FillFields => string.Join(", ", Request.FillFields);

    public bool ShowFrameWarning => IsFill && Request.TopOrigin is not null;

    public string FrameWarning =>
        $"This form is inside a frame on {(Request.TopOriginUnknown ? "an unknown site" : Request.TopOrigin ?? "another site")}. "
        + "kagisecure matched the frame, not the page — check that you meant to sign in here.";

    // --- What and where -------------------------------------------------------------------------

    public bool ShowVariables => Request.Variables.Count > 0;

    public IReadOnlyList<string> Variables => Request.Variables;

    public bool ShowCommand => Request.Command.Count > 0;

    public string CommandLine => string.Join(" ", Request.Command);

    /// <summary>"File" for a target path, "Directory" otherwise.</summary>
    public string? LocationLabel => Request.TargetPath is not null ? "File" : Request.Directory is not null ? "Directory" : null;

    public string? LocationValue => Request.TargetPath ?? Request.Directory;

    public string? EnvironmentName => Request.EnvironmentName;

    public string? CallerCwd => Request.ClientCwd is { } cwd && cwd != Request.Directory ? cwd : null;

    /// <summary>The red "not gitignored" callout.</summary>
    public bool ShowGitWarning => Request.Gitignored == false;

    /// <summary>The destructive case M-16 names: replacing a file kagisecure did not write.</summary>
    public bool ShowOverwriteWarning => Request.OverwriteRequested && Request.TargetExists == true && Request.TargetWrittenByUs != true;

    // --- Lease ----------------------------------------------------------------------------------

    public bool ShowTtl => Request.MintsLease || IsFill;

    public double TtlMinimum => 60;

    public double TtlMaximum => Math.Max(60, Request.RequestedTtlSeconds);

    private double ttlSeconds;

    /// <summary>The TTL the user settled on: starts at what was asked for and can only go down (Rust clamps it again).</summary>
    public double TtlSeconds
    {
        get => ttlSeconds;
        set
        {
            double clamped = Math.Clamp(Math.Round(value / 60) * 60, TtlMinimum, TtlMaximum);
            if (SetProperty(ref ttlSeconds, clamped))
            {
                OnPropertyChanged(nameof(TtlText));
                OnPropertyChanged(nameof(Summary));
            }
        }
    }

    public string TtlText => ApprovalText.Duration((ulong)TtlSeconds);

    public string TtlHelp => IsFill
        ? "“Allow for this session” lets this item fill on this website for that long without asking again. "
          + "Every fill still needs your click in the page, and locking the vault ends it."
        : $"The caller asked for {ApprovalText.Duration(Request.RequestedTtlSeconds)}. You can shorten it, never lengthen it.";

    public string Summary => ApprovalText.Summary(Request, (ulong)TtlSeconds);

    // --- Countdown ------------------------------------------------------------------------------

    public double RemainingSeconds => Math.Max(0, (double)Request.ExpiresAt - host.Now.ToUnixTimeSeconds());

    public double TotalSeconds => Math.Max(1, (double)Request.ExpiresAt - Request.CreatedAt);

    public bool IsUrgent => RemainingSeconds < 15;

    public string CountdownText => $"{(int)RemainingSeconds} s to answer, then the caller is told nobody replied.";

    // --- Answering ------------------------------------------------------------------------------

    private bool isBusy;
    private string? problem;
    private bool showPasswordFallback;
    private string fallbackPassword = string.Empty;

    /// <summary>A prompt is up or an answer is being sent: the buttons are disabled.</summary>
    public bool IsBusy
    {
        get => isBusy;
        private set
        {
            if (SetProperty(ref isBusy, value))
            {
                DenyCommand.NotifyCanExecuteChanged();
                AllowOnceCommand.NotifyCanExecuteChanged();
                AllowSessionCommand.NotifyCanExecuteChanged();
                ApproveWithPasswordCommand.NotifyCanExecuteChanged();
            }
        }
    }

    /// <summary>Why the last Allow did not go through. Nothing was granted.</summary>
    public string? Problem
    {
        get => problem;
        private set => SetProperty(ref problem, value);
    }

    /// <summary>Windows Hello is unavailable for this request: show the master-password field.</summary>
    public bool ShowPasswordFallback
    {
        get => showPasswordFallback;
        private set => SetProperty(ref showPasswordFallback, value);
    }

    /// <summary>The master password typed for the fallback. Cleared as soon as it is used.</summary>
    public string FallbackPassword
    {
        get => fallbackPassword;
        set
        {
            if (SetProperty(ref fallbackPassword, value ?? string.Empty))
            {
                ApproveWithPasswordCommand.NotifyCanExecuteChanged();
            }
        }
    }

    /// <summary>The decision the fallback will make — whichever Allow button raised it.</summary>
    private ApprovalDecision? pendingDecision;

    public string ApproveWithPasswordLabel => pendingDecision is ApprovalDecision.AllowSession ? "Allow for this session with password" : "Allow once with password";

    private bool NotBusy => !IsBusy;

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private void Deny()
    {
        FallbackPassword = string.Empty;
        host.Deny(Request);
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private Task AllowOnceAsync() => AllowAsync(new ApprovalDecision.AllowOnce());

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private Task AllowSessionAsync() => AllowAsync(new ApprovalDecision.AllowSession((ulong)TtlSeconds, Request.RequestedUses));

    private bool CanApproveWithPassword => NotBusy && FallbackPassword.Length > 0 && pendingDecision is not null;

    [RelayCommand(CanExecute = nameof(CanApproveWithPassword))]
    private async Task ApproveWithPasswordAsync()
    {
        if (pendingDecision is null)
        {
            return;
        }

        // Which button raised the fallback, with the TTL the slider shows *now*: the user may have
        // shortened it while typing the password.
        ApprovalDecision decision = pendingDecision is ApprovalDecision.AllowSession
            ? new ApprovalDecision.AllowSession((ulong)TtlSeconds, Request.RequestedUses)
            : new ApprovalDecision.AllowOnce();
        IsBusy = true;
        Problem = null;
        string password = FallbackPassword;
        FallbackPassword = string.Empty;
        try
        {
            ConsentOutcome outcome = await host.AllowWithPasswordAsync(Request, decision, password).ConfigureAwait(true);
            if (outcome.Status != ConsentStatus.Verified)
            {
                Problem = outcome.Message ?? "Nothing has been granted.";
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task AllowAsync(ApprovalDecision decision)
    {
        IsBusy = true;
        Problem = null;
        try
        {
            ConsentOutcome outcome = await host.AllowAsync(Request, decision).ConfigureAwait(true);
            switch (outcome.Status)
            {
                case ConsentStatus.Verified:
                    break;
                case ConsentStatus.Cancelled:
                    // Back to the sheet: a cancelled prompt is not a decision.
                    Problem = "Windows Hello was cancelled. Nothing has been granted.";
                    break;
                case ConsentStatus.Unavailable:
                    pendingDecision = decision;
                    OnPropertyChanged(nameof(ApproveWithPasswordLabel));
                    ShowPasswordFallback = host.PasswordFallbackAllowed(Request);
                    Problem = $"{outcome.Message ?? "Windows Hello is unavailable."} Approve with your master password instead, or deny.";
                    ApproveWithPasswordCommand.NotifyCanExecuteChanged();
                    break;
                default:
                    Problem = $"{outcome.Message ?? "Windows Hello did not verify you."} Nothing has been granted.";
                    break;
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    // --- Host plumbing --------------------------------------------------------------------------

    private void OnHostPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(AgentHostService.Now))
        {
            OnPropertyChanged(nameof(RemainingSeconds));
            OnPropertyChanged(nameof(IsUrgent));
            OnPropertyChanged(nameof(CountdownText));
        }
    }

    private void OnHostCurrentChanged(object? sender, EventArgs e)
    {
        if (host.Current?.Id != Request.Id)
        {
            RequestClose();
        }
    }

    private void OnHostVerdictChanged(object? sender, EventArgs e) => RefreshVerdict();

    private void RefreshVerdict() => Verdict = host.VerdictFor(Request.Id);

    private void RequestClose()
    {
        if (closed)
        {
            return;
        }

        closed = true;
        FallbackPassword = string.Empty;
        CloseRequested?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Whether the sheet has been told to close.</summary>
    public bool IsClosed => closed;

    /// <summary>
    /// The user closed the window without pressing a button. Saying no is always allowed, and a
    /// sheet that vanished without an answer would leave the caller waiting out its minute, so it
    /// is a Deny.
    /// </summary>
    public void DenyIfStillPending()
    {
        if (!closed && host.Current?.Id == Request.Id)
        {
            host.Deny(Request);
        }
    }

    public void Dispose()
    {
        host.PropertyChanged -= OnHostPropertyChanged;
        host.CurrentChanged -= OnHostCurrentChanged;
        host.VerdictChanged -= OnHostVerdictChanged;
        FallbackPassword = string.Empty;
    }
}
