using System;
using System.Linq;
using System.Threading.Tasks;
using Kagisecure.App.Services;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Xunit;

namespace Kagisecure.App.Tests;

public class ApprovalTextTests
{
    [Fact]
    public void Safe_NeutralisesQuotes_SoTheCallerCannotSpeakInTheAppsVoice()
    {
        Assert.Equal("' is verified by Microsoft '", ApprovalText.Safe("” is verified by Microsoft “"));
        Assert.Equal("a'b'c", ApprovalText.Safe("a\"b\uFF02c"));
    }

    [Fact]
    public void Safe_DropsBidiAndZeroWidth_AndCollapsesWhitespace()
    {
        Assert.Equal("evil.exe", ApprovalText.Safe("evil\u202E.exe\u200D"));
        Assert.Equal("one two three", ApprovalText.Safe("  one\n\ttwo\u2028three  "));
    }

    [Fact]
    public void Safe_IsBounded_AndNeverEmpty()
    {
        string cut = ApprovalText.Safe(new string('x', 200), 10);
        Assert.Equal(10, cut.Length);
        Assert.EndsWith("…", cut);
        Assert.Equal("unnamed", ApprovalText.Safe("\u200B\u202E"));
        Assert.Equal("unnamed", ApprovalText.Safe(null));
    }

    [Fact]
    public void Sentence_QuotesTheSelfReportedName()
    {
        Assert.Equal("“Claude Code” wants to write 2 variables to a .env file", ApprovalText.Sentence(Requests.Env()));
        Assert.Equal(
            "“Claude Code” wants to run npm run migrate with environment variables",
            ApprovalText.Sentence(Requests.Env(action: ApprovalAction.RunWithEnv, command: new[] { "npm", "run", "migrate" })));
        Assert.Equal("“x' (verified)” wants to create the environment staging",
            ApprovalText.Sentence(Requests.Env(action: ApprovalAction.CreateEnvironment, clientName: "x” (verified)", mintsLease: false)));
    }

    [Fact]
    public void Sentence_ForAFill_NamesTheBrowserUnquoted_AndTheItemQuoted()
    {
        Assert.Equal("Google Chrome wants the password for “Example account”", ApprovalText.Sentence(Requests.Fill()));
    }

    [Fact]
    public void Summary_StatesTheScope()
    {
        Assert.Equal(
            @"This grants access to DATABASE_URL, STRIPE_SECRET_KEY in C:\code\acme for 10 minutes, up to 10 uses.",
            ApprovalText.Summary(Requests.Env(), 600));
        Assert.Equal(
            "This changes the structure of your vault. It grants no access to any value.",
            ApprovalText.Summary(Requests.Env(action: ApprovalAction.CreateEnvironment, mintsLease: false), 600));
        Assert.StartsWith("This sends the password for “Example account” to https://example.com, once.", ApprovalText.Summary(Requests.Fill(), 300));
    }

    [Theory]
    [InlineData(45UL, "45 s")]
    [InlineData(60UL, "1 minute")]
    [InlineData(900UL, "15 minutes")]
    [InlineData(5400UL, "1.5 hours")]
    public void Duration_ReadsNaturally(ulong seconds, string expected) => Assert.Equal(expected, ApprovalText.Duration(seconds));
}

public sealed class ApprovalViewModelTests : IDisposable
{
    private readonly FakeAgentRuntime runtime = new();
    private readonly FakeConsentGate gate = new();
    private readonly FakeAgentVault vault = new();
    private readonly FakeDispatcher dispatcher = new();
    private readonly AgentHostService host;

    public ApprovalViewModelTests()
    {
        host = new AgentHostService(runtime, gate, vault, dispatcher, () => DateTimeOffset.FromUnixTimeSeconds(1_000), _ => null);
        host.Start();
    }

    public void Dispose() => host.Stop();

    private ApprovalViewModel Sheet(ApprovalRequest request)
    {
        runtime.Enqueue(request);
        dispatcher.PumpUntil(() => host.Current?.Id == request.Id, "the request");
        host.VerificationTask(request.Id)!.Wait(TimeSpan.FromSeconds(5));
        dispatcher.Pump();
        return new ApprovalViewModel(host, request);
    }

    [Fact]
    public void ShowsTheFacts_AndTheVerdictAsAWarning()
    {
        using ApprovalViewModel vm = Sheet(Requests.Env(gitignored: false));

        Assert.Equal("Unverified — proceed with caution", vm.VerdictTitle);
        Assert.Equal("Authenticode: not signed (test)", vm.VerdictEvidence);
        Assert.True(vm.ShowGitWarning);
        Assert.True(vm.ShowVariables);
        Assert.Equal("File", vm.LocationLabel);
        Assert.Equal(@"C:\code\acme\.env", vm.LocationValue);
        Assert.Equal("staging", vm.EnvironmentName);
        Assert.Contains("4242", vm.ProcessLine);
        Assert.True(vm.ShowTtl);
        // Unverified is a warning, never a gate: the Allow buttons are live.
        Assert.True(vm.AllowOnceCommand.CanExecute(null));
    }

    [Fact]
    public void Ttl_CanBeShortened_NeverLengthened()
    {
        using ApprovalViewModel vm = Sheet(Requests.Env());
        Assert.Equal(900, vm.TtlSeconds);

        vm.TtlSeconds = 5_000;
        Assert.Equal(900, vm.TtlSeconds);

        vm.TtlSeconds = 290;
        Assert.Equal(300, vm.TtlSeconds);
        Assert.Contains("for 5 minutes", vm.Summary);
    }

    [Fact]
    public async Task AllowForThisSession_SendsTheShortenedTtl()
    {
        using ApprovalViewModel vm = Sheet(Requests.Env());
        vm.TtlSeconds = 300;

        await vm.AllowSessionCommand.ExecuteAsync(null);

        var resolution = Assert.Single(runtime.Resolutions);
        Assert.Equal(new ApprovalDecision.AllowSession(300, 10), resolution.Decision);
        Assert.True(vm.IsClosed);
    }

    [Fact]
    public async Task ConsentRefused_KeepsTheSheetUp_WithAReason()
    {
        using ApprovalViewModel vm = Sheet(Requests.Env());
        gate.Next = new ConsentOutcome(ConsentStatus.Cancelled);

        await vm.AllowOnceCommand.ExecuteAsync(null);

        Assert.Empty(runtime.Resolutions);
        Assert.False(vm.IsClosed);
        Assert.Contains("Nothing has been granted", vm.Problem);
        Assert.False(vm.ShowPasswordFallback);
    }

    [Fact]
    public async Task HelloUnavailable_ShowsThePasswordFallback()
    {
        using ApprovalViewModel vm = Sheet(Requests.Env());
        gate.Next = new ConsentOutcome(ConsentStatus.Unavailable, "Windows Hello is not set up for this account.");

        await vm.AllowOnceCommand.ExecuteAsync(null);
        Assert.True(vm.ShowPasswordFallback);
        Assert.False(vm.ApproveWithPasswordCommand.CanExecute(null));

        vm.FallbackPassword = vault.MasterPassword;
        await vm.ApproveWithPasswordCommand.ExecuteAsync(null);

        var resolution = Assert.Single(runtime.Resolutions);
        Assert.IsType<ApprovalDecision.AllowOnce>(resolution.Decision);
        Assert.Equal(string.Empty, vm.FallbackPassword);
    }

    [Fact]
    public async Task PasswordFallback_GrantsTheTtlShownNow_NotTheOneWhenHelloFailed()
    {
        using ApprovalViewModel vm = Sheet(Requests.Env());
        gate.Next = new ConsentOutcome(ConsentStatus.Unavailable, "no Hello");
        await vm.AllowSessionCommand.ExecuteAsync(null); // at 15 minutes

        vm.TtlSeconds = 120; // shortened while typing the password
        vm.FallbackPassword = vault.MasterPassword;
        await vm.ApproveWithPasswordCommand.ExecuteAsync(null);

        var resolution = Assert.Single(runtime.Resolutions);
        Assert.Equal(new ApprovalDecision.AllowSession(120, 10), resolution.Decision);
    }

    [Fact]
    public void AnUnknownHelloAvailability_FailsClosed_AndDoesNotOpenThePasswordFallback()
    {
        ConsentOutcome outcome = WindowsHelloConsentGate.FromAvailability((Windows.Security.Credentials.UI.UserConsentVerifierAvailability)99);
        Assert.Equal(ConsentStatus.Failed, outcome.Status);
    }

    [Fact]
    public void ClosingTheWindow_IsADeny()
    {
        using ApprovalViewModel vm = Sheet(Requests.Env());

        vm.DenyIfStillPending();

        var resolution = Assert.Single(runtime.Resolutions);
        Assert.IsType<ApprovalDecision.Deny>(resolution.Decision);
    }

    [Fact]
    public void FillSheet_ShowsBothVerdictsAndTheTarget()
    {
        using ApprovalViewModel vm = Sheet(Requests.Fill());

        Assert.True(vm.IsFill);
        Assert.Equal("Browser: unverified", vm.BrowserVerdictTitle);
        Assert.Equal("Helper: unverified", vm.HelperVerdictTitle);
        Assert.Equal("Example account", vm.FillItem);
        Assert.Equal("https://example.com", vm.FillWebsite);
        Assert.Equal("password", vm.FillFields);
        Assert.Contains("abcdefghijklmnop", vm.ExtensionIdLine);
        Assert.StartsWith("The value goes to the browser", vm.Headline);
    }
}

public sealed class AgentAccessPageViewModelTests : IDisposable
{
    private readonly FakeAgentRuntime runtime = new();
    private readonly FakeAgentVault vault = new();
    private readonly FakeDispatcher dispatcher = new();
    private readonly AgentHostService host;

    public AgentAccessPageViewModelTests()
    {
        host = new AgentHostService(runtime, new FakeConsentGate(), vault, dispatcher, () => DateTimeOffset.FromUnixTimeSeconds(1_000), _ => null);
    }

    public void Dispose() => host.Stop();

    [Fact]
    public void Leases_ListBothKinds_WithCountdowns_AndRevoke()
    {
        runtime.LiveLeases.Add(new Lease("l1", "env-1", @"C:\code", new ValueList<string>(new[] { "A", "B" }), "env-file", "Claude Code", 1_030, 3));
        runtime.LiveFillLeases.Add(new FillLease("https://example.com", "item-1", "Example", new ValueList<string>(new[] { "password" }), "Google Chrome", 1_300));
        host.Start();
        using var vm = new LeasesViewModel(host);

        LeaseRowViewModel row = Assert.Single(vm.Leases);
        Assert.Equal("30 s", row.Remaining);
        Assert.True(row.IsUrgent);
        Assert.Equal("A, B", row.Variables);
        Assert.Equal("5 minutes", Assert.Single(vm.FillLeases).Remaining);

        row.RevokeCommand.Execute(null);
        Assert.Equal(new[] { "l1" }, runtime.RevokedLeases);
        Assert.Empty(vm.Leases);
        Assert.True(vm.HasFillLeases);
    }

    [Fact]
    public async Task BrowserExtension_InstallWritesExactlyTheRecordShown_ThroughTheRuntime()
    {
        var copied = new System.Collections.Generic.List<string>();
        using var vm = new BrowserExtensionViewModel(runtime, host, copied.Add);
        await vm.RefreshAsync();

        BrowserManifestRowViewModel chrome = Assert.Single(vm.Browsers);
        Assert.Null(chrome.Manifest.RegistryKey); // the fake never names a real registry key
        await chrome.InstallCommand.ExecuteAsync(null);

        Assert.Same(chrome.Manifest, Assert.Single(runtime.Installed));
        vm.CopyExtensionIdCommand.Execute(null);
        Assert.Equal(new[] { "abcdefghijklmnop" }, copied);
    }

    [Fact]
    public async Task McpSetup_CopiesTheSnippet()
    {
        var copied = new System.Collections.Generic.List<string>();
        using var vm = new McpSetupViewModel(runtime, host, copied.Add);
        await vm.LoadAsync();

        Assert.Equal(@"C:\fake\kagisecure-mcp.exe", vm.SidecarPath);
        Assert.False(vm.SidecarMissing);
        vm.Snippets.Single().CopyCommand.Execute(null);
        Assert.Equal(new[] { "claude mcp add kagisecure" }, copied);
    }

    [Fact]
    public async Task Environments_CreateAddAndRemoveVariables_AndShare()
    {
        using var vm = new EnvironmentsViewModel(vault, host);
        await vm.RefreshAsync();
        Assert.True(vm.IsEmpty);

        vm.NewEnvironmentName = "  staging  ";
        await vm.CreateCommand.ExecuteAsync(null);
        Assert.Equal("staging", vm.Selected!.Name);
        Assert.False(vm.SelectedShared); // new environments are hidden from agents

        vm.NewVariableName = "DATABASE_URL";
        vm.NewVariableValue = "postgres://secret";
        await vm.AddVariableCommand.ExecuteAsync(null);
        Assert.Equal(string.Empty, vm.NewVariableValue);
        Assert.Equal("DATABASE_URL", Assert.Single(vm.Variables).Name);
        Assert.Contains(("env-1", "DATABASE_URL", "postgres://secret"), vault.ValuesSet);

        await vm.Variables.Single().RemoveCommand.ExecuteAsync(null);
        Assert.Empty(vm.Variables);

        vm.VaultShared = true;
        await Task.Yield();
        Assert.True(vault.Shared);
    }
}
