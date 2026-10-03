using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Kagisecure.Interop.Tests;

/// <summary>
/// The agent and the extension listener are process globals sharing one approval queue, so every
/// test that starts either runs in this one collection, one at a time.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ProcessGlobals
{
    public const string Name = "Process-global listeners";
}

/// <summary>
/// ADR-0014 end to end: a request arrives on the agent's named pipe from a client speaking the
/// real frame protocol, surfaces through <see cref="Agent.NextRequest"/>, and the decision made
/// through <see cref="Agent.Resolve"/> reaches the client.
/// </summary>
[Collection(ProcessGlobals.Name)]
public class AgentTests
{
    private static readonly TimeSpan Poll = TimeSpan.FromMilliseconds(100);

    private static string UniquePipe() => $"kagisecure-interop-{Guid.NewGuid():N}.sock";

    private static Task<ApprovalRequest> NextRequest() =>
        Agent.NextRequestAsync(Poll, new CancellationTokenSource(TimeSpan.FromSeconds(20)).Token);

    [Fact]
    public async Task A_request_on_the_pipe_is_answered_through_the_queue_and_mints_a_lease()
    {
        using var temp = new TempVault();
        using var session = temp.Create();
        string pipe = UniquePipe();
        try
        {
            string endpoint = Agent.Start(session, pipe);
            Assert.Contains(pipe, endpoint);
            AgentStatus status = Agent.Status();
            Assert.True(status.Running);
            Assert.True(status.VaultUnlocked);
            Assert.Equal(endpoint, status.Endpoint);
            Assert.Throws<KagisecureException.Invalid>(() => Agent.Start(session, UniquePipe()));

            await using var client = await AgentPipeClient.ConnectAsync(endpoint);

            // The agent reaches only agent-visible vaults: an invisible one answers exactly as a
            // vault that does not exist would (threat-model M-8), create_environment included.
            session.SetVaultAgentVisible(session.DefaultVaultId(), true);

            // create_environment: approved once.
            Task<JsonElement> created = client.RequestAsync(new { op = "CreateEnvironment", name = "From an agent" });
            ApprovalRequest ask = await NextRequest();
            Assert.Equal(ApprovalAction.CreateEnvironment, ask.Action);
            Assert.Equal("From an agent", ask.EnvironmentName);
            Assert.Equal("xunit", ask.ClientName);
            Assert.False(ask.MintsLease);
            Assert.True(ask.ExpiresAt > ask.CreatedAt);
            Assert.Contains(Agent.PendingRequests(), r => r.Id == ask.Id);
            Assert.Equal(1u, Agent.Status().PendingApprovals);

            Assert.True(Agent.Resolve(ask.Id, new ApprovalDecision.AllowOnce(), new ClientVerification(false, "xunit: not checked")));
            Assert.False(Agent.Resolve(ask.Id, new ApprovalDecision.Deny(), ClientVerification.Unchecked));
            JsonElement reply = await created;
            Assert.Equal("Environment", reply.GetProperty("reply").GetString());
            string envId = reply.GetProperty("environment").GetProperty("id").GetString()!;
            Assert.Contains(session.Environments(), e => e.Id == envId && e.Name == "From an agent");
            Assert.Empty(Agent.PendingRequests());

            // write_env_file: approved for a session, which mints a lease.
            session.SetVariableValue(envId, "TOKEN", "s3cret");
            string project = Directory.CreateDirectory(Path.Combine(temp.Directory, "project")).FullName;
            Task<JsonElement> written = client.RequestAsync(new
            {
                op = "WriteEnvFile",
                environment_id = envId,
                directory = project,
                filename = ".env",
                overwrite = false,
                ttl_seconds = 120,
            });
            ApprovalRequest write = await NextRequest();
            Assert.Equal(ApprovalAction.WriteEnvFile, write.Action);
            Assert.True(write.MintsLease);
            Assert.Equal(new[] { "TOKEN" }, write.Variables);
            Assert.EndsWith(".env", write.TargetPath);
            Assert.False(write.TargetExists);
            Assert.True(Agent.Resolve(write.Id, new ApprovalDecision.AllowSession(60, 3), ClientVerification.Unchecked));
            JsonElement wrote = await written;
            Assert.Equal("WroteEnvFile", wrote.GetProperty("reply").GetString());
            Assert.True(File.Exists(Path.Combine(project, ".env")));

            Lease lease = Assert.Single(Agent.Leases());
            Assert.Equal(envId, lease.EnvironmentId);
            Assert.Equal(new[] { "TOKEN" }, lease.Variables);
            Assert.Equal("env-file", lease.Kind);
            Assert.InRange(lease.UsesRemaining, 1u, 3u);
            Assert.Equal(1u, Agent.Status().ActiveLeases);
            Assert.True(Agent.RevokeLease(lease.Id));
            Assert.False(Agent.RevokeLease(lease.Id));
            Assert.Empty(Agent.Leases());
            Assert.False(File.Exists(Path.Combine(project, ".env")), "revoking a lease shreds what it wrote");
            Assert.Throws<KagisecureException.Invalid>(() => Agent.RevokeLease("not-a-lease-id"));
            Agent.RevokeAllLeases();

            // A denial reaches the client as a denial.
            Task<JsonElement> denied = client.RequestAsync(new { op = "CreateEnvironment", name = "Refused" });
            ApprovalRequest refuse = await NextRequest();
            Assert.True(Agent.Resolve(refuse.Id, new ApprovalDecision.Deny(), ClientVerification.Unchecked));
            JsonElement no = await denied;
            Assert.Equal("Error", no.GetProperty("reply").GetString());
            Assert.Contains("USER_DENIED", no.ToString());

            // `kagisecure lock` over IPC raises a flag the app consumes once.
            Assert.False(Agent.TakeLockRequest());
            JsonElement locked = await client.RequestAsync(new { op = "Lock" });
            Assert.Equal("Locked", locked.GetProperty("reply").GetString());
            Assert.True(Agent.TakeLockRequest());
            Assert.False(Agent.TakeLockRequest());
        }
        finally
        {
            Agent.Stop();
        }

        Assert.False(Agent.Status().Running);
        Assert.Equal(string.Empty, Agent.Status().Endpoint);
        Agent.Stop(); // idempotent
    }

    [Fact]
    public async Task Polling_times_out_empty_and_cancellation_takes_effect_between_polls()
    {
        Assert.Null(Agent.NextRequest(TimeSpan.FromMilliseconds(20)));
        Assert.Empty(Agent.PendingRequests());

        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
        var started = DateTime.UtcNow;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Agent.NextRequestAsync(Poll, cancel.Token));
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(5), "cancellation waits at most one poll");
    }

    [Fact]
    public void A_filesystem_path_is_refused_as_an_endpoint_with_a_legible_message()
    {
        using var temp = new TempVault();
        using var session = temp.Create();
        try
        {
            var error = Assert.Throws<KagisecureException.Invalid>(
                () => Agent.Start(session, Path.Combine(temp.Directory, "agent.sock")));
            Assert.Contains("pipe", error.Message);
            Assert.False(Agent.Status().Running);
        }
        finally
        {
            Agent.Stop();
        }
    }

    [Fact]
    public void A_peer_signature_verdict_crosses_with_its_evidence()
    {
        using var self = System.Diagnostics.Process.GetCurrentProcess();
        string executable = self.MainModule!.FileName;

        // The test host is not one of our helpers, and this build is unsigned: never verified.
        ClientVerification own = Agent.VerifyPeerCodeSignature((uint)self.Id, executable, PeerRequirement.OwnHelper);
        Assert.False(own.Verified);
        Assert.StartsWith("Authenticode", own.Evidence);

        // Nor is it a browser. The evidence names why rather than coming back empty.
        ClientVerification browser = Agent.VerifyPeerCodeSignature((uint)self.Id, executable, PeerRequirement.Browser);
        Assert.False(browser.Verified);
        Assert.False(string.IsNullOrWhiteSpace(browser.Evidence));

        Assert.Throws<KagisecureException.Invalid>(
            () => Agent.VerifyPeerCodeSignature((uint)self.Id, executable, (PeerRequirement)99));
    }

    [Fact]
    public void The_mcp_setup_screen_always_has_something_to_show()
    {
        McpSetup setup = Agent.McpSetup(@"Z:\nowhere\at\all");

        Assert.Equal(4, setup.Snippets.Count);
        Assert.Contains(setup.Snippets, s => s.Title == "Claude Code");
        Assert.All(setup.Snippets, s => Assert.False(string.IsNullOrEmpty(s.Body)));
        Assert.Equal(setup, Agent.McpSetup(@"Z:\nowhere\at\all"));
    }
}

/// <summary>The browser-extension listener, and the manifests its setup screen writes.</summary>
[Collection(ProcessGlobals.Name)]
public class BrowserExtensionTests
{
    [Fact]
    public void The_listener_starts_reports_and_stops()
    {
        using var temp = new TempVault();
        using var session = temp.Create();
        string pipe = $"kagisecure-interop-ext-{Guid.NewGuid():N}.sock";
        try
        {
            string endpoint = BrowserExtension.Start(session, pipe);
            Assert.Contains(pipe, endpoint);
            ExtensionStatus status = BrowserExtension.Status();
            Assert.True(status.Running);
            Assert.True(status.VaultUnlocked);
            Assert.Equal(0u, status.ConnectedHosts);
            Assert.Equal(0u, status.FillLeases);
            Assert.Throws<KagisecureException.Invalid>(() => BrowserExtension.Start(session, pipe + "2"));

            Assert.Empty(BrowserExtension.FillLeases());
            Assert.False(BrowserExtension.RevokeFillLease("https://example.com", "no-such-item"));
            BrowserExtension.RevokeAllFillLeases();
        }
        finally
        {
            BrowserExtension.Stop();
        }

        Assert.False(BrowserExtension.Status().Running);
        BrowserExtension.Stop(); // idempotent
    }

    [Fact]
    public void The_setup_screen_lists_manifests_that_install_and_uninstall_exactly_as_shown()
    {
        ExtensionSetup setup = BrowserExtension.Setup(@"Z:\nowhere\at\all");
        Assert.Equal(32, setup.ExtensionId.Length);
        Assert.Equal("com.kagisecure.nmhost", setup.HostName);
        Assert.NotEmpty(setup.Manifests);
        Assert.All(setup.Manifests, m => Assert.Contains(setup.ExtensionId, m.Body));

        using var temp = new TempVault();
        Assert.All(setup.Manifests, m => Assert.StartsWith(@"Software\", m.RegistryKey));
        // RegistryKey cleared: installing with it would write the real browser's HKCU key for our
        // host name. The registry half is covered in Rust (browser_setup.rs) under a throwaway key;
        // this test is about the record crossing the C ABI and the file landing where it says.
        BrowserManifest shown = setup.Manifests[0] with
        {
            Path = Path.Combine(temp.Directory, "Sub", "com.kagisecure.nmhost.json"),
            RegistryKey = null,
        };
        BrowserExtension.InstallManifest(shown);
        Assert.Equal(shown.Body, File.ReadAllText(shown.Path));
        BrowserExtension.UninstallManifest(shown);
        Assert.False(File.Exists(shown.Path));
        BrowserExtension.UninstallManifest(shown); // absent is success
    }
}
