using System.Linq;
using System.Threading.Tasks;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Xunit;

namespace Kagisecure.App.Tests;

public class AuditViewModelTests
{
    private static AuditRow MakeRow(
        ulong seq, string actor, string tool, string outcome, string? detail = null, string? targetPath = null) => new(
        seq, 1_700_000_000, actor, tool, outcome, null, null, ValueList<string>.Empty, targetPath, detail);

    [Fact]
    public async Task Construction_LoadsRowsAndDurabilityFromTheService()
    {
        var service = new FakeVaultService
        {
            AuditRowsToReturn = new[] { MakeRow(1, "mcp", "fill_credential", "allowed") },
            AuditCountToReturn = 1,
            AuditIntactToReturn = true,
            AuditDurabilityToReturn = new AuditDurability(0, null),
        };
        var vm = new AuditViewModel(service);
        await vm.RefreshCommand.ExecuteAsync(null);

        Assert.Single(vm.Rows);
        Assert.True(vm.AuditIntact);
        Assert.Equal(1u, vm.Total);
        Assert.Null(vm.SaveWarningText);
        Assert.False(vm.IsEmpty);
    }

    [Fact]
    public async Task UnsavedEntries_ProducesASaveWarningWithTheReason()
    {
        var service = new FakeVaultService
        {
            AuditDurabilityToReturn = new AuditDurability(3, "disk full"),
        };
        var vm = new AuditViewModel(service);
        await vm.RefreshCommand.ExecuteAsync(null);

        Assert.Equal("3 audit entries are not saved to disk yet — the last save failed: disk full", vm.SaveWarningText);
    }

    [Fact]
    public async Task Filters_ByOutcomeActorToolAndQuery()
    {
        var rows = new[]
        {
            MakeRow(1, "mcp", "fill_credential", "denied", detail: "unverified caller"),
            MakeRow(2, "mcp", "totp_code", "allowed"),
            MakeRow(3, "cli", "item_list", "allowed", targetPath: @"C:\acme\.env"),
            MakeRow(4, "app", "write_env_file", "failed"),
        };
        var service = new FakeVaultService { AuditRowsToReturn = rows };
        var vm = new AuditViewModel(service);
        await vm.RefreshCommand.ExecuteAsync(null);
        Assert.Equal(4, vm.Rows.Count);

        vm.OutcomeFilter = "denied";
        Assert.Equal(new ulong[] { 1 }, vm.Rows.Select(r => r.Seq));

        vm.OutcomeFilter = "all";
        vm.ActorFilter = "mcp";
        Assert.Equal(new ulong[] { 1, 2 }, vm.Rows.Select(r => r.Seq));

        vm.ActorFilter = "all";
        vm.ToolFilter = "other"; // neither fill_credential nor totp_code
        Assert.Equal(new ulong[] { 3, 4 }, vm.Rows.Select(r => r.Seq));

        vm.ToolFilter = "all";
        vm.Query = ".env";
        Assert.Equal(new ulong[] { 3 }, vm.Rows.Select(r => r.Seq));
    }

    [Fact]
    public void FilterRows_IsPureAndDeterministic_ForDenialsByDefault()
    {
        var rows = new[] { MakeRow(1, "mcp", "run_with_env", "denied"), MakeRow(2, "mcp", "run_with_env", "allowed") };

        var filtered = AuditViewModel.FilterRows(rows, "all", "all", "all", string.Empty).ToList();

        Assert.Equal(2, filtered.Count); // denials are shown by default — the point of the filter defaults.
    }
}
