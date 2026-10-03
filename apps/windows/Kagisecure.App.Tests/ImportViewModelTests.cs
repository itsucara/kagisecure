using System.Linq;
using System.Threading.Tasks;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Xunit;

namespace Kagisecure.App.Tests;

public class ImportViewModelTests
{
    private static ImportReport MakeReport(uint items = 3, uint duplicates = 0, ImportFormat source = ImportFormat.OnePasswordCsv, ValueList<ImportItemRow>? rows = null) => new(
        source, "export.csv", $"{items} items", new ImportTotals(items, items, 0, 0, 0),
        ValueList<ImportCategoryCount>.Empty, ValueList<DropNote>.Empty, ValueList<ImportDecision>.Empty,
        ValueList<ImportActionCount>.Empty, duplicates, true, rows ?? ValueList<ImportItemRow>.Empty);

    private static ImportItemRow MakeRow(string title, ImportItemAction? action, string vault = "Personal") =>
        new(title, "login", false, vault, 3, 0, ValueList<DropNote>.Empty, action);

    [Fact]
    public async Task LoadAsync_Success_MovesToPreviewing_AndHoldsTheReport()
    {
        var service = new FakeVaultService
        {
            ImportPlanTokenToReturn = "token-1",
            ImportReportToReturn = MakeReport(items: 5, duplicates: 2),
        };
        var vm = new ImportViewModel(service);

        await vm.LoadAsync(@"C:\export.csv", null);

        Assert.Equal(ImportPhase.Previewing, vm.Phase);
        Assert.NotNull(vm.Report);
        Assert.Equal(5u, vm.Report!.Totals.Items);
        Assert.True(vm.CanImport);
        Assert.Equal("2 of these are already in this vault.", vm.DuplicateSentence);
        Assert.Contains("token-1", service.OutstandingPlanTokens);
    }

    [Fact]
    public async Task LoadAsync_Failure_MovesToFailed()
    {
        var service = new FakeVaultService
        {
            ImportPreviewThrows = KagisecureExceptionFactory.Create<KagisecureException.Invalid>("not a recognised file"),
        };
        var vm = new ImportViewModel(service);

        await vm.LoadAsync(@"C:\bad.csv", null);

        Assert.Equal(ImportPhase.Failed, vm.Phase);
        Assert.Equal("not a recognised file", vm.ErrorMessage);
    }

    [Fact]
    public async Task ChangingPolicy_RePreviewsAgainstTheVault()
    {
        var service = new FakeVaultService { ImportPlanTokenToReturn = "token-2", ImportReportToReturn = MakeReport() };
        var vm = new ImportViewModel(service);
        await vm.LoadAsync(@"C:\export.csv", null);

        vm.Policy = DuplicatePolicy.Update;
        await Task.Delay(50); // OnPolicyChanged fires RefreshReportAsync fire-and-forget

        Assert.Contains(service.ImportPreviewAgainstCalls, c => c.Token == "token-2" && c.Policy == DuplicatePolicy.Update);
    }

    [Fact]
    public async Task CommitAsync_CallsService_ThenMovesToShredPrompt_AndSpendsTheToken()
    {
        var outcome = new ImportOutcome(3, 0, 0, 0, 0, ValueList<string>.Empty, "Imported 3 items", MakeReport());
        var service = new FakeVaultService
        {
            ImportPlanTokenToReturn = "token-3",
            ImportReportToReturn = MakeReport(),
            ImportOutcomeToReturn = outcome,
        };
        var vm = new ImportViewModel(service);
        await vm.LoadAsync(@"C:\export.csv", null);
        vm.TargetVault = "vault-2";

        await vm.CommitCommand.ExecuteAsync(null);

        Assert.Equal(ImportPhase.ShredPrompt, vm.Phase);
        Assert.Same(outcome, vm.Outcome);
        Assert.Contains(service.ImportCommitCalls, c => c.Token == "token-3" && c.TargetVault == "vault-2");
        Assert.DoesNotContain("token-3", service.OutstandingPlanTokens);
    }

    [Fact]
    public async Task ShredSourceAsync_CallsService_AndShowsTheCaveat()
    {
        var service = new FakeVaultService
        {
            ImportPlanTokenToReturn = "token-4",
            ImportReportToReturn = MakeReport(),
            ShredOutcomeToReturn = new ShredOutcome(true, true, "Overwritten once. Not a secure erase on this filesystem."),
        };
        var vm = new ImportViewModel(service);
        await vm.LoadAsync(@"C:\export.csv", null);
        await vm.CommitCommand.ExecuteAsync(null);

        await vm.ShredSourceCommand.ExecuteAsync(null);

        Assert.Equal(ImportPhase.Finished, vm.Phase);
        Assert.Equal("Overwritten once. Not a secure erase on this filesystem.", vm.FinishedSentence);
    }

    [Fact]
    public async Task KeepSource_MovesToFinished_WithoutShredding()
    {
        var service = new FakeVaultService { ImportPlanTokenToReturn = "token-5", ImportReportToReturn = MakeReport() };
        var vm = new ImportViewModel(service);
        await vm.LoadAsync(@"C:\export.csv", null);
        await vm.CommitCommand.ExecuteAsync(null);

        vm.KeepSourceCommand.Execute(null);

        Assert.Equal(ImportPhase.Finished, vm.Phase);
        Assert.Equal("The source file was left where it was.", vm.FinishedSentence);
    }

    [Fact]
    public async Task DisposePlan_ReleasesAnUncommittedToken()
    {
        var service = new FakeVaultService { ImportPlanTokenToReturn = "token-6", ImportReportToReturn = MakeReport() };
        var vm = new ImportViewModel(service);
        await vm.LoadAsync(@"C:\export.csv", null);

        vm.DisposePlan();

        Assert.DoesNotContain("token-6", service.OutstandingPlanTokens);
    }

    // ---------------------------------------------------------------------------------------
    // Manual format override (import.md §3)
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task LoadAsync_DefaultsToDetectAutomatically()
    {
        var service = new FakeVaultService { ImportPlanTokenToReturn = "token-7", ImportReportToReturn = MakeReport() };
        var vm = new ImportViewModel(service);

        await vm.LoadAsync(@"C:\export.csv", null);

        Assert.Null(vm.FormatOverride);
        Assert.Null(vm.SelectedFormatOption.Format);
        Assert.Equal("Detect automatically", vm.SelectedFormatOption.DisplayName);
    }

    [Fact]
    public async Task ChangeFormatAsync_Success_ReparsesUnderTheChosenFormat_AndReleasesThePreviousPlan()
    {
        var service = new FakeVaultService
        {
            ImportPlanTokenToReturn = "token-a",
            ImportReportToReturn = MakeReport(items: 2, source: ImportFormat.ChromiumCsv),
        };
        var vm = new ImportViewModel(service);
        await vm.LoadAsync(@"C:\export.csv", null);
        Assert.Contains("token-a", service.OutstandingPlanTokens);

        service.ImportPlanTokenToReturn = "token-b";
        service.ImportReportToReturn = MakeReport(items: 7, source: ImportFormat.FirefoxCsv);

        await vm.ChangeFormatAsync(ImportFormat.FirefoxCsv);

        Assert.Equal(ImportFormat.FirefoxCsv, vm.FormatOverride);
        Assert.Equal(ImportPhase.Previewing, vm.Phase);
        Assert.Equal(7u, vm.Report!.Totals.Items);
        Assert.DoesNotContain("token-a", service.OutstandingPlanTokens); // the replaced plan is released, not leaked
        Assert.Contains("token-b", service.OutstandingPlanTokens);
    }

    [Fact]
    public async Task ChangeFormatAsync_WrongFormat_MovesToFailed_WithTheParsersMessage_AndStillReleasesThePreviousPlan()
    {
        var service = new FakeVaultService { ImportPlanTokenToReturn = "token-c", ImportReportToReturn = MakeReport() };
        var vm = new ImportViewModel(service);
        await vm.LoadAsync(@"C:\export.1pux", null);
        Assert.Equal(ImportPhase.Previewing, vm.Phase);

        service.ImportPreviewThrows = KagisecureExceptionFactory.Create<KagisecureException.Invalid>(
            "1pux import source is malformed: not a zip archive");

        await vm.ChangeFormatAsync(ImportFormat.OnePux);

        Assert.Equal(ImportPhase.Failed, vm.Phase);
        Assert.Equal("1pux import source is malformed: not a zip archive", vm.ErrorMessage);
        Assert.DoesNotContain("token-c", service.OutstandingPlanTokens);
    }

    [Fact]
    public async Task ChangeFormatAsync_SameFormatAgain_DoesNothing()
    {
        var service = new FakeVaultService { ImportPlanTokenToReturn = "token-d", ImportReportToReturn = MakeReport() };
        var vm = new ImportViewModel(service);
        await vm.LoadAsync(@"C:\export.csv", null);
        int callsBefore = service.OutstandingPlanTokens.Count;

        await vm.ChangeFormatAsync(null); // already null — no re-parse

        Assert.Equal(callsBefore, service.OutstandingPlanTokens.Count);
        Assert.Contains("token-d", service.OutstandingPlanTokens);
    }

    // ---------------------------------------------------------------------------------------
    // Per-item detail table (import.md §8's ks.import.detailTable, mirrored from macOS)
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task LoadAsync_PopulatesTheItemTable_FromTheReport()
    {
        ValueList<ImportItemRow> rows = new(new[]
        {
            MakeRow("Bank", ImportItemAction.Create),
            MakeRow("Email", ImportItemAction.Skip),
        });
        var service = new FakeVaultService
        {
            ImportPlanTokenToReturn = "token-e",
            ImportReportToReturn = MakeReport(items: 2, rows: rows),
        };
        var vm = new ImportViewModel(service);

        await vm.LoadAsync(@"C:\export.csv", null);

        Assert.Equal(2, vm.Items.Count);
        Assert.Contains(vm.Items, r => r.Title == "Bank" && r.Action == ImportItemAction.Create);
        Assert.Contains(vm.Items, r => r.Title == "Email" && r.Action == ImportItemAction.Skip);
    }

    [Fact]
    public async Task ActionFilter_NarrowsTheItemTable_ToOneAction()
    {
        ValueList<ImportItemRow> rows = new(new[]
        {
            MakeRow("Bank", ImportItemAction.Create),
            MakeRow("Email", ImportItemAction.Skip),
            MakeRow("Shop", ImportItemAction.Create),
        });
        var service = new FakeVaultService
        {
            ImportPlanTokenToReturn = "token-f",
            ImportReportToReturn = MakeReport(items: 3, rows: rows),
        };
        var vm = new ImportViewModel(service);
        await vm.LoadAsync(@"C:\export.csv", null);
        Assert.Equal(3, vm.Items.Count);

        vm.ActionFilter = "create";

        Assert.Equal(2, vm.Items.Count);
        Assert.All(vm.Items, r => Assert.Equal(ImportItemAction.Create, r.Action));

        vm.ActionFilter = "all";

        Assert.Equal(3, vm.Items.Count);
    }

    [Fact]
    public void FilterItems_IsPureAndDeterministic()
    {
        var rows = new[]
        {
            MakeRow("Bank", ImportItemAction.Create),
            MakeRow("Email", ImportItemAction.Update),
            MakeRow("Shop", ImportItemAction.Skip),
            MakeRow("Old", ImportItemAction.KeepBoth),
            MakeRow("Blind", null), // a report built with no vault — never matches a specific filter
        };

        Assert.Equal(5, ImportViewModel.FilterItems(rows, "all").Count());
        Assert.Equal(new[] { "Bank" }, ImportViewModel.FilterItems(rows, "create").Select(r => r.Title));
        Assert.Equal(new[] { "Email" }, ImportViewModel.FilterItems(rows, "update").Select(r => r.Title));
        Assert.Equal(new[] { "Shop" }, ImportViewModel.FilterItems(rows, "skip").Select(r => r.Title));
        Assert.Equal(new[] { "Old" }, ImportViewModel.FilterItems(rows, "keepboth").Select(r => r.Title));
    }
}
