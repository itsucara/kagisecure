using System;
using System.IO;
using System.Linq;
using Xunit;

namespace Kagisecure.Interop.Tests;

/// <summary>The second object handle, and a report that is names and counts end to end.</summary>
public class ImportTests
{
    private const string Csv =
        "name,url,username,password\n" +
        "GitHub,https://github.com,ada,hunter2\n" +
        "Example,https://example.com,bob,correct-horse\n";

    private static string WriteExport(TempVault temp)
    {
        string path = Path.Combine(temp.Directory, "Chrome Passwords.csv");
        File.WriteAllText(path, Csv);
        return path;
    }

    [Fact]
    public void Every_format_the_build_reads_is_listed()
    {
        var formats = Importer.Formats();

        Assert.Equal(Enum.GetValues<ImportFormat>().Length, formats.Count);
        Assert.Contains(formats, f => f.Format == ImportFormat.ChromiumCsv && f.Id == "chromium-csv");
        Assert.All(formats, f => Assert.False(string.IsNullOrEmpty(f.DisplayName)));
    }

    [Fact]
    public void A_plan_previews_then_commits_once_and_carries_no_value()
    {
        using var temp = new TempVault();
        using var session = temp.Create();
        string path = WriteExport(temp);

        using ImportPlan plan = session.ImportPreview(path);
        Assert.Equal(path, plan.SourcePath);
        Assert.False(plan.IsSpent);

        ImportReport blind = plan.Report();
        Assert.Equal(ImportFormat.ChromiumCsv, blind.Source);
        Assert.Equal("Chrome Passwords.csv", blind.SourceName);
        Assert.Equal(2u, blind.Totals.Items);
        Assert.False(blind.VaultAware);
        Assert.Equal(0u, blind.Duplicates);
        Assert.Empty(blind.ByAction);
        Assert.All(blind.Items, row => Assert.Null(row.Action));
        Assert.Equal(new[] { "Example", "GitHub" }, blind.Items.Select(r => r.Title).OrderBy(t => t));
        Assert.Contains(blind.ByCategory, c => c.Category == "login" && c.Items == 2);
        Assert.False(string.IsNullOrEmpty(blind.Headline));
        Assert.Equal(blind, plan.Report()); // value equality all the way down

        ImportReport aware = session.ImportPreviewAgainst(plan, DuplicatePolicy.Skip);
        Assert.True(aware.VaultAware);
        Assert.Equal(new ImportActionCount(ImportItemAction.Create, 2), Assert.Single(aware.ByAction));
        Assert.All(aware.Items, row => Assert.Equal(ImportItemAction.Create, row.Action));

        ImportOutcome outcome = session.ImportCommit(plan, DuplicatePolicy.Skip, "Imported");
        Assert.Equal(2u, outcome.Created);
        Assert.Equal(0u, outcome.Skipped);
        Assert.Equal(new[] { "Imported" }, outcome.VaultsCreated);
        Assert.True(outcome.Report.VaultAware);
        Assert.False(string.IsNullOrEmpty(outcome.Headline));

        Assert.True(plan.IsSpent);
        Assert.Throws<KagisecureException.Invalid>(() => plan.Report());
        Assert.Throws<KagisecureException.Invalid>(() => session.ImportCommit(plan, DuplicatePolicy.Skip));
        Assert.Throws<KagisecureException.Invalid>(() => session.ImportPreviewAgainst(plan, DuplicatePolicy.Skip));

        Assert.Equal(2, session.ListItems(new ItemFilter.Category("login")).Count);
        Assert.Contains(session.Vaults(), v => v.Name == "Imported" && v.ItemCount == 2);

        // Importing the same file again under Skip finds both as duplicates.
        using ImportPlan again = session.ImportPreview(path, ImportFormat.ChromiumCsv);
        ImportReport second = session.ImportPreviewAgainst(again, DuplicatePolicy.Skip);
        Assert.Equal(2u, second.Duplicates);
        Assert.Equal(ImportItemAction.Skip, second.Items[0].Action);
    }

    [Fact]
    public void A_manual_format_override_that_does_not_match_the_file_fails_with_a_readable_message()
    {
        using var temp = new TempVault();
        using var session = temp.Create();
        string path = WriteExport(temp); // a Chromium CSV, not a zip archive

        var ex = Assert.Throws<KagisecureException.Invalid>(() => session.ImportPreview(path, ImportFormat.OnePux));
        Assert.False(string.IsNullOrEmpty(ex.Message));
        Assert.DoesNotContain("hunter2", ex.Message); // the report/error carries no value (import.md §1.1)
        Assert.DoesNotContain("correct-horse", ex.Message);
    }

    [Fact]
    public void A_disposed_plan_cannot_be_used_and_a_missing_file_is_not_found()
    {
        using var temp = new TempVault();
        using var session = temp.Create();

        ImportPlan plan = session.ImportPreview(WriteExport(temp));
        plan.Dispose();
        Assert.Throws<ObjectDisposedException>(() => plan.Report());
        Assert.Throws<ObjectDisposedException>(() => session.ImportCommit(plan, DuplicatePolicy.Skip));
        plan.Dispose();

        Assert.Throws<KagisecureException.NotFound>(() => session.ImportPreview(Path.Combine(temp.Directory, "missing.csv")));
    }

    [Fact]
    public void The_source_file_is_shredded_on_request_with_the_caveat_said_first()
    {
        using var temp = new TempVault();
        string path = WriteExport(temp);

        string caveat = Importer.ShredCaveat();
        Assert.Contains("best effort", caveat);

        ShredOutcome outcome = Importer.ShredSourceFile(path);
        Assert.True(outcome.Overwritten);
        Assert.True(outcome.Removed);
        Assert.False(string.IsNullOrEmpty(outcome.Caveat));
        Assert.False(File.Exists(path));
        Assert.Throws<KagisecureException.NotFound>(() => Importer.ShredSourceFile(path));
    }
}
