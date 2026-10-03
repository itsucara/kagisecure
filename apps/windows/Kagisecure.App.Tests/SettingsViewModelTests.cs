using System.Threading.Tasks;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Xunit;

namespace Kagisecure.App.Tests;

public class SettingsViewModelTests
{
    [Fact]
    public void Construction_ReadsInitialValuesFromTheSettingsService()
    {
        var settings = new FakeSettingsService { AutoLockIdleMinutes = 30, LockOnMinimize = true, ClipboardClearSeconds = 120 };
        var vm = new SettingsViewModel(new FakeVaultService(), new FakeClipboardService(), settings);

        Assert.Equal(30, vm.AutoLockIdleMinutes);
        Assert.True(vm.LockOnMinimize);
        Assert.Equal(120, vm.ClipboardClearSeconds);
    }

    [Fact]
    public void ChangingAutoLockIdleMinutes_WritesThroughToTheSettingsService()
    {
        var settings = new FakeSettingsService();
        var vm = new SettingsViewModel(new FakeVaultService(), new FakeClipboardService(), settings);

        vm.AutoLockIdleMinutes = 60;

        Assert.Equal(60, settings.AutoLockIdleMinutes);
    }

    [Fact]
    public void ChangingLockOnMinimize_WritesThroughToTheSettingsService()
    {
        var settings = new FakeSettingsService();
        var vm = new SettingsViewModel(new FakeVaultService(), new FakeClipboardService(), settings);

        vm.LockOnMinimize = true;

        Assert.True(settings.LockOnMinimize);
    }

    [Fact]
    public void ChangingClipboardClearSeconds_WritesThroughToBothSettingsAndClipboardService()
    {
        var settings = new FakeSettingsService();
        var clipboard = new FakeClipboardService();
        var vm = new SettingsViewModel(new FakeVaultService(), clipboard, settings);

        vm.ClipboardClearSeconds = 15;

        Assert.Equal(15, settings.ClipboardClearSeconds);
        Assert.Equal(15, clipboard.ClearAfterSeconds);
    }

    [Fact]
    public async Task RefreshAuditStateAsync_ReportsIntactChainWithNoWarning()
    {
        var service = new FakeVaultService { AuditIntactToReturn = true, AuditDurabilityToReturn = new AuditDurability(0, null) };
        var vm = new SettingsViewModel(service, new FakeClipboardService(), new FakeSettingsService());

        await vm.RefreshAuditStateCommand.ExecuteAsync(null);

        Assert.Equal("Chain intact", vm.AuditStateText);
        Assert.Null(vm.AuditSaveWarning);
    }

    [Fact]
    public async Task RefreshAuditStateAsync_UnsavedEntries_ProducesAWarning()
    {
        var service = new FakeVaultService { AuditDurabilityToReturn = new AuditDurability(2, "disk full") };
        var vm = new SettingsViewModel(service, new FakeClipboardService(), new FakeSettingsService());

        await vm.RefreshAuditStateCommand.ExecuteAsync(null);

        Assert.Equal("2 audit entries are not saved to disk yet — the last save failed: disk full", vm.AuditSaveWarning);
    }
}
