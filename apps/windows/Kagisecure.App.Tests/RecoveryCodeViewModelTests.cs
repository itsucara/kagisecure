using Kagisecure.App.ViewModels;
using Xunit;

namespace Kagisecure.App.Tests;

public class RecoveryCodeViewModelTests
{
    [Fact]
    public void CanContinue_FalseUntilAcknowledged()
    {
        var vm = new RecoveryCodeViewModel(new FakeClipboardService(), "XXXX-XXXX-XXXX");
        Assert.False(vm.CanContinue);

        vm.Acknowledged = true;
        Assert.True(vm.CanContinue);
    }

    [Fact]
    public void RecoveryCode_IsExposedVerbatim()
    {
        var vm = new RecoveryCodeViewModel(new FakeClipboardService(), "ABCD-1234-EFGH-5678");
        Assert.Equal("ABCD-1234-EFGH-5678", vm.RecoveryCode);
    }

    [Fact]
    public void Copy_UsesTheClipboardService_AndShowsAConfirmation()
    {
        var clipboard = new FakeClipboardService { ClearAfterSeconds = 45 };
        var vm = new RecoveryCodeViewModel(clipboard, "ABCD-1234-EFGH-5678");

        vm.CopyCommand.Execute(null);

        Assert.Single(clipboard.Copies);
        Assert.Equal("ABCD-1234-EFGH-5678", clipboard.Copies[0].Value);
        Assert.Equal("Copied — clears in 45s", vm.CopiedNotice);
    }
}
