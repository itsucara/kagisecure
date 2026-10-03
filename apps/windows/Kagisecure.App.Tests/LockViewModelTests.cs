using System.Threading.Tasks;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Xunit;

namespace Kagisecure.App.Tests;

public class LockViewModelTests
{
    [Fact]
    public async Task UnlockAsync_Success_RaisesUnlocked_AndClearsPassword()
    {
        var service = new FakeVaultService();
        var vm = new LockViewModel(service) { MasterPassword = "correct horse battery staple" };

        bool raised = false;
        vm.Unlocked += (_, _) => raised = true;

        await vm.UnlockCommand.ExecuteAsync(null);

        Assert.True(raised);
        Assert.Null(vm.ErrorMessage);
        Assert.Equal(string.Empty, vm.MasterPassword);
        Assert.True(service.IsUnlocked);
    }

    [Fact]
    public async Task UnlockAsync_WrongPassword_SetsInlineError_AndDoesNotRaiseUnlocked()
    {
        var service = new FakeVaultService
        {
            UnlockThrows = KagisecureExceptionFactory.Create<KagisecureException.WrongCredential>("bad password"),
        };
        var vm = new LockViewModel(service) { MasterPassword = "wrong" };

        bool raised = false;
        vm.Unlocked += (_, _) => raised = true;

        await vm.UnlockCommand.ExecuteAsync(null);

        Assert.False(raised);
        Assert.Equal("Wrong password.", vm.ErrorMessage);
        Assert.False(vm.IsBusy);
        Assert.False(service.IsUnlocked);
    }

    [Fact]
    public async Task UnlockAsync_NotFound_SetsPathInErrorMessage()
    {
        var service = new FakeVaultService
        {
            UnlockThrows = KagisecureExceptionFactory.Create<KagisecureException.NotFound>("no such file"),
        };
        var vm = new LockViewModel(service) { MasterPassword = "anything" };

        await vm.UnlockCommand.ExecuteAsync(null);

        Assert.Contains(vm.VaultPath, vm.ErrorMessage);
    }

    [Fact]
    public void CanUnlock_FalseUntilPasswordTyped()
    {
        var vm = new LockViewModel(new FakeVaultService());
        Assert.False(vm.CanUnlock);

        vm.MasterPassword = "x";
        Assert.True(vm.CanUnlock);
    }

    [Fact]
    public void ToggleRecoveryCode_FlipsTheDisclosure()
    {
        var vm = new LockViewModel(new FakeVaultService());
        Assert.False(vm.ShowRecoveryCode);

        vm.ToggleRecoveryCodeCommand.Execute(null);
        Assert.True(vm.ShowRecoveryCode);

        vm.ToggleRecoveryCodeCommand.Execute(null);
        Assert.False(vm.ShowRecoveryCode);
    }

    [Fact]
    public void CanUnlockWithRecovery_FalseUntilCodeTyped()
    {
        var vm = new LockViewModel(new FakeVaultService());
        Assert.False(vm.CanUnlockWithRecovery);

        vm.RecoveryCode = "XXXX-XXXX";
        Assert.True(vm.CanUnlockWithRecovery);
    }

    [Fact]
    public async Task UnlockWithRecoveryAsync_Success_RaisesUnlocked_AndClearsTheCode()
    {
        var service = new FakeVaultService();
        var vm = new LockViewModel(service) { RecoveryCode = "AAAA-BBBB-CCCC" };

        bool raised = false;
        vm.Unlocked += (_, _) => raised = true;

        await vm.UnlockWithRecoveryCommand.ExecuteAsync(null);

        Assert.True(raised);
        Assert.Equal(string.Empty, vm.RecoveryCode);
        Assert.True(service.IsUnlocked);
        Assert.Equal((vm.VaultPath, "AAAA-BBBB-CCCC"), service.LastRecoveryUnlockArgs);
    }

    [Fact]
    public async Task UnlockWithRecoveryAsync_InvalidCode_SetsInlineError()
    {
        var service = new FakeVaultService
        {
            UnlockWithRecoveryThrows = KagisecureExceptionFactory.Create<KagisecureException.Invalid>("bad checksum"),
        };
        var vm = new LockViewModel(service) { RecoveryCode = "not-a-code" };

        await vm.UnlockWithRecoveryCommand.ExecuteAsync(null);

        Assert.Equal("That recovery code isn't valid.", vm.ErrorMessage);
        Assert.False(service.IsUnlocked);
    }

    [Fact]
    public async Task UnlockWithRecoveryAsync_WrongVault_SetsInlineError()
    {
        var service = new FakeVaultService
        {
            UnlockWithRecoveryThrows = KagisecureExceptionFactory.Create<KagisecureException.WrongCredential>("does not open this vault"),
        };
        var vm = new LockViewModel(service) { RecoveryCode = "AAAA-BBBB-CCCC" };

        await vm.UnlockWithRecoveryCommand.ExecuteAsync(null);

        Assert.Equal("That recovery code doesn't open this vault.", vm.ErrorMessage);
    }
}
