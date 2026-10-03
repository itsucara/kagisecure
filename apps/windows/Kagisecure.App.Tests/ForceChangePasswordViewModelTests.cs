using System.Threading.Tasks;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Xunit;

namespace Kagisecure.App.Tests;

public class ForceChangePasswordViewModelTests
{
    [Fact]
    public void CanSave_RequiresMatchingNonEmptyPasswords()
    {
        var vm = new ForceChangePasswordViewModel(new FakeVaultService());
        Assert.False(vm.CanSave);

        vm.NewPassword = "correct horse battery staple";
        Assert.False(vm.CanSave); // confirmation not typed yet

        vm.ConfirmPassword = "correct horse battery staple";
        Assert.True(vm.CanSave);
    }

    [Fact]
    public async Task SaveAsync_CallsService_AndRaisesPasswordChanged()
    {
        var service = new FakeVaultService();
        var vm = new ForceChangePasswordViewModel(service)
        {
            NewPassword = "new password 123",
            ConfirmPassword = "new password 123",
        };

        bool raised = false;
        vm.PasswordChanged += (_, _) => raised = true;

        await vm.SaveCommand.ExecuteAsync(null);

        Assert.True(raised);
        Assert.Equal("new password 123", service.LastChangedPassword);
        Assert.Equal(string.Empty, vm.NewPassword);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task SaveAsync_Mismatch_SetsError_AndDoesNotCallService()
    {
        // CanSave gates the command in the UI, but the guard inside SaveAsync is what protects a
        // caller that bypasses CanExecute (e.g. pressing Enter mid-edit) — this test exercises it
        // directly, by calling SaveCommand even though CanSave is false.
        var service = new FakeVaultService();
        var vm = new ForceChangePasswordViewModel(service) { NewPassword = "a", ConfirmPassword = "b" };

        await vm.SaveCommand.ExecuteAsync(null);

        Assert.Null(service.LastChangedPassword);
        Assert.Equal("Passwords don't match.", vm.ErrorMessage);
    }

    [Fact]
    public async Task SaveAsync_ServiceThrows_SetsErrorMessage_AndDoesNotRaisePasswordChanged()
    {
        var service = new FakeVaultService
        {
            ChangeMasterPasswordThrows = KagisecureExceptionFactory.Create<KagisecureException.Invalid>("password too short"),
        };
        var vm = new ForceChangePasswordViewModel(service) { NewPassword = "x", ConfirmPassword = "x" };

        bool raised = false;
        vm.PasswordChanged += (_, _) => raised = true;

        await vm.SaveCommand.ExecuteAsync(null);

        Assert.False(raised);
        Assert.Equal("password too short", vm.ErrorMessage);
        Assert.False(vm.IsBusy);
    }
}
