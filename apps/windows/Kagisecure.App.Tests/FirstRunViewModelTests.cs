using System.Threading.Tasks;
using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Xunit;

namespace Kagisecure.App.Tests;

public class FirstRunViewModelTests
{
    [Fact]
    public void DefaultsVaultPathFromService()
    {
        var service = new FakeVaultService { DefaultVaultPath = @"C:\users\me\vault.kagivault" };
        var vm = new FirstRunViewModel(service);

        Assert.Equal(service.DefaultVaultPath, vm.VaultPath);
    }

    [Fact]
    public void CannotCreateUntilPasswordsMatchAndAreNonEmpty()
    {
        var vm = new FirstRunViewModel(new FakeVaultService());

        Assert.False(vm.CanCreate); // both passwords empty

        vm.MasterPassword = "correct horse";
        Assert.False(vm.CanCreate); // confirm still empty

        vm.ConfirmPassword = "correct horse";
        Assert.True(vm.CanCreate);

        vm.ConfirmPassword = "different";
        Assert.False(vm.CanCreate);
    }

    [Fact]
    public async Task CreateAsync_CallsServiceAndRaisesVaultCreated()
    {
        var service = new FakeVaultService();
        var vm = new FirstRunViewModel(service)
        {
            VaultName = "Personal",
            MasterPassword = "correct horse battery staple",
            ConfirmPassword = "correct horse battery staple",
        };

        bool raised = false;
        vm.VaultCreated += (_, _) => raised = true;

        service.RecoveryCodeToReturn = "ABCD-1234-EFGH-5678";

        await vm.CreateCommand.ExecuteAsync(null);

        Assert.True(raised);
        Assert.Null(vm.ErrorMessage);
        Assert.Equal((vm.VaultPath, "correct horse battery staple", "Personal"), service.LastCreateArgs);
        Assert.Equal("ABCD-1234-EFGH-5678", vm.RecoveryCode);
    }

    [Fact]
    public async Task CreateAsync_AlreadyExists_SetsErrorMessage_AndDoesNotRaiseVaultCreated()
    {
        var service = new FakeVaultService
        {
            CreateVaultThrows = KagisecureExceptionFactory.Create<KagisecureException.AlreadyExists>("already there"),
        };
        var vm = new FirstRunViewModel(service)
        {
            MasterPassword = "correct horse battery staple",
            ConfirmPassword = "correct horse battery staple",
        };

        bool raised = false;
        vm.VaultCreated += (_, _) => raised = true;

        await vm.CreateCommand.ExecuteAsync(null);

        Assert.False(raised);
        Assert.NotNull(vm.ErrorMessage);
        Assert.False(vm.IsBusy);
    }

    [Fact]
    public void StrengthLabel_EmptyUntilTyped_ThenReflectsServiceEstimate()
    {
        var service = new FakeVaultService
        {
            StrengthToReturn = new Strength(65, StrengthBucket.Good, "Good", 0.65),
        };
        var vm = new FirstRunViewModel(service);

        Assert.Equal(string.Empty, vm.StrengthLabel); // nothing typed yet

        vm.MasterPassword = "correct horse battery staple";
        Assert.Equal("Good", vm.StrengthLabel); // from the core's estimator, not a local guess
    }
}
