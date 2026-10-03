using Kagisecure.App.ViewModels;
using Kagisecure.Interop;
using Xunit;

namespace Kagisecure.App.Tests;

public class GeneratorViewModelTests
{
    [Fact]
    public void ConstructingRegeneratesImmediately()
    {
        var service = new FakeVaultService { GeneratePasswordResult = "abc123" };
        var vm = new GeneratorViewModel(service, new FakeClipboardService());

        Assert.Equal("abc123", vm.GeneratedPassword);
        Assert.NotNull(service.LastGeneratorRecipe);
    }

    [Fact]
    public void ChangingAnOptionRegenerates()
    {
        var service = new FakeVaultService();
        var vm = new GeneratorViewModel(service, new FakeClipboardService());

        service.GeneratePasswordResult = "second-call";
        vm.Length = 32;

        Assert.Equal("second-call", vm.GeneratedPassword);
        Assert.Equal(32u, service.LastGeneratorRecipe!.Value.Length);
    }

    [Fact]
    public void CopyToClipboard_ForwardsToClipboardService()
    {
        var service = new FakeVaultService { GeneratePasswordResult = "s3cr3t" };
        var clipboard = new FakeClipboardService();
        var vm = new GeneratorViewModel(service, clipboard);

        vm.CopyToClipboardCommand.Execute(null);

        Assert.Single(clipboard.Copies);
        Assert.Equal("s3cr3t", clipboard.Copies[0].Value);
        Assert.Contains("Copied", vm.CopiedNotice);
    }

    [Fact]
    public void Invalid_FromService_ShowsErrorAndClearsPassword()
    {
        var service = new FakeVaultService();
        var vm = new GeneratorViewModel(service, new FakeClipboardService());
        Assert.NotEmpty(vm.GeneratedPassword); // the constructor's own regenerate succeeded

        // Simulate the core refusing a recipe with every character class off
        // (kgs_generate_password's real Invalid case — see PasswordGenerator.Generate's docs).
        service.GeneratePasswordThrows = KagisecureExceptionFactory.Create<KagisecureException.Invalid>("no character classes");
        vm.Symbols = !vm.Symbols; // any option change re-triggers Regenerate()

        Assert.Equal(string.Empty, vm.GeneratedPassword);
        Assert.Equal("Turn on at least one character class.", vm.ErrorMessage);
    }

    [Fact]
    public void StrengthComesFromTheServicesEstimator()
    {
        var service = new FakeVaultService { StrengthToReturn = new Strength(90, StrengthBucket.Excellent, "Excellent", 1.0) };
        var vm = new GeneratorViewModel(service, new FakeClipboardService());

        Assert.Equal("Excellent", vm.StrengthLabel);
        Assert.Equal(1.0, vm.StrengthFraction);
    }

    [Fact]
    public void ConstructorClampsDefaultsToTheServicesLimits()
    {
        var service = new FakeVaultService { GeneratorLimitsToReturn = new GeneratorLimits(30, 40, 5, 6, 7776) };
        var vm = new GeneratorViewModel(service, new FakeClipboardService());

        // ui-spec.md §8 defaults (20 chars, 4 words) fall outside these limits, so the ctor must
        // clamp into range rather than send an out-of-bounds recipe.
        Assert.InRange(vm.Length, 30, 40);
        Assert.InRange(vm.Words, 5, 6);
    }

    [Fact]
    public void WordsMode_SendsWordsModeRecipe()
    {
        var service = new FakeVaultService();
        var vm = new GeneratorViewModel(service, new FakeClipboardService())
        {
            Mode = GeneratorMode.Words,
            Words = 6,
        };

        Assert.Equal(GeneratorMode.Words, service.LastGeneratorRecipe!.Value.Mode);
        Assert.Equal(6u, service.LastGeneratorRecipe!.Value.Words);
    }
}
