using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Kagisecure.App.Services;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>The password generator (ui-spec.md §8).</summary>
public sealed partial class GeneratorViewModel : ObservableObject
{
    private readonly IVaultService vaultService;
    private readonly IClipboardService clipboardService;

    public GeneratorViewModel(IVaultService vaultService, IClipboardService clipboardService)
    {
        this.vaultService = vaultService;
        this.clipboardService = clipboardService;

        GeneratorLimits limits = vaultService.GeneratorLimits();
        Limits = limits;
        length = limits.MinLength <= 20 && 20 <= limits.MaxLength ? 20 : (int)limits.MinLength; // ui-spec.md §8 default
        words = limits.MinWords <= 4 && 4 <= limits.MaxWords ? 4 : (int)limits.MinWords; // ui-spec.md §8 default

        Regenerate();
    }

    /// <summary>The slider bounds and wordlist size, from the core rather than hardcoded.</summary>
    public GeneratorLimits Limits { get; }

    [ObservableProperty]
    private GeneratorMode mode = GeneratorMode.Characters;

    [ObservableProperty]
    private int length;

    [ObservableProperty]
    private bool lowercase = true;

    [ObservableProperty]
    private bool uppercase = true;

    [ObservableProperty]
    private bool digits = true;

    [ObservableProperty]
    private bool symbols = true;

    [ObservableProperty]
    private bool avoidAmbiguous;

    [ObservableProperty]
    private int words;

    [ObservableProperty]
    private WordSeparator separator = WordSeparator.Hyphen;

    [ObservableProperty]
    private bool capitalize;

    [ObservableProperty]
    private bool includeDigit;

    [ObservableProperty]
    private string generatedPassword = string.Empty;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private string? copiedNotice;

    [ObservableProperty]
    private string strengthLabel = string.Empty;

    [ObservableProperty]
    private double strengthFraction;

    private GeneratorRecipe BuildRecipe() => new()
    {
        Mode = Mode,
        Length = (uint)Length,
        Lowercase = Lowercase,
        Uppercase = Uppercase,
        Digits = Digits,
        Symbols = Symbols,
        AvoidAmbiguous = AvoidAmbiguous,
        Words = (uint)Words,
        Separator = Separator,
        Capitalize = Capitalize,
        IncludeDigit = IncludeDigit,
    };

    [RelayCommand]
    private void Regenerate()
    {
        ErrorMessage = null;
        GeneratorRecipe recipe = BuildRecipe();
        try
        {
            GeneratedPassword = vaultService.GeneratePassword(recipe);
        }
        catch (KagisecureException.Invalid)
        {
            GeneratedPassword = string.Empty;
            ErrorMessage = "Turn on at least one character class.";
        }

        // The strength meter is driven by the recipe (ui-spec.md §8: "the bar is driven by the
        // recipe's entropy"), from the core's own estimator, so it moves monotonically as the
        // slider does rather than jittering on every regenerated candidate.
        Strength strength = vaultService.RecipeStrength(recipe);
        StrengthLabel = strength.Label;
        StrengthFraction = strength.Fraction;
    }

    [RelayCommand]
    private void CopyToClipboard()
    {
        if (string.IsNullOrEmpty(GeneratedPassword))
        {
            return;
        }

        clipboardService.CopySecret(GeneratedPassword, "Generated password");
        CopiedNotice = $"Copied — clears in {clipboardService.ClearAfterSeconds}s";
    }

    // Any option change regenerates live (ui-spec.md §8: "recomputed live as options change").
    partial void OnModeChanged(GeneratorMode value) => Regenerate();
    partial void OnLengthChanged(int value) => Regenerate();
    partial void OnLowercaseChanged(bool value) => Regenerate();
    partial void OnUppercaseChanged(bool value) => Regenerate();
    partial void OnDigitsChanged(bool value) => Regenerate();
    partial void OnSymbolsChanged(bool value) => Regenerate();
    partial void OnAvoidAmbiguousChanged(bool value) => Regenerate();
    partial void OnWordsChanged(int value) => Regenerate();
    partial void OnSeparatorChanged(WordSeparator value) => Regenerate();
    partial void OnCapitalizeChanged(bool value) => Regenerate();
    partial void OnIncludeDigitChanged(bool value) => Regenerate();
}
