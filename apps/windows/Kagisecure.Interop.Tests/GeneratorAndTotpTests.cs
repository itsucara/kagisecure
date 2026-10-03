using System.Linq;
using Xunit;

namespace Kagisecure.Interop.Tests;

/// <summary>A record crossing inbound, strings and records crossing outbound, and errors in between.</summary>
public class GeneratorAndTotpTests
{
    private const string Seed = "JBSWY3DPEHPK3PXP";

    private static readonly GeneratorRecipe DigitsOnly = new()
    {
        Mode = GeneratorMode.Characters,
        Length = 24,
        Digits = true,
        Words = 4,
        Separator = WordSeparator.Hyphen,
    };

    [Fact]
    public void A_characters_recipe_is_honoured_field_by_field()
    {
        string password = PasswordGenerator.Generate(DigitsOnly);

        Assert.Equal(24, password.Length);
        Assert.All(password, c => Assert.InRange(c, '0', '9'));
    }

    [Fact]
    public void A_words_recipe_uses_its_separator_and_word_count()
    {
        var recipe = DigitsOnly with { Mode = GeneratorMode.Words, Words = 5, Separator = WordSeparator.Period };

        string password = PasswordGenerator.Generate(recipe);

        Assert.Equal(5, password.Split('.').Length);
        Assert.All(password.Split('.'), word => Assert.NotEmpty(word));
    }

    [Fact]
    public void Each_call_draws_fresh_randomness()
    {
        var passwords = Enumerable.Range(0, 5).Select(_ => PasswordGenerator.Generate(DigitsOnly)).ToHashSet();
        Assert.Equal(5, passwords.Count);
    }

    [Fact]
    public void A_recipe_with_every_class_off_is_a_typed_error()
    {
        var error = Assert.Throws<KagisecureException.Invalid>(
            () => PasswordGenerator.Generate(DigitsOnly with { Digits = false }));
        Assert.False(string.IsNullOrWhiteSpace(error.Message));
    }

    [Fact]
    public void An_enum_value_this_build_does_not_know_is_invalid_not_undefined_behaviour()
    {
        var error = Assert.Throws<KagisecureException.Invalid>(
            () => PasswordGenerator.Generate(DigitsOnly with { Mode = (GeneratorMode)42 }));
        Assert.Contains("unknown generator mode", error.Message);
    }

    [Fact]
    public void Limits_and_strength_come_from_the_core()
    {
        GeneratorLimits limits = PasswordGenerator.Limits();
        Assert.Equal(7776u, limits.WordlistSize);
        Assert.True(limits.MinLength < limits.MaxLength);
        Assert.True(limits.MinWords < limits.MaxWords);

        Strength weak = PasswordGenerator.RecipeStrength(DigitsOnly with { Length = limits.MinLength });
        Strength strong = PasswordGenerator.RecipeStrength(DigitsOnly with { Length = limits.MaxLength });
        Assert.True(strong.Bits > weak.Bits);
        Assert.Equal(StrengthBucket.Excellent, strong.Bucket);
        Assert.InRange(strong.Fraction, 0.0, 1.0);
        Assert.False(string.IsNullOrEmpty(strong.Label));

        char[] typed = "password".ToCharArray();
        Strength existing = PasswordGenerator.PasswordStrength(typed);
        System.Array.Clear(typed);
        Assert.Equal(StrengthBucket.VeryWeak, existing.Bucket);
    }

    [Fact]
    public void A_hand_typed_seed_becomes_a_uri_that_describes_and_previews_itself()
    {
        string uri = Totp.UriFromParts(Seed, new TotpParams(TotpAlgorithm.Sha256, 8, 60, "ACME", "ada@example.com", null));

        Assert.StartsWith("otpauth://totp/", uri);
        Assert.True(Totp.UriIsValid(uri));

        TotpParams parameters = Totp.Describe(uri);
        Assert.Equal(TotpAlgorithm.Sha256, parameters.Algorithm);
        Assert.Equal(8, parameters.Digits);
        Assert.Equal(60u, parameters.Period);
        Assert.Equal("ACME", parameters.Issuer);
        Assert.Equal("ada@example.com", parameters.Account);
        Assert.Contains("ACME", parameters.Caption);

        TotpCode code = Totp.Preview(uri, 59);
        Assert.Equal(8, code.Code.Length);
        Assert.Equal(1u, code.SecondsRemaining);
        Assert.Equal(parameters, code.Params);
        Assert.Equal(code.Code, Totp.Preview(uri, 1).Code);
        Assert.NotEqual(code.Code, Totp.Preview(uri, 60).Code);
    }

    [Fact]
    public void A_bad_uri_or_seed_is_invalid_and_the_message_does_not_quote_it()
    {
        const string bad = "otpauth://totp/x?secret=!!!";
        Assert.False(Totp.UriIsValid(bad));
        var error = Assert.Throws<KagisecureException.Invalid>(() => Totp.Describe(bad));
        Assert.DoesNotContain("!!!", error.Message);
        Assert.Throws<KagisecureException.Invalid>(() => Totp.Preview(bad, 0));
        Assert.Throws<KagisecureException.Invalid>(
            () => Totp.UriFromParts("not base32 at all!", new TotpParams(TotpAlgorithm.Sha1, 6, 30, null, null, null)));
    }

    [Fact]
    public void The_category_catalogue_comes_from_the_core()
    {
        var catalog = Categories.Catalog();

        Assert.Contains(catalog, c => c.Id == "login" && c.DisplayName == "Login");
        Assert.Contains(catalog, c => c.Id == "secure-note");
        Assert.All(catalog, c => Assert.False(string.IsNullOrEmpty(c.SymbolName)));
        Assert.Equal(catalog.Count, catalog.Select(c => c.Id).Distinct().Count());
    }
}
