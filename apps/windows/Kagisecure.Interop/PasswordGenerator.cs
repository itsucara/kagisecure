using System;
using Kagisecure.Interop.Native;
using static Kagisecure.Interop.Native.Marshalling;

namespace Kagisecure.Interop;

/// <summary>Which of the generator's two modes a recipe is in.</summary>
public enum GeneratorMode : uint
{
    /// <summary>Random characters.</summary>
    Characters = (uint)KgsGeneratorMode.Characters,

    /// <summary>Memorable words from the EFF list.</summary>
    Words = (uint)KgsGeneratorMode.Words,
}

/// <summary>What goes between the words of a memorable password.</summary>
public enum WordSeparator : uint
{
    /// <summary><c>-</c></summary>
    Hyphen = (uint)KgsWordSeparator.Hyphen,

    /// <summary><c>_</c></summary>
    Underscore = (uint)KgsWordSeparator.Underscore,

    /// <summary><c>.</c></summary>
    Period = (uint)KgsWordSeparator.Period,

    /// <summary>A space.</summary>
    Space = (uint)KgsWordSeparator.Space,

    /// <summary>Nothing at all.</summary>
    None = (uint)KgsWordSeparator.None,
}

/// <summary>The five buckets a strength meter labels.</summary>
public enum StrengthBucket : uint
{
    /// <summary>Under 28 bits.</summary>
    VeryWeak = (uint)KgsStrengthBucket.VeryWeak,

    /// <summary>28–39 bits.</summary>
    Weak = (uint)KgsStrengthBucket.Weak,

    /// <summary>40–59 bits.</summary>
    Fair = (uint)KgsStrengthBucket.Fair,

    /// <summary>60–79 bits.</summary>
    Good = (uint)KgsStrengthBucket.Good,

    /// <summary>80 bits and up.</summary>
    Excellent = (uint)KgsStrengthBucket.Excellent,
}

/// <summary>
/// Every knob the generator sheet has, in one flat record — the C# mirror of Rust's
/// <c>GeneratorRecipe</c>. Lengths are clamped by the core, not here.
/// </summary>
public readonly record struct GeneratorRecipe
{
    /// <summary>Which mode.</summary>
    public GeneratorMode Mode { get; init; }

    /// <summary>Characters mode: how many characters.</summary>
    public uint Length { get; init; }

    /// <summary>Characters mode: include <c>a</c>-<c>z</c>.</summary>
    public bool Lowercase { get; init; }

    /// <summary>Characters mode: include <c>A</c>-<c>Z</c>.</summary>
    public bool Uppercase { get; init; }

    /// <summary>Characters mode: include <c>0</c>-<c>9</c>.</summary>
    public bool Digits { get; init; }

    /// <summary>Characters mode: include symbols.</summary>
    public bool Symbols { get; init; }

    /// <summary>Characters mode: leave out <c>0 O 1 l I</c>.</summary>
    public bool AvoidAmbiguous { get; init; }

    /// <summary>Words mode: how many words.</summary>
    public uint Words { get; init; }

    /// <summary>Words mode: what separates them.</summary>
    public WordSeparator Separator { get; init; }

    /// <summary>Words mode: capitalize each word.</summary>
    public bool Capitalize { get; init; }

    /// <summary>Words mode: append one random digit.</summary>
    public bool IncludeDigit { get; init; }

    internal KgsGeneratorRecipe ToNative() => new()
    {
        mode = (uint)Mode,
        length = Length,
        words = Words,
        separator = (uint)Separator,
        lowercase = Byte(Lowercase),
        uppercase = Byte(Uppercase),
        digits = Byte(Digits),
        symbols = Byte(Symbols),
        avoid_ambiguous = Byte(AvoidAmbiguous),
        capitalize = Byte(Capitalize),
        include_digit = Byte(IncludeDigit),
    };
}

/// <summary>The bounds the sliders must not exceed, from the core rather than hardcoded.</summary>
/// <param name="MinLength">Shortest character-mode password.</param>
/// <param name="MaxLength">Longest character-mode password.</param>
/// <param name="MinWords">Fewest words.</param>
/// <param name="MaxWords">Most words.</param>
/// <param name="WordlistSize">How many words the embedded list holds.</param>
public sealed record GeneratorLimits(uint MinLength, uint MaxLength, uint MinWords, uint MaxWords, uint WordlistSize);

/// <summary>What the meter under the generator's field shows.</summary>
/// <param name="Bits">Estimated entropy in bits.</param>
/// <param name="Bucket">The bucket.</param>
/// <param name="Label">The label for that bucket, from the core so every front end agrees.</param>
/// <param name="Fraction">How full a 0–1 bar should be.</param>
public sealed record Strength(double Bits, StrengthBucket Bucket, string Label, double Fraction)
{
    internal static unsafe Strength Take(ref KgsStrength native)
    {
        try
        {
            return new Strength(native.bits, (StrengthBucket)native.bucket, Str(native.label), native.fraction);
        }
        finally
        {
            fixed (KgsStrength* p = &native)
            {
                NativeMethods.kgs_strength_free(p);
            }
        }
    }
}

/// <summary>The password generator.</summary>
public static class PasswordGenerator
{
    /// <summary>
    /// Generate one password. ADR-0008 crossing 5, outbound: the result is a managed
    /// <see cref="string"/> and cannot be zeroized, which is the documented C# weakness
    /// (ADR-0003 rule 5), accepted because showing it is the feature. Rust has zeroized its copy.
    /// </summary>
    /// <exception cref="KagisecureException.Invalid">The recipe turns every character class off.</exception>
    public static unsafe string Generate(GeneratorRecipe recipe)
    {
        EnsureAbi();
        KgsGeneratorRecipe native = recipe.ToNative();
        KgsBuffer output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_generate_password(&native, &output, &error), ref error);
        return TakeString(ref output);
    }

    /// <summary>The slider bounds and the wordlist size.</summary>
    public static unsafe GeneratorLimits Limits()
    {
        EnsureAbi();
        KgsGeneratorLimits native = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_generator_limits(&native, &error), ref error);
        return new GeneratorLimits(native.min_length, native.max_length, native.min_words, native.max_words, native.wordlist_size);
    }

    /// <summary>The strength of what <paramref name="recipe"/> will produce — a property of the settings.</summary>
    public static unsafe Strength RecipeStrength(GeneratorRecipe recipe)
    {
        EnsureAbi();
        KgsGeneratorRecipe native = recipe.ToNative();
        KgsStrength output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_recipe_strength(&native, &output, &error), ref error);
        return Strength.Take(ref output);
    }

    /// <summary>
    /// The strength of a password that already exists. Takes a span so a caller holding the
    /// password in a clearable buffer never makes a <see cref="string"/> of it.
    /// </summary>
    public static unsafe Strength PasswordStrength(ReadOnlySpan<char> password)
    {
        EnsureAbi();
        using var pw = new PinnedUtf8(password);
        KgsStrength output = default;
        KgsBuffer error = default;
        Check(NativeMethods.kgs_password_strength(pw.Slice, &output, &error), ref error);
        return Strength.Take(ref output);
    }
}
