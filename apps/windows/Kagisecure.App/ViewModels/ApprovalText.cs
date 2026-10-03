using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Kagisecure.Interop;

namespace Kagisecure.App.ViewModels;

/// <summary>
/// The approval sheet's security-critical strings (ui-spec.md §10.2, §10.5), as static functions
/// so tests assert them — a port of the macOS <c>ApprovalSheet.sentence/summary/safe/duration</c>
/// and <c>AgentService.reason</c>, kept word for word so the two apps say the same thing.
/// </summary>
/// <remarks>
/// Quotation marks mean "the caller said so". A self-reported client name is always quoted and
/// always passed through <see cref="Safe"/>; the browser name on a fill is the app's own
/// conclusion from process ancestry and is not quoted.
/// </remarks>
public static class ApprovalText
{
    /// <summary>How much of an untrusted run the sentence carries before it is cut.</summary>
    public const int UntrustedRunLimit = 64;

    /// <summary>Quote characters an untrusted run could use to close — or forge — the sheet's own quoting.</summary>
    private static readonly HashSet<int> QuoteScalars = new()
    {
        0x0022, 0x00AB, 0x00BB, 0x2018, 0x2019, 0x201A, 0x201B, 0x201C, 0x201D, 0x201E, 0x201F,
        0x2033, 0x2036, 0x2039, 0x203A, 0x301D, 0x301E, 0x301F, 0xFF02,
    };

    /// <summary>
    /// Sanitize one attacker-controlled run for display inside the app's own sentence: any quote
    /// glyph becomes <c>'</c>; Unicode format characters (bidi overrides, isolates, zero-width
    /// joiners), surrogates and private-use scalars are dropped; control characters, line and
    /// paragraph separators and whitespace runs collapse to one space; and the result is cut at
    /// <paramref name="limit"/> user-perceived characters with a visible <c>…</c>. Empty becomes
    /// <c>unnamed</c>.
    /// </summary>
    public static string Safe(string? raw, int limit = UntrustedRunLimit)
    {
        var builder = new StringBuilder();
        bool pendingSpace = false;
        foreach (Rune rune in (raw ?? string.Empty).EnumerateRunes())
        {
            if (QuoteScalars.Contains(rune.Value))
            {
                if (pendingSpace && builder.Length > 0)
                {
                    builder.Append(' ');
                }

                pendingSpace = false;
                builder.Append('\'');
                continue;
            }

            switch (Rune.GetUnicodeCategory(rune))
            {
                case UnicodeCategory.Format:
                case UnicodeCategory.Surrogate:
                case UnicodeCategory.PrivateUse:
                    // Invisible by construction: dropped outright rather than turned into a space.
                    continue;
                case UnicodeCategory.Control:
                case UnicodeCategory.LineSeparator:
                case UnicodeCategory.ParagraphSeparator:
                    pendingSpace = true;
                    continue;
            }

            if (Rune.IsWhiteSpace(rune))
            {
                pendingSpace = true;
                continue;
            }

            if (pendingSpace && builder.Length > 0)
            {
                builder.Append(' ');
            }

            pendingSpace = false;
            builder.Append(rune.ToString());
        }

        string collapsed = builder.ToString();
        if (collapsed.Length == 0)
        {
            return "unnamed";
        }

        var info = new StringInfo(collapsed);
        if (info.LengthInTextElements <= limit)
        {
            return collapsed;
        }

        return info.SubstringByTextElements(0, Math.Max(0, limit - 1)) + "…";
    }

    /// <summary>The plain-language sentence at the top of the sheet (ui-spec.md §10.2, §10.5).</summary>
    public static string Sentence(ApprovalRequest request)
    {
        string who = $"“{Safe(request.ClientName)}”";
        switch (request.Action)
        {
            case ApprovalAction.WriteEnvFile:
                int n = request.Variables.Count;
                return $"{who} wants to write {n} variable{(n == 1 ? string.Empty : "s")} to a .env file";
            case ApprovalAction.RunWithEnv:
                return $"{who} wants to run {Safe(string.Join(" ", request.Command), 80)} with environment variables";
            case ApprovalAction.CreateEnvironment:
                return $"{who} wants to create the environment {Safe(request.EnvironmentName ?? string.Empty)}";
            case ApprovalAction.AddVariables:
                return $"{who} wants to add variables to {Safe(request.EnvironmentName ?? "an environment")}";
            case ApprovalAction.FillCredential:
                string browser = request.Browser ?? "A browser";
                string what = request.FillFields.Contains("one-time password") ? "the one-time code for" : "the password for";
                return $"{browser} wants {what} “{Safe(request.ItemTitle ?? "an item")}”";
            default:
                return $"{who} wants something this app does not recognise";
        }
    }

    /// <summary>The line under the sentence.</summary>
    public static string Headline(ApprovalRequest request) =>
        request.Action == ApprovalAction.FillCredential
            ? "The value goes to the browser only if you allow it, and only for this page."
            : "No secret value is shown to the caller either way.";

    /// <summary>The one-line scope summary (ui-spec.md §10.2).</summary>
    public static string Summary(ApprovalRequest request, ulong ttlSeconds)
    {
        if (request.Action == ApprovalAction.FillCredential)
        {
            string fields = string.Join(" and ", request.FillFields);
            return $"This sends the {Safe(fields, 80)} for “{Safe(request.ItemTitle ?? "this item")}” to "
                + $"{Safe(request.Origin ?? "this page", 120)}, once. Nothing else is sent, and nothing is "
                + "stored in the browser.";
        }

        if (!request.MintsLease)
        {
            return "This changes the structure of your vault. It grants no access to any value.";
        }

        string names = request.Variables.Count == 0
            ? "no variables"
            : Safe(string.Join(", ", request.Variables), 100);
        string place = Safe(request.Directory ?? request.TargetPath ?? "this directory", 100);
        uint uses = request.RequestedUses;
        return $"This grants access to {names} in {place} for {Duration(ttlSeconds)}, up to {uses} use{(uses == 1 ? string.Empty : "s")}.";
    }

    /// <summary>The text of the Windows Hello prompt. Names the action and the caller, never a value.</summary>
    public static string Reason(ApprovalRequest request)
    {
        switch (request.Action)
        {
            case ApprovalAction.WriteEnvFile:
                int n = request.Variables.Count;
                return $"approve writing {n} variable{(n == 1 ? string.Empty : "s")} to a .env file";
            case ApprovalAction.RunWithEnv:
                return $"approve running {Safe(request.Command.FirstOrDefault() ?? "a command")} with secrets in its environment";
            case ApprovalAction.CreateEnvironment:
                return "approve creating an environment";
            case ApprovalAction.AddVariables:
                return "approve adding variables to an environment";
            case ApprovalAction.FillCredential:
                return $"fill {Safe(request.ItemTitle ?? "a login")} into {Safe(request.Origin ?? "this page", 120)}";
            default:
                return "approve a request";
        }
    }

    /// <summary><c>900</c> → <c>15 minutes</c>. Used on the sheet and in the leases tables, so they agree.</summary>
    public static string Duration(ulong seconds)
    {
        if (seconds < 60)
        {
            return $"{seconds} s";
        }

        ulong minutes = seconds / 60;
        if (minutes < 60)
        {
            return $"{minutes} minute{(minutes == 1 ? string.Empty : "s")}";
        }

        double hours = seconds / 3600.0;
        return string.Format(CultureInfo.InvariantCulture, "{0:0.0} hours", hours);
    }

    /// <summary>The Fluent glyph for a request kind (the macOS SF Symbol's counterpart).</summary>
    public static string Glyph(ApprovalAction action) => action switch
    {
        ApprovalAction.WriteEnvFile => "",      // Document
        ApprovalAction.RunWithEnv => "",        // CommandPrompt
        ApprovalAction.CreateEnvironment => "", // NewFolder
        ApprovalAction.AddVariables => "",      // Add
        ApprovalAction.FillCredential => "",    // Permissions (key)
        _ => "",                                // Info
    };
}
