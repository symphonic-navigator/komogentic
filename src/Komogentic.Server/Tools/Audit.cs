// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Globalization;
using System.Text;
using Komogentic.Server.Auth;

namespace Komogentic.Server.Tools;

/// <summary>
/// One line per tool call (spec §6, Decision 9), in its own log category: who (the Komodo user), through which
/// credential and app, which tool on which stack, and how it ended. Komodo records the user as the operator; this
/// line tells the user by hand from the user's agent. Never a secret, never log text or search terms.
/// </summary>
public static class Audit
{
    public const string Category = "Komogentic.Audit";

    public const int MaxTextLength = 100;

    public static void Log(ILogger log, RequestCaller caller, string tool, string? stack, string outcome) =>
        log.LogInformation(
            "Tool {Tool} on {Stack} by {Username} via {Kind} {CredentialName} ({CredentialId}), client {Client}: {Outcome}",
            tool, stack ?? "-", caller.User.Username, KindWord(caller.Kind), caller.CredentialName ?? "-", caller.CredentialId ?? "-",
            caller.ClientName ?? "-", outcome);

    /// <summary>An agent's text for the line: without the characters a credential name may not hold (control and
    /// invisible formatting, <see cref="Accounts.CredentialRules"/>), nor line or paragraph separators, so that it stays
    /// one line that shows what it says; then cut to <see cref="MaxTextLength"/> characters, never inside a surrogate pair.</summary>
    public static string Text(string text)
    {
        var clean = new StringBuilder(Math.Min(text.Length, MaxTextLength));
        foreach (var c in text)
        {
            if (clean.Length == MaxTextLength) break;
            if (char.IsControl(c)) continue;
            if (char.GetUnicodeCategory(c) is UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator) continue;
            clean.Append(c);
        }

        if (clean.Length == MaxTextLength && char.IsHighSurrogate(clean[^1])) clean.Length--;
        return clean.ToString();
    }

    private static string KindWord(CallerKind kind) => kind switch
    {
        CallerKind.ApiKey => "api key",
        CallerKind.Connection => "connection",
        _ => "session",
    };
}
