// SPDX-License-Identifier: AGPL-3.0-or-later
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

    public static void Log(ILogger log, RequestCaller caller, string tool, string? stack, string outcome) =>
        log.LogInformation(
            "Tool {Tool} on {Stack} by {Username} via {Kind} {CredentialName} ({CredentialId}), client {Client}: {Outcome}",
            tool, stack ?? "-", caller.User.Username, KindWord(caller.Kind), caller.CredentialName ?? "-", caller.CredentialId ?? "-",
            caller.ClientName ?? "-", outcome);

    private static string KindWord(CallerKind kind) => kind switch
    {
        CallerKind.ApiKey => "api key",
        CallerKind.Connection => "connection",
        _ => "session",
    };
}
