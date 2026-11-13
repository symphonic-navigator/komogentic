// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Accounts;
using Komogentic.Server.Auth;

namespace Komogentic.Server.Tools;

/// <summary>What a tool does when Komodo rejects the caller's own Komodo key (spec §2: deleted in Komodo).</summary>
public interface ICredentialHealth
{
    /// <summary>The caller's credential stops working, if <paramref name="komodoKey"/> is still its Komodo key
    /// (amendment R1). Komodo's rate limiter (429) is never a reason to call this.</summary>
    Task KomodoKeyRejectedAsync(RequestCaller caller, string komodoKey, CancellationToken ct);
}

public sealed class CredentialHealth(ApiKeys apiKeys, Connections connections) : ICredentialHealth
{
    public const string KomodoKeyRejected = ConnectionReasons.KomodoKeyRejected;

    public Task KomodoKeyRejectedAsync(RequestCaller caller, string komodoKey, CancellationToken ct) => caller.Kind switch
    {
        CallerKind.ApiKey => apiKeys.MarkDeadAsync(caller.CredentialId!, komodoKey, KomodoKeyRejected, ct),
        // Needs a reconnect, which a new consent on the same URL makes.
        CallerKind.Connection => connections.MarkKomodoKeyRejectedAsync(caller.CredentialId!, komodoKey, ct),
        // A session's JWT is never a Komodo key: a rejected JWT ends the session (ApiErrors.Filter).
        _ => Task.CompletedTask,
    };
}
