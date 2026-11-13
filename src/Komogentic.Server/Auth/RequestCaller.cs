// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Accounts;
using Komogentic.Server.Komodo;

namespace Komogentic.Server.Auth;

public enum CallerKind
{
    Session,
    ApiKey,
    Connection,
}

/// <summary>
/// Who a request comes from, as <see cref="CallerMiddleware"/> resolved it, and how its Komodo calls authenticate. One
/// per request (scoped); built only by the middleware, after the credential was checked. Tools take it from DI and
/// never see the bearer or the cookie.
/// </summary>
public sealed class RequestCaller
{
    private RequestCaller(
        CallerKind kind, KomodoUser user, KomodoAuth komodo, string? credentialId, string? credentialName, string? clientName, bool readOnly, DateTime? expiresAt)
    {
        Kind = kind;
        User = user;
        Komodo = komodo;
        CredentialId = credentialId;
        CredentialName = credentialName;
        ClientName = clientName;
        ReadOnly = readOnly;
        ExpiresAt = expiresAt;
    }

    public CallerKind Kind { get; }

    /// <summary>The signed-in user, or the API key's or connection's owner.</summary>
    public KomodoUser User { get; }

    /// <summary>The session's JWT, or the agent's own Komodo API key, unsealed for this request.</summary>
    public KomodoAuth Komodo { get; }

    /// <summary>The API key's or connection's id; null for a session.</summary>
    public string? CredentialId { get; }

    /// <summary>The API key's or connection's name, for the audit; null for a session.</summary>
    public string? CredentialName { get; }

    /// <summary>The connected app's name; null for a session and an API key.</summary>
    public string? ClientName { get; }

    /// <summary>A grant of <c>komodo:read</c> alone: the read tools only.</summary>
    public bool ReadOnly { get; }

    /// <summary>When the credential ends at the latest: a session's end (never past its JWT); null if it doesn't.</summary>
    public DateTime? ExpiresAt { get; }

    public static RequestCaller ForSession(KomodoUser user, string jwt, DateTime expiresAt) =>
        new(CallerKind.Session, user, new KomodoAuth.Jwt(jwt), null, null, null, false, expiresAt);

    /// <summary>An agent with an API key that <see cref="ApiKeys.ResolveAsync"/> found active: Komodo as the key's own Komodo key.</summary>
    public static RequestCaller ForApiKey(ResolvedApiKey key) =>
        new(CallerKind.ApiKey, key.User, key.Komodo, key.Id, key.Name, null, false, key.ExpiresAt);

    /// <summary>An app on a connection's URL with an access token that <see cref="OAuth.OAuthTokens.ResolveAccessAsync"/>
    /// found valid: Komodo as the connection's own Komodo key, the read tools only if the grant is read-only.</summary>
    public static RequestCaller ForConnection(OAuth.ResolvedConnection connection) =>
        new(CallerKind.Connection, connection.User, connection.Komodo, connection.ConnectionId, connection.Name, connection.ClientName, connection.ReadOnly, connection.ExpiresAt);

    /// <summary>The caller of the current request. Fails closed: a service asking on a request without a
    /// caller (an anonymous endpoint) is a bug, never a reason to fall back to some default.</summary>
    internal static RequestCaller Current(IServiceProvider services) =>
        services.GetRequiredService<IHttpContextAccessor>().HttpContext?.Features.Get<RequestCaller>()
        ?? throw new InvalidOperationException("This request has no caller: it reached an endpoint that needs one without CallerMiddleware");
}
