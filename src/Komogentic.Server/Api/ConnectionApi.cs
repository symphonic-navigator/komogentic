// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Accounts;
using Komogentic.Server.Auth;
using Komogentic.Server.Komodo;
using Komogentic.Server.OAuth;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Options;
using ConnectionInfo = Komogentic.Server.Accounts.ConnectionInfo;

namespace Komogentic.Server.Api;

/// <summary>
/// A connection as its owner sees it: <c>url</c> is its own MCP URL, to paste into the app. <c>state</c> is
/// <c>waiting</c>, <c>connected</c>, <c>needs_reconnect</c>, <c>revoked</c> or <c>expired</c>; <c>reason</c> goes with
/// the last three (e.g. <c>komodo_key_rejected</c>); <c>client</c> is null until an app was allowed.
/// </summary>
public sealed record ConnectionView(
    string Id, string Name, string Url, DateTime CreatedAt, DateTime? LastUsedAt, DateTime? ExpiresAt, ConnectionState State, string? Reason, ConnectedClient? Client);

/// <summary><c>expiresInDays</c>: 30, 90 or 365; left out or null, the connection doesn't expire.</summary>
public sealed record CreateConnectionRequest(string Name, int? ExpiresInDays = null);

/// <summary>
/// What the consent page shows for a pending authorisation. <c>client</c>: the app asking; <c>redirectHost</c>: where
/// the browser returns, in its IDN (punycode) form like the client's host. <c>connection</c>: the connection its URL
/// names; null when the address is no connection's.
/// <c>readOnly</c>: the app asked for <c>komodo:read</c> alone, so the grant gets the read tools only.
/// <c>renewal</c>: the connection was authorised before. <c>problem</c>: null, <c>not_a_connection</c>, <c>revoked</c>
/// or <c>expired</c>; with a problem only Deny is possible. A request for another account's connection is a 404 to this
/// one, for the view and the decision alike.
/// </summary>
public sealed record ConsentView(
    string RequestId, ConnectedClient Client, string RedirectHost, ConsentConnectionView? Connection, bool ReadOnly, bool Renewal, string? Problem);

/// <summary>A connection on the consent page: its name, its expiry, and the app it is authorised for now, if any.</summary>
public sealed record ConsentConnectionView(string Name, DateTime? ExpiresAt, ConnectedClient? CurrentClient);

/// <summary><c>allow</c>: the user's Allow (true) or Deny (false).</summary>
public sealed record ConsentDecisionRequest(bool Allow);

/// <summary>Where the consent page sends the browser: back to the app, with a code or an error.</summary>
public sealed record ConsentDecisionView(string Redirect);

/// <summary>
/// The dashboard's connections and the consent page's calls (spec §2), for the signed-in user only: an agent's key or
/// token never makes or authorises a credential. The POSTs pass the Origin check (<see cref="Security.UseCallerRules"/>),
/// which is their CSRF guard.
/// </summary>
public static class ConnectionApi
{
    private const string RequestExpired = "This request has expired; start the connection again in the app.";
    private const string ClientGone = "The app could not be identified any more; start the connection again in the app.";
    private const string ClientBusy = "The app could not be identified just now; try again in a minute.";
    private const string OtherAccount = "This request is for another Komodo user's connection; sign in as the connection's owner.";

    public static void MapConnectionApi(this IEndpointRouteBuilder app)
    {
        var connections = app.MapGroup("/api/connections").AddEndpointFilter(ApiErrors.Filter);
        connections.MapGet("", ListAsync);
        connections.MapPost("", CreateAsync);
        connections.MapDelete("/{id}", RevokeAsync);

        var consent = app.MapGroup("/api/oauth/requests").AddEndpointFilter(ApiErrors.Filter);
        consent.MapGet("/{id}", ConsentAsync);
        consent.MapPost("/{id}/decision", DecideAsync);
    }

    private static async Task<Ok<ConnectionView[]>> ListAsync(HttpContext http, RequestCaller caller, Connections connections, IOptions<KomogenticOptions> options, CancellationToken ct)
    {
        var origin = OAuthUrls.Origin(http, options.Value.PublicUrl);
        return TypedResults.Ok((await connections.ListAsync(Session(caller).User.Id, ct)).Select(c => View(c, origin)).ToArray());
    }

    private static async Task<Created<ConnectionView>> CreateAsync(
        CreateConnectionRequest body, HttpContext http, RequestCaller caller, Connections connections, IOptions<KomogenticOptions> options, CancellationToken ct)
    {
        var info = await connections.CreateAsync(Session(caller).User, body.Name, body.ExpiresInDays, ct);
        return TypedResults.Created($"/api/connections/{info.Id}", View(info, OAuthUrls.Origin(http, options.Value.PublicUrl)));
    }

    private static async Task<Results<NoContent, JsonHttpResult<ApiError>>> RevokeAsync(
        string id, RequestCaller caller, Connections connections, HttpContext http, CancellationToken ct)
    {
        var (user, jwt) = Session(caller);
        bool revoked;
        try
        {
            revoked = await connections.RevokeAsync(user, jwt, id, ct);
        }
        catch (KomodoException e) when (e.Kind == KomodoErrorKind.Unauthorized)
        {
            // The connection is revoked and its Komodo key queued for the next sign-in: what was asked is done. Only the
            // JWT has ended, and with it the session, but a 401 would read as a failed revoke.
            await SessionApi.EndSessionAsync(http, CancellationToken.None);
            return TypedResults.NoContent();
        }

        return revoked
            ? TypedResults.NoContent()
            : TypedResults.Json(new ApiError("You have no such connection, or it is revoked already."), statusCode: StatusCodes.Status404NotFound);
    }

    private static async Task<Ok<ConsentView>> ConsentAsync(
        string id, RequestCaller caller, AuthorizationRequests requests, OAuthClients clients, Connections connections, TimeProvider time, CancellationToken ct)
    {
        var (user, _) = Session(caller);
        var request = await requests.GetAsync(id, ct) ?? throw ApiErrors.NotFound(RequestExpired);
        await RequireOwnerAsync(request, user, connections, ct);
        OAuthClient? client;
        try
        {
            client = await clients.ResolveAsync(request.ClientId, ct);
        }
        catch (ClientMetadataUnavailableException)
        {
            throw new ApiException(StatusCodes.Status503ServiceUnavailable, ClientBusy);
        }

        if (client is null) throw ApiErrors.NotFound(ClientGone);
        var (problem, connection, renewal) = await ConsentConnectionAsync(request, connections, time, ct);
        return TypedResults.Ok(new ConsentView(
            request.Id, new ConnectedClient(client.Name, client.Host, client.Verified), new Uri(request.RedirectUri).IdnHost, connection, request.ReadOnly, renewal, problem));
    }

    /// <summary>
    /// The decision, which takes the request (single use): Deny always redirects with <c>access_denied</c>
    /// (<c>invalid_target</c> for an address that is no connection's); Allow with a problem is a 409 and leaves the
    /// request, so the page can still offer the way back; Allow issues the code for the signed-in user. Another
    /// account's request is a 404 either way, before anything is taken. Should Allow issue nothing because Komodo or the
    /// app's metadata document couldn't be reached (or the session's JWT has ended), the request goes back, so that
    /// "try again" means this request.
    /// </summary>
    private static async Task<Ok<ConsentDecisionView>> DecideAsync(
        string id, ConsentDecisionRequest body, HttpContext http, RequestCaller caller, AuthorizationRequests requests, OAuthClients clients, OAuthTokens tokens,
        Connections connections, IOptions<KomogenticOptions> options, TimeProvider time, ILoggerFactory logs, CancellationToken ct)
    {
        var (user, jwt) = Session(caller);
        var log = logs.CreateLogger(OAuthEndpoints.LogCategory);
        var pending = await requests.GetAsync(id, ct) ?? throw ApiErrors.NotFound(RequestExpired);
        await RequireOwnerAsync(pending, user, connections, ct);
        var clientHost = OAuthEndpoints.ClientHost(pending.ClientId, pending.RedirectUri);
        if (body.Allow)
        {
            var (problem, _, _) = await ConsentConnectionAsync(pending, connections, time, ct);
            if (problem is not null)
            {
                OAuthEndpoints.LogStep(log, "consent", "conflict", pending.ConnectionId, clientHost, pending.Id);
                throw new ApiException(StatusCodes.Status409Conflict, ProblemText(problem));
            }
        }

        // Taken only now: of two decisions at once, one gets it and the other a 404.
        var request = await requests.TakeAsync(id, ct) ?? throw ApiErrors.NotFound(RequestExpired);
        var issuer = OAuthUrls.Origin(http, options.Value.PublicUrl);
        if (!body.Allow)
        {
            OAuthEndpoints.LogStep(log, "consent", "denied", request.ConnectionId, clientHost, request.Id);
            var error = request.Problem == AuthorizationRequests.NotAConnection ? "invalid_target" : "access_denied";
            var description = error == "invalid_target" ? "The address given is no connection's URL." : "The user denied the request.";
            return TypedResults.Ok(new ConsentDecisionView(OAuthEndpoints.Redirect(request.RedirectUri, issuer, request.State, ("error", error), ("error_description", description))));
        }

        string code;
        try
        {
            code = await tokens.IssueCodeAsync(user, jwt, request, ct);
        }
        catch (ConnectionUnavailableException e)
        {
            // Revoked, expired or gone between the check above and the transaction: the request is spent.
            OAuthEndpoints.LogStep(log, "consent", "conflict", request.ConnectionId, clientHost, request.Id);
            throw new ApiException(StatusCodes.Status409Conflict, e.Message);
        }
        catch (ClientMetadataUnavailableException)
        {
            await requests.PutBackAsync(request, CancellationToken.None);
            OAuthEndpoints.LogStep(log, "consent", "busy", request.ConnectionId, clientHost, request.Id);
            throw new ApiException(StatusCodes.Status503ServiceUnavailable, ClientBusy);
        }
        catch (KomodoException e)
        {
            // Nothing was issued (ApiErrors.Filter answers: 503 unreachable, 401 and the session ended for a JWT Komodo
            // no longer accepts, ...).
            await requests.PutBackAsync(request, CancellationToken.None);
            OAuthEndpoints.LogStep(log, "consent", e.Kind == KomodoErrorKind.Unreachable ? "busy" : "komodo_refused", request.ConnectionId, clientHost, request.Id);
            throw;
        }

        // After the commit: should this fail, the code is never seen and expires harmlessly within 60 s.
        await clients.MarkAuthorisedAsync(request.ClientId, CancellationToken.None);
        OAuthEndpoints.LogStep(log, "consent", "allowed", request.ConnectionId, clientHost, request.Id);
        return TypedResults.Ok(new ConsentDecisionView(OAuthEndpoints.Redirect(request.RedirectUri, issuer, request.State, ("code", code))));
    }

    /// <summary>A request naming another account's connection is not found for this one: not shown, allowed or denied.</summary>
    private static async Task RequireOwnerAsync(PendingAuthorisation request, KomodoUser user, Connections connections, CancellationToken ct)
    {
        if (request.ConnectionId is null) return;
        if (await connections.FindAsync(request.ConnectionId, ct) is { } doc && doc.User != user.Id)
            throw ApiErrors.NotFound(OtherAccount, ApiErrors.OtherAccount);
    }

    /// <summary>The connection a request names, which <see cref="RequireOwnerAsync"/> found to be the signed-in user's:
    /// its problem if any, its name, expiry and client, and whether it was authorised before.</summary>
    private static async Task<(string? Problem, ConsentConnectionView? Connection, bool Renewal)> ConsentConnectionAsync(
        PendingAuthorisation request, Connections connections, TimeProvider time, CancellationToken ct)
    {
        if (request.Problem is not null || request.ConnectionId is null) return (request.Problem ?? AuthorizationRequests.NotAConnection, null, false);
        var doc = await connections.FindAsync(request.ConnectionId, ct);
        if (doc is null) return (AuthorizationRequests.NotAConnection, null, false);
        var view = new ConsentConnectionView(doc.Name, doc.ExpiresAt, doc.Client);
        var renewal = doc.AuthorisedAt is not null || doc.Client is not null;
        if (doc.RevokedAt is not null) return (ConnectionReasons.Revoked, view, renewal);
        if (time.GetUtcNow().UtcDateTime >= doc.ExpiresAt) return (ConnectionReasons.Expired, view, renewal);
        return (null, view, renewal);
    }

    private static string ProblemText(string problem) => problem switch
    {
        AuthorizationRequests.NotAConnection => "This address isn't a connection; it can't be allowed.",
        ConnectionReasons.Expired => "This connection has expired.",
        _ => "This connection was revoked.",
    };

    private static ConnectionView View(ConnectionInfo info, string origin) =>
        new(info.Id, info.Name, OAuthUrls.Resource(origin, info.Id), info.CreatedAt, info.LastUsedAt, info.ExpiresAt, info.State, info.Reason, info.Client);

    /// <summary>The session's user and JWT. CallerMiddleware gives <c>/api</c> nothing but sessions; this holds if that changes.</summary>
    private static (KomodoUser User, KomodoAuth.Jwt Jwt) Session(RequestCaller caller) =>
        caller is { Kind: CallerKind.Session, Komodo: KomodoAuth.Jwt jwt }
            ? (caller.User, jwt)
            : throw new ApiException(StatusCodes.Status401Unauthorized, CallerMiddleware.SignInSentence);
}
