// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Komogentic.Server.Accounts;
using Komogentic.Server.Api;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace Komogentic.Server.OAuth;

/// <summary>The authorisation server's endpoints (spec §5). CORS is applied by <see cref="OAuthCors"/>.</summary>
public static partial class OAuthEndpoints
{
    /// <summary>Registration metadata is a few hundred bytes; more is not a client.</summary>
    public const int MaxRegistrationBytes = 16 * 1024;

    /// <summary>The category of the flow's log lines (<see cref="LogStep"/>).</summary>
    internal const string LogCategory = "Komogentic.Server.OAuth.Flow";

    /// <summary>A <c>state</c> is the app's own value, echoed back; claude.ai's is far shorter. Longer is refused
    /// rather than stored.</summary>
    public const int MaxStateLength = 1024;

    public static void MapOAuthEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/oauth/register", RegisterAsync).AllowAnonymous().ExcludeFromDescription();
        app.MapGet("/oauth/authorize", AuthorizeAsync).AllowAnonymous().ExcludeFromDescription();
    }

    /// <summary>
    /// The authorisation endpoint. Anonymous, and it never reads the cookie: claude.ai's navigation here is
    /// cross-site, so the <c>SameSite=Strict</c> session cookie isn't sent anyway. It checks the request, stores it for
    /// <see cref="AuthorizationRequests.Lifetime"/> and sends the browser to the consent page, whose own same-site calls
    /// carry the session. Until the redirect URI is known to be the client's own, errors stay on Komogentic's page and
    /// nothing goes to the given URI; after that, protocol errors are redirected to it with <c>error</c>, <c>state</c>
    /// and <c>iss</c> (RFC 6749 §4.1.2.1, RFC 9207). A <c>resource</c> that names no connection is not an error here:
    /// the consent page explains what to do.
    /// </summary>
    private static async Task<IResult> AuthorizeAsync(
        HttpContext http, OAuthClients clients, Connections connections, AuthorizationRequests requests, OAuthLimits limits, IOptions<KomogenticOptions> options,
        TimeProvider time, ILoggerFactory logs, CancellationToken ct)
    {
        http.Response.Headers.CacheControl = "no-store";
        // The URL holds the state and the challenge; whatever page comes next is not told it.
        http.Response.Headers["Referrer-Policy"] = "no-referrer";
        var log = logs.CreateLogger(LogCategory);
        var query = http.Request.Query;

        // One value each (RFC 6749 §3.1); a repeated parameter counts as missing.
        var clientId = One(query, "client_id");
        IResult Unavailable(string outcome)
        {
            LogStep(log, "authorize", outcome, null, HostOf(clientId), null);
            return SeeOther(http, "/consent?error=temporarily_unavailable");
        }

        // Fetching a metadata document is a request to wherever the stranger says: limited per address and per host.
        if (clientId is not null && clients.WouldFetch(clientId) && limits.MetadataFetch(http, new Uri(clientId).IdnHost) is not null) return Unavailable("rate_limited");

        OAuthClient? client;
        try
        {
            client = clientId is null ? null : await clients.ResolveAsync(clientId, ct);
        }
        catch (ClientMetadataUnavailableException)
        {
            return Unavailable("busy");
        }

        if (client is null)
        {
            LogStep(log, "authorize", "unknown_client", null, HostOf(clientId), null);
            return SeeOther(http, "/consent?error=unknown_client");
        }

        var redirectUri = One(query, "redirect_uri");
        if (redirectUri is null || !OAuthClients.RedirectMatches(client, redirectUri))
        {
            LogStep(log, "authorize", "invalid_redirect_uri", null, client.Host, null);
            return SeeOther(http, "/consent?error=invalid_redirect_uri");
        }

        // From here on the redirect URI is the client's own.
        var clientHost = ClientHost(client.ClientId, redirectUri);
        var issuer = OAuthUrls.Origin(http, options.Value.PublicUrl);
        // A state sent twice or too long isn't echoed: which one would the app expect?
        var states = query["state"];
        var stateUsable = states.Count == 0 || states.Count == 1 && states[0]!.Length <= MaxStateLength;
        var state = stateUsable && states.Count == 1 && states[0]!.Length > 0 ? states[0] : null;
        IResult Refuse(string error, string description)
        {
            LogStep(log, "authorize", error, null, clientHost, null);
            return SeeOther(http, Redirect(redirectUri, issuer, state, ("error", error), ("error_description", description)));
        }

        if (!stateUsable) return Refuse("invalid_request", $"state must be sent once, and at most {MaxStateLength} characters long.");
        if (One(query, "response_type") != "code") return Refuse("unsupported_response_type", "Only the authorization code flow (response_type=code) is supported.");
        var challenge = One(query, "code_challenge");
        if (challenge is null || !ChallengeShape().IsMatch(challenge)) return Refuse("invalid_request", "A PKCE code_challenge (S256) is required.");
        if (One(query, "code_challenge_method") != "S256") return Refuse("invalid_request", "Only the S256 code_challenge_method is supported.");

        // RFC 8707: the connection's URL. Missing, sent twice or naming no connection, the consent page explains.
        var resource = One(query, "resource");
        var connectionId = resource is null ? null : OAuthUrls.ConnectionIdOf(issuer, resource);
        if (connectionId is not null && await connections.FindAsync(connectionId, ct) is null) connectionId = null;
        var scopes = (One(query, "scope") ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var readOnly = scopes.Contains(OAuthScopes.Read, StringComparer.Ordinal) && !scopes.Contains(OAuthScopes.Operate, StringComparer.Ordinal);

        var pending = new PendingAuthorisation(
            AuthorizationRequests.NewId(), client.ClientId, redirectUri, state, challenge, resource ?? "", connectionId, readOnly,
            connectionId is null ? AuthorizationRequests.NotAConnection : null, time.GetUtcNow().UtcDateTime + AuthorizationRequests.Lifetime);
        await requests.CreateAsync(pending, ct);
        LogStep(log, "authorize", connectionId is null ? AuthorizationRequests.NotAConnection : "pending", connectionId, clientHost, pending.Id);
        return SeeOther(http, $"/consent?request={pending.Id}");
    }

    /// <summary>
    /// The redirect back to the app: <paramref name="redirectUri"/> (keeping any query it has) with
    /// <paramref name="values"/>, then <c>state</c> if the app sent one and <c>iss</c> (RFC 9207). Only for a redirect
    /// URI already matched against the client's.
    /// </summary>
    internal static string Redirect(string redirectUri, string issuer, string? state, params (string Name, string Value)[] values)
    {
        var query = values.Select(v => new KeyValuePair<string, string?>(v.Name, v.Value)).ToList();
        if (state is not null) query.Add(new("state", state));
        query.Add(new("iss", issuer));
        return QueryHelpers.AddQueryString(redirectUri, query);
    }

    /// <summary>
    /// One line per step of an authorisation, so that a "connected but never used" report can be followed from the
    /// server's side. Ids and hosts only: never a code, token, verifier, challenge, state or metadata document.
    /// </summary>
    internal static void LogStep(ILogger log, string step, string outcome, string? connectionId, string? clientHost, string? requestId) =>
        log.LogInformation(
            "OAuth {Step} {Outcome} for connection {ConnectionId}, client {ClientHost}, request {RequestId}",
            step, outcome, connectionId ?? "-", clientHost ?? "-", requestId ?? "-");

    /// <summary>The single non-empty value of <paramref name="name"/>, or null if it is missing, empty or repeated.</summary>
    private static string? One(IQueryCollection query, string name)
    {
        var values = query[name];
        return values.Count == 1 && !string.IsNullOrEmpty(values[0]) ? values[0] : null;
    }

    /// <summary>For the log, once the redirect URI is trusted: the host of a metadata document's client id, else
    /// (a registered client) the host the redirect goes to.</summary>
    internal static string ClientHost(string clientId, string redirectUri) => HostOf(clientId) ?? new Uri(redirectUri).IdnHost;

    /// <summary>For the log: the host of a client id that is a URL, else nothing (a stranger's string isn't logged).</summary>
    private static string? HostOf(string? clientId) =>
        clientId is not null && Uri.TryCreate(clientId, UriKind.Absolute, out var uri) && uri.Host.Length > 0 ? uri.IdnHost : null;

    /// <summary>A redirect the browser follows with GET; relative to our own origin for our consent page.</summary>
    private static IResult SeeOther(HttpContext http, string location)
    {
        http.Response.Headers.Location = location;
        return TypedResults.StatusCode(StatusCodes.Status303SeeOther);
    }

    /// <summary>An S256 challenge: the base64url of a SHA-256, 43 characters without padding (RFC 7636 §4.2).</summary>
    [GeneratedRegex("^[A-Za-z0-9_-]{43}$")]
    private static partial Regex ChallengeShape();

    /// <summary>
    /// Dynamic client registration (RFC 7591) of a public client, limited per network (<see cref="OAuthLimits"/>).
    /// ChatGPT's web app needs it; the MCP SDK's client asks for <c>client_secret_post</c> and is answered <c>none</c>.
    /// </summary>
    private static async Task<IResult> RegisterAsync(HttpContext http, OAuthClients clients, OAuthLimits limits, TimeProvider time, CancellationToken ct)
    {
        http.Response.Headers.CacheControl = "no-store";
        if (limits.Registration(http) is { } retryAfter)
        {
            ApiErrors.SetRetryAfter(http, retryAfter);
            return Error(StatusCodes.Status429TooManyRequests, "invalid_client_metadata", "Too many registrations from this network; try again later.");
        }

        var body = await ReadBodyAsync(http.Request, MaxRegistrationBytes, ct);
        if (body is null) return Error(StatusCodes.Status413PayloadTooLarge, "invalid_client_metadata", "The request body is too large.");

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 8 });
        }
        catch (JsonException)
        {
            return Error(StatusCodes.Status400BadRequest, "invalid_client_metadata", "The body must be a JSON object.");
        }

        using (document)
        {
            OAuthClient client;
            try
            {
                client = await clients.RegisterAsync(document.RootElement, ct);
            }
            catch (RegistrationException e)
            {
                return Error(StatusCodes.Status400BadRequest, e.Code, e.Message);
            }

            return TypedResults.Json(new JsonObject
            {
                ["client_id"] = client.ClientId,
                ["client_id_issued_at"] = time.GetUtcNow().ToUnixTimeSeconds(),
                ["client_name"] = client.Name,
                ["redirect_uris"] = new JsonArray(client.RedirectUris.Select(u => (JsonNode)JsonValue.Create(u)!).ToArray()),
                ["grant_types"] = new JsonArray("authorization_code", "refresh_token"),
                ["response_types"] = new JsonArray("code"),
                ["token_endpoint_auth_method"] = "none",
            }, statusCode: StatusCodes.Status201Created);
        }
    }

    /// <summary>The whole body, or null if it exceeds <paramref name="limit"/>; read in pieces so a body without Content-Length is capped too.</summary>
    private static async Task<byte[]?> ReadBodyAsync(HttpRequest request, int limit, CancellationToken ct)
    {
        if (request.ContentLength > limit) return null;
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int read;
        while ((read = await request.Body.ReadAsync(chunk, ct)) > 0)
        {
            if (buffer.Length + read > limit) return null;
            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    // RFC 7591 §3.2.2 / RFC 6749 §5.2: {"error", "error_description"}.
    private static IResult Error(int status, string error, string description) =>
        TypedResults.Json(new { error, error_description = description }, statusCode: status);
}
