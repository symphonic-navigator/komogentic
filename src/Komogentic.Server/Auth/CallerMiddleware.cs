// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Accounts;
using Komogentic.Server.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.Options;

namespace Komogentic.Server.Auth;

/// <summary>
/// Resolves every request that needs one to a <see cref="RequestCaller"/> (spec §6, "Caller per request"):
/// <list type="bullet">
/// <item>under <c>/api</c>, only the session cookie <see cref="SessionCookie"/>;</item>
/// <item>under <c>/mcp</c>, only an API key (<see cref="ApiKeyCallerAsync"/>);</item>
/// <item>on a connection's URL <c>/mcp/c/{id}</c>, only that connection's access tokens (<see cref="ConnectionUrlAsync"/>), and an unknown id is a 404.</item>
/// </list>
/// Which requests need one fails closed: every matched endpoint unless it is marked <c>AllowAnonymous()</c>
/// (<c>/healthz</c>, discovery, the OAuth endpoints, <c>POST /api/session</c>), and every path under <c>/api</c> or
/// <c>/mcp</c> (case-insensitively, as routing matches literal segments), also without an endpoint, unless an
/// anonymous endpoint is mapped there itself: an anonymous fallback (the web app's) doesn't count. Runs after routing
/// and before any endpoint; never logs a key, a token or a cookie.
/// </summary>
public sealed class CallerMiddleware(
    RequestDelegate next, IOptions<KomogenticOptions> options, Sessions sessions, ApiKeys apiKeys, Connections connections, OAuthTokens tokens, WrongKeyLimiter wrongKeys)
{
    public const string SessionCookie = "kgt_session";

    /// <summary>What <c>/api</c> answers, with a 401, a request without a session: also a session ended meanwhile.</summary>
    internal const string SignInSentence = "Sign in with your Komodo username and password.";

    private const string BearerScheme = "Bearer ";

    private static readonly string[] GuardedPrefixes = ["mcp", "api"];

    public async Task InvokeAsync(HttpContext context)
    {
        // Everything under /mcp/c is a connection's, /mcp/c and /mcp/c/ without an id too: never the API keys'.
        if (IsUnder(context, "/mcp/c"))
        {
            await ConnectionUrlAsync(context, ConnectionIdSegment(context) ?? "");
            return;
        }

        if (!NeedsCaller(context))
        {
            await next(context);
            return;
        }

        RequestCaller? caller;
        if (IsUnder(context, "/api")) caller = await SessionCallerAsync(context);
        else
        {
            (caller, var retryAfter) = await ApiKeyCallerAsync(context);
            if (retryAfter is { } wait)
            {
                await TooManyAsync(context, wait);
                return;
            }
        }

        if (caller is null)
        {
            await UnauthorisedAsync(context);
            return;
        }

        context.Features.Set(caller);
        await next(context);
    }

    /// <summary>
    /// The session of the cookie. Only the dashboard's API takes it: a cookie on <c>/mcp</c> would let a page on a
    /// sibling subdomain (same site, so <c>SameSite=Strict</c> doesn't stop it) post a blind no-cors tool call with the
    /// user's session. A bearer header is not read here.
    /// </summary>
    private async Task<RequestCaller?> SessionCallerAsync(HttpContext context) =>
        SessionCookies(context) == 1
        && context.Request.Cookies.TryGetValue(SessionCookie, out var secret)
        && await sessions.ResolveAsync(secret, context.RequestAborted) is { } session
            ? RequestCaller.ForSession(session.User, session.Jwt, session.ExpiresAt)
            : null;

    /// <summary>
    /// How many <see cref="SessionCookie"/> cookies the request carries. More than one is refused: a sibling subdomain
    /// can set one of that name for the parent domain ("cookie tossing"), and which of the two a parser keeps is not
    /// the user's choice. Counted case-insensitively, as <c>Request.Cookies</c> looks them up.
    /// </summary>
    private static int SessionCookies(HttpContext context)
    {
        var count = 0;
        foreach (var header in context.Request.Headers.Cookie)
        {
            foreach (var pair in (header ?? "").Split(';'))
            {
                var name = pair.Split('=', 2)[0].Trim();
                if (name.Equals(SessionCookie, StringComparison.OrdinalIgnoreCase)) count++;
            }
        }

        return count;
    }

    /// <summary>
    /// Plain <c>/mcp</c>: an API key as <c>Authorization: Bearer kgt_…</c>, nothing else (no cookie: see
    /// <see cref="SessionCallerAsync"/>). Every bearer is checked under the <see cref="WrongKeyLimiter"/>, and one that
    /// doesn't open uses up a permit, so that keys can't be guessed; with the permits used up, every bearer from that
    /// address is refused (the wait is answered). A revoked, expired or dead key is refused here, before any Komodo call.
    /// </summary>
    private async Task<(RequestCaller? Caller, TimeSpan? RetryAfter)> ApiKeyCallerAsync(HttpContext context)
    {
        var header = context.Request.Headers.Authorization.ToString();
        if (!header.StartsWith(BearerScheme, StringComparison.OrdinalIgnoreCase)) return (null, null);

        var ip = WrongKeyLimiter.Partition(context.Connection.RemoteIpAddress);
        if (wrongKeys.TryReserve(ip) is { } retryAfter) return (null, retryAfter);
        ResolvedApiKey? key;
        bool known;
        try
        {
            (key, known) = await apiKeys.ResolveAsync(header[BearerScheme.Length..].Trim(), context.RequestAborted);
        }
        catch
        {
            // MongoDB unreachable or the request aborted: not a wrong key.
            wrongKeys.Release(ip);
            throw;
        }

        if (key is null)
        {
            // A key that exists but no longer opens (revoked, expired, dead) is an agent behind the times, not a guess:
            // counting it would let one stale agent lock every valid key of its address out.
            if (known) wrongKeys.Release(ip);
            else wrongKeys.Failed(ip);
            return (null, null);
        }

        wrongKeys.Release(ip);
        return (RequestCaller.ForApiKey(key), null);
    }

    /// <summary>
    /// A connection's own URL takes only its access tokens (spec §5): API keys and the cookie are not resolved here, so a
    /// credential for <c>/mcp</c> or <c>/api</c> opens nothing on it, and an access token is resolved nowhere else. An id
    /// that is no connection's is a 404, like its metadata URL; a known one, in any state, answers a request without a
    /// valid token with a 401 and the challenge that leads an app to the metadata. An access token is looked up under
    /// the wrong-key limit; one that is known but no longer valid here (expired, another connection's, revoked
    /// meanwhile) isn't a guess and gives its permit back, an unknown one uses it up. Any other bearer is refused
    /// without a lookup.
    /// </summary>
    private async Task ConnectionUrlAsync(HttpContext context, string id)
    {
        if (!OAuthUrls.IsConnectionId(id) || await connections.FindAsync(id, context.RequestAborted) is null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsJsonAsync(new Api.ApiError("Not found."));
            return;
        }

        var origin = OAuthUrls.Origin(context, options.Value.PublicUrl);
        var header = context.Request.Headers.Authorization.ToString();
        var bearer = header.StartsWith(BearerScheme, StringComparison.OrdinalIgnoreCase) ? header[BearerScheme.Length..].Trim() : null;
        if (bearer is not null && bearer.StartsWith(OAuthTokens.AccessPrefix, StringComparison.Ordinal))
        {
            var ip = WrongKeyLimiter.Partition(context.Connection.RemoteIpAddress);
            if (wrongKeys.TryReserve(ip) is { } retryAfter)
            {
                await TooManyAsync(context, retryAfter);
                return;
            }

            AccessResolution resolution;
            try
            {
                resolution = await tokens.ResolveAccessAsync(bearer, id, OAuthUrls.Resource(origin, id), context.RequestAborted);
            }
            catch
            {
                // MongoDB unreachable or the request aborted: not a wrong key.
                wrongKeys.Release(ip);
                throw;
            }

            if (resolution.Known) wrongKeys.Release(ip);
            else wrongKeys.Failed(ip);
            if (resolution.Connection is { } connection)
            {
                context.Features.Set(RequestCaller.ForConnection(connection));
                await next(context);
                return;
            }
        }

        var challenge = $"Bearer resource_metadata=\"{OAuthUrls.ResourceMetadata(origin, id)}\", scope=\"{OAuthScopes.Challenge}\"";
        if (bearer is not null) challenge += ", error=\"invalid_token\"";
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.WWWAuthenticate = challenge;
    }

    /// <summary>The third segment of <c>/mcp/c/{id}…</c> (the prefix case-insensitive, as routing is), else null.</summary>
    private static string? ConnectionIdSegment(HttpContext context)
    {
        if (!context.Request.Path.StartsWithSegments("/mcp/c", StringComparison.OrdinalIgnoreCase, out var rest)) return null;
        var segments = rest.Value!.Split('/', 3, StringSplitOptions.RemoveEmptyEntries);
        return segments.Length == 0 ? null : segments[0];
    }

    private static bool NeedsCaller(HttpContext context)
    {
        var endpoint = context.GetEndpoint();
        var anonymous = endpoint?.Metadata.GetMetadata<IAllowAnonymous>() is not null;
        foreach (var prefix in GuardedPrefixes)
        {
            // Under /mcp and /api only an endpoint mapped there may be anonymous. An anonymous fallback (the web
            // app's MapFallbackToFile) matches unmapped /api and /mcp paths too, and must not answer them.
            if (IsUnder(context, "/" + prefix)) return !(anonymous && IsMappedUnder(endpoint!, prefix));
        }

        return endpoint is not null && !anonymous;
    }

    /// <summary>A route of its own under <paramref name="prefix"/>: its first segment is that literal, and it
    /// isn't a fallback (MapFallback gives its endpoints the last order, int.MaxValue).</summary>
    private static bool IsMappedUnder(Endpoint endpoint, string prefix) =>
        endpoint is RouteEndpoint { Order: < int.MaxValue } route
        && route.RoutePattern.PathSegments is [{ IsSimple: true, Parts: [RoutePatternLiteralPart literal] }, ..]
        && literal.Content.Equals(prefix, StringComparison.OrdinalIgnoreCase);

    private static bool IsUnder(HttpContext context, string prefix) =>
        context.Request.Path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase);

    private static Task UnauthorisedAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        if (IsUnder(context, "/api")) return context.Response.WriteAsJsonAsync(new Api.ApiError(SignInSentence));
        context.Response.Headers.WWWAuthenticate = "Bearer";
        return Task.CompletedTask;
    }

    /// <summary>Only <c>/mcp</c> reaches this; MCP clients read the status and <c>Retry-After</c>, not a body.</summary>
    private static Task TooManyAsync(HttpContext context, TimeSpan retryAfter)
    {
        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        Api.ApiErrors.SetRetryAfter(context, retryAfter);
        return Task.CompletedTask;
    }
}
