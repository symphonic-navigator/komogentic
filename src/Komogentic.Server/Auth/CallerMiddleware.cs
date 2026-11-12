// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Accounts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Routing.Patterns;

namespace Komogentic.Server.Auth;

/// <summary>
/// Resolves every request that needs one to a <see cref="RequestCaller"/> (spec §6, "Caller per request"):
/// <list type="bullet">
/// <item>under <c>/api</c>, only the session cookie <see cref="SessionCookie"/>;</item>
/// <item>under <c>/mcp</c>, only an API key (<see cref="ApiKeyCallerAsync"/>);</item>
/// <item>on a connection's URL <c>/mcp/c/{id}</c>, only that connection's access tokens (<see cref="ConnectionCallerAsync"/>).</item>
/// </list>
/// Which requests need one fails closed: every matched endpoint unless it is marked <c>AllowAnonymous()</c>
/// (<c>/healthz</c>, discovery, the OAuth endpoints, <c>POST /api/session</c>), and every path under <c>/api</c> or
/// <c>/mcp</c> (case-insensitively, as routing matches literal segments), also without an endpoint, unless an
/// anonymous endpoint is mapped there itself: an anonymous fallback (the web app's) doesn't count. Runs after routing
/// and before any endpoint; never logs a key, a token or a cookie.
/// </summary>
public sealed class CallerMiddleware(RequestDelegate next, Sessions sessions, ApiKeys apiKeys, WrongKeyLimiter wrongKeys)
{
    public const string SessionCookie = "kgt_session";

    /// <summary>What <c>/api</c> answers, with a 401, a request without a session: also a session ended meanwhile.</summary>
    internal const string SignInSentence = "Sign in with your Komodo username and password.";

    private const string BearerScheme = "Bearer ";

    private static readonly string[] GuardedPrefixes = ["mcp", "api"];

    public async Task InvokeAsync(HttpContext context)
    {
        if (!NeedsCaller(context))
        {
            await next(context);
            return;
        }

        RequestCaller? caller;
        if (IsUnder(context, "/api")) caller = await SessionCallerAsync(context);
        else if (ConnectionIdSegment(context) is { } id) caller = await ConnectionCallerAsync(context, id);
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
        context.Request.Cookies.TryGetValue(SessionCookie, out var secret)
        && await sessions.ResolveAsync(secret, context.RequestAborted) is { } session
            ? RequestCaller.ForSession(session.User, session.Jwt, session.ExpiresAt)
            : null;

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
        try
        {
            key = await apiKeys.ResolveAsync(header[BearerScheme.Length..].Trim(), context.RequestAborted);
        }
        catch
        {
            // MongoDB unreachable or the request aborted: not a wrong key.
            wrongKeys.Release(ip);
            throw;
        }

        if (key is null)
        {
            wrongKeys.Failed(ip);
            return (null, null);
        }

        wrongKeys.Release(ip);
        return (RequestCaller.ForApiKey(key), null);
    }

    /// <summary>A connection's URL: that connection's access tokens only (Task 8a). Until then nothing opens it, and an
    /// unknown id is a 401 like a known one.</summary>
    private static Task<RequestCaller?> ConnectionCallerAsync(HttpContext context, string connectionId) => Task.FromResult<RequestCaller?>(null);

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
