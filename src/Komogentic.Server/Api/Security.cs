// SPDX-License-Identifier: AGPL-3.0-or-later
namespace Komogentic.Server.Api;

public static class Security
{
    /// <summary>
    /// Only the app's own scripts, styles, images and connections, as in Kumbu² (without what only its PDF viewer
    /// needed). <c>base-uri</c> and <c>form-action</c> don't fall back to <c>default-src</c>: no <c>&lt;base&gt;</c> may
    /// redirect relative URLs, and forms may only post to the app. <c>object-src 'none'</c> is stricter than the
    /// <c>'self'</c> it would inherit: no plug-in content at all.
    /// </summary>
    public const string ContentSecurityPolicy =
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; " +
        "base-uri 'none'; form-action 'self'; object-src 'none'";

    /// <summary>One year, and for the subdomains too; no <c>preload</c>, which can't be undone quickly.</summary>
    public const string StrictTransportSecurity = "max-age=31536000; includeSubDomains";

    private static bool IsLoopbackHost(string host) =>
        host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host is "127.0.0.1" or "[::1]";

    /// <summary>
    /// The security headers, on every response (API, MCP, OAuth, static files and errors alike), and
    /// <c>Cache-Control: no-store</c> on the API's. Added when the response starts, so that a handler clearing the
    /// response doesn't drop them. HSTS when the public URL is https or the request came over https as the app sees it:
    /// behind a trusted proxy that is <c>X-Forwarded-Proto</c> (Program.cs), otherwise the connection itself, except to
    /// a loopback host (as ASP.NET's own UseHsts): pinned there, the browser would force https on every local port for
    /// a year.
    /// </summary>
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app, string? publicUrl)
    {
        var httpsPublicUrl = publicUrl is not null && publicUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        return app.Use((context, next) =>
        {
            context.Response.OnStarting(() =>
            {
                var headers = context.Response.Headers;
                headers.XContentTypeOptions = "nosniff";
                headers.TryAdd("Referrer-Policy", "same-origin"); // unless stricter already, as on /oauth/authorize
                headers.ContentSecurityPolicy = ContentSecurityPolicy;
                if (httpsPublicUrl || (context.Request.IsHttps && !IsLoopbackHost(context.Request.Host.Host))) headers.StrictTransportSecurity = StrictTransportSecurity;
                // API answers are per user, and some will carry a secret shown once (a new API key): no browser or
                // proxy cache may keep them.
                if (context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase)) headers.CacheControl = "no-store";
                return Task.CompletedTask;
            });
            return next(context);
        });
    }

    /// <summary>
    /// Before <see cref="Auth.CallerMiddleware"/>, so that a refused request never resolves (nor keeps alive) a session;
    /// for <c>/api</c>: a state-changing request (not GET, HEAD, OPTIONS),
    /// signed in or anonymous (sign-in itself), needs an <c>Origin</c> equal to <c>Komogentic:PublicUrl</c>'s, else 403;
    /// a missing <c>Origin</c> is refused too (browsers send it on every such request). This is the CSRF check behind
    /// <c>SameSite=Strict</c>, which a page on a sibling subdomain (the same site) gets past. Without a
    /// <c>PublicUrl</c> (development, tests) the request's own scheme and host stand in for it, so only same-origin
    /// pages pass. The consent page posts from <c>/consent</c> on the same origin, so it passes.
    /// </summary>
    public static IApplicationBuilder UseCallerRules(this IApplicationBuilder app, string? publicUrl)
    {
        var expected = OwnOrigin(publicUrl);
        return app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase)
                && !IsSafe(context.Request.Method)
                && !FromOwnPages(context, expected))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new ApiError("This request didn't come from Komogentic's own pages."));
                return;
            }

            await next(context);
        });
    }

    /// <summary>The origin of <c>Komogentic:PublicUrl</c>, which <see cref="FromOwnPages"/> expects; null without one.</summary>
    internal static string? OwnOrigin(string? publicUrl) =>
        string.IsNullOrEmpty(publicUrl) ? null : new Uri(publicUrl).GetLeftPart(UriPartial.Authority);

    /// <summary>Whether the request's <c>Origin</c> is <paramref name="expected"/> (<see cref="OwnOrigin"/>), else, without
    /// one, the request's own scheme and host.</summary>
    internal static bool FromOwnPages(HttpContext context, string? expected) =>
        string.Equals(
            context.Request.Headers.Origin.ToString(), expected ?? $"{context.Request.Scheme}://{context.Request.Host}", StringComparison.OrdinalIgnoreCase);

    private static bool IsSafe(string method) => HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method);
}
