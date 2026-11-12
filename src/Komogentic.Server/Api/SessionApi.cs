// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Accounts;
using Komogentic.Server.Auth;
using Komogentic.Server.Komodo;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Komogentic.Server.Api;

public sealed record SignInRequest(string Username, string Password)
{
    public override string ToString() => $"SignInRequest {{ Username = {Username} }}";
}

public sealed record SessionView(string Username, DateTime ExpiresAt);

/// <summary>
/// Signing in to the dashboard with a Komodo username and password (spec §5): Komodo's local login answers a JWT,
/// which the session keeps, sealed, until it ends. The password goes to Komodo and nowhere else.
/// </summary>
public static class SessionApi
{
    private const string Refused = "Komodo refused this username and password.";
    private const string TwoFactor = "Two-factor sign-in is not supported: sign in with a Komodo user without a second factor.";
    private const string Unreachable = "Komodo could not be reached; try again in a minute.";
    private const string RateLimited = "Komodo is refusing sign-ins for a moment after several failures; try again in a minute.";
    private const string Unreadable = "Komodo's answer to the sign-in could not be read; try again in a minute.";

    /// <summary>Far more than any username or password; more is not a sign-in, and isn't sent to Komodo.</summary>
    private const int MaxLength = 1024;

    private static readonly TimeSpan KomodoRetryAfter = TimeSpan.FromMinutes(1);

    public static void MapSessionApi(this IEndpointRouteBuilder app)
    {
        var open = app.MapGroup("/api").AddEndpointFilter(ApiErrors.Filter).AllowAnonymous();
        open.MapPost("/session", SignInAsync);

        var session = app.MapGroup("/api").AddEndpointFilter(ApiErrors.Filter);
        session.MapGet("/session", Current);
        session.MapDelete("/session", SignOutAsync);
    }

    private static async Task<Ok<SessionView>> SignInAsync(
        SignInRequest body, HttpContext http, KomodoClient komodo, Sessions sessions, PendingDeletions deletions, SignInLimiter limiter, TimeProvider time,
        ILoggerFactory logs, CancellationToken ct)
    {
        var log = logs.CreateLogger(typeof(SessionApi).FullName!);
        if (limiter.Attempt(http, body.Username) is { } retryAfter) throw ApiErrors.TooMany(retryAfter, "Too many sign-in attempts; try again in a minute.");
        if (body.Username.Length is 0 or > MaxLength || body.Password.Length is 0 or > MaxLength)
            throw ApiErrors.BadRequest("Enter your Komodo username and password.");

        LoginResult login;
        try
        {
            login = await komodo.LoginLocalUserAsync(body.Username, body.Password, ct);
        }
        catch (KomodoException e)
        {
            log.LogInformation("Sign-in refused: Komodo answered {Kind} (HTTP {Status})", e.Kind, e.Status);
            throw e.Kind switch
            {
                KomodoErrorKind.Unauthorized => new ApiException(StatusCodes.Status401Unauthorized, Refused),
                KomodoErrorKind.RateLimited => new ApiException(StatusCodes.Status429TooManyRequests, RateLimited, KomodoRetryAfter),
                _ => new ApiException(StatusCodes.Status503ServiceUnavailable, Unreachable),
            };
        }

        if (login.TwoFactor) throw ApiErrors.BadRequest(TwoFactor);
        // Never a session without a user and an end: a JWT whose payload doesn't read, or that has expired already.
        if (login.Jwt is not { } jwt || KomodoJwt.Read(jwt) is not var (userId, expiresAt) || expiresAt <= time.GetUtcNow().UtcDateTime)
        {
            log.LogWarning("Sign-in failed: Komodo's JWT could not be read or has expired already");
            throw new ApiException(StatusCodes.Status503ServiceUnavailable, Unreadable);
        }

        // Signing in again in the same browser replaces its session rather than leaving the old one behind.
        if (http.Request.Cookies.TryGetValue(CallerMiddleware.SessionCookie, out var old)) await sessions.EndAsync(old, ct);

        var user = new KomodoUser(userId, body.Username);
        var secret = await sessions.StartAsync(user, jwt, expiresAt, ct);
        var resolved = await sessions.ResolveAsync(secret, ct) ?? throw new InvalidOperationException("A session just started does not resolve");
        log.LogInformation("User {UserId} signed in", user.Id);

        // Keys of revoked or dead credentials, now that a JWT is at hand. Komodo's failures never fail the sign-in.
        await deletions.DrainAsync(user.Id, new KomodoAuth.Jwt(jwt), ct);

        var options = CookieOptions();
        options.MaxAge = resolved.ExpiresAt - time.GetUtcNow().UtcDateTime;
        http.Response.Cookies.Append(CallerMiddleware.SessionCookie, secret, options);
        return TypedResults.Ok(new SessionView(user.Username, resolved.ExpiresAt));
    }

    private static Ok<SessionView> Current(RequestCaller caller) =>
        TypedResults.Ok(new SessionView(caller.User.Username, caller.ExpiresAt!.Value));

    private static async Task<NoContent> SignOutAsync(HttpContext http, CancellationToken ct)
    {
        await EndSessionAsync(http, ct);
        return TypedResults.NoContent();
    }

    /// <summary>
    /// Ends the session of the request's cookie and clears the cookie: signing out, and a JWT that Komodo refused
    /// (<see cref="ApiErrors.Filter"/>, amendment R14).
    /// </summary>
    internal static async Task EndSessionAsync(HttpContext http, CancellationToken ct)
    {
        if (http.Request.Cookies.TryGetValue(CallerMiddleware.SessionCookie, out var secret))
            await http.RequestServices.GetRequiredService<Sessions>().EndAsync(secret, ct);
        http.Response.Cookies.Delete(CallerMiddleware.SessionCookie, CookieOptions());
    }

    /// <summary>Only under <c>/api</c>, never readable by scripts, never over plain http, never sent cross-site.</summary>
    private static CookieOptions CookieOptions() => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = "/api",
        IsEssential = true,
    };
}
