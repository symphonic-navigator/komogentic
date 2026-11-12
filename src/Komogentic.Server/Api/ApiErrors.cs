// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Globalization;
using Komogentic.Server.Accounts;
using Komogentic.Server.Auth;
using Komogentic.Server.Komodo;

namespace Komogentic.Server.Api;

/// <summary>Every error the dashboard's API returns: one sentence for a person to read.</summary>
public sealed record ApiError(string Error);

/// <summary>Thrown by a handler to answer with <see cref="Status"/> and an <see cref="ApiError"/>; turned into
/// the response by <see cref="ApiErrors.Filter"/>, so handlers can keep their typed success results.</summary>
public sealed class ApiException(int status, string message, TimeSpan? retryAfter = null) : Exception(message)
{
    public int Status { get; } = status;

    public TimeSpan? RetryAfter { get; } = retryAfter;
}

public static class ApiErrors
{
    /// <summary>What a session whose JWT Komodo no longer accepts is told; the session is ended with it.</summary>
    public const string KomodoSignInEnded = "Your Komodo sign-in has ended; sign in again.";

    public static ApiException BadRequest(string message) => new(StatusCodes.Status400BadRequest, message);

    public static ApiException TooMany(TimeSpan retryAfter, string message = "Too many attempts; try again in a minute.") =>
        new(StatusCodes.Status429TooManyRequests, message, retryAfter);

    /// <summary>
    /// The endpoint filter of every <c>/api</c> group: the refusals handlers and services throw become statuses. Only
    /// these: anything else is a fault and stays a 500, without its message. A Komodo call with the session's JWT that
    /// Komodo refuses as unauthorised (the JWT expired or was invalidated early) ends the session: the dashboard shows
    /// sign-in again. It never marks a credential.
    /// </summary>
    public static async ValueTask<object?> Filter(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            return await next(context);
        }
        catch (ApiException e)
        {
            if (e.RetryAfter is { } retryAfter) SetRetryAfter(context.HttpContext, retryAfter);
            return Result(e.Status, e.Message);
        }
        catch (KomodoException e) when (e.Kind == KomodoErrorKind.Unauthorized
            && context.HttpContext.Features.Get<RequestCaller>() is { Kind: CallerKind.Session, Komodo: KomodoAuth.Jwt })
        {
            await SessionApi.EndSessionAsync(context.HttpContext, CancellationToken.None);
            return Result(StatusCodes.Status401Unauthorized, KomodoSignInEnded);
        }
        catch (ConnectionNameTakenException e)
        {
            return Result(StatusCodes.Status409Conflict, e.Message);
        }
        // Exactly ArgumentException: the services throw it for input they refuse, with a sentence meant for the
        // user. Its subclasses (ArgumentNullException, ...) come from bugs and say nothing a user could act on.
        catch (ArgumentException e) when (e.GetType() == typeof(ArgumentException))
        {
            return Result(StatusCodes.Status400BadRequest, Sentence(e));
        }
    }

    public static IResult Result(int status, string message) => TypedResults.Json(new ApiError(message), statusCode: status);

    /// <summary>Whole seconds, at least one.</summary>
    public static void SetRetryAfter(HttpContext context, TimeSpan retryAfter) =>
        context.Response.Headers.RetryAfter = ((int)Math.Ceiling(Math.Max(1, retryAfter.TotalSeconds))).ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// A body that can't be bound (not JSON, a required field missing or null, no body at all) is refused by
    /// minimal APIs before any filter runs; <c>ThrowOnBadRequest</c> makes it an exception, caught here, so
    /// <c>/api</c> answers it in its own shape. Elsewhere (MCP, OAuth) only the status is kept.
    /// </summary>
    public static async Task BadRequestsAsync(HttpContext context, RequestDelegate next)
    {
        try
        {
            await next(context);
        }
        catch (BadHttpRequestException e) when (!context.Response.HasStarted)
        {
            context.Response.Clear();
            context.Response.StatusCode = e.StatusCode;
            if (context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase))
            {
                // Not e.Message: it names .NET parameter types, which tell a client nothing useful.
                await context.Response.WriteAsJsonAsync(new ApiError(e.StatusCode switch
                {
                    StatusCodes.Status415UnsupportedMediaType => "Send the body as JSON (Content-Type: application/json).",
                    StatusCodes.Status413PayloadTooLarge => "The request body is too large.",
                    _ => "The request body is missing, not JSON, or lacks a required field.",
                }));
            }
        }
    }

    /// <summary>The exception's message without the " (Parameter 'x')" that .NET appends.</summary>
    private static string Sentence(ArgumentException e) =>
        e.ParamName is { } name ? e.Message.Replace($" (Parameter '{name}')", "", StringComparison.Ordinal) : e.Message;
}
