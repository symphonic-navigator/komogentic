// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Globalization;
using Komogentic.Server.Accounts;
using Komogentic.Server.Auth;
using Komogentic.Server.Komodo;

namespace Komogentic.Server.Api;

/// <summary>Every error the dashboard's API returns: one sentence for a person to read; <c>Type</c> for the few the web
/// app answers itself (<see cref="ApiErrors.OtherAccount"/>), left out otherwise.</summary>
public sealed record ApiError(
    string Error,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? Type = null);

/// <summary>Thrown by a handler to answer with <see cref="Status"/> and an <see cref="ApiError"/>; turned into
/// the response by <see cref="ApiErrors.Filter"/>, so handlers can keep their typed success results.</summary>
public sealed class ApiException(int status, string message, TimeSpan? retryAfter = null, string? type = null) : Exception(message)
{
    public int Status { get; } = status;

    public TimeSpan? RetryAfter { get; } = retryAfter;

    public string? Type { get; } = type;
}

public static class ApiErrors
{
    /// <summary>What a session whose JWT Komodo no longer accepts is told; the session is ended with it.</summary>
    public const string KomodoSignInEnded = "Your Komodo sign-in has ended; sign in again.";

    /// <summary>What the dashboard is told when Komodo did not answer.</summary>
    public const string KomodoUnreachable = "Komodo could not be reached; try again in a minute.";

    /// <summary>The <c>type</c> of a 404 for a request of another account's connection: the consent page offers to sign out.</summary>
    public const string OtherAccount = "other-account";

    private static readonly TimeSpan KomodoRetryAfter = TimeSpan.FromMinutes(1);

    public static ApiException NotFound(string message, string? type = null) => new(StatusCodes.Status404NotFound, message, type: type);

    public static ApiException BadRequest(string message) => new(StatusCodes.Status400BadRequest, message);

    public static ApiException TooMany(TimeSpan retryAfter, string message = "Too many attempts; try again in a minute.") =>
        new(StatusCodes.Status429TooManyRequests, message, retryAfter);

    /// <summary>
    /// The endpoint filter of every <c>/api</c> group: the refusals handlers and services throw become statuses. Only
    /// these: anything else is a fault and stays a 500, without its message. A Komodo call with the session's JWT that
    /// Komodo refuses as unauthorised (the JWT expired or was invalidated early) ends the session: the dashboard shows
    /// sign-in again. It never marks a credential. Komodo's other failures: 503 when it did not answer, 429 when its
    /// rate limiter refuses Komogentic, else 502 with Komodo's own message (which never holds a credential).
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
            return Result(e.Status, e.Message, e.Type);
        }
        catch (KomodoException e) when (e.Kind == KomodoErrorKind.Unauthorized
            && context.HttpContext.Features.Get<RequestCaller>() is { Kind: CallerKind.Session, Komodo: KomodoAuth.Jwt })
        {
            await SessionApi.EndSessionAsync(context.HttpContext, CancellationToken.None);
            return Result(StatusCodes.Status401Unauthorized, KomodoSignInEnded);
        }
        catch (KomodoException e) when (e.Kind != KomodoErrorKind.Unauthorized)
        {
            if (e.Kind == KomodoErrorKind.Unreachable) return Result(StatusCodes.Status503ServiceUnavailable, KomodoUnreachable);
            if (e.Kind != KomodoErrorKind.RateLimited) return Result(StatusCodes.Status502BadGateway, $"Komodo refused this: {e.Message}");
            SetRetryAfter(context.HttpContext, KomodoRetryAfter);
            return Result(StatusCodes.Status429TooManyRequests, e.Message);
        }
        catch (CredentialNameTakenException e)
        {
            return Result(StatusCodes.Status409Conflict, e.Message);
        }
        // The services' refusals of input, with a sentence meant for the user. An ArgumentException comes from a bug
        // and says nothing a user could act on: it stays a 500, without its message.
        catch (UserInputException e)
        {
            return Result(StatusCodes.Status400BadRequest, e.Message);
        }
    }

    public static IResult Result(int status, string message, string? type = null) => TypedResults.Json(new ApiError(message, type), statusCode: status);

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
}
