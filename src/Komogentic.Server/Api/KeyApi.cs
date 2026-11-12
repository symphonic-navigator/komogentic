// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Accounts;
using Komogentic.Server.Auth;
using Komogentic.Server.Komodo;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Komogentic.Server.Api;

public sealed record CreateKeyRequest(string Name, int? ExpiresInDays = null);

/// <summary>A new API key: shown once, in this answer only.</summary>
public sealed record CreatedKeyView(ApiKeyInfo Key, string Secret);

/// <summary>The dashboard's API keys (spec §2, step 4), for the signed-in user only: an agent's own key never manages keys.</summary>
public static class KeyApi
{
    public static void MapKeyApi(this IEndpointRouteBuilder app)
    {
        var keys = app.MapGroup("/api/keys").AddEndpointFilter(ApiErrors.Filter);
        keys.MapGet("", ListAsync);
        keys.MapPost("", CreateAsync);
        keys.MapDelete("/{id}", RevokeAsync);
    }

    private static async Task<Ok<IReadOnlyList<ApiKeyInfo>>> ListAsync(RequestCaller caller, ApiKeys keys, CancellationToken ct) =>
        TypedResults.Ok(await keys.ListAsync(Session(caller).User.Id, ct));

    private static async Task<Created<CreatedKeyView>> CreateAsync(CreateKeyRequest body, RequestCaller caller, ApiKeys keys, CancellationToken ct)
    {
        var (user, jwt) = Session(caller);
        var (info, secret) = await keys.CreateAsync(user, jwt, body.Name, body.ExpiresInDays, ct);
        return TypedResults.Created($"/api/keys/{info.Id}", new CreatedKeyView(info, secret));
    }

    private static async Task<Results<NoContent, JsonHttpResult<ApiError>>> RevokeAsync(string id, RequestCaller caller, ApiKeys keys, CancellationToken ct)
    {
        var (user, jwt) = Session(caller);
        return await keys.RevokeAsync(user, jwt, id, ct)
            ? TypedResults.NoContent()
            : TypedResults.Json(new ApiError("You have no such API key, or it is revoked already."), statusCode: StatusCodes.Status404NotFound);
    }

    /// <summary>The session's user and JWT. CallerMiddleware gives <c>/api</c> nothing but sessions; this holds if that changes.</summary>
    private static (KomodoUser User, KomodoAuth.Jwt Jwt) Session(RequestCaller caller) =>
        caller is { Kind: CallerKind.Session, Komodo: KomodoAuth.Jwt jwt }
            ? (caller.User, jwt)
            : throw new ApiException(StatusCodes.Status401Unauthorized, CallerMiddleware.SignInSentence);
}
