// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Text.Json.Nodes;
using Komogentic.Server.Accounts;
using Microsoft.Extensions.Options;

namespace Komogentic.Server.OAuth;

/// <summary>
/// The metadata an app finds from a connection's URL: RFC 9728 protected resource metadata, named by the 401
/// challenge, and RFC 8414 authorisation server metadata on the origin. Both are anonymous and cacheable. There is
/// deliberately none for the plain <c>/mcp</c> URL or the origin as a resource, and no OpenID document.
/// </summary>
public static class Discovery
{
    private const string CacheControl = "public, max-age=300";

    public static void MapDiscovery(this IEndpointRouteBuilder app)
    {
        app.MapGet(OAuthUrls.ResourceMetadataPrefix + "/mcp/c/{id}", ResourceMetadataAsync).AllowAnonymous().ExcludeFromDescription();
        app.MapGet("/.well-known/oauth-authorization-server", AuthorizationServerMetadata).AllowAnonymous().ExcludeFromDescription();
    }

    private static async Task<IResult> ResourceMetadataAsync(string id, HttpContext http, Connections connections, IOptions<KomogenticOptions> options, CancellationToken ct)
    {
        if (!OAuthUrls.IsConnectionId(id) || await connections.FindAsync(id, ct) is null) return NotFound();
        var origin = OAuthUrls.Origin(http, options.Value.PublicUrl);
        // The form it was asked for: a client compares the resource with the URL it started from.
        var resource = OAuthUrls.Resource(origin, id) + (http.Request.Path.Value!.EndsWith('/') ? "/" : "");
        http.Response.Headers.CacheControl = CacheControl;
        return TypedResults.Json(new JsonObject
        {
            ["resource"] = resource,
            ["authorization_servers"] = new JsonArray(origin),
            ["bearer_methods_supported"] = new JsonArray("header"),
            ["scopes_supported"] = Scopes(),
            ["resource_name"] = "Komogentic",
        });
    }

    private static IResult AuthorizationServerMetadata(HttpContext http, IOptions<KomogenticOptions> options)
    {
        var origin = OAuthUrls.Origin(http, options.Value.PublicUrl);
        http.Response.Headers.CacheControl = CacheControl;
        return TypedResults.Json(new JsonObject
        {
            ["issuer"] = origin,
            ["authorization_endpoint"] = origin + "/oauth/authorize",
            ["token_endpoint"] = origin + "/oauth/token",
            ["registration_endpoint"] = origin + "/oauth/register",
            ["revocation_endpoint"] = origin + "/oauth/revoke",
            ["response_types_supported"] = new JsonArray("code"),
            ["grant_types_supported"] = new JsonArray("authorization_code", "refresh_token"),
            ["code_challenge_methods_supported"] = new JsonArray("S256"),
            ["token_endpoint_auth_methods_supported"] = new JsonArray("none"),
            ["revocation_endpoint_auth_methods_supported"] = new JsonArray("none"),
            ["scopes_supported"] = Scopes(),
            ["client_id_metadata_document_supported"] = true,
            ["authorization_response_iss_parameter_supported"] = true,
        });
    }

    private static JsonArray Scopes() => new(OAuthScopes.Supported.Select(s => (JsonNode)JsonValue.Create(s)!).ToArray());

    internal static IResult NotFound() => TypedResults.Json(new { error = "Not found." }, statusCode: StatusCodes.Status404NotFound);
}

/// <summary>
/// CORS for the documents and endpoints a browser-based client (the Inspector's web UI) calls: any
/// origin, no credentials. Not on <c>/mcp/c/{id}</c> (the Inspector reaches it through its proxy) nor on
/// <c>/oauth/authorize</c>. A preflight is answered here, before any check of a caller.
/// </summary>
internal static class OAuthCors
{
    private static readonly string[] Paths =
    [
        OAuthUrls.ResourceMetadataPrefix, "/.well-known/oauth-authorization-server", "/oauth/token", "/oauth/register", "/oauth/revoke",
    ];

    public static IApplicationBuilder UseOAuthCors(this IApplicationBuilder app) => app.Use(async (context, next) =>
    {
        if (!Paths.Any(p => context.Request.Path.StartsWithSegments(p, StringComparison.OrdinalIgnoreCase)))
        {
            await next(context);
            return;
        }

        var headers = context.Response.Headers;
        headers.AccessControlAllowOrigin = "*";
        headers.AccessControlAllowMethods = "GET, POST, OPTIONS";
        headers.AccessControlAllowHeaders = "Content-Type, Authorization, MCP-Protocol-Version";
        headers.AccessControlMaxAge = "600";
        if (HttpMethods.IsOptions(context.Request.Method))
        {
            context.Response.StatusCode = StatusCodes.Status204NoContent;
            return;
        }

        await next(context);
    });
}
