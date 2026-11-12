// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using System.Text.Json.Nodes;
using Komogentic.Server.Accounts;
using Komogentic.Server.OAuth;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace Komogentic.Server.Tests.OAuth;

/// <summary>A connection's protected resource metadata and the authorisation server's metadata (RFC 9728, RFC 8414).</summary>
[Collection("app")]
public sealed class DiscoveryTests(AppFactory app)
{
    private const string Origin = AppFactory.PublicUrl;

    private static readonly KomodoUser Anna = new("u-anna", "anna");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private WebApplicationFactory<Program> Api => app.PublicApi;

    private async Task<string> ConnectionAsync() =>
        (await Api.Services.GetRequiredService<Connections>().CreateAsync(Anna, "claude " + Guid.NewGuid().ToString("N")[..8], null, Ct)).Id;

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string? origin = null)
    {
        using var request = new HttpRequestMessage(method, path);
        if (origin is not null) request.Headers.Add("Origin", origin);
        request.Headers.Add("X-Forwarded-For", $"198.21.{Random.Shared.Next(256)}.{Random.Shared.Next(1, 255)}");
        using var client = Api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri("https://localhost") });
        return await client.SendAsync(request, Ct);
    }

    private static async Task<JsonNode> JsonAsync(HttpResponseMessage response) => JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;

    [Fact]
    public async Task Plain_mcp_points_nowhere()
    {
        using var root = await SendAsync(HttpMethod.Get, "/.well-known/oauth-protected-resource");
        using var plain = await SendAsync(HttpMethod.Get, "/.well-known/oauth-protected-resource/mcp");
        using var openid = await SendAsync(HttpMethod.Get, "/.well-known/openid-configuration");

        Assert.Equal(HttpStatusCode.NotFound, root.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, plain.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, openid.StatusCode);
    }

    [Fact]
    public async Task Protected_resource_metadata_names_the_connection()
    {
        var id = await ConnectionAsync();

        using var response = await SendAsync(HttpMethod.Get, $"/.well-known/oauth-protected-resource/mcp/c/{id}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("public, max-age=300", response.Headers.CacheControl!.ToString());
        var json = await JsonAsync(response);
        Assert.Equal($"{Origin}/mcp/c/{id}", json["resource"]!.GetValue<string>());
        Assert.Equal([Origin], json["authorization_servers"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Equal(["header"], json["bearer_methods_supported"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Equal(["komodo:read", "komodo:operate"], json["scopes_supported"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Equal("Komogentic", json["resource_name"]!.GetValue<string>());
    }

    [Fact]
    public async Task Unknown_ids_have_no_metadata()
    {
        const string random = "abcdefghijklmnop";

        using var metadata = await SendAsync(HttpMethod.Get, $"/.well-known/oauth-protected-resource/mcp/c/{random}");
        using var odd = await SendAsync(HttpMethod.Get, "/.well-known/oauth-protected-resource/mcp/c/not-an-id");

        Assert.Equal(HttpStatusCode.NotFound, metadata.StatusCode);
        Assert.Equal("Not found.", (await JsonAsync(metadata))["error"]!.GetValue<string>());
        Assert.Equal(HttpStatusCode.NotFound, odd.StatusCode);
    }

    [Fact]
    public async Task Trailing_slash_and_host_case_reach_the_same_connection()
    {
        var id = await ConnectionAsync();

        using var slash = await SendAsync(HttpMethod.Get, $"/.well-known/oauth-protected-resource/mcp/c/{id}/");

        Assert.Equal(HttpStatusCode.OK, slash.StatusCode);
        Assert.Equal($"{Origin}/mcp/c/{id}/", (await JsonAsync(slash))["resource"]!.GetValue<string>());
        Assert.Equal(id, OAuthUrls.ConnectionIdOf(Origin, $"HTTPS://KOMOGENTIC.TEST:443/mcp/c/{id}/"));
        Assert.Equal(id, OAuthUrls.ConnectionIdOf(Origin, $"https://komogentic.test/mcp/c/{id}"));
        Assert.Null(OAuthUrls.ConnectionIdOf(Origin, $"https://komogentic.test/mcp/c/{id.ToUpperInvariant()}"));
        Assert.Null(OAuthUrls.ConnectionIdOf(Origin, "https://komogentic.test/mcp"));
        Assert.Null(OAuthUrls.ConnectionIdOf(Origin, $"https://other.test/mcp/c/{id}"));
        Assert.Null(OAuthUrls.ConnectionIdOf(Origin, $"http://komogentic.test/mcp/c/{id}"));
        Assert.Null(OAuthUrls.ConnectionIdOf(Origin, $"https://komogentic.test/mcp/c/{id}/more"));
    }

    [Fact]
    public async Task Authorization_server_metadata_is_complete()
    {
        using var response = await SendAsync(HttpMethod.Get, "/.well-known/oauth-authorization-server");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("public, max-age=300", response.Headers.CacheControl!.ToString());
        var json = (await JsonAsync(response)).AsObject();
        var expected = new JsonObject
        {
            ["issuer"] = Origin,
            ["authorization_endpoint"] = Origin + "/oauth/authorize",
            ["token_endpoint"] = Origin + "/oauth/token",
            ["registration_endpoint"] = Origin + "/oauth/register",
            ["revocation_endpoint"] = Origin + "/oauth/revoke",
            ["response_types_supported"] = new JsonArray("code"),
            ["grant_types_supported"] = new JsonArray("authorization_code", "refresh_token"),
            ["code_challenge_methods_supported"] = new JsonArray("S256"),
            ["token_endpoint_auth_methods_supported"] = new JsonArray("none"),
            ["revocation_endpoint_auth_methods_supported"] = new JsonArray("none"),
            ["scopes_supported"] = new JsonArray("komodo:read", "komodo:operate"),
            ["client_id_metadata_document_supported"] = true,
            ["authorization_response_iss_parameter_supported"] = true,
        };
        Assert.True(JsonNode.DeepEquals(expected, json), json.ToJsonString());
        Assert.DoesNotContain("offline_access", json.ToJsonString());
    }

    [Fact]
    public async Task Oauth_documents_allow_cross_origin_reads()
    {
        var id = await ConnectionAsync();

        using var preflight = await SendAsync(HttpMethod.Options, "/oauth/token", origin: "http://localhost:6274");
        using var document = await SendAsync(HttpMethod.Get, "/.well-known/oauth-authorization-server", origin: "http://localhost:6274");
        using var connection = await SendAsync(HttpMethod.Options, $"/mcp/c/{id}", origin: "http://localhost:6274");
        using var authorize = await SendAsync(HttpMethod.Options, "/oauth/authorize", origin: "http://localhost:6274");

        Assert.Equal(HttpStatusCode.NoContent, preflight.StatusCode);
        Assert.Equal("*", preflight.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.Equal("GET, POST, OPTIONS", preflight.Headers.GetValues("Access-Control-Allow-Methods").Single());
        Assert.Equal("Content-Type, Authorization, MCP-Protocol-Version", preflight.Headers.GetValues("Access-Control-Allow-Headers").Single());
        Assert.Equal("600", preflight.Headers.GetValues("Access-Control-Max-Age").Single());
        Assert.Equal("*", document.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.False(connection.Headers.Contains("Access-Control-Allow-Origin"));
        Assert.False(authorize.Headers.Contains("Access-Control-Allow-Origin"));
    }
}
