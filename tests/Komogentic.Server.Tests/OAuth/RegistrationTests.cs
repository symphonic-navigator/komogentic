// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Komogentic.Server.OAuth;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Komogentic.Server.Tests.OAuth;

/// <summary>Dynamic client registration (RFC 7591) for public clients, and its limits (spec §5).</summary>
[Collection("app")]
public sealed class RegistrationTests(AppFactory app)
{
    private const string Callback = "http://localhost:6274/oauth/callback";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static string NewAddress() => $"198.22.{Random.Shared.Next(256)}.{Random.Shared.Next(1, 255)}";

    private static async Task<HttpResponseMessage> RegisterAsync(WebApplicationFactory<Program> api, string body, string? address = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth/register")
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        request.Headers.Add("X-Forwarded-For", address ?? NewAddress());
        using var client = api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri("https://localhost") });
        return await client.SendAsync(request, Ct);
    }

    private static string Metadata(string? extra = null, string redirects = $"[\"{Callback}\"]") =>
        $$"""{"client_name":"Inspector","redirect_uris":{{redirects}}{{(extra is null ? "" : "," + extra)}}}""";

    private static async Task<JsonObject> JsonAsync(HttpResponseMessage response) =>
        (JsonObject)JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;

    [Fact]
    public async Task Registers_a_public_client()
    {
        using var response = await RegisterAsync(app.PublicApi, Metadata());

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("*", response.Headers.GetValues("Access-Control-Allow-Origin").Single());
        var body = await JsonAsync(response);
        var id = body["client_id"]!.GetValue<string>();
        Assert.StartsWith(OAuthClients.RegisteredPrefix, id);
        Assert.Equal(OAuthClients.RegisteredPrefix.Length + 22, id.Length);
        Assert.Equal("none", body["token_endpoint_auth_method"]!.GetValue<string>());
        Assert.Equal("Inspector", body["client_name"]!.GetValue<string>());
        Assert.Equal([Callback], body["redirect_uris"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Equal(["authorization_code", "refresh_token"], body["grant_types"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Equal(["code"], body["response_types"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.True(body["client_id_issued_at"]!.GetValue<long>() > 0);
        Assert.Null(body["client_secret"]);

        var client = await app.PublicApi.Services.GetRequiredService<OAuthClients>().ResolveAsync(id, Ct);
        Assert.NotNull(client);
        Assert.False(client.Verified);
        Assert.Equal("localhost", client.Host);
        Assert.Equal("Inspector", client.Name);
        Assert.Equal([Callback], client.RedirectUris);
    }

    [Fact]
    public async Task Every_client_is_registered_as_public_without_a_secret()
    {
        using var absent = await RegisterAsync(app.PublicApi, Metadata());
        Assert.Equal("none", (await JsonAsync(absent))["token_endpoint_auth_method"]!.GetValue<string>());

        // RFC 7591 §3.2.1: a requested secret method is replaced, not refused; the MCP SDK always asks for one.
        using var secret = await RegisterAsync(app.PublicApi, Metadata("\"token_endpoint_auth_method\":\"client_secret_post\""));
        Assert.Equal(HttpStatusCode.Created, secret.StatusCode);
        var body = await JsonAsync(secret);
        Assert.Equal("none", body["token_endpoint_auth_method"]!.GetValue<string>());
        Assert.Null(body["client_secret"]);

        using var malformed = await RegisterAsync(app.PublicApi, Metadata("\"token_endpoint_auth_method\":42"));
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        Assert.Equal("invalid_client_metadata", (await JsonAsync(malformed))["error"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("""["http://example.org/cb"]""")]
    [InlineData("""["/cb"]""")]
    [InlineData("""["https://example.org/cb#frag"]""")]
    [InlineData("""["https://user:pw@example.org/cb"]""")]
    [InlineData("""[42]""")]
    [InlineData("""["https://example.org/cb", "http://example.org/cb"]""")]
    public async Task Refuses_unusable_redirect_uris(string redirects)
    {
        using var response = await RegisterAsync(app.PublicApi, Metadata(redirects: redirects));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await JsonAsync(response);
        Assert.Equal("invalid_redirect_uri", body["error"]!.GetValue<string>());
        Assert.False(string.IsNullOrEmpty(body["error_description"]!.GetValue<string>()));
    }

    [Fact]
    public async Task Refuses_a_missing_redirect_uri_member_and_bodies_that_are_no_object()
    {
        using var missing = await RegisterAsync(app.PublicApi, """{"client_name":"x"}""");
        Assert.Equal("invalid_redirect_uri", (await JsonAsync(missing))["error"]!.GetValue<string>());

        foreach (var body in new[] { "[]", "\"x\"", "not json", "" })
        {
            using var response = await RegisterAsync(app.PublicApi, body);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("invalid_client_metadata", (await JsonAsync(response))["error"]!.GetValue<string>());
        }
    }

    [Fact]
    public async Task Cleans_the_name_that_the_consent_page_will_show()
    {
        using var response = await RegisterAsync(app.PublicApi, Metadata().Replace("Inspector", "  Evil\\u202eApp\\n  "));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("EvilApp", (await JsonAsync(response))["client_name"]!.GetValue<string>());
    }

    [Fact]
    public async Task Limits_registrations_per_network()
    {
        var address = NewAddress();
        for (var i = 0; i < 30; i++)
        {
            using var ok = await RegisterAsync(app.PublicApi, Metadata(), address);
            Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
        }

        using var limited = await RegisterAsync(app.PublicApi, Metadata(), address);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.True(limited.Headers.RetryAfter is not null);
        Assert.Equal("*", limited.Headers.GetValues("Access-Control-Allow-Origin").Single());

        using var other = await RegisterAsync(app.PublicApi, Metadata(), NewAddress());
        Assert.Equal(HttpStatusCode.Created, other.StatusCode);
    }

    [Fact]
    public async Task Unused_registrations_expire_after_a_day()
    {
        // Real "now": the TTL index compares expiresAt with MongoDB's clock, which must not already have passed.
        var fake = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var api = app.PublicApi.WithWebHostBuilder(b => b.ConfigureServices(s =>
        {
            s.RemoveAll<TimeProvider>();
            s.AddSingleton<TimeProvider>(fake);
        }));
        var clients = api.Services.GetRequiredService<OAuthClients>();

        string unused, used;
        using (var first = await RegisterAsync(api, Metadata())) unused = (await JsonAsync(first))["client_id"]!.GetValue<string>();
        using (var second = await RegisterAsync(api, Metadata())) used = (await JsonAsync(second))["client_id"]!.GetValue<string>();
        await clients.MarkAuthorisedAsync(used, Ct);

        Assert.NotNull(await clients.ResolveAsync(unused, Ct));
        fake.Advance(TimeSpan.FromHours(25));

        Assert.Null(await clients.ResolveAsync(unused, Ct));
        Assert.NotNull(await clients.ResolveAsync(used, Ct));
    }

    [Fact]
    public async Task Resolves_nothing_for_unknown_or_malformed_ids()
    {
        var clients = app.PublicApi.Services.GetRequiredService<OAuthClients>();

        Assert.Null(await clients.ResolveAsync(OAuthClients.RegisteredPrefix + "0000000000000000000000", Ct));
        Assert.Null(await clients.ResolveAsync("kgt_client_", Ct));
        Assert.Null(await clients.ResolveAsync("someone", Ct));
    }

    [Fact]
    public async Task Takes_no_body_larger_than_16_KiB()
    {
        var collection = app.Database.GetCollection<BsonDocument>("oauth_clients");
        var before = await collection.CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty, cancellationToken: Ct);
        var padding = new string('a', 17 * 1024);

        using var response = await RegisterAsync(app.PublicApi, Metadata($"\"software_id\":\"{padding}\""));

        Assert.True(response.StatusCode is HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.BadRequest, response.StatusCode.ToString());
        Assert.Equal(before, await collection.CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty, cancellationToken: Ct));
    }

    /// <summary>A request context from <paramref name="address"/>, as the limiter sees one.</summary>
    private static Microsoft.AspNetCore.Http.DefaultHttpContext From(string address) =>
        new() { Connection = { RemoteIpAddress = System.Net.IPAddress.Parse(address) } };

    [Fact]
    public void Token_failures_are_limited_per_client_id_and_network()
    {
        using var limits = new OAuthLimits();
        var here = From("203.0.113.5");
        for (var i = 0; i < 20; i++)
        {
            Assert.Null(limits.TokenReserve(here, "a"));
            limits.TokenFailed(here, "a");
        }

        Assert.NotNull(limits.TokenReserve(here, "a"));
        Assert.Null(limits.TokenReserve(here, "b"));
        limits.TokenRelease(here, "b");
        // The same client id from another network has a budget of its own; the same /64 doesn't.
        Assert.Null(limits.TokenReserve(From("198.51.100.7"), "a"));
        var v6 = From("2001:db8::1");
        for (var i = 0; i < 20; i++)
        {
            limits.TokenReserve(v6, "a");
            limits.TokenFailed(v6, "a");
        }

        Assert.NotNull(limits.TokenReserve(From("2001:db8::2"), "a"));
    }

    [Fact]
    public void Token_limit_keys_are_cut_to_256_characters()
    {
        using var limits = new OAuthLimits();
        var here = From("203.0.113.6");
        var prefix = new string('x', 256);
        for (var i = 0; i < 20; i++)
        {
            limits.TokenReserve(here, prefix + "1");
            limits.TokenFailed(here, prefix + "1");
        }

        // Padding past the cut doesn't buy a fresh budget.
        Assert.NotNull(limits.TokenReserve(here, prefix + "2"));
    }
}
