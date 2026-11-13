// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using System.Text;
using Komogentic.Server.Accounts;
using Komogentic.Server.Tests.Api;
using Komogentic.Server.Tests.Komodo;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Komogentic.Server.Tests.OAuth;

/// <summary>
/// The token endpoint and a connection's callers (spec §5): a code exchanged once for an access and a refresh token,
/// each with the connection's Komodo key sealed under it, and the access token accepted only on its connection's URL,
/// with the consented scope, until it expires.
/// </summary>
[Collection("app")]
public sealed class TokenTests(AppFactory app) : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private WebApplicationFactory<Program> Api => app.PublicApi;

    private IMongoCollection<BsonDocument> Collection(string name) => app.Database.GetCollection<BsonDocument>(name);

    public void Dispose()
    {
        app.Komodo.Time = TimeProvider.System;
        app.Komodo.ClearFailures();
    }

    /// <summary>The public app with a clock of the test's own, starting now.</summary>
    private WebApplicationFactory<Program> WithClock(FakeTimeProvider time) =>
        Api.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
        {
            s.RemoveAll<TimeProvider>();
            s.AddSingleton<TimeProvider>(time);
        }));

    /// <summary>A new user's connection, authorised by a fresh registered client: the flow holds the code.</summary>
    private async Task<OAuthFlow> AllowedAsync(WebApplicationFactory<Program> api, int? expiresInDays = null, string? scope = null)
    {
        var flow = await OAuthFlow.NewAsync(app, api, expiresInDays, scope);
        await flow.AllowAsync();
        return flow;
    }

    private async Task<(OAuthFlow Flow, Pair Pair)> ConnectedAsync(WebApplicationFactory<Program> api)
    {
        var flow = await AllowedAsync(api);
        return (flow, await flow.ExchangeAsync());
    }

    private static string OwnAddress() => $"10.{Random.Shared.Next(256)}.{Random.Shared.Next(256)}.{Random.Shared.Next(1, 255)}";

    private static string Challenge(HttpResponseMessage response) => response.Headers.GetValues("WWW-Authenticate").Single();

    /// <summary>The MCP SDK's client on the connection's URL with the access token.</summary>
    private static async Task<McpClient> McpAsync(WebApplicationFactory<Program> api, string connectionId, string access)
    {
        var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(OAuthFlow.ResourceOf(connectionId)),
                AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = $"Bearer {access}", ["X-Forwarded-For"] = Dashboard.NewAddress() },
            },
            api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) }),
            NullLoggerFactory.Instance,
            ownsHttpClient: true);
        return await McpClient.CreateAsync(transport, cancellationToken: Ct);
    }

    private async Task<BsonDocument> RecordAsync(string connectionId, string kind) =>
        await Collection("oauth_tokens").Find(new BsonDocument { ["connection"] = connectionId, ["kind"] = kind, ["revokedAt"] = new BsonDocument("$exists", false) }).SingleAsync(Ct);

    private async Task<BsonDocument> ConnectionDocAsync(string id) => await Collection("connections").Find(new BsonDocument("_id", id)).SingleAsync(Ct);

    [Fact]
    public async Task Exchanges_a_code_for_tokens()
    {
        var flow = await AllowedAsync(Api);

        using var response = await flow.TokenAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl!.NoStore);
        Assert.Equal("no-cache", response.Headers.Pragma.ToString());
        var json = await Dashboard.JsonAsync(response);
        Assert.Equal("Bearer", json.GetProperty("token_type").GetString());
        Assert.Equal(3600, json.GetProperty("expires_in").GetInt32());
        Assert.True(Secrets.IsWellFormed(json.GetProperty("access_token").GetString()!, "kgt_at_"));
        Assert.True(Secrets.IsWellFormed(json.GetProperty("refresh_token").GetString()!, "kgt_rt_"));
        Assert.True(Secrets.IsWellFormed(flow.Code!, "kgt_ac_"));
        Assert.Equal("komodo:read komodo:operate", json.GetProperty("scope").GetString());
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
    }

    [Fact]
    public async Task A_read_only_grant_answers_the_read_scope_and_gets_the_read_tools()
    {
        var flow = await AllowedAsync(Api, scope: "komodo:read");
        var pair = await flow.ExchangeAsync();

        await using var client = await McpAsync(Api, flow.ConnectionId, pair.Access);
        var tools = (await client.ListToolsAsync(cancellationToken: Ct)).Select(t => t.Name).Order(StringComparer.Ordinal);
        var deploy = await client.CallToolAsync("deploy_stack", new Dictionary<string, object?> { ["stack"] = "app" }, cancellationToken: Ct);

        Assert.Equal("komodo:read", pair.Scope);
        Assert.Equal(["get_stack_logs", "get_stack_status", "list_stack_updates", "list_stacks"], tools);
        Assert.True(deploy.IsError);
        Assert.Contains("read-only", Assert.IsType<TextContentBlock>(deploy.Content[0]).Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_access_token_works_on_its_connection_url_with_the_connections_komodo_key()
    {
        var (flow, pair) = await ConnectedAsync(Api);
        var komodoKey = (await ConnectionDocAsync(flow.ConnectionId))["komodoKey"].AsString;

        await using var client = await McpAsync(Api, flow.ConnectionId, pair.Access);
        var tools = (await client.ListToolsAsync(cancellationToken: Ct)).Select(t => t.Name).Order(StringComparer.Ordinal);
        var listed = await client.CallToolAsync("list_stacks", cancellationToken: Ct);

        // The same six tools as plain /mcp.
        Assert.Equal(["deploy_stack", "get_stack_logs", "get_stack_status", "list_stack_updates", "list_stacks", "restart_stack"], tools);
        Assert.NotEqual(true, listed.IsError);
        var request = app.Komodo.Requests.Last(r => r.Type == "ListStacks");
        Assert.Equal(("key", komodoKey), (request.AuthKind, request.ApiKey));
        Assert.Equal($"komogentic/{(await ConnectionDocAsync(flow.ConnectionId))["name"].AsString}", app.Komodo.ApiKeys.Single(k => k.Key == komodoKey).Name);
    }

    [Fact]
    public async Task The_access_token_is_refused_elsewhere()
    {
        var (flow, pair) = await ConnectedAsync(Api);
        var otherId = await OAuthFlow.ConnectionAsync(Api, flow.Owner);

        using var mcp = await OAuthFlow.InitializeAsync(Api, "/mcp", pair.Access);
        using var api = await Api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) })
            .SendAsync(new HttpRequestMessage(HttpMethod.Get, "/api/keys") { Headers = { Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", pair.Access) } }, Ct);
        using var elsewhere = await OAuthFlow.InitializeAsync(Api, $"/mcp/c/{otherId}", pair.Access);
        using var refreshOnOwn = await OAuthFlow.InitializeAsync(Api, $"/mcp/c/{flow.ConnectionId}", pair.Refresh);

        Assert.Equal(HttpStatusCode.Unauthorized, mcp.StatusCode);
        Assert.Equal("Bearer", Challenge(mcp));
        Assert.Equal(HttpStatusCode.Unauthorized, api.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, elsewhere.StatusCode);
        Assert.EndsWith("error=\"invalid_token\"", Challenge(elsewhere), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Unauthorized, refreshOnOwn.StatusCode);
    }

    [Fact]
    public async Task Wrong_verifier_resource_client_or_redirect_is_invalid_grant()
    {
        var flow = await AllowedAsync(Api);
        var otherResource = OAuthFlow.ResourceOf(await OAuthFlow.ConnectionAsync(Api, flow.Owner));
        var otherClient = await OAuthFlow.RegisterAsync(Api);

        async Task<(HttpStatusCode, string)> Variation(params (string, string?)[] change)
        {
            var again = await flow.AgainAsync();
            await again.AllowAsync();
            using var response = await again.TokenAsync(change);
            return (response.StatusCode, response.IsSuccessStatusCode ? "" : await OAuthFlow.ErrorOf(response));
        }

        Assert.Equal((HttpStatusCode.BadRequest, "invalid_grant"), await Variation(("code_verifier", OAuthFlow.NewVerifier())));
        Assert.Equal((HttpStatusCode.BadRequest, "invalid_grant"), await Variation(("client_id", otherClient)));
        Assert.Equal((HttpStatusCode.BadRequest, "invalid_grant"), await Variation(("redirect_uri", OAuthFlow.Callback + "/other")));
        Assert.Equal((HttpStatusCode.BadRequest, "invalid_target"), await Variation(("resource", otherResource)));
        // Without a resource the code's own is meant (RFC 8707 makes it optional here).
        var (status, _) = await Variation(("resource", null));
        Assert.Equal(HttpStatusCode.OK, status);
    }

    [Fact]
    public async Task Pkce_is_checked_against_the_challenge()
    {
        var flow = await AllowedAsync(Api);

        // A verifier of the right shape whose S256 is not the challenge: refused, and the code is spent.
        using var wrong = await flow.TokenAsync(("code_verifier", OAuthFlow.NewVerifier()));
        Assert.Equal("invalid_grant", await OAuthFlow.ErrorOf(wrong));

        var again = await flow.AgainAsync();
        await again.AllowAsync();
        using var right = await again.TokenAsync();
        Assert.Equal(HttpStatusCode.OK, right.StatusCode);
    }

    [Fact]
    public async Task A_code_is_spent_by_the_first_request_that_presents_it()
    {
        var flow = await AllowedAsync(Api);

        using var wrong = await flow.TokenAsync(("code_verifier", OAuthFlow.NewVerifier()));
        using var right = await flow.TokenAsync();

        Assert.Equal("invalid_grant", await OAuthFlow.ErrorOf(wrong));
        Assert.Equal("invalid_grant", await OAuthFlow.ErrorOf(right));
        Assert.Equal("waiting", (await flow.StateAsync()).State);
    }

    [Fact]
    public async Task A_reused_code_revokes_what_it_issued()
    {
        var (flow, pair) = await ConnectedAsync(Api);

        using var again = await flow.TokenAsync();

        Assert.Equal("invalid_grant", await OAuthFlow.ErrorOf(again));
        Assert.Equal(HttpStatusCode.Unauthorized, await flow.InitializeStatusAsync(pair.Access));
        using var refresh = await flow.RefreshAsync(pair.Refresh);
        Assert.Equal("invalid_grant", await OAuthFlow.ErrorOf(refresh));
        Assert.Equal(("needs_reconnect", "code_reused"), await flow.StateAsync());
    }

    [Fact]
    public async Task An_expired_code_is_refused()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var api = WithClock(time);
        var flow = await AllowedAsync(api);

        time.Advance(TimeSpan.FromSeconds(61));
        using var response = await flow.TokenAsync();

        Assert.Equal("invalid_grant", await OAuthFlow.ErrorOf(response));
    }

    [Fact]
    public async Task Json_bodies_and_unknown_grants_are_refused()
    {
        var flow = await AllowedAsync(Api);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth/token")
        {
            Content = new StringContent(
                $$"""{"grant_type":"authorization_code","code":"{{flow.Code}}","redirect_uri":"{{OAuthFlow.Callback}}","client_id":"{{flow.ClientId}}","code_verifier":"{{flow.Verifier}}"}""",
                Encoding.UTF8, "application/json"),
        };
        request.Headers.Add("X-Forwarded-For", Dashboard.NewAddress());
        using var client = Api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) });

        using var json = await client.SendAsync(request, Ct);
        using var unknown = await flow.TokenAsync(("grant_type", "password"));
        using var twice = await OAuthFlow.PostFormAsync(Api, "/oauth/token", Dashboard.NewAddress(), ("grant_type", "authorization_code"), ("grant_type", "authorization_code"), ("client_id", flow.ClientId));
        using var shortVerifier = await flow.TokenAsync(("code_verifier", "too-short"));
        // The code survived all of that: none of those requests reached it.
        using var exchanged = await flow.TokenAsync();

        Assert.Equal("invalid_request", await OAuthFlow.ErrorOf(json));
        Assert.True(json.Headers.CacheControl!.NoStore);
        Assert.Equal("unsupported_grant_type", await OAuthFlow.ErrorOf(unknown));
        Assert.Equal("invalid_request", await OAuthFlow.ErrorOf(twice));
        Assert.Equal("invalid_request", await OAuthFlow.ErrorOf(shortVerifier));
        Assert.Equal(HttpStatusCode.OK, exchanged.StatusCode);
        Assert.Equal("*", exchanged.Headers.GetValues("Access-Control-Allow-Origin").Single());
    }

    [Fact]
    public async Task Access_tokens_expire_and_their_records_are_kept_a_day()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var api = WithClock(time);
        var (flow, pair) = await ConnectedAsync(api);

        var record = await RecordAsync(flow.ConnectionId, "access");
        var expiresAt = record["expiresAt"].ToUniversalTime();
        Assert.InRange(expiresAt, time.GetUtcNow().UtcDateTime.AddMinutes(60).AddSeconds(-1), time.GetUtcNow().UtcDateTime.AddMinutes(60));
        Assert.Equal(expiresAt.AddHours(24), record["purgeAt"].ToUniversalTime());
        // The connection doesn't expire, nor does its refresh token.
        Assert.False((await RecordAsync(flow.ConnectionId, "refresh")).Contains("expiresAt"));
        // The code's record stays, spent, to recognise a reuse; its Komodo key and grant are gone.
        var code = await RecordAsync(flow.ConnectionId, "code");
        Assert.True(code.Contains("usedAt"));
        Assert.False(code.Contains("sealed"));
        Assert.False(code.Contains("grant"));

        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(pair.Access));
        time.Advance(TimeSpan.FromMinutes(61));
        using var after = await OAuthFlow.InitializeAsync(api, $"/mcp/c/{flow.ConnectionId}", pair.Access);

        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        Assert.EndsWith("error=\"invalid_token\"", Challenge(after), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Expired_access_tokens_do_not_count_as_wrong_keys()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var api = WithClock(time);
        var (flow, pair) = await ConnectedAsync(api);
        var path = $"/mcp/c/{flow.ConnectionId}";
        var address = OwnAddress();
        time.Advance(TimeSpan.FromMinutes(61));

        for (var i = 0; i < 25; i++)
        {
            using var expired = await OAuthFlow.InitializeAsync(api, path, pair.Access, address);
            Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode);
        }

        var unknown = "kgt_at_" + new string('A', 43);
        for (var i = 0; i < 20; i++)
        {
            using var wrong = await OAuthFlow.InitializeAsync(api, path, unknown, address);
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        using var limited = await OAuthFlow.InitializeAsync(api, path, unknown, address);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
    }

    [Fact]
    public async Task A_connection_expiry_caps_the_tokens_and_the_komodo_key()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        app.Komodo.Time = time;
        await using var api = WithClock(time);
        var owner = await Owner.NewAsync(app, api);
        var id = await OAuthFlow.ConnectionAsync(api, owner, expiresInDays: 30);

        time.Advance(TimeSpan.FromDays(30) - TimeSpan.FromMinutes(10));
        owner = await owner.SignInAgainAsync(api);
        var flow = await OAuthFlow.StartAsync(api, owner, id, await OAuthFlow.RegisterAsync(api));
        await flow.AllowAsync();
        var pair = await flow.ExchangeAsync();

        Assert.Equal(600, pair.ExpiresIn);
        var connection = await ConnectionDocAsync(id);
        var expiresAt = connection["expiresAt"].ToUniversalTime();
        Assert.Equal(expiresAt, (await RecordAsync(id, "access"))["expiresAt"].ToUniversalTime());
        Assert.Equal(expiresAt, (await RecordAsync(id, "refresh"))["expiresAt"].ToUniversalTime());
        Assert.Equal(new DateTimeOffset(expiresAt).ToUnixTimeMilliseconds(), app.Komodo.ApiKeys.Single(k => k.Key == connection["komodoKey"].AsString).Expires);
    }

    [Fact]
    public async Task Failed_token_requests_are_limited_per_client_and_network()
    {
        var client = "https://limited.test/" + Guid.NewGuid().ToString("N");
        var address = OwnAddress();
        (string, string)[] Bad(string id) =>
        [
            ("grant_type", "authorization_code"), ("code", "kgt_ac_" + new string('B', 43)), ("redirect_uri", OAuthFlow.Callback), ("client_id", id),
            ("code_verifier", OAuthFlow.NewVerifier()),
        ];

        for (var i = 0; i < 20; i++)
        {
            using var bad = await OAuthFlow.PostFormAsync(Api, "/oauth/token", address, Bad(client));
            Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        }

        using var tooMany = await OAuthFlow.PostFormAsync(Api, "/oauth/token", address, Bad(client));
        // Someone else naming the same client id (say, claude.ai's) from another network isn't stopped by these,
        // nor is another client from this network.
        using var elsewhere = await OAuthFlow.PostFormAsync(Api, "/oauth/token", OwnAddress(), Bad(client));
        using var otherClient = await OAuthFlow.PostFormAsync(Api, "/oauth/token", address, Bad(client + "x"));

        Assert.Equal(HttpStatusCode.TooManyRequests, tooMany.StatusCode);
        Assert.True(tooMany.Headers.RetryAfter is not null);
        Assert.Equal(HttpStatusCode.BadRequest, elsewhere.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, otherClient.StatusCode);
    }

    [Fact]
    public async Task A_second_exchange_replaces_the_connections_tokens()
    {
        var (flow, first) = await ConnectedAsync(Api);

        var again = await flow.AgainAsync();
        await again.AllowAsync();
        var second = await again.ExchangeAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, await flow.InitializeStatusAsync(first.Access));
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(second.Access));
        // One family per connection: one live access and one live refresh token; the first family's are tombstones,
        // their grant and Komodo key gone.
        var records = await Collection("oauth_tokens").Find(new BsonDocument("connection", flow.ConnectionId)).ToListAsync(Ct);
        Assert.Equal(["access", "refresh"], records.Where(d => !d.Contains("revokedAt") && d["kind"] != "code").Select(d => d["kind"].AsString).Order(StringComparer.Ordinal));
        var tombstones = records.Where(d => d.Contains("revokedAt") && d["kind"] != "code").ToList();
        Assert.Equal(["access", "refresh"], tombstones.Select(d => d["kind"].AsString).Order(StringComparer.Ordinal));
        Assert.All(tombstones, d => Assert.False(d.Contains("grant") || d.Contains("sealed")));
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
    }

    [Fact]
    public async Task Revoked_access_tokens_do_not_count_as_wrong_keys()
    {
        var (flow, pair) = await ConnectedAsync(Api);
        var address = OwnAddress();
        using (var revoked = await flow.RevokeAsync(pair.Refresh)) Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);

        for (var i = 0; i < 25; i++)
        {
            using var refused = await OAuthFlow.InitializeAsync(Api, $"/mcp/c/{flow.ConnectionId}", pair.Access, address);
            Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
            Assert.EndsWith("error=\"invalid_token\"", Challenge(refused), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task A_changed_expiry_in_the_database_extends_nothing()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var api = WithClock(time);
        var (flow, pair) = await ConnectedAsync(api);
        var record = await RecordAsync(flow.ConnectionId, "access");
        await Collection("oauth_tokens").UpdateOneAsync(
            new BsonDocument("_id", record["_id"]), new BsonDocument("$set", new BsonDocument("expiresAt", time.GetUtcNow().UtcDateTime.AddDays(1))), cancellationToken: Ct);

        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(pair.Access));
        time.Advance(TimeSpan.FromMinutes(61));
        using var after = await OAuthFlow.InitializeAsync(api, $"/mcp/c/{flow.ConnectionId}", pair.Access);

        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        Assert.EndsWith("error=\"invalid_token\"", Challenge(after), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Two_exchanges_of_one_code_at_once_give_one_pair()
    {
        var flow = await AllowedAsync(Api);

        var responses = await Task.WhenAll(flow.TokenAsync(), flow.TokenAsync());

        try
        {
            Assert.Equal(1, responses.Count(r => r.StatusCode == HttpStatusCode.OK));
            Assert.Equal("invalid_grant", await OAuthFlow.ErrorOf(responses.Single(r => r.StatusCode != HttpStatusCode.OK)));
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }
    }

    [Fact]
    public void Exchanges_and_pairs_print_no_secrets()
    {
        var exchange = new Komogentic.Server.OAuth.CodeExchange("kgt_ac_secretcode", "client", OAuthFlow.Callback, "verifier-secret", null);
        var pair = new Komogentic.Server.OAuth.TokenPair("kgt_at_secret", "kgt_rt_secret", 3600, "komodo:read");

        Assert.DoesNotContain("secret", exchange.ToString(), StringComparison.Ordinal);
        Assert.Contains("client", exchange.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret", pair.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret", new Komogentic.Server.OAuth.TokenResult(pair, null, null).ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Path_edges_of_connection_urls()
    {
        var (flow, pair) = await ConnectedAsync(Api);

        // Routing matches the prefix case-insensitively, so the middleware does too; the id is lower-case only.
        using var upper = await OAuthFlow.InitializeAsync(Api, $"/MCP/C/{flow.ConnectionId}", pair.Access);
        using var upperId = await OAuthFlow.InitializeAsync(Api, $"/mcp/c/{flow.ConnectionId.ToUpperInvariant()}", pair.Access);
        using var unknown = await OAuthFlow.InitializeAsync(Api, "/mcp/c/abcdefghijklmnop", pair.Access);
        using var bare = await OAuthFlow.InitializeAsync(Api, "/mcp/c", pair.Access);
        using var cookie = await OAuthFlow.InitializeAsync(Api, $"/mcp/c/{flow.ConnectionId}", bearer: null, cookie: flow.Owner.Session);

        Assert.Equal(HttpStatusCode.OK, upper.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, upperId.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.False(unknown.Headers.Contains("WWW-Authenticate"));
        Assert.Equal(HttpStatusCode.NotFound, bare.StatusCode);
        Assert.False(bare.Headers.Contains("WWW-Authenticate"));
        Assert.Equal(HttpStatusCode.Unauthorized, cookie.StatusCode);
        Assert.DoesNotContain("invalid_token", Challenge(cookie), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Nothing_of_a_token_or_the_komodo_secret_reaches_the_log_or_the_database()
    {
        var log = new CapturedLog();
        await using var api = Api.WithWebHostBuilder(b => b.ConfigureLogging(l => l.AddProvider(log)));
        var flow = await AllowedAsync(api);
        var pair = await flow.ExchangeAsync();
        await using (var client = await McpAsync(api, flow.ConnectionId, pair.Access)) await client.CallToolAsync("list_stacks", cancellationToken: Ct);
        using (var refreshed = await flow.RefreshAsync(pair.Refresh)) await OAuthFlow.PairOf(refreshed);
        var komodoKey = (await ConnectionDocAsync(flow.ConnectionId))["komodoKey"].AsString;
        var komodoSecret = app.Komodo.ApiKeys.Single(k => k.Key == komodoKey).Secret;

        var docs = new List<string>();
        foreach (var name in new[] { "oauth_tokens", "connections", "pending_deletions", "oauth_requests" })
            docs.AddRange((await Collection(name).Find(FilterDefinition<BsonDocument>.Empty).ToListAsync(Ct)).Select(d => d.ToJson()));
        foreach (var secret in new[] { flow.Code!, flow.Verifier, pair.Access, pair.Refresh, komodoSecret, komodoSecret[2..^2] })
        {
            Assert.False(log.Lines.Any(l => l.Contains(secret, StringComparison.Ordinal)), "a secret is in the log");
            Assert.False(docs.Any(d => d.Contains(secret, StringComparison.Ordinal)), "a secret is in the database");
        }

        Assert.Contains(log.Lines, l => l.Contains("OAuth token issued", StringComparison.Ordinal) && l.Contains(flow.ConnectionId, StringComparison.Ordinal));
        Assert.Contains(log.Lines, l => l.Contains("OAuth refresh issued", StringComparison.Ordinal) && l.Contains(flow.ConnectionId, StringComparison.Ordinal));
    }
}
