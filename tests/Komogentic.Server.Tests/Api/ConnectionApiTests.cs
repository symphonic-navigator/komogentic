// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using System.Net.Http.Headers;
using Komogentic.Server.Accounts;
using Komogentic.Server.Auth;
using Komogentic.Server.Komodo;
using Komogentic.Server.OAuth;
using Komogentic.Server.Tests.Komodo;
using Komogentic.Server.Tests.OAuth;
using Komogentic.Server.Tools;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Komogentic.Server.Tests.Api;

/// <summary>
/// The dashboard's connections (spec §2): each with its own URL and, once an app is allowed, a Komodo key of its own;
/// Revoke is final and deletes the Komodo key; a connection whose tokens are lost, or whose Komodo key Komodo rejects,
/// needs a reconnect, which a new consent on the same URL makes.
/// </summary>
[Collection("app")]
public sealed class ConnectionApiTests(AppFactory app) : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private WebApplicationFactory<Program> Api => app.PublicApi;

    private IMongoCollection<BsonDocument> Collection(string name) => app.Database.GetCollection<BsonDocument>(name);

    public void Dispose()
    {
        app.Komodo.Down = false;
        app.Komodo.ClearFailures();
    }

    private async Task<(OAuthFlow Flow, Pair Pair)> ConnectedAsync(WebApplicationFactory<Program>? api = null)
    {
        var flow = await OAuthFlow.NewAsync(app, api ?? Api);
        await flow.AllowAsync();
        return (flow, await flow.ExchangeAsync());
    }

    private async Task<BsonDocument> ConnectionDocAsync(string id) => await Collection("connections").Find(new BsonDocument("_id", id)).SingleAsync(Ct);

    private async Task<List<string>> PendingAsync(string userId) =>
        (await Collection("pending_deletions").Find(new BsonDocument("user", userId)).ToListAsync(Ct)).Select(d => d["komodoKey"].AsString).ToList();

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

    [Fact]
    public async Task Create_list_revoke()
    {
        var owner = await Owner.NewAsync(app, Api);

        using var created = await Api.SendAsync(HttpMethod.Post, "/api/connections", new { name = "Grok assistant", expiresInDays = 90 }, owner.Session);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var view = await Dashboard.JsonAsync(created);
        var id = view.GetProperty("id").GetString()!;
        Assert.Matches("^[a-z2-7]{16}$", id);
        Assert.Equal($"/api/connections/{id}", created.Headers.Location!.OriginalString);
        Assert.Equal(
            ["client", "createdAt", "expiresAt", "id", "lastUsedAt", "name", "reason", "state", "url"],
            view.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
        Assert.Equal(("Grok assistant", $"{AppFactory.PublicUrl}/mcp/c/{id}", "waiting"),
            (view.GetProperty("name").GetString(), view.GetProperty("url").GetString(), view.GetProperty("state").GetString()));
        Assert.InRange(view.GetProperty("expiresAt").GetDateTime().ToUniversalTime() - DateTime.UtcNow, TimeSpan.FromDays(90) - TimeSpan.FromMinutes(1), TimeSpan.FromDays(90));
        // Nothing in Komodo until an app is allowed.
        Assert.DoesNotContain(app.Komodo.ApiKeys, k => k.UserId == owner.UserId);

        using var list = await Api.SendAsync(HttpMethod.Get, "/api/connections", session: owner.Session);
        var listed = Assert.Single((await Dashboard.JsonAsync(list)).EnumerateArray());
        Assert.Equal(id, listed.GetProperty("id").GetString());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, listed.GetProperty("client").ValueKind);

        using var revoke = await Api.SendAsync(HttpMethod.Delete, $"/api/connections/{id}", session: owner.Session);
        using var again = await Api.SendAsync(HttpMethod.Delete, $"/api/connections/{id}", session: owner.Session);
        using var after = await Api.SendAsync(HttpMethod.Get, "/api/connections", session: owner.Session);

        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, again.StatusCode);
        var revoked = Assert.Single((await Dashboard.JsonAsync(after)).EnumerateArray());
        Assert.Equal(("revoked", "revoked"), (revoked.GetProperty("state").GetString(), revoked.GetProperty("reason").GetString()));
        // The name is free again.
        using var reused = await Api.SendAsync(HttpMethod.Post, "/api/connections", new { name = "Grok assistant" }, owner.Session);
        Assert.Equal(HttpStatusCode.Created, reused.StatusCode);
    }

    [Fact]
    public async Task Duplicate_name_is_409_and_bad_input_400()
    {
        var owner = await Owner.NewAsync(app, Api);
        using (var first = await Api.SendAsync(HttpMethod.Post, "/api/connections", new { name = "Grok" }, owner.Session)) Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        using var duplicate = await Api.SendAsync(HttpMethod.Post, "/api/connections", new { name = "grok" }, owner.Session);
        using var expiry = await Api.SendAsync(HttpMethod.Post, "/api/connections", new { name = "Other", expiresInDays = 7 }, owner.Session);
        using var empty = await Api.SendAsync(HttpMethod.Post, "/api/connections", new { name = " " }, owner.Session);

        Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
        Assert.Equal("You already have a connection named 'grok'.", await Dashboard.ErrorAsync(duplicate));
        Assert.Equal(HttpStatusCode.BadRequest, expiry.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, empty.StatusCode);
    }

    [Fact]
    public async Task Connection_api_needs_a_session_and_is_per_user()
    {
        var (flow, pair) = await ConnectedAsync();
        var ben = await Owner.NewAsync(app, Api);

        using var bearer = await Api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) })
            .SendAsync(new HttpRequestMessage(HttpMethod.Get, "/api/connections") { Headers = { Authorization = new AuthenticationHeaderValue("Bearer", pair.Access) } }, Ct);
        using var noOrigin = await Api.SendAsync(HttpMethod.Post, "/api/connections", new { name = "x" }, flow.Owner.Session, origin: null);
        using var bensList = await Api.SendAsync(HttpMethod.Get, "/api/connections", session: ben.Session);
        using var bensRevoke = await Api.SendAsync(HttpMethod.Delete, $"/api/connections/{flow.ConnectionId}", session: ben.Session);

        Assert.Equal(HttpStatusCode.Unauthorized, bearer.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, noOrigin.StatusCode);
        Assert.Empty((await Dashboard.JsonAsync(bensList)).EnumerateArray());
        Assert.Equal(HttpStatusCode.NotFound, bensRevoke.StatusCode);
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
    }

    [Fact]
    public async Task Revoke_deletes_the_komodo_key_and_kills_the_tokens()
    {
        var (flow, pair) = await ConnectedAsync();
        var komodoKey = (await ConnectionDocAsync(flow.ConnectionId))["komodoKey"].AsString;
        var pending = await flow.AgainAsync();

        using var revoke = await Api.SendAsync(HttpMethod.Delete, $"/api/connections/{flow.ConnectionId}", session: flow.Owner.Session);

        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.True(app.Komodo.ApiKeys.Single(k => k.Key == komodoKey).Deleted);
        Assert.Empty(await PendingAsync(flow.Owner.UserId));
        Assert.Equal(HttpStatusCode.Unauthorized, await flow.InitializeStatusAsync(pair.Access));
        using (var refresh = await flow.RefreshAsync(pair.Refresh)) Assert.Equal("invalid_grant", await OAuthFlow.ErrorOf(refresh));
        // Every record is a tombstone: revoked, its lookup kept, nothing sealed, gone within a day.
        var records = await Collection("oauth_tokens").Find(new BsonDocument("connection", flow.ConnectionId)).ToListAsync(Ct);
        Assert.Equal(3, records.Count);
        Assert.All(records, d =>
        {
            Assert.True(d.Contains("revokedAt") && d.Contains("lookup"));
            Assert.False(d.Contains("grant") || d.Contains("sealed") || d.Contains("successor"));
            Assert.InRange(d["purgeAt"].ToUniversalTime(), d["revokedAt"].ToUniversalTime().AddHours(24).AddSeconds(-1), d["revokedAt"].ToUniversalTime().AddHours(24).AddSeconds(1));
        });
        // Its pending requests went with it, and its name is free.
        Assert.Equal(0, await Collection("oauth_requests").CountDocumentsAsync(new BsonDocument("_id", pending.RequestId), cancellationToken: Ct));
        Assert.False((await ConnectionDocAsync(flow.ConnectionId)).Contains("nameKey"));
        Assert.Equal(("revoked", "revoked"), await flow.StateAsync());
    }

    [Fact]
    public async Task Revoking_in_the_list_is_final()
    {
        var (flow, _) = await ConnectedAsync();
        using (var revoke = await Api.SendAsync(HttpMethod.Delete, $"/api/connections/{flow.ConnectionId}", session: flow.Owner.Session))
            Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);

        // A new consent on the same URL is refused: the user makes a new connection.
        var again = await flow.AgainAsync();
        Assert.Equal("revoked", (await again.ConsentAsync()).GetProperty("problem").GetString());
        using var allow = await again.DecideAsync(allow: true);
        Assert.Equal(HttpStatusCode.Conflict, allow.StatusCode);
        Assert.Equal(("revoked", "revoked"), await flow.StateAsync());
    }

    [Fact]
    public async Task Revoke_when_komodo_is_down_queues_the_deletion()
    {
        var (flow, pair) = await ConnectedAsync();
        var komodoKey = (await ConnectionDocAsync(flow.ConnectionId))["komodoKey"].AsString;
        app.Komodo.Down = true;

        using var revoke = await Api.SendAsync(HttpMethod.Delete, $"/api/connections/{flow.ConnectionId}", session: flow.Owner.Session);

        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, await flow.InitializeStatusAsync(pair.Access));
        Assert.Equal([komodoKey], await PendingAsync(flow.Owner.UserId));
        Assert.False(app.Komodo.ApiKeys.Single(k => k.Key == komodoKey).Deleted);

        // The next sign-in deletes it.
        app.Komodo.Down = false;
        await flow.Owner.SignInAgainAsync(Api);
        Assert.True(app.Komodo.ApiKeys.Single(k => k.Key == komodoKey).Deleted);
        Assert.Empty(await PendingAsync(flow.Owner.UserId));
    }

    [Fact]
    public async Task Revoke_with_a_rejected_jwt_ends_the_session()
    {
        var (flow, _) = await ConnectedAsync();
        var komodoKey = (await ConnectionDocAsync(flow.ConnectionId))["komodoKey"].AsString;
        app.Komodo.FailNext("DeleteApiKey", 401, FakeKomodo.ErrorBody("Invalid user credentials"));

        using var revoke = await Api.SendAsync(HttpMethod.Delete, $"/api/connections/{flow.ConnectionId}", session: flow.Owner.Session);
        using var session = await Api.SendAsync(HttpMethod.Get, "/api/session", session: flow.Owner.Session);

        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, session.StatusCode);
        Assert.Equal([komodoKey], await PendingAsync(flow.Owner.UserId));
        var owner = await flow.Owner.SignInAgainAsync(Api);
        using var list = await Api.SendAsync(HttpMethod.Get, "/api/connections", session: owner.Session);
        Assert.Equal("revoked", (await Dashboard.JsonAsync(list)).EnumerateArray().Single(c => c.GetProperty("id").GetString() == flow.ConnectionId).GetProperty("state").GetString());
    }

    [Fact]
    public async Task Lost_tokens_show_needs_reconnect()
    {
        var (flow, pair) = await ConnectedAsync();

        using (var revoked = await flow.RevokeAsync(pair.Refresh)) Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);

        var listed = await flow.ListedAsync();
        Assert.Equal(("needs_reconnect", "client_revoked"), (listed.GetProperty("state").GetString(), listed.GetProperty("reason").GetString()));
        Assert.Equal("Test app", listed.GetProperty("client").GetProperty("name").GetString());

        // A new consent through the same URL connects it again.
        var again = await flow.AgainAsync();
        await again.AllowAsync();
        var renewed = await again.ExchangeAsync();
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(renewed.Access));
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
    }

    [Fact]
    public async Task Rejected_komodo_key_shows_needs_reconnect()
    {
        var (flow, pair) = await ConnectedAsync();
        var komodoKey = (await ConnectionDocAsync(flow.ConnectionId))["komodoKey"].AsString;
        app.Komodo.DeleteKey(komodoKey);

        CallToolResult result;
        await using (var client = await McpAsync(Api, flow.ConnectionId, pair.Access)) result = await client.CallToolAsync("list_stacks", cancellationToken: Ct);

        Assert.True(result.IsError);
        Assert.Equal(ToolErrors.KomodoKeyRejected, Assert.IsType<TextContentBlock>(result.Content[0]).Text);
        Assert.Equal(("needs_reconnect", "komodo_key_rejected"), await flow.StateAsync());
        Assert.Equal(HttpStatusCode.Unauthorized, await flow.InitializeStatusAsync(pair.Access));
        Assert.Contains(komodoKey, await PendingAsync(flow.Owner.UserId));

        // A new consent through the same URL connects it again, with a new Komodo key.
        var again = await flow.AgainAsync();
        await again.AllowAsync();
        var renewed = await again.ExchangeAsync();
        Assert.NotEqual(komodoKey, (await ConnectionDocAsync(flow.ConnectionId))["komodoKey"].AsString);
        await using (var client = await McpAsync(Api, flow.ConnectionId, renewed.Access))
            Assert.NotEqual(true, (await client.CallToolAsync("list_stacks", cancellationToken: Ct)).IsError);
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
    }

    [Fact]
    public async Task Old_tokens_after_reconnect_do_not_kill_the_new_grant()
    {
        var (flow, first) = await ConnectedAsync();
        var tokens = Api.Services.GetRequiredService<OAuthTokens>();
        // A tool call checked before the reconnect: its caller holds the old Komodo key.
        var inFlight = RequestCaller.ForConnection((await tokens.ResolveAccessAsync(first.Access, flow.ConnectionId, flow.Resource, Ct)).Connection!);
        var oldKey = ((KomodoAuth.Key)inFlight.Komodo).ApiKey;

        var again = await flow.AgainAsync();
        await again.AllowAsync();
        var renewed = await again.ExchangeAsync();
        // The reconnect deleted the old key, so Komodo answers the call in flight with a 401, which reports it.
        Assert.True(app.Komodo.ApiKeys.Single(k => k.Key == oldKey).Deleted);
        await Api.Services.GetRequiredService<ICredentialHealth>().KomodoKeyRejectedAsync(inFlight, oldKey, Ct);

        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
        await using var client = await McpAsync(Api, flow.ConnectionId, renewed.Access);
        Assert.NotEqual(true, (await client.CallToolAsync("list_stacks", cancellationToken: Ct)).IsError);
    }

    [Fact]
    public async Task An_access_token_in_flight_finishes_but_the_next_is_refused()
    {
        var (flow, pair) = await ConnectedAsync();
        var tokens = Api.Services.GetRequiredService<OAuthTokens>();
        // A request checked before the revocation: its token resolved, as the middleware does first.
        var resolved = await tokens.ResolveAccessAsync(pair.Access, flow.ConnectionId, flow.Resource, Ct);
        Assert.NotNull(resolved.Connection);

        using (var revoke = await Api.SendAsync(HttpMethod.Delete, $"/api/connections/{flow.ConnectionId}", session: flow.Owner.Session))
            Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);

        // The next request checks again.
        var next = await tokens.ResolveAccessAsync(pair.Access, flow.ConnectionId, flow.Resource, Ct);
        Assert.Null(next.Connection);
        Assert.True(next.Known);
        Assert.Equal(HttpStatusCode.Unauthorized, await flow.InitializeStatusAsync(pair.Access));
    }

    [Fact]
    public async Task Secret_is_sealed_in_every_token_record()
    {
        var (flow, pair) = await ConnectedAsync();
        using (var refreshed = await flow.RefreshAsync(pair.Refresh)) await OAuthFlow.PairOf(refreshed);
        var again = await flow.AgainAsync();
        await again.AllowAsync();
        await again.ExchangeAsync();

        var secrets = app.Komodo.ApiKeys.Where(k => k.UserId == flow.Owner.UserId).Select(k => k.Secret).ToList();
        Assert.Equal(2, secrets.Count);
        var records = await Collection("oauth_tokens").Find(new BsonDocument("connection", flow.ConnectionId)).ToListAsync(Ct);
        var dump = records.Select(d => d.ToJson()).Append((await ConnectionDocAsync(flow.ConnectionId)).ToJson()).ToList();
        foreach (var secret in secrets)
        {
            Assert.False(dump.Any(d => d.Contains(secret, StringComparison.Ordinal) || d.Contains(secret[2..^2], StringComparison.Ordinal)), "a Komodo secret is stored in the clear");
        }

        // Each live token carries the Komodo key sealed under itself.
        Assert.All(records.Where(d => !d.Contains("revokedAt") && !d.Contains("usedAt")), d => Assert.True(d.Contains("sealed")));
    }

    [Fact]
    public async Task Using_a_connection_is_noted_at_most_once_a_minute()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var api = Api.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
        {
            s.RemoveAll<TimeProvider>();
            s.AddSingleton<TimeProvider>(time);
        }));
        var (flow, pair) = await ConnectedAsync(api);
        Assert.Equal(System.Text.Json.JsonValueKind.Null, (await flow.ListedAsync()).GetProperty("lastUsedAt").ValueKind);

        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(pair.Access));
        var first = (await flow.ListedAsync()).GetProperty("lastUsedAt").GetDateTime();
        time.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(pair.Access));
        Assert.Equal(first, (await flow.ListedAsync()).GetProperty("lastUsedAt").GetDateTime());
        time.Advance(TimeSpan.FromSeconds(31));
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(pair.Access));
        Assert.True((await flow.ListedAsync()).GetProperty("lastUsedAt").GetDateTime() > first);
    }
}
