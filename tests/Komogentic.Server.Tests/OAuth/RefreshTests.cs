// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using Komogentic.Server.Accounts;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Komogentic.Server.Tests.OAuth;

/// <summary>
/// The <c>refresh_token</c> grant (spec §5): every refresh rotates both tokens and seals the Komodo key under the new
/// ones, a retry within 30 seconds gets the same pair back, a reuse after that revokes the connection's tokens.
/// </summary>
[Collection("app")]
public sealed class RefreshTests(AppFactory app) : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private WebApplicationFactory<Program> Api => app.PublicApi;

    private IMongoCollection<BsonDocument> Collection(string name) => app.Database.GetCollection<BsonDocument>(name);

    public void Dispose() => app.Komodo.Time = TimeProvider.System;

    private WebApplicationFactory<Program> WithClock(FakeTimeProvider time) =>
        Api.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
        {
            s.RemoveAll<TimeProvider>();
            s.AddSingleton<TimeProvider>(time);
        }));

    private async Task<(OAuthFlow Flow, Pair Pair)> ConnectedAsync(WebApplicationFactory<Program> api, int? expiresInDays = null)
    {
        var flow = await OAuthFlow.NewAsync(app, api, expiresInDays);
        await flow.AllowAsync();
        return (flow, await flow.ExchangeAsync());
    }

    private static async Task<Pair> RefreshedAsync(OAuthFlow flow, string refresh)
    {
        using var response = await flow.RefreshAsync(refresh);
        return await OAuthFlow.PairOf(response);
    }

    private static async Task<string> RefreshErrorAsync(OAuthFlow flow, string refresh, params (string, string?)[] form)
    {
        using var response = await flow.RefreshAsync(refresh, form);
        return await OAuthFlow.ErrorOf(response);
    }

    /// <summary>The record of a token, found by its lookup value as the server finds it.</summary>
    private async Task<BsonDocument> RecordOfAsync(string token) =>
        await Collection("oauth_tokens").Find(new BsonDocument("lookup", new BsonBinaryData(Komogentic.Server.OAuth.OAuthTokens.Lookup(token)))).SingleAsync(Ct);

    [Fact]
    public async Task Refreshing_rotates_both_tokens()
    {
        var (flow, first) = await ConnectedAsync(Api);
        var oldRecord = await RecordOfAsync(first.Refresh);

        var second = await RefreshedAsync(flow, first.Refresh);

        Assert.NotEqual(first.Access, second.Access);
        Assert.NotEqual(first.Refresh, second.Refresh);
        Assert.True(Secrets.IsWellFormed(second.Access, "kgt_at_"));
        Assert.True(Secrets.IsWellFormed(second.Refresh, "kgt_rt_"));
        Assert.Equal(3600, second.ExpiresIn);
        Assert.Equal("komodo:read komodo:operate", second.Scope);
        // The old access token lives out its hour; the new one works too.
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(first.Access));
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(second.Access));
        // The old refresh token's record stays, spent, without its grant and Komodo key, for 30 days.
        var used = await RecordOfAsync(first.Refresh);
        Assert.True(used.Contains("usedAt"));
        Assert.False(used.Contains("grant"));
        Assert.False(used.Contains("sealed"));
        Assert.False(used.Contains("revokedAt"));
        Assert.Equal(used["usedAt"].ToUniversalTime().AddDays(30), used["purgeAt"].ToUniversalTime());
        Assert.Equal(oldRecord["_id"], used["_id"]);
        // The new tokens carry the Komodo key sealed under them, and name the old record as their parent.
        var newRefresh = await RecordOfAsync(second.Refresh);
        var newAccess = await RecordOfAsync(second.Access);
        Assert.True(newRefresh.Contains("sealed") && newAccess.Contains("sealed"));
        Assert.Equal(oldRecord["_id"], newRefresh["parent"]);
        Assert.Equal(oldRecord["_id"], newAccess["parent"]);
        // The pair kept for a retry is sealed: neither token is anywhere in the clear.
        foreach (var name in new[] { "oauth_tokens", "connections" })
        {
            var docs = await Collection(name).Find(FilterDefinition<BsonDocument>.Empty).ToListAsync(Ct);
            Assert.False(docs.Any(d => d.ToJson().Contains(second.Access, StringComparison.Ordinal) || d.ToJson().Contains(second.Refresh, StringComparison.Ordinal)), $"a token is in {name}");
        }

        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
    }

    [Fact]
    public async Task A_retry_within_the_grace_period_gets_the_same_pair()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var api = WithClock(time);
        var (flow, first) = await ConnectedAsync(api);

        var second = await RefreshedAsync(flow, first.Refresh);
        time.Advance(TimeSpan.FromSeconds(5));
        var retried = await RefreshedAsync(flow, first.Refresh);

        Assert.Equal(second.Access, retried.Access);
        Assert.Equal(second.Refresh, retried.Refresh);
        Assert.Equal(second.Scope, retried.Scope);
        Assert.Equal(3595, retried.ExpiresIn);
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(second.Access));
        // And the pair it got back still rotates.
        await RefreshedAsync(flow, retried.Refresh);
    }

    [Fact]
    public async Task Parallel_refreshes_get_the_same_pair()
    {
        var (flow, first) = await ConnectedAsync(Api);

        var responses = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => flow.RefreshAsync(first.Refresh)));
        Pair[] pairs;
        try
        {
            pairs = await Task.WhenAll(responses.Select(OAuthFlow.PairOf));
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }

        Assert.Single(pairs.Distinct());
        // One live refresh token, the one they all got, and the connection is untouched.
        var live = await Collection("oauth_tokens").Find(
                new BsonDocument { ["connection"] = flow.ConnectionId, ["kind"] = "refresh", ["usedAt"] = new BsonDocument("$exists", false), ["revokedAt"] = new BsonDocument("$exists", false) })
            .ToListAsync(Ct);
        Assert.Equal((await RecordOfAsync(pairs[0].Refresh))["_id"], Assert.Single(live)["_id"]);
        Assert.Equal(2, await Collection("oauth_tokens").CountDocumentsAsync(
            new BsonDocument { ["connection"] = flow.ConnectionId, ["kind"] = "access", ["revokedAt"] = new BsonDocument("$exists", false) }, cancellationToken: Ct));
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(pairs[0].Access));
    }

    [Fact]
    public async Task Reuse_after_the_grace_period_revokes_the_family()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var api = WithClock(time);
        var (flow, first) = await ConnectedAsync(api);

        var second = await RefreshedAsync(flow, first.Refresh);
        time.Advance(TimeSpan.FromSeconds(31));
        var reused = await RefreshErrorAsync(flow, first.Refresh);

        Assert.Equal("invalid_grant", reused);
        Assert.Equal(HttpStatusCode.Unauthorized, await flow.InitializeStatusAsync(second.Access));
        Assert.Equal(HttpStatusCode.Unauthorized, await flow.InitializeStatusAsync(first.Access));
        Assert.Equal("invalid_grant", await RefreshErrorAsync(flow, second.Refresh));
        Assert.Equal(("needs_reconnect", "refresh_reused"), await flow.StateAsync());
        // The kept pair went with the revocation; the used record keeps its 30 days to recognise a later reuse.
        var used = await RecordOfAsync(first.Refresh);
        Assert.False(used.Contains("successor"));
        Assert.True(used.Contains("revokedAt"));
        Assert.Equal(used["usedAt"].ToUniversalTime().AddDays(30), used["purgeAt"].ToUniversalTime());
        Assert.All(
            await Collection("oauth_tokens").Find(new BsonDocument("connection", flow.ConnectionId)).ToListAsync(Ct),
            d => Assert.False(d.Contains("sealed") || d.Contains("grant")));

        // A new consent through the same URL connects it again.
        var again = await flow.AgainAsync();
        await again.AllowAsync();
        var renewed = await again.ExchangeAsync();
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(renewed.Access));
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
    }

    [Fact]
    public async Task A_replaced_refresh_token_presented_again_revokes_the_new_family()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var api = WithClock(time);
        var (flow, first) = await ConnectedAsync(api);
        var again = await flow.AgainAsync();
        await again.AllowAsync();
        var renewed = await again.ExchangeAsync();

        // Within the grace period, a refresh still in flight when the family was replaced is only refused.
        Assert.Equal("invalid_grant", await RefreshErrorAsync(flow, first.Refresh));
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
        time.Advance(TimeSpan.FromSeconds(31));
        Assert.Equal("invalid_grant", await RefreshErrorAsync(flow, first.Refresh));

        Assert.Equal(HttpStatusCode.Unauthorized, await flow.InitializeStatusAsync(renewed.Access));
        Assert.Equal(("needs_reconnect", "refresh_reused"), await flow.StateAsync());
    }

    [Fact]
    public async Task A_refresh_token_belongs_to_its_client()
    {
        var (flow, first) = await ConnectedAsync(Api);
        var other = await OAuthFlow.RegisterAsync(Api);

        Assert.Equal("invalid_grant", await RefreshErrorAsync(flow, first.Refresh, ("client_id", other)));

        // Nothing was revoked or spent: the right client still refreshes.
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(first.Access));
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
        await RefreshedAsync(flow, first.Refresh);
    }

    [Fact]
    public async Task A_sent_resource_must_be_the_connections()
    {
        var (flow, first) = await ConnectedAsync(Api);

        Assert.Equal("invalid_target", await RefreshErrorAsync(flow, first.Refresh, ("resource", OAuthFlow.ResourceOf("aaaaaaaaaaaaaaaa"))));
        using var malformed = await flow.RefreshAsync("kgt_rt_short");
        Assert.Equal("invalid_grant", await OAuthFlow.ErrorOf(malformed));
        using var noToken = await flow.RefreshAsync(first.Refresh, ("refresh_token", null));
        Assert.Equal("invalid_request", await OAuthFlow.ErrorOf(noToken));

        // Still unspent; with the connection's own URL, and with a scope, it rotates.
        using var response = await flow.RefreshAsync(first.Refresh, ("resource", flow.Resource + "/"), ("scope", "komodo:read komodo:operate"));
        await OAuthFlow.PairOf(response);
    }

    [Fact]
    public async Task Refresh_after_the_connection_expired_is_invalid_grant()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        app.Komodo.Time = time;
        await using var api = WithClock(time);
        var (flow, first) = await ConnectedAsync(api, expiresInDays: 30);
        var expiresAt = (await Collection("connections").Find(new BsonDocument("_id", flow.ConnectionId)).SingleAsync(Ct))["expiresAt"].ToUniversalTime();

        var second = await RefreshedAsync(flow, first.Refresh);
        Assert.Equal(expiresAt, (await RecordOfAsync(second.Refresh))["expiresAt"].ToUniversalTime());

        time.Advance(TimeSpan.FromDays(30) + TimeSpan.FromSeconds(1));

        Assert.Equal("invalid_grant", await RefreshErrorAsync(flow, second.Refresh));
    }

    [Fact]
    public async Task No_successor_outlives_its_use()
    {
        var (flow, first) = await ConnectedAsync(Api);

        var second = await RefreshedAsync(flow, first.Refresh);
        Assert.True((await RecordOfAsync(first.Refresh)).Contains("successor"));
        await RefreshedAsync(flow, second.Refresh);

        Assert.False((await RecordOfAsync(first.Refresh)).Contains("successor"));
        Assert.True((await RecordOfAsync(second.Refresh)).Contains("successor"));
        // Once its successor is used, a retry of the first token within the grace period has nothing to give back.
        Assert.Equal("invalid_grant", await RefreshErrorAsync(flow, first.Refresh));
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
    }

    [Fact]
    public async Task A_refreshed_token_still_reaches_komodo_as_the_connection()
    {
        var (flow, first) = await ConnectedAsync(Api);
        var second = await RefreshedAsync(flow, first.Refresh);
        var third = await RefreshedAsync(flow, second.Refresh);

        var resolved = await Api.Services.GetRequiredService<Komogentic.Server.OAuth.OAuthTokens>().ResolveAccessAsync(third.Access, flow.ConnectionId, flow.Resource, Ct);

        var komodoKey = (await Collection("connections").Find(new BsonDocument("_id", flow.ConnectionId)).SingleAsync(Ct))["komodoKey"].AsString;
        Assert.NotNull(resolved.Connection);
        Assert.Equal(komodoKey, resolved.Connection.Komodo.ApiKey);
        Assert.Equal(app.Komodo.ApiKeys.Single(k => k.Key == komodoKey).Secret, resolved.Connection.Komodo.Secret);
        Assert.Equal(flow.Owner.UserId, resolved.Connection.User.Id);
        Assert.Equal("Test app", resolved.Connection.ClientName);
        Assert.False(resolved.Connection.ReadOnly);
    }
}
