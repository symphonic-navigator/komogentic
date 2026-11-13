// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Komogentic.Server.Tests.OAuth;

/// <summary>
/// Revocation (spec §5): by the client (RFC 7009), where a refresh token ends the whole family and the connection
/// needs a reconnect, and an access token ends only itself; by the owner in the dashboard, which is final.
/// </summary>
[Collection("app")]
public sealed class RevocationTests(AppFactory app)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private WebApplicationFactory<Program> Api => app.PublicApi;

    private IMongoCollection<BsonDocument> Collection(string name) => app.Database.GetCollection<BsonDocument>(name);

    private async Task<(OAuthFlow Flow, Pair Pair)> ConnectedAsync()
    {
        var flow = await OAuthFlow.NewAsync(app, Api);
        await flow.AllowAsync();
        return (flow, await flow.ExchangeAsync());
    }

    private static async Task<string> RefreshErrorAsync(OAuthFlow flow, string refresh)
    {
        using var response = await flow.RefreshAsync(refresh);
        return await OAuthFlow.ErrorOf(response);
    }

    private async Task<string> KomodoKeyAsync(string connectionId) =>
        (await Collection("connections").Find(new BsonDocument("_id", connectionId)).SingleAsync(Ct))["komodoKey"].AsString;

    private async Task<List<string>> PendingAsync(string userId) =>
        (await Collection("pending_deletions").Find(new BsonDocument("user", userId)).ToListAsync(Ct)).Select(d => d["komodoKey"].AsString).ToList();

    [Fact]
    public async Task The_client_can_revoke()
    {
        var (flow, first) = await ConnectedAsync();
        var (bystander, theirs) = await ConnectedAsync();

        using (var random = await flow.RevokeAsync("not-a-token-" + Guid.NewGuid()))
        {
            Assert.Equal(HttpStatusCode.OK, random.StatusCode);
            Assert.True(random.Headers.CacheControl!.NoStore);
            Assert.Equal("*", random.Headers.GetValues("Access-Control-Allow-Origin").Single());
        }

        using (var unknown = await flow.RevokeAsync("kgt_rt_" + new string('C', 43))) Assert.Equal(HttpStatusCode.OK, unknown.StatusCode);
        using (var code = await flow.RevokeAsync(flow.Code!)) Assert.Equal(HttpStatusCode.OK, code.StatusCode);
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(first.Access));

        using var revoked = await flow.RevokeAsync(first.Refresh, "refresh_token");

        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        Assert.True(revoked.Headers.CacheControl!.NoStore);
        Assert.Equal(HttpStatusCode.Unauthorized, await flow.InitializeStatusAsync(first.Access));
        Assert.Equal("invalid_grant", await RefreshErrorAsync(flow, first.Refresh));
        Assert.Equal(("needs_reconnect", "client_revoked"), await flow.StateAsync());
        // Nobody holds the Komodo key's secret any more: the key waits for the owner's next JWT to be deleted.
        Assert.Contains(await KomodoKeyAsync(flow.ConnectionId), await PendingAsync(flow.Owner.UserId));
        // Revoking again, or with the revoked access token, changes nothing and still answers 200.
        using (var twice = await flow.RevokeAsync(first.Refresh)) Assert.Equal(HttpStatusCode.OK, twice.StatusCode);
        using (var access = await flow.RevokeAsync(first.Access)) Assert.Equal(HttpStatusCode.OK, access.StatusCode);
        Assert.Equal(("needs_reconnect", "client_revoked"), await flow.StateAsync());
        // Someone else's connection is untouched.
        Assert.Equal(HttpStatusCode.OK, await bystander.InitializeStatusAsync(theirs.Access));
        Assert.Equal(("connected", (string?)null), await bystander.StateAsync());
    }

    [Fact]
    public async Task Revoking_an_access_token_revokes_only_it()
    {
        var (flow, first) = await ConnectedAsync();

        using var revoked = await flow.RevokeAsync(first.Access, "access_token");

        Assert.Equal(HttpStatusCode.OK, revoked.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, await flow.InitializeStatusAsync(first.Access));
        var record = await Collection("oauth_tokens").Find(new BsonDocument { ["connection"] = flow.ConnectionId, ["kind"] = "access" }).SingleAsync(Ct);
        Assert.True(record.Contains("revokedAt"));
        Assert.False(record.Contains("sealed") || record.Contains("grant"));
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
        Assert.DoesNotContain(await KomodoKeyAsync(flow.ConnectionId), await PendingAsync(flow.Owner.UserId));
        using var refreshed = await flow.RefreshAsync(first.Refresh);
        var second = await OAuthFlow.PairOf(refreshed);
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(second.Access));
    }
}
