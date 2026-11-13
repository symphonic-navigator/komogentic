// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Komogentic.Server.Tests.Api;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Komogentic.Server.Tests.OAuth;

/// <summary>
/// The consent API (spec §2 step 3–4, §5): the pending request shown to its owner only, the decision bound to the
/// signed-in owner's session and to that request, used once; Allow creates the connection's Komodo key with the
/// session's JWT and issues a one-time code, a reconnect replaces the Komodo key and deletes the old one.
/// </summary>
[Collection("app")]
public sealed class ConsentTests(AppFactory app) : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private WebApplicationFactory<Program> Api => app.PublicApi;

    private IMongoCollection<BsonDocument> Collection(string name) => app.Database.GetCollection<BsonDocument>(name);

    public void Dispose()
    {
        app.Komodo.Down = false;
        app.Komodo.ClearFailures();
        app.Komodo.Time = TimeProvider.System;
    }

    private Task<OAuthFlow> FlowAsync(string? scope = null) => OAuthFlow.NewAsync(app, Api, scope: scope);

    private async Task<BsonDocument> ConnectionDocAsync(string id) => await Collection("connections").Find(new BsonDocument("_id", id)).SingleAsync(Ct);

    private Task<long> TokensAsync(string connectionId) =>
        Collection("oauth_tokens").CountDocumentsAsync(new BsonDocument("connection", connectionId), cancellationToken: Ct);

    private async Task<List<BsonDocument>> PendingAsync(string userId) =>
        await Collection("pending_deletions").Find(new BsonDocument("user", userId)).ToListAsync(Ct);

    private List<Komodo.FakeApiKey> KomodoKeys(string userId) => app.Komodo.ApiKeys.Where(k => k.UserId == userId).ToList();

    [Fact]
    public async Task Allow_creates_a_komodo_key_and_redirects_with_code_and_iss()
    {
        var flow = await FlowAsync();
        var name = (await ConnectionDocAsync(flow.ConnectionId))["name"].AsString;

        var redirect = await flow.RedirectAfterAsync(allow: true);

        Assert.StartsWith(OAuthFlow.Callback + "?", redirect, StringComparison.Ordinal);
        var query = OAuthFlow.QueryOf(redirect);
        Assert.True(Komogentic.Server.Accounts.Secrets.IsWellFormed(query["code"], "kgt_ac_"));
        Assert.Equal(flow.State, query["state"]);
        Assert.Equal(OAuthFlow.Issuer, query["iss"]);
        // The Komodo key was made with the session's JWT, named after the connection, and is the connection's now.
        var key = Assert.Single(KomodoKeys(flow.Owner.UserId));
        Assert.Equal(($"komogentic/{name}", 0L, false), (key.Name, key.Expires, key.Deleted));
        Assert.Equal("jwt", app.Komodo.Requests.Last(r => r.Type == "CreateApiKey").AuthKind);
        var connection = await ConnectionDocAsync(flow.ConnectionId);
        Assert.Equal(key.Key, connection["komodoKey"].AsString);
        Assert.Equal("Test app", connection["client"]["name"].AsString);
        Assert.Equal("claude.test", connection["client"]["host"].AsString);
        Assert.False(connection["client"]["verified"].AsBoolean);
        // The registration no longer expires.
        Assert.False((await Collection("oauth_clients").Find(new BsonDocument("_id", flow.ClientId)).SingleAsync(Ct)).Contains("expiresAt"));
        // Until the code is exchanged its Komodo key waits to be deleted, not before the code expires (amendment R6) ...
        var pending = Assert.Single(await PendingAsync(flow.Owner.UserId));
        Assert.Equal((key.Key, "code_unused"), (pending["komodoKey"].AsString, pending["reason"].AsString));
        Assert.InRange(pending["notBefore"].ToUniversalTime(), DateTime.UtcNow.AddSeconds(30), DateTime.UtcNow.AddSeconds(61));
        Assert.Equal(("waiting", (string?)null), await flow.StateAsync());

        // ... and once it is, the key is the connection's for good.
        using (var exchanged = await flow.TokenAsync(("code", query["code"]))) await OAuthFlow.PairOf(exchanged);
        Assert.Empty(await PendingAsync(flow.Owner.UserId));
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
    }

    [Fact]
    public async Task A_redirect_uri_with_a_query_keeps_it()
    {
        var owner = await Owner.NewAsync(app, Api);
        var id = await OAuthFlow.ConnectionAsync(Api, owner);
        var client = await OAuthFlow.RegisterAsync(Api, OAuthFlow.Callback + "?app=1");
        var flow = await OAuthFlow.StartAsync(Api, owner, id, client, OAuthFlow.Callback + "?app=1");

        var redirect = await flow.RedirectAfterAsync(allow: true);

        Assert.StartsWith(OAuthFlow.Callback + "?app=1&", redirect, StringComparison.Ordinal);
        Assert.Equal("1", OAuthFlow.QueryOf(redirect)["app"]);
    }

    [Fact]
    public async Task Deny_redirects_access_denied()
    {
        var flow = await FlowAsync();

        var redirect = await flow.RedirectAfterAsync(allow: false);

        Assert.StartsWith(OAuthFlow.Callback + "?", redirect, StringComparison.Ordinal);
        var query = OAuthFlow.QueryOf(redirect);
        Assert.Equal("access_denied", query["error"]);
        Assert.Equal(flow.State, query["state"]);
        Assert.Equal(OAuthFlow.Issuer, query["iss"]);
        Assert.False(query.ContainsKey("code"));
        Assert.Equal(0, await TokensAsync(flow.ConnectionId));
        Assert.Empty(KomodoKeys(flow.Owner.UserId));
        Assert.Equal(("waiting", (string?)null), await flow.StateAsync());
    }

    [Fact]
    public async Task The_consent_view_shows_the_connection()
    {
        var flow = await FlowAsync();
        var name = (await ConnectionDocAsync(flow.ConnectionId))["name"].AsString;

        var view = await flow.ConsentAsync();

        Assert.Equal(flow.RequestId, view.GetProperty("requestId").GetString());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, view.GetProperty("problem").ValueKind);
        Assert.False(view.GetProperty("renewal").GetBoolean());
        Assert.False(view.GetProperty("readOnly").GetBoolean());
        var client = view.GetProperty("client");
        Assert.Equal(("Test app", "claude.test", false), (client.GetProperty("name").GetString(), client.GetProperty("host").GetString(), client.GetProperty("verified").GetBoolean()));
        Assert.Equal("claude.test", view.GetProperty("redirectHost").GetString());
        var connection = view.GetProperty("connection");
        Assert.Equal(name, connection.GetProperty("name").GetString());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, connection.GetProperty("expiresAt").ValueKind);
        Assert.Equal(System.Text.Json.JsonValueKind.Null, connection.GetProperty("currentClient").ValueKind);
    }

    [Fact]
    public async Task A_homograph_host_is_shown_in_its_punycode_form()
    {
        // "claudе.ai" with a Cyrillic е: in Unicode it reads as claude.ai.
        const string redirect = "https://claud\u0435.ai/cb";
        var owner = await Owner.NewAsync(app, Api);
        var connectionId = await OAuthFlow.ConnectionAsync(Api, owner);
        var flow = await OAuthFlow.StartAsync(Api, owner, connectionId, await OAuthFlow.RegisterAsync(Api, redirect, name: ""), redirect);

        var view = await flow.ConsentAsync();

        Assert.Equal("xn--claud-3we.ai", view.GetProperty("client").GetProperty("host").GetString());
        Assert.Equal("xn--claud-3we.ai", view.GetProperty("client").GetProperty("name").GetString());
        Assert.Equal("xn--claud-3we.ai", view.GetProperty("redirectHost").GetString());
    }

    [Fact]
    public async Task A_second_consent_is_a_renewal()
    {
        var first = await FlowAsync();
        await first.AllowAsync();

        var second = await first.AgainAsync();
        var view = await second.ConsentAsync();

        Assert.True(view.GetProperty("renewal").GetBoolean());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, view.GetProperty("problem").ValueKind);
        Assert.Equal("Test app", view.GetProperty("connection").GetProperty("currentClient").GetProperty("name").GetString());
    }

    [Fact]
    public async Task Read_only_scope_is_shown_and_granted()
    {
        var read = await FlowAsync("komodo:read");
        var both = await read.AgainAsync(changes: ("scope", "komodo:read komodo:operate offline_access"));
        var none = await read.AgainAsync(changes: ("scope", "openid"));

        Assert.True((await read.ConsentAsync()).GetProperty("readOnly").GetBoolean());
        Assert.False((await both.ConsentAsync()).GetProperty("readOnly").GetBoolean());
        Assert.False((await none.ConsentAsync()).GetProperty("readOnly").GetBoolean());

        await read.AllowAsync();
        var pair = await read.ExchangeAsync();
        Assert.Equal("komodo:read", pair.Scope);
        var resolved = await Api.Services.GetRequiredService<Komogentic.Server.OAuth.OAuthTokens>().ResolveAccessAsync(pair.Access, read.ConnectionId, read.Resource, Ct);
        Assert.True(resolved.Connection!.ReadOnly);
    }

    [Fact]
    public async Task Other_users_request_is_404_other_account()
    {
        var flow = await FlowAsync();
        var name = (await ConnectionDocAsync(flow.ConnectionId))["name"].AsString;
        var ben = await Owner.NewAsync(app, Api);

        using var view = await flow.GetConsentAsync(ben);
        var body = await view.Content.ReadAsStringAsync(Ct);
        using var allow = await flow.DecideAsync(allow: true, ben);
        using var deny = await flow.DecideAsync(allow: false, ben);
        var denyBody = await deny.Content.ReadAsStringAsync(Ct);

        Assert.Equal(HttpStatusCode.NotFound, view.StatusCode);
        Assert.Equal("other-account", (await Dashboard.JsonAsync(view)).GetProperty("type").GetString());
        foreach (var hidden in new[] { name, "Test app", "claude.test", flow.ConnectionId, flow.RequestId, flow.State })
        {
            Assert.DoesNotContain(hidden, body, StringComparison.Ordinal);
            Assert.DoesNotContain(hidden, denyBody, StringComparison.Ordinal);
        }

        Assert.Equal(HttpStatusCode.NotFound, allow.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, deny.StatusCode);
        Assert.Equal("other-account", (await Dashboard.JsonAsync(deny)).GetProperty("type").GetString());
        Assert.Equal(0, await TokensAsync(flow.ConnectionId));
        Assert.Empty(KomodoKeys(ben.UserId));
        Assert.Empty(KomodoKeys(flow.Owner.UserId));
        Assert.Equal(1, await Collection("oauth_requests").CountDocumentsAsync(new BsonDocument("_id", flow.RequestId), cancellationToken: Ct));

        // The owner still sees it and can decide: the other user's decisions didn't consume the request.
        Assert.Equal(System.Text.Json.JsonValueKind.Null, (await flow.ConsentAsync()).GetProperty("problem").ValueKind);
        Assert.StartsWith("kgt_ac_", await flow.AllowAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_request_is_used_once()
    {
        var flow = await FlowAsync();
        await flow.AllowAsync();

        using var again = await flow.DecideAsync(allow: true);
        using var deny = await flow.DecideAsync(allow: false);
        using var view = await flow.GetConsentAsync();

        Assert.Equal(HttpStatusCode.NotFound, again.StatusCode);
        Assert.Equal("This request has expired; start the connection again in the app.", await Dashboard.ErrorAsync(again));
        Assert.Equal(HttpStatusCode.NotFound, deny.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, view.StatusCode);
        Assert.Equal(1, await TokensAsync(flow.ConnectionId));
        Assert.Single(KomodoKeys(flow.Owner.UserId));
    }

    [Fact]
    public async Task Unknown_and_expired_requests_are_404()
    {
        var flow = await FlowAsync();

        using var unknown = await Api.SendAsync(HttpMethod.Get, "/api/oauth/requests/" + new string('0', 32), session: flow.Owner.Session);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);

        // Ten minutes, checked in code: the TTL index only tidies up.
        await Collection("oauth_requests").UpdateOneAsync(
            new BsonDocument("_id", flow.RequestId), new BsonDocument("$set", new BsonDocument("expiresAt", DateTime.UtcNow.AddSeconds(-1))), cancellationToken: Ct);
        using var expired = await flow.GetConsentAsync();
        using var decision = await flow.DecideAsync(allow: true);
        Assert.Equal(HttpStatusCode.NotFound, expired.StatusCode);
        Assert.Equal("This request has expired; start the connection again in the app.", await Dashboard.ErrorAsync(expired));
        Assert.Equal(HttpStatusCode.NotFound, decision.StatusCode);
        Assert.Empty(KomodoKeys(flow.Owner.UserId));
    }

    [Fact]
    public async Task A_client_that_no_longer_resolves_is_said_so()
    {
        var flow = await FlowAsync();
        await Collection("oauth_clients").DeleteOneAsync(new BsonDocument("_id", flow.ClientId), Ct);

        using var view = await flow.GetConsentAsync();

        Assert.Equal(HttpStatusCode.NotFound, view.StatusCode);
        Assert.Equal("The app could not be identified any more; start the connection again in the app.", await Dashboard.ErrorAsync(view));
    }

    [Fact]
    public async Task The_decision_needs_our_origin_and_a_session()
    {
        var flow = await FlowAsync();
        using var created = await Api.SendAsync(HttpMethod.Post, "/api/keys", new { name = "Hermes" }, flow.Owner.Session);
        var key = (await Dashboard.JsonAsync(created)).GetProperty("secret").GetString()!;
        var path = $"/api/oauth/requests/{flow.RequestId}/decision";

        async Task<HttpResponseMessage> PostAsync(string? cookie, string? origin, string? bearer)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new StringContent("""{"allow":true}""", Encoding.UTF8, "application/json") };
            if (cookie is not null) request.Headers.Add("Cookie", $"{Dashboard.Cookie}={cookie}");
            if (origin is not null) request.Headers.Add("Origin", origin);
            if (bearer is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            request.Headers.Add("X-Forwarded-For", Dashboard.NewAddress());
            using var client = Api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, AllowAutoRedirect = false, BaseAddress = new Uri(AppFactory.PublicUrl) });
            return await client.SendAsync(request, Ct);
        }

        using var noOrigin = await PostAsync(flow.Owner.Session, origin: null, bearer: null);
        using var foreignOrigin = await PostAsync(flow.Owner.Session, origin: "https://claude.test", bearer: null);
        using var apiKey = await PostAsync(cookie: null, origin: null, bearer: key);
        using var apiKeyWithOrigin = await PostAsync(cookie: null, origin: AppFactory.PublicUrl, bearer: key);
        using var noCookie = await PostAsync(cookie: null, origin: AppFactory.PublicUrl, bearer: null);
        using var apiKeyRead = await Api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) })
            .SendAsync(new HttpRequestMessage(HttpMethod.Get, $"/api/oauth/requests/{flow.RequestId}") { Headers = { Authorization = new AuthenticationHeaderValue("Bearer", key) } }, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, noOrigin.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, foreignOrigin.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, apiKey.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, apiKeyWithOrigin.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, noCookie.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, apiKeyRead.StatusCode);
        Assert.Equal(0, await TokensAsync(flow.ConnectionId));

        // None of them consumed the request.
        Assert.StartsWith("kgt_ac_", await flow.AllowAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Revoked_and_expired_connections_cannot_be_allowed()
    {
        // Revoking deletes the connection's pending requests; a request made afterwards names a revoked connection.
        var earlier = await FlowAsync();
        using (var revoke = await Api.SendAsync(HttpMethod.Delete, $"/api/connections/{earlier.ConnectionId}", session: earlier.Owner.Session))
            Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        using (var gone = await earlier.GetConsentAsync()) Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
        var revoked = await earlier.AgainAsync();

        var expired = await FlowAsync();
        await Collection("connections").UpdateOneAsync(
            new BsonDocument("_id", expired.ConnectionId), new BsonDocument("$set", new BsonDocument("expiresAt", DateTime.UtcNow.AddMinutes(-1))), cancellationToken: Ct);

        foreach (var (flow, problem) in new[] { (revoked, "revoked"), (expired, "expired") })
        {
            Assert.Equal(problem, (await flow.ConsentAsync()).GetProperty("problem").GetString());
            using var allow = await flow.DecideAsync(allow: true);
            Assert.Equal(HttpStatusCode.Conflict, allow.StatusCode);
            Assert.Equal(0, await TokensAsync(flow.ConnectionId));
            Assert.Empty(KomodoKeys(flow.Owner.UserId));
            Assert.Equal("access_denied", OAuthFlow.QueryOf(await flow.RedirectAfterAsync(allow: false))["error"]);
        }
    }

    [Fact]
    public async Task Not_a_connection_can_only_be_denied_with_invalid_target()
    {
        var owner = await Owner.NewAsync(app, Api);
        var client = await OAuthFlow.RegisterAsync(Api);
        var flow = await OAuthFlow.StartAsync(Api, owner, "aaaaaaaaaaaaaaaa", client);

        var view = await flow.ConsentAsync();
        using var allow = await flow.DecideAsync(allow: true);

        Assert.Equal("not_a_connection", view.GetProperty("problem").GetString());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, view.GetProperty("connection").ValueKind);
        Assert.Equal(HttpStatusCode.Conflict, allow.StatusCode);
        Assert.Equal("invalid_target", OAuthFlow.QueryOf(await flow.RedirectAfterAsync(allow: false))["error"]);
    }

    [Fact]
    public async Task Allow_when_komodo_is_down_is_503_and_keeps_the_request()
    {
        var flow = await FlowAsync();
        app.Komodo.Down = true;

        using var allow = await flow.DecideAsync(allow: true);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, allow.StatusCode);
        Assert.Equal("Komodo could not be reached; try again in a minute.", await Dashboard.ErrorAsync(allow));
        Assert.Equal(0, await TokensAsync(flow.ConnectionId));
        Assert.False((await ConnectionDocAsync(flow.ConnectionId)).Contains("komodoKey"));

        // The request is still there: once Komodo is back, the same Allow works.
        app.Komodo.Down = false;
        Assert.Equal(HttpStatusCode.OK, (await flow.GetConsentAsync()).StatusCode);
        await flow.AllowAsync();
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync((await flow.ExchangeAsync()).Access));
    }

    [Fact]
    public async Task Allow_with_a_rejected_jwt_ends_the_session_and_keeps_the_request()
    {
        var flow = await FlowAsync();
        app.Komodo.FailNext("CreateApiKey", 401, Komodo.FakeKomodo.ErrorBody("Invalid user credentials"));

        using var allow = await flow.DecideAsync(allow: true);

        Assert.Equal(HttpStatusCode.Unauthorized, allow.StatusCode);
        Assert.Equal("Your Komodo sign-in has ended; sign in again.", await Dashboard.ErrorAsync(allow));
        using (var session = await Api.SendAsync(HttpMethod.Get, "/api/session", session: flow.Owner.Session)) Assert.Equal(HttpStatusCode.Unauthorized, session.StatusCode);
        var again = await flow.AgainAsync(await flow.Owner.SignInAgainAsync(Api));
        Assert.Equal(1, await Collection("oauth_requests").CountDocumentsAsync(new BsonDocument("_id", flow.RequestId), cancellationToken: Ct));
        Assert.StartsWith("kgt_ac_", await again.AllowAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reconnect_creates_a_new_key_and_deletes_the_old()
    {
        var flow = await FlowAsync();
        await flow.AllowAsync();
        var first = await flow.ExchangeAsync();
        var oldKey = (await ConnectionDocAsync(flow.ConnectionId))["komodoKey"].AsString;

        var again = await flow.AgainAsync();
        await again.AllowAsync();

        // The old key is deleted with the JWT at once; the new one is the connection's.
        var newKey = (await ConnectionDocAsync(flow.ConnectionId))["komodoKey"].AsString;
        Assert.NotEqual(oldKey, newKey);
        Assert.True(KomodoKeys(flow.Owner.UserId).Single(k => k.Key == oldKey).Deleted);
        Assert.False(KomodoKeys(flow.Owner.UserId).Single(k => k.Key == newKey).Deleted);
        Assert.DoesNotContain(await PendingAsync(flow.Owner.UserId), d => d["komodoKey"].AsString == oldKey);
        // The earlier tokens are revoked by the new consent; until its code is exchanged the dashboard says why.
        Assert.Equal(HttpStatusCode.Unauthorized, await flow.InitializeStatusAsync(first.Access));
        Assert.Equal(("needs_reconnect", "reconnected"), await flow.StateAsync());

        var renewed = await again.ExchangeAsync();
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(renewed.Access));
        Assert.Equal(("connected", (string?)null), await flow.StateAsync());
        Assert.Empty(await PendingAsync(flow.Owner.UserId));
    }

    [Fact]
    public async Task Unexchanged_code_leaves_no_live_key()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var api = Api.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
        {
            s.RemoveAll<TimeProvider>();
            s.AddSingleton<TimeProvider>(time);
        }));
        var flow = await OAuthFlow.NewAsync(app, api);
        await flow.AllowAsync();
        var key = Assert.Single(KomodoKeys(flow.Owner.UserId));

        // A sign-in within the code's minute leaves its key alone: the code may still be exchanged.
        await flow.Owner.SignInAgainAsync(api);
        Assert.False(key.Deleted);
        Assert.Equal(("waiting", (string?)null), await flow.StateAsync());

        time.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(("needs_reconnect", "code_unused"), await flow.StateAsync());
        using (var late = await flow.TokenAsync()) Assert.Equal("invalid_grant", await OAuthFlow.ErrorOf(late));
        await flow.Owner.SignInAgainAsync(api);

        Assert.True(key.Deleted);
        Assert.Empty(await PendingAsync(flow.Owner.UserId));
    }

    [Fact]
    public async Task Consent_before_the_first_code_is_exchanged_replaces_its_key()
    {
        var flow = await FlowAsync();
        var firstCode = await flow.AllowAsync();
        var firstKey = (await ConnectionDocAsync(flow.ConnectionId))["komodoKey"].AsString;

        var again = await flow.AgainAsync();
        await again.AllowAsync();

        // The first code's key is deleted at once, and the first code no longer exchanges.
        Assert.True(KomodoKeys(flow.Owner.UserId).Single(k => k.Key == firstKey).Deleted);
        using (var stale = await again.TokenAsync(("code", firstCode))) Assert.Equal("invalid_grant", await OAuthFlow.ErrorOf(stale));
        var pair = await again.ExchangeAsync();
        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(pair.Access));
    }

    [Fact]
    public async Task The_flow_is_logged_without_its_secrets()
    {
        var log = new CapturedLog();
        await using var api = Api.WithWebHostBuilder(b => b.ConfigureLogging(l => l.AddProvider(log)));
        var flow = await OAuthFlow.NewAsync(app, api);

        var code = await flow.AllowAsync();
        await flow.ExchangeAsync();

        var lines = log.Lines.Where(l => l.Contains("OAuth ", StringComparison.Ordinal)).ToList();
        Assert.Contains(lines, l => l.Contains("OAuth authorize pending", StringComparison.Ordinal) && l.Contains(flow.ConnectionId, StringComparison.Ordinal)
            && l.Contains("claude.test", StringComparison.Ordinal) && l.Contains(flow.RequestId, StringComparison.Ordinal));
        Assert.Contains(lines, l => l.Contains("OAuth consent allowed", StringComparison.Ordinal) && l.Contains(flow.ConnectionId, StringComparison.Ordinal));
        var secret = KomodoKeys(flow.Owner.UserId).Single().Secret;
        foreach (var (what, value) in new[] { ("code", code), ("state", flow.State), ("challenge", OAuthFlow.ChallengeOf(flow.Verifier)), ("verifier", flow.Verifier), ("Komodo secret", secret) })
        {
            // Not Assert.DoesNotContain: its failure message would print the secret.
            Assert.False(log.Lines.Any(l => l.Contains(value, StringComparison.Ordinal)), $"the {what} is in the log");
        }
    }
}
