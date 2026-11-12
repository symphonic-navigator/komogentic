// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Komogentic.Server.Accounts;
using Komogentic.Server.Tests.Komodo;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Komogentic.Server.Tests.Api;

/// <summary>
/// API keys for local agents (spec §2, step 4): each owns a Komodo API key of its user, created with the session's JWT,
/// its secret sealed under the API key, which is shown once and opens plain <c>/mcp</c> only.
/// </summary>
[Collection("app")]
public sealed class KeyApiTests : IDisposable
{
    private static int _users;

    private readonly AppFactory _app;
    private readonly FakeTimeProvider _time = new(DateTimeOffset.UtcNow);

    /// <summary>A host of the test's own: its clock and its in-memory limits.</summary>
    private readonly WebApplicationFactory<Program> _api;

    /// <summary>A Komodo user of this test alone, so that the shared fake's keys of other tests don't count.</summary>
    private readonly string _userId;

    private readonly string _username;

    private const string Password = "anna-komodo-password";

    public KeyApiTests(AppFactory app)
    {
        _app = app;
        var n = Interlocked.Increment(ref _users);
        _userId = $"u-anna-keys-{n}";
        _username = $"anna-keys-{n}";
        app.Komodo.AddUser(_userId, _username, Password);
        _api = app.PublicApi.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
        {
            s.RemoveAll<TimeProvider>();
            s.AddSingleton<TimeProvider>(_time);
        }));
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        _api.Dispose();
        _app.Komodo.Down = false;
        _app.Komodo.ClearFailures();
        _app.Komodo.Delay("CreateApiKey", TimeSpan.Zero);
        _app.Komodo.DelayAnswer("CreateApiKey", TimeSpan.Zero);
    }

    [Fact]
    public async Task Create_key_creates_a_komodo_key_named_after_it()
    {
        var session = await SignInAsync();

        using var response = await _api.SendAsync(HttpMethod.Post, "/api/keys", new { name = "Hermes", expiresInDays = 90 }, session);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await Dashboard.JsonAsync(response);
        var key = body.GetProperty("key");
        Assert.Equal(("Hermes", "active"), (key.GetProperty("name").GetString(), key.GetProperty("state").GetString()));
        var expiresAt = new DateTimeOffset(key.GetProperty("expiresAt").GetDateTime().ToUniversalTime());
        Assert.InRange(expiresAt - _time.GetUtcNow(), TimeSpan.FromDays(90) - TimeSpan.FromSeconds(1), TimeSpan.FromDays(90));
        var komodoKey = Assert.Single(KomodoKeys());
        Assert.Equal(("komogentic/Hermes", expiresAt.ToUnixTimeMilliseconds(), false), (komodoKey.Name, komodoKey.Expires, komodoKey.Deleted));
        Assert.Equal("jwt", _app.Komodo.Requests.Last(r => r.Type == "CreateApiKey").AuthKind);
    }

    [Fact]
    public async Task Key_is_shown_once_and_not_listed()
    {
        var session = await SignInAsync();
        var (id, secret) = await CreateAsync(session, "Hermes");
        Assert.True(Secrets.IsWellFormed(secret, "kgt_"));

        using var list = await _api.SendAsync(HttpMethod.Get, "/api/keys", session: session);

        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        var text = await list.Content.ReadAsStringAsync(Ct);
        var listed = Assert.Single((await Dashboard.JsonAsync(list)).EnumerateArray());
        Assert.Equal((id, "Hermes"), (listed.GetProperty("id").GetString(), listed.GetProperty("name").GetString()));
        Assert.False(text.Contains(secret, StringComparison.Ordinal), "the list shows the key's secret");
        Assert.DoesNotContain("secret", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(KomodoKeys().Single().Key, text);
    }

    [Fact]
    public async Task Secret_is_sealed_not_stored()
    {
        var session = await SignInAsync();
        var (id, secret) = await CreateAsync(session, "Hermes");
        var komodoKey = Assert.Single(KomodoKeys());

        var doc = await _app.Database.GetCollection<BsonDocument>("api_keys").Find(new BsonDocument("_id", id)).SingleAsync(Ct);

        var bytes = doc.ToBson();
        Assert.False(Contains(bytes, komodoKey.Secret), "the document holds the Komodo secret");
        Assert.False(Contains(bytes, secret), "the document holds the API key");
        Assert.False(Contains(bytes, secret["kgt_".Length..]), "the document holds the API key's random part");
        // The Komodo key's id is kept in the clear, to delete it with a JWT later (spec §2).
        Assert.Equal(komodoKey.Key, doc["komodoKey"].AsString);
    }

    [Fact]
    public async Task Revoke_deletes_the_komodo_key()
    {
        var session = await SignInAsync();
        var (id, _) = await CreateAsync(session, "Hermes");

        using var revoke = await _api.SendAsync(HttpMethod.Delete, $"/api/keys/{id}", session: session);

        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.True(Assert.Single(KomodoKeys()).Deleted);
        Assert.Equal("revoked", await StateAsync(session, id));
        Assert.Empty(await PendingAsync());
        using var again = await _api.SendAsync(HttpMethod.Delete, $"/api/keys/{id}", session: session);
        Assert.Equal(HttpStatusCode.NotFound, again.StatusCode);
    }

    [Fact]
    public async Task Revoke_when_komodo_is_down_queues_the_deletion()
    {
        var session = await SignInAsync();
        var (id, _) = await CreateAsync(session, "Hermes");
        _app.Komodo.Down = true;

        using var revoke = await _api.SendAsync(HttpMethod.Delete, $"/api/keys/{id}", session: session);

        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.False(Assert.Single(KomodoKeys()).Deleted);
        Assert.Equal([KomodoKeys().Single().Key], await PendingAsync());
        _app.Komodo.Down = false;
        Assert.Equal("revoked", await StateAsync(session, id));
    }

    [Fact]
    public async Task Revoke_with_a_rejected_jwt_ends_the_session()
    {
        var session = await SignInAsync();
        var (id, _) = await CreateAsync(session, "Hermes");
        _app.Komodo.FailNext("DeleteApiKey", 500, FakeKomodo.ErrorBody("Invalid user credentials"));

        using var revoke = await _api.SendAsync(HttpMethod.Delete, $"/api/keys/{id}", session: session);

        // The key is revoked: that is the answer. The session ends with it, the cookie cleared.
        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.StartsWith(Dashboard.Cookie + "=;", Dashboard.SetCookie(revoke));
        using (var after = await _api.SendAsync(HttpMethod.Get, "/api/session", session: session))
            Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        // The key is revoked all the same, and its Komodo key waits for the next sign-in.
        Assert.Equal([KomodoKeys().Single().Key], await PendingAsync());
        Assert.Equal("revoked", await StateAsync(await SignInAsync(), id));
        Assert.True(KomodoKeys().Single().Deleted);
    }

    [Fact]
    public async Task Revoke_of_a_dead_key_deletes_its_komodo_key()
    {
        var session = await SignInAsync();
        var (id, _) = await CreateAsync(session, "Hermes");
        var komodoKey = KomodoKeys().Single().Key;
        await _api.Services.GetRequiredService<ApiKeys>().MarkDeadAsync(id, komodoKey, "komodo_key_rejected", Ct);

        using var revoke = await _api.SendAsync(HttpMethod.Delete, $"/api/keys/{id}", session: session);

        Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        Assert.True(KomodoKeys().Single().Deleted);
        Assert.Equal("revoked", await StateAsync(session, id));
    }

    [Fact]
    public async Task Revoked_key_retries_do_not_lock_out_valid_keys()
    {
        var session = await SignInAsync();
        var (old, stale) = await CreateAsync(session, "Old agent");
        var (_, valid) = await CreateAsync(session, "Hermes");
        using (var revoke = await _api.SendAsync(HttpMethod.Delete, $"/api/keys/{old}", session: session))
            Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        var address = Dashboard.NewAddress();

        for (var i = 0; i < 25; i++)
        {
            using var refused = await McpAsync(stale, address);
            Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        }

        using var works = await McpAsync(valid, address);
        Assert.Equal(HttpStatusCode.OK, works.StatusCode);
    }

    [Fact]
    public async Task Creating_a_key_survives_a_cancelled_request()
    {
        await SignInAsync();
        var keys = _api.Services.GetRequiredService<ApiKeys>();
        var jwt = new Server.Komodo.KomodoAuth.Jwt(_app.Komodo.IssueJwt(_userId));
        // Komodo makes the key at once; its answer comes after the client has gone.
        _app.Komodo.DelayAnswer("CreateApiKey", TimeSpan.FromMilliseconds(400));
        using var hangUp = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        try
        {
            await keys.CreateAsync(new KomodoUser(_userId, _username), jwt, "Hung up", null, hangUp.Token);
        }
        catch (OperationCanceledException)
        {
        }

        await Task.Delay(TimeSpan.FromMilliseconds(600), Ct);
        var komodoKey = Assert.Single(KomodoKeys(), k => k.Name == "komogentic/Hung up");
        var stored = await _app.Database.GetCollection<ApiKeyDocument>("api_keys").Find(k => k.KomodoKey == komodoKey.Key).AnyAsync(Ct);
        Assert.True(stored || komodoKey.Deleted || (await PendingAsync()).Contains(komodoKey.Key), "Komodo's key is neither stored, deleted nor queued");
    }

    [Fact]
    public async Task Extended_expiry_does_not_open_the_key()
    {
        var session = await SignInAsync();
        var (id, secret) = await CreateAsync(session, "Hermes", 30);
        var docs = _app.Database.GetCollection<ApiKeyDocument>("api_keys");
        var doc = await docs.Find(k => k.Id == id).SingleAsync(Ct);

        // Someone who may write the database moves the expiry a year on.
        await docs.UpdateOneAsync(k => k.Id == id, Builders<ApiKeyDocument>.Update.Set(k => k.ExpiresAt, doc.ExpiresAt!.Value.AddDays(365)), cancellationToken: Ct);
        using var refused = await McpAsync(secret);

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        var listed = await KeyAsync(session, id);
        Assert.Equal(("dead", "unreadable"), (listed.GetProperty("state").GetString(), listed.GetProperty("reason").GetString()));
    }

    [Fact]
    public async Task Unreadable_key_is_marked_dead()
    {
        var session = await SignInAsync();
        var (id, secret) = await CreateAsync(session, "Hermes");
        var docs = _app.Database.GetCollection<ApiKeyDocument>("api_keys");
        var doc = await docs.Find(k => k.Id == id).SingleAsync(Ct);
        var damaged = (byte[])doc.Sealed.Clone();
        damaged[^1] ^= 1;
        await docs.UpdateOneAsync(k => k.Id == id, Builders<ApiKeyDocument>.Update.Set(k => k.Sealed, damaged), cancellationToken: Ct);

        using var refused = await McpAsync(secret);

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        var listed = await KeyAsync(session, id);
        Assert.Equal(("dead", "unreadable"), (listed.GetProperty("state").GetString(), listed.GetProperty("reason").GetString()));
        Assert.Equal([doc.KomodoKey], await PendingAsync());
    }

    [Theory]
    [InlineData("/mcp/c")]
    [InlineData("/mcp/c/")]
    [InlineData("/MCP/C/")]
    [InlineData("/mcp/c//x")]
    public async Task Api_key_does_not_open_connection_paths(string path)
    {
        var session = await SignInAsync();
        var (_, secret) = await CreateAsync(session, "Hermes");

        using var request = McpRequest(secret, path: path);
        using var response = await Client().SendAsync(request, Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Api_key_works_on_mcp_and_is_refused_after_revoke()
    {
        var session = await SignInAsync();
        var (id, secret) = await CreateAsync(session, "Hermes");

        using (var listed = await McpAsync(secret))
        {
            Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
            Assert.Contains("\"name\":\"list_stacks\"", await listed.Content.ReadAsStringAsync(Ct));
        }

        using (var revoke = await _api.SendAsync(HttpMethod.Delete, $"/api/keys/{id}", session: session))
            Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        using var refused = await McpAsync(secret);

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Equal("Bearer", refused.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task Using_a_key_is_noted_at_most_once_a_minute()
    {
        var session = await SignInAsync();
        var (id, secret) = await CreateAsync(session, "Hermes");

        using (var first = await McpAsync(secret)) Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var firstUse = await LastUsedAsync(session, id);
        _time.Advance(TimeSpan.FromSeconds(30));
        using (var second = await McpAsync(secret)) Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(firstUse, await LastUsedAsync(session, id));
        _time.Advance(TimeSpan.FromSeconds(31));
        using (var third = await McpAsync(secret)) Assert.Equal(HttpStatusCode.OK, third.StatusCode);

        Assert.NotNull(firstUse);
        Assert.True(await LastUsedAsync(session, id) > firstUse);
    }

    [Fact]
    public async Task Expired_key_is_refused()
    {
        var session = await SignInAsync();
        var (id, secret) = await CreateAsync(session, "Hermes", 30);
        using (var during = await McpAsync(secret)) Assert.Equal(HttpStatusCode.OK, during.StatusCode);

        _time.Advance(TimeSpan.FromDays(31));
        using var after = await McpAsync(secret);

        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        // Komodo's JWTs run on the real clock, so the list is read behind the dashboard's back.
        var listed = Assert.Single(await _api.Services.GetRequiredService<ApiKeys>().ListAsync(_userId, Ct));
        Assert.Equal((id, ApiKeyState.Expired), (listed.Id, listed.State));
    }

    [Fact]
    public async Task Dead_key_is_refused_without_calling_komodo()
    {
        var session = await SignInAsync();
        var (id, secret) = await CreateAsync(session, "Hermes");
        var komodoKey = KomodoKeys().Single().Key;
        await _api.Services.GetRequiredService<ApiKeys>().MarkDeadAsync(id, komodoKey, "komodo_key_rejected", Ct);
        var before = _app.Komodo.Requests.Count;

        using var refused = await McpAsync(secret);

        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Equal(before, _app.Komodo.Requests.Count);
        var listed = await KeyAsync(session, id);
        Assert.Equal(("dead", "komodo_key_rejected"), (listed.GetProperty("state").GetString(), listed.GetProperty("reason").GetString()));
        Assert.Equal([komodoKey], await PendingAsync());
    }

    [Fact]
    public async Task Mark_dead_ignores_a_stale_komodo_key()
    {
        var session = await SignInAsync();
        var (id, secret) = await CreateAsync(session, "Hermes");
        var keys = _api.Services.GetRequiredService<ApiKeys>();

        // A 401 for a Komodo key the API key no longer has (amendment R1).
        await keys.MarkDeadAsync(id, "K_an_earlier_key_K", "komodo_key_rejected", Ct);

        Assert.Equal("active", await StateAsync(session, id));
        Assert.Empty(await PendingAsync());
        using var works = await McpAsync(secret);
        Assert.Equal(HttpStatusCode.OK, works.StatusCode);
    }

    [Fact]
    public async Task Wrong_keys_are_rate_limited()
    {
        var session = await SignInAsync();
        var (_, secret) = await CreateAsync(session, "Hermes");
        var address = Dashboard.NewAddress();

        for (var i = 0; i < 20; i++)
        {
            using var wrong = await McpAsync(Secrets.New("kgt_"), address);
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        using var limited = await McpAsync(Secrets.New("kgt_"), address);
        using var evenTheRightOne = await McpAsync(secret, address);
        using var elsewhere = await McpAsync(secret);

        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.NotNull(limited.Headers.RetryAfter);
        Assert.Equal(HttpStatusCode.TooManyRequests, evenTheRightOne.StatusCode);
        Assert.Equal(HttpStatusCode.OK, elsewhere.StatusCode);
    }

    [Fact]
    public async Task Key_api_needs_a_session()
    {
        var session = await SignInAsync();
        var (_, secret) = await CreateAsync(session, "Hermes");
        using var request = Dashboard.Request(HttpMethod.Get, "/api/keys");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);

        using var response = await Client().SendAsync(request, Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Session_cookie_does_not_open_mcp()
    {
        var session = await SignInAsync();
        using var request = McpRequest(null);
        request.Headers.Add("Cookie", $"{Dashboard.Cookie}={session}");

        using var response = await Client().SendAsync(request, Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Bearer", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task Duplicate_name_is_409()
    {
        var session = await SignInAsync();
        var (id, _) = await CreateAsync(session, "Hermes");

        using var same = await _api.SendAsync(HttpMethod.Post, "/api/keys", new { name = "hermes " }, session);
        Assert.Equal(HttpStatusCode.Conflict, same.StatusCode);
        Assert.Equal("You already have an API key named 'hermes'.", await Dashboard.ErrorAsync(same));
        // Refused before Komodo was asked: no Komodo key for nothing.
        Assert.Single(KomodoKeys());

        using (var revoke = await _api.SendAsync(HttpMethod.Delete, $"/api/keys/{id}", session: session))
            Assert.Equal(HttpStatusCode.NoContent, revoke.StatusCode);
        using var again = await _api.SendAsync(HttpMethod.Post, "/api/keys", new { name = "Hermes" }, session);
        Assert.Equal(HttpStatusCode.Created, again.StatusCode);
    }

    [Theory]
    [InlineData("", 30, "An API key's name has 1 to 60 characters.")]
    [InlineData("Hermes", 7, "An API key expires after 30, 90, 365 days, or never.")]
    [InlineData("Her​mes", null, "An API key's name can't contain control or invisible formatting characters.")]
    public async Task Name_and_expiry_are_checked_before_komodo_is_asked(string name, int? expiresInDays, string error)
    {
        var session = await SignInAsync();

        using var response = await _api.SendAsync(HttpMethod.Post, "/api/keys", new { name, expiresInDays }, session);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(error, await Dashboard.ErrorAsync(response));
        Assert.Empty(KomodoKeys());
    }

    [Fact]
    public async Task Komodo_key_is_deleted_when_the_key_cannot_be_stored()
    {
        var session = await SignInAsync();
        await CreateAsync(session, "Hermes");
        var keys = _api.Services.GetRequiredService<ApiKeys>();
        var user = new KomodoUser(_userId, _username);
        var jwt = new Server.Komodo.KomodoAuth.Jwt(_app.Komodo.IssueJwt(_userId));
        // Two at once with one name: both pass the check while Komodo makes a key for each, the unique index takes one.
        _app.Komodo.Delay("CreateApiKey", TimeSpan.FromMilliseconds(500));
        var both = await Task.WhenAll(Enumerable.Range(0, 2).Select(async _ =>
        {
            try
            {
                await keys.CreateAsync(user, jwt, "Ben's agent", null, Ct);
                return true;
            }
            catch (ApiKeyNameTakenException)
            {
                return false;
            }
        }));

        Assert.Equal(1, both.Count(created => created));
        var komodoKeys = KomodoKeys().Where(k => k.Name == "komogentic/Ben's agent").ToList();
        Assert.Equal(2, komodoKeys.Count);
        Assert.Single(komodoKeys, k => !k.Deleted);
    }

    [Fact]
    public async Task Komodo_down_at_create_is_503_and_stores_nothing()
    {
        var session = await SignInAsync();
        _app.Komodo.Down = true;

        using var response = await _api.SendAsync(HttpMethod.Post, "/api/keys", new { name = "Hermes" }, session);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("Komodo could not be reached; try again in a minute.", await Dashboard.ErrorAsync(response));
        _app.Komodo.Down = false;
        using var list = await _api.SendAsync(HttpMethod.Get, "/api/keys", session: session);
        Assert.Empty((await Dashboard.JsonAsync(list)).EnumerateArray());
    }

    private Task<string> SignInAsync() => _api.SignInAsync(_username, Password);

    private async Task<(string Id, string Secret)> CreateAsync(string session, string name, int? expiresInDays = null)
    {
        using var response = await _api.SendAsync(HttpMethod.Post, "/api/keys", new { name, expiresInDays }, session);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await Dashboard.JsonAsync(response);
        return (body.GetProperty("key").GetProperty("id").GetString()!, body.GetProperty("secret").GetString()!);
    }

    private async Task<System.Text.Json.JsonElement> KeyAsync(string session, string id)
    {
        using var list = await _api.SendAsync(HttpMethod.Get, "/api/keys", session: session);
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        return (await Dashboard.JsonAsync(list)).EnumerateArray().Single(k => k.GetProperty("id").GetString() == id);
    }

    private async Task<string?> StateAsync(string session, string id) => (await KeyAsync(session, id)).GetProperty("state").GetString();

    private async Task<DateTime?> LastUsedAsync(string session, string id) =>
        (await KeyAsync(session, id)).GetProperty("lastUsedAt") is { ValueKind: System.Text.Json.JsonValueKind.String } at ? at.GetDateTime() : null;

    private List<FakeApiKey> KomodoKeys() => _app.Komodo.ApiKeys.Where(k => k.UserId == _userId).ToList();

    private async Task<List<string>> PendingAsync() =>
        (await _app.Database.GetCollection<PendingDeletionDocument>("pending_deletions").Find(d => d.User == _userId).ToListAsync(Ct))
        .Select(d => d.KomodoKey)
        .ToList();

    private HttpClient Client() =>
        _api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) });

    /// <summary>A raw MCP <c>tools/list</c>, as an agent sends it over Streamable HTTP.</summary>
    private static HttpRequestMessage McpRequest(string? bearer, string? address = null, string path = "/mcp")
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}""", Encoding.UTF8, "application/json"),
        };
        request.Headers.Add("X-Forwarded-For", address ?? Dashboard.NewAddress());
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.Accept.ParseAdd("text/event-stream");
        if (bearer is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return request;
    }

    private async Task<HttpResponseMessage> McpAsync(string bearer, string? address = null)
    {
        using var request = McpRequest(bearer, address);
        return await Client().SendAsync(request, Ct);
    }

    private static bool Contains(byte[] haystack, string needle) =>
        haystack.AsSpan().IndexOf(Encoding.UTF8.GetBytes(needle)) >= 0;
}
