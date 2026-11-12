// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Buffers.Text;
using System.Net;
using System.Text;
using Komogentic.Server.Accounts;
using Komogentic.Server.Api;
using Komogentic.Server.Auth;
using Komogentic.Server.Komodo;
using Komogentic.Server.Tests.Komodo;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Komogentic.Server.Tests.Api;

/// <summary>
/// Signing in to the dashboard with a Komodo username and password (spec §5, "What is different from Kumbu²"): the
/// JWT Komodo answers is kept, sealed, for a session that ends after 30 minutes idle, 12 hours, or with the JWT.
/// </summary>
[Collection("app")]
public sealed class SessionTests : IDisposable
{
    private const string AnnaId = "u-anna";
    private const string AnnaPassword = "anna-komodo-password";
    private const string BenPassword = "ben-komodo-password";

    private readonly AppFactory _app;
    private readonly FakeTimeProvider _time = new(DateTimeOffset.UtcNow);
    private readonly CapturedLog _log = new();

    /// <summary>A host of the test's own: its clock, its log and its in-memory limits.</summary>
    private readonly WebApplicationFactory<Program> _api;

    public SessionTests(AppFactory app)
    {
        _app = app;
        app.Komodo.AddUser(AnnaId, "anna", AnnaPassword);
        app.Komodo.AddUser("u-ben", "ben", BenPassword, twoFactor: true);
        _api = app.PublicApi.WithWebHostBuilder(b => b
            .ConfigureLogging(l => l.AddProvider(_log))
            .ConfigureTestServices(s =>
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
        _app.Komodo.RateLimited = false;
        _app.Komodo.JwtLifetime = TimeSpan.FromDays(1);
        _app.Komodo.ClearFailures();
    }

    [Fact]
    public async Task Sign_in_sets_a_strict_cookie_under_api()
    {
        using var response = await _api.PostSessionAsync("anna", AnnaPassword);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await Dashboard.JsonAsync(response);
        Assert.Equal("anna", body.GetProperty("username").GetString());
        Assert.True(body.GetProperty("expiresAt").GetDateTime() > _time.GetUtcNow().UtcDateTime);
        var attributes = Dashboard.SetCookie(response)!.Split(';').Skip(1).Select(a => a.Trim().ToLowerInvariant()).ToList();
        Assert.Contains("path=/api", attributes);
        Assert.Contains("httponly", attributes);
        Assert.Contains("secure", attributes);
        Assert.Contains("samesite=strict", attributes);
        Assert.Contains(attributes, a => a.StartsWith("max-age=", StringComparison.Ordinal) && int.Parse(a["max-age=".Length..]) > 0);
    }

    [Fact]
    public async Task Wrong_password_is_401_and_sets_no_cookie()
    {
        using var response = await _api.PostSessionAsync("anna", "not-annas-password");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Komodo refused this username and password.", await Dashboard.ErrorAsync(response));
        Assert.Null(Dashboard.SetCookie(response));
    }

    [Fact]
    public async Task Two_factor_user_is_refused_with_a_clear_error()
    {
        using var response = await _api.PostSessionAsync("ben", BenPassword);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(
            "Two-factor sign-in is not supported: sign in with a Komodo user without a second factor.", await Dashboard.ErrorAsync(response));
        Assert.Null(Dashboard.SetCookie(response));
    }

    [Fact]
    public async Task Session_answers_who_is_signed_in()
    {
        var session = await _api.SignInAsync("anna", AnnaPassword);

        using var response = await _api.SendAsync(HttpMethod.Get, "/api/session", session: session);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\"username\":\"anna\"", await response.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task Session_ends_with_the_jwt()
    {
        _app.Komodo.JwtLifetime = TimeSpan.FromMinutes(20);
        using var signIn = await _api.PostSessionAsync("anna", AnnaPassword);
        var session = Dashboard.SessionCookie(signIn);
        var expiresAt = (await Dashboard.JsonAsync(signIn)).GetProperty("expiresAt").GetDateTime().ToUniversalTime();
        Assert.InRange(expiresAt - DateTime.UtcNow, TimeSpan.FromMinutes(19), TimeSpan.FromMinutes(20));

        _time.Advance(TimeSpan.FromMinutes(10));
        using (var during = await _api.SendAsync(HttpMethod.Get, "/api/session", session: session))
            Assert.Equal(HttpStatusCode.OK, during.StatusCode);
        _time.Advance(TimeSpan.FromMinutes(11));
        using var after = await _api.SendAsync(HttpMethod.Get, "/api/session", session: session);

        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Fact]
    public async Task Session_ends_after_30_minutes_idle()
    {
        var session = await _api.SignInAsync("anna", AnnaPassword);

        // Each use moves the idle clock on.
        foreach (var _ in Enumerable.Range(0, 2))
        {
            _time.Advance(TimeSpan.FromMinutes(29));
            using var used = await _api.SendAsync(HttpMethod.Get, "/api/session", session: session);
            Assert.Equal(HttpStatusCode.OK, used.StatusCode);
        }

        _time.Advance(TimeSpan.FromMinutes(31));
        using var idle = await _api.SendAsync(HttpMethod.Get, "/api/session", session: session);

        Assert.Equal(HttpStatusCode.Unauthorized, idle.StatusCode);
    }

    [Fact]
    public async Task A_refused_cross_origin_post_does_not_move_the_idle_clock()
    {
        var session = await _api.SignInAsync("anna", AnnaPassword);
        _time.Advance(TimeSpan.FromMinutes(29));

        using (var forged = await _api.SendAsync(HttpMethod.Delete, "/api/session", session: session, origin: "https://elsewhere.example.org"))
            Assert.Equal(HttpStatusCode.Forbidden, forged.StatusCode);
        _time.Advance(TimeSpan.FromMinutes(2));
        using var idle = await _api.SendAsync(HttpMethod.Get, "/api/session", session: session);

        Assert.Equal(HttpStatusCode.Unauthorized, idle.StatusCode);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Two_session_cookies_are_refused(bool ownFirst)
    {
        var session = await _api.SignInAsync("anna", AnnaPassword);
        // A sibling subdomain can set a cookie of the same name for the parent domain ("cookie tossing").
        var tossed = await _api.SignInAsync("anna", AnnaPassword);
        var cookies = ownFirst ? $"kgt_session={session}; other=1; kgt_session={tossed}" : $"kgt_session={tossed};kgt_session={session}";
        using var request = Dashboard.Request(HttpMethod.Get, "/api/session");
        request.Headers.Add("Cookie", cookies);

        using var response = await _api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) })
            .SendAsync(request, Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        using var alone = await _api.SendAsync(HttpMethod.Get, "/api/session", session: tossed);
        Assert.Equal(HttpStatusCode.OK, alone.StatusCode);
    }

    [Fact]
    public async Task Session_ends_after_12_hours()
    {
        var session = await _api.SignInAsync("anna", AnnaPassword);

        for (var minutes = 0; minutes < 12 * 60 - 20; minutes += 20)
        {
            _time.Advance(TimeSpan.FromMinutes(20));
            using var used = await _api.SendAsync(HttpMethod.Get, "/api/session", session: session);
            Assert.Equal(HttpStatusCode.OK, used.StatusCode);
        }

        _time.Advance(TimeSpan.FromMinutes(20));
        using var ended = await _api.SendAsync(HttpMethod.Get, "/api/session", session: session);

        Assert.Equal(HttpStatusCode.Unauthorized, ended.StatusCode);
    }

    [Fact]
    public async Task Sign_out_ends_the_session()
    {
        var session = await _api.SignInAsync("anna", AnnaPassword);

        using var signOut = await _api.SendAsync(HttpMethod.Delete, "/api/session", session: session);
        using var after = await _api.SendAsync(HttpMethod.Get, "/api/session", session: session);

        Assert.Equal(HttpStatusCode.NoContent, signOut.StatusCode);
        var cleared = Dashboard.SetCookie(signOut);
        Assert.NotNull(cleared);
        Assert.StartsWith(Dashboard.Cookie + "=;", cleared);
        Assert.Contains("path=/api", cleared, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Fact]
    public async Task Signing_in_again_ends_the_earlier_session_of_the_browser()
    {
        var first = await _api.SignInAsync("anna", AnnaPassword);

        using var again = await _api.SendAsync(HttpMethod.Post, "/api/session", new { username = "anna", password = AnnaPassword }, session: first);
        using var old = await _api.SendAsync(HttpMethod.Get, "/api/session", session: first);
        using var fresh = await _api.SendAsync(HttpMethod.Get, "/api/session", session: Dashboard.SessionCookie(again));

        Assert.Equal(HttpStatusCode.Unauthorized, old.StatusCode);
        Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
    }

    [Fact]
    public async Task Jwt_is_not_stored_in_clear()
    {
        var session = await _api.SignInAsync("anna", AnnaPassword);
        var jwt = _app.Komodo.IssuedJwts[^1];

        var documents = await _app.Database.GetCollection<BsonDocument>("sessions")
            .Find(Builders<BsonDocument>.Filter.Eq("user", AnnaId)).ToListAsync(Ct);
        Assert.NotEmpty(documents);
        foreach (var document in documents)
        {
            var bytes = document.ToBson();
            Assert.False(Contains(bytes, Encoding.UTF8.GetBytes(jwt)), "A session document holds the JWT.");
            // Any JWT, not only this one: its header is base64url JSON, "eyJ…".
            Assert.False(Contains(bytes, "eyJ"u8.ToArray()), "A session document holds something that looks like a JWT.");
            Assert.False(Contains(bytes, Encoding.UTF8.GetBytes(session)), "A session document holds the cookie's secret.");
            Assert.False(Contains(bytes, Base64Url.DecodeFromChars(session)), "A session document holds the cookie's secret bytes.");
        }

        Assert.True(documents.All(d => d["jwt"].IsBsonBinaryData), "The JWT is not stored as sealed bytes.");
    }

    [Fact]
    public async Task Sign_in_is_rate_limited_per_address()
    {
        var address = Dashboard.NewAddress();
        for (var i = 0; i < 5; i++)
        {
            using var attempt = await _api.PostSessionAsync($"nobody-{i}-{Guid.NewGuid():N}", "wrong", address);
            Assert.Equal(HttpStatusCode.Unauthorized, attempt.StatusCode);
        }

        var before = _app.Komodo.Requests.Count;
        using var sixth = await _api.PostSessionAsync("anna", AnnaPassword, address);

        Assert.Equal(HttpStatusCode.TooManyRequests, sixth.StatusCode);
        Assert.True(sixth.Headers.RetryAfter?.Delta > TimeSpan.Zero);
        Assert.Null(Dashboard.SetCookie(sixth));
        Assert.Equal(before, _app.Komodo.Requests.Count);
        using var elsewhere = await _api.PostSessionAsync("anna", AnnaPassword);
        Assert.Equal(HttpStatusCode.OK, elsewhere.StatusCode);
    }

    [Fact]
    public async Task Sign_in_is_rate_limited_per_username()
    {
        var name = "carla-" + Guid.NewGuid().ToString("N")[..8];
        _app.Komodo.AddUser("u-" + name, name, "carla-password");
        // Successful attempts count too, and case aside: Komodo sees every one from Komogentic's address.
        using (var ok = await _api.PostSessionAsync(name, "carla-password"))
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        using (var upper = await _api.PostSessionAsync(name.ToUpperInvariant(), "wrong"))
            Assert.Equal(HttpStatusCode.Unauthorized, upper.StatusCode);
        using (var wrong = await _api.PostSessionAsync(name, "wrong"))
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);

        using var fourth = await _api.PostSessionAsync(name, "carla-password");

        Assert.Equal(HttpStatusCode.TooManyRequests, fourth.StatusCode);
        Assert.True(fourth.Headers.RetryAfter?.Delta > TimeSpan.Zero);
    }

    [Fact]
    public async Task Sign_in_drains_pending_deletions()
    {
        var deletions = _api.Services.GetRequiredService<PendingDeletions>();
        var live = _app.Komodo.IssueKey(AnnaId, "komogentic/old");
        var gone = _app.Komodo.IssueKey(AnnaId, "komogentic/gone");
        _app.Komodo.DeleteKey(gone.Key);
        var later = _app.Komodo.IssueKey(AnnaId, "komogentic/code");
        await deletions.AddAsync(null, AnnaId, live.Key, "revoked", Ct);
        await deletions.AddAsync(null, AnnaId, gone.Key, "revoked", Ct);
        await deletions.AddAsync(null, AnnaId, later.Key, "code_unused", Ct, notBefore: _time.GetUtcNow().UtcDateTime.AddMinutes(1));

        await _api.SignInAsync("anna", AnnaPassword);

        Assert.True(_app.Komodo.ApiKeys.Single(k => k.Key == live.Key).Deleted);
        Assert.Contains(_app.Komodo.Requests, r => r.Type == "DeleteApiKey" && r.AuthKind == "jwt" && r.Params.GetProperty("key").GetString() == live.Key);
        Assert.False(_app.Komodo.ApiKeys.Single(k => k.Key == later.Key).Deleted);
        Assert.Equal([later.Key], await PendingKeysAsync());

        // Once its time has come, the next sign-in deletes it too.
        _time.Advance(TimeSpan.FromMinutes(2));
        await _api.SignInAsync("anna", AnnaPassword);

        Assert.True(_app.Komodo.ApiKeys.Single(k => k.Key == later.Key).Deleted);
        Assert.Empty(await PendingKeysAsync());
    }

    [Fact]
    public async Task A_key_of_someone_else_is_dropped_from_the_queue()
    {
        var deletions = _api.Services.GetRequiredService<PendingDeletions>();
        var bens = _app.Komodo.IssueKey("u-ben", "komogentic/bens");
        await deletions.AddAsync(null, AnnaId, bens.Key, "revoked", Ct);

        await deletions.DrainAsync(AnnaId, new KomodoAuth.Jwt(_app.Komodo.IssueJwt(AnnaId)), Ct);

        Assert.DoesNotContain(bens.Key, await PendingKeysAsync());
        Assert.False(_app.Komodo.ApiKeys.Single(k => k.Key == bens.Key).Deleted);
        Assert.Contains(_log.Lines, l => l.StartsWith("Warning ", StringComparison.Ordinal) && l.Contains("does not belong", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_key_tried_more_than_ten_times_is_dropped()
    {
        var deletions = _api.Services.GetRequiredService<PendingDeletions>();
        var stuck = _app.Komodo.IssueKey(AnnaId, "komogentic/stuck");
        await deletions.AddAsync(null, AnnaId, stuck.Key, "revoked", Ct);
        _app.Komodo.Fail("DeleteApiKey", 500, FakeKomodo.ErrorBody("something odd"));
        var jwt = new KomodoAuth.Jwt(_app.Komodo.IssueJwt(AnnaId));

        for (var i = 0; i < 10; i++) await deletions.DrainAsync(AnnaId, jwt, Ct);
        Assert.Contains(stuck.Key, await PendingKeysAsync());
        await deletions.DrainAsync(AnnaId, jwt, Ct);

        Assert.DoesNotContain(stuck.Key, await PendingKeysAsync());
        Assert.Contains(_log.Lines, l => l.StartsWith("Warning ", StringComparison.Ordinal) && l.Contains("11 attempts", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_key_komodo_failed_to_delete_stays_pending()
    {
        var deletions = _api.Services.GetRequiredService<PendingDeletions>();
        var key = _app.Komodo.IssueKey(AnnaId, "komogentic/kept");
        await deletions.AddAsync(null, AnnaId, key.Key, "revoked", Ct);
        _app.Komodo.FailNext("DeleteApiKey", 500, FakeKomodo.ErrorBody("database unavailable"));

        await _api.SignInAsync("anna", AnnaPassword);

        Assert.Equal([key.Key], await PendingKeysAsync());
        await deletions.RemoveAsync(null, AnnaId, key.Key, Ct);
        Assert.Empty(await PendingKeysAsync());
    }

    [Fact]
    public async Task Komodo_down_at_sign_in_is_503()
    {
        _app.Komodo.Down = true;

        using var response = await _api.PostSessionAsync("anna", AnnaPassword);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("Komodo could not be reached; try again in a minute.", await Dashboard.ErrorAsync(response));
        Assert.Null(Dashboard.SetCookie(response));
    }

    [Fact]
    public async Task Komodo_rate_limit_is_explained()
    {
        _app.Komodo.RateLimited = true;

        using var response = await _api.PostSessionAsync("anna", AnnaPassword);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("Komodo is refusing sign-ins for a moment after several failures; try again in a minute.", await Dashboard.ErrorAsync(response));
        Assert.True(response.Headers.RetryAfter?.Delta > TimeSpan.Zero);
        Assert.Null(Dashboard.SetCookie(response));
    }

    [Fact]
    public async Task Unreadable_jwt_gives_no_session()
    {
        _app.Komodo.FailNext("LoginLocalUser", 200, """{"type":"Jwt","data":{"jwt":"not-a-jwt"}}""");

        using var response = await _api.PostSessionAsync("anna", AnnaPassword);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Null(Dashboard.SetCookie(response));
    }

    [Fact]
    public async Task A_jwt_komodo_rejects_ends_the_session()
    {
        var session = await _api.SignInAsync("anna", AnnaPassword);
        var resolved = await _api.Services.GetRequiredService<Sessions>().ResolveAsync(session, Ct);
        Assert.NotNull(resolved);

        // An /api endpoint whose Komodo call with the session's JWT is refused, as ApiErrors.Filter sees it.
        using var scope = _api.Services.CreateScope();
        var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        http.Request.Headers.Cookie = $"{Dashboard.Cookie}={session}";
        http.Response.Body = new MemoryStream();
        http.Features.Set(RequestCaller.ForSession(resolved.User, resolved.Jwt, resolved.ExpiresAt));
        var result = await ApiErrors.Filter(
            new DefaultEndpointFilterInvocationContext(http),
            _ => throw new KomodoException(KomodoErrorKind.Unauthorized, 500, "CreateApiKey: Invalid user credentials"));
        await Assert.IsAssignableFrom<IResult>(result).ExecuteAsync(http);

        Assert.Equal(StatusCodes.Status401Unauthorized, http.Response.StatusCode);
        http.Response.Body.Position = 0;
        Assert.Contains("Your Komodo sign-in has ended; sign in again.", await new StreamReader(http.Response.Body).ReadToEndAsync(Ct));
        Assert.StartsWith(Dashboard.Cookie + "=;", http.Response.Headers.SetCookie.ToString());
        using var after = await _api.SendAsync(HttpMethod.Get, "/api/session", session: session);
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Fact]
    public async Task Sign_in_logs_no_password_or_jwt()
    {
        using (var wrong = await _api.PostSessionAsync("anna", "anna-wrong-password"))
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        var session = await _api.SignInAsync("anna", AnnaPassword);
        var jwt = _app.Komodo.IssuedJwts[^1];
        using (var who = await _api.SendAsync(HttpMethod.Get, "/api/session", session: session))
            Assert.Equal(HttpStatusCode.OK, who.StatusCode);
        using (var signOut = await _api.SendAsync(HttpMethod.Delete, "/api/session", session: session))
            Assert.Equal(HttpStatusCode.NoContent, signOut.StatusCode);

        Assert.NotEmpty(_log.Lines);
        foreach (var line in _log.Lines)
        {
            Assert.False(line.Contains(AnnaPassword, StringComparison.Ordinal), "A log line holds the password.");
            Assert.False(line.Contains("anna-wrong-password", StringComparison.Ordinal), "A log line holds a wrong password.");
            Assert.False(line.Contains(jwt, StringComparison.Ordinal) || line.Contains("eyJ", StringComparison.Ordinal), "A log line holds the JWT.");
            Assert.False(line.Contains(session, StringComparison.Ordinal), "A log line holds the session cookie.");
        }
    }

    private async Task<List<string>> PendingKeysAsync() =>
        (await _app.Database.GetCollection<BsonDocument>("pending_deletions").Find(Builders<BsonDocument>.Filter.Eq("user", AnnaId)).ToListAsync(Ct))
            .Select(d => d["komodoKey"].AsString).ToList();

    private static bool Contains(byte[] haystack, byte[] needle) => haystack.AsSpan().IndexOf(needle) >= 0;
}
