// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Komogentic.Server.Accounts;
using Komogentic.Server.OAuth;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Komogentic.Server.Tests.OAuth;

/// <summary>
/// The authorisation endpoint (spec §5): anonymous, it checks the request, stores it server-side for ten minutes and
/// sends the browser to the consent page; errors stay on our page until the redirect URI is the client's own.
/// </summary>
[Collection("app")]
public sealed class AuthorizeTests(AppFactory app)
{
    private const string Callback = "https://claude.test/cb";
    private const string Issuer = AppFactory.PublicUrl;

    private static readonly KomodoUser Anna = new("u-anna", "anna");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private WebApplicationFactory<Program> Api => app.PublicApi;

    private IMongoCollection<BsonDocument> Collection(string name) => app.Database.GetCollection<BsonDocument>(name);

    /// <summary>One authorisation request: a connection of Anna's, a registered client, a fresh verifier and state.</summary>
    private sealed record Flow(string ConnectionId, string ClientId, string RedirectUri, string Verifier, string State, string? Scope)
    {
        public string Resource => $"{Issuer}/mcp/c/{ConnectionId}";

        /// <summary>The query sent to <c>/oauth/authorize</c>; a change with a null value removes that parameter.</summary>
        public Dictionary<string, string?> Parameters(params (string Name, string? Value)[] changes)
        {
            var query = new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["client_id"] = ClientId,
                ["redirect_uri"] = RedirectUri,
                ["code_challenge"] = ChallengeOf(Verifier),
                ["code_challenge_method"] = "S256",
                ["state"] = State,
                ["resource"] = Resource,
            };
            if (Scope is not null) query["scope"] = Scope;
            foreach (var (name, value) in changes) query[name] = value;
            return query;
        }
    }

    private async Task<Flow> FlowAsync(string? scope = null, string redirectUri = Callback, WebApplicationFactory<Program>? api = null)
    {
        api ??= Api;
        var connection = await api.Services.GetRequiredService<Connections>().CreateAsync(Anna, "claude " + Guid.NewGuid().ToString("N")[..8], null, Ct);
        var client = await RegisterAsync(api, redirectUri);
        return new Flow(connection.Id, client, redirectUri, NewVerifier(), "st-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8)), scope);
    }

    private static async Task<string> RegisterAsync(WebApplicationFactory<Program> api, string redirectUri)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth/register")
        {
            Content = new StringContent(JsonSerializer.Serialize(new { client_name = "Test app", redirect_uris = new[] { redirectUri } }), Encoding.UTF8, "application/json"),
        };
        request.Headers.Add("X-Forwarded-For", Address());
        using var client = api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri("https://localhost") });
        using var response = await client.SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
        return body.RootElement.GetProperty("client_id").GetString()!;
    }

    /// <summary>A GET of <c>/oauth/authorize</c> as a browser navigating there: no cookie unless given, no redirect followed.</summary>
    private static async Task<HttpResponseMessage> AuthorizeAsync(WebApplicationFactory<Program> api, IEnumerable<KeyValuePair<string, string?>> query, string? cookie = null)
    {
        var url = QueryHelpers.AddQueryString("/oauth/authorize", query.Where(p => p.Value is not null));
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (cookie is not null) request.Headers.Add("Cookie", cookie);
        request.Headers.Add("X-Forwarded-For", Address());
        using var client = api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
        return await client.SendAsync(request, Ct);
    }

    /// <summary>Asserts the 303 to the consent page and returns the stored request.</summary>
    private async Task<BsonDocument> PendingAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        var location = Location(response);
        Assert.StartsWith("/consent?request=", location, StringComparison.Ordinal);
        var id = QueryOf(location)["request"];
        Assert.Matches("^[0-9a-f]{32}$", id);
        return await Collection("oauth_requests").Find(new BsonDocument("_id", id)).SingleAsync(Ct);
    }

    private static string NewVerifier() => Base64Url(RandomNumberGenerator.GetBytes(32));

    private static string ChallengeOf(string verifier) => Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static Dictionary<string, string> QueryOf(string url)
    {
        var question = url.IndexOf('?', StringComparison.Ordinal);
        return question < 0 ? [] : QueryHelpers.ParseQuery(url[question..]).ToDictionary(p => p.Key, p => p.Value.ToString());
    }

    /// <summary>An address of its own per request, so the per-address limits of other tests don't reach it.</summary>
    private static string Address() => $"198.23.{Random.Shared.Next(256)}.{Random.Shared.Next(1, 255)}";

    private static string Location(HttpResponseMessage response) => response.Headers.Location!.OriginalString;

    private static void AssertRedirectedError(HttpResponseMessage response, Flow flow, string error)
    {
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        var location = Location(response);
        Assert.StartsWith(flow.RedirectUri + "?", location, StringComparison.Ordinal);
        var query = QueryOf(location);
        Assert.Equal(error, query["error"]);
        Assert.False(string.IsNullOrEmpty(query["error_description"]));
        Assert.Equal(flow.State, query["state"]);
        Assert.Equal(Issuer, query["iss"]);
        Assert.False(query.ContainsKey("code"));
    }

    [Fact]
    public async Task A_valid_request_is_stored_for_ten_minutes_and_goes_to_the_consent_page()
    {
        var flow = await FlowAsync();

        using var response = await AuthorizeAsync(Api, flow.Parameters());
        var request = await PendingAsync(response);

        Assert.Equal(flow.ClientId, request["client"].AsString);
        Assert.Equal(Callback, request["redirectUri"].AsString);
        Assert.Equal(flow.State, request["state"].AsString);
        Assert.Equal(ChallengeOf(flow.Verifier), request["codeChallenge"].AsString);
        Assert.Equal(flow.Resource, request["resource"].AsString);
        Assert.Equal(flow.ConnectionId, request["connection"].AsString);
        Assert.False(request["readOnly"].AsBoolean);
        Assert.False(request.Contains("problem"));
        Assert.InRange(request["expiresAt"].ToUniversalTime(), DateTime.UtcNow.AddMinutes(10).AddSeconds(-30), DateTime.UtcNow.AddMinutes(10).AddSeconds(1));
        var indexes = await (await Collection("oauth_requests").Indexes.ListAsync(Ct)).ToListAsync(Ct);
        Assert.Contains(indexes, i => i["key"].AsBsonDocument.Contains("expiresAt") && i.Contains("expireAfterSeconds"));

        var pending = await Api.Services.GetRequiredService<AuthorizationRequests>().GetAsync(request["_id"].AsString, Ct);
        Assert.NotNull(pending);
        Assert.Equal(flow.ConnectionId, pending.ConnectionId);
    }

    [Fact]
    public async Task Plain_pkce_is_refused()
    {
        var flow = await FlowAsync();

        foreach (var change in new (string, string?)[] { ("code_challenge_method", "plain"), ("code_challenge_method", null), ("code_challenge", null), ("code_challenge", "short") })
        {
            using var response = await AuthorizeAsync(Api, flow.Parameters(change));
            AssertRedirectedError(response, flow, "invalid_request");
        }
    }

    [Fact]
    public async Task Other_response_types_are_refused()
    {
        var flow = await FlowAsync();

        using var token = await AuthorizeAsync(Api, flow.Parameters(("response_type", "token")));
        using var missing = await AuthorizeAsync(Api, flow.Parameters(("response_type", null)));

        AssertRedirectedError(token, flow, "unsupported_response_type");
        AssertRedirectedError(missing, flow, "unsupported_response_type");
    }

    [Fact]
    public async Task A_missing_state_is_left_out_of_the_redirect()
    {
        var flow = await FlowAsync();

        using var response = await AuthorizeAsync(Api, flow.Parameters(("state", null), ("code_challenge_method", "plain")));

        var query = QueryOf(Location(response));
        Assert.Equal("invalid_request", query["error"]);
        Assert.False(query.ContainsKey("state"));
        Assert.Equal(Issuer, query["iss"]);
    }

    [Fact]
    public async Task A_state_that_is_too_long_is_refused_and_not_echoed()
    {
        var flow = await FlowAsync();

        using var response = await AuthorizeAsync(Api, flow.Parameters(("state", new string('s', OAuthEndpoints.MaxStateLength + 1))));

        var query = QueryOf(Location(response));
        Assert.Equal("invalid_request", query["error"]);
        Assert.False(query.ContainsKey("state"));
    }

    [Fact]
    public async Task A_redirect_uri_with_a_query_keeps_it()
    {
        var flow = await FlowAsync(redirectUri: Callback + "?app=1");

        using var response = await AuthorizeAsync(Api, flow.Parameters(("code_challenge_method", "plain")));

        var location = Location(response);
        Assert.StartsWith(Callback + "?app=1&", location, StringComparison.Ordinal);
        Assert.Equal("1", QueryOf(location)["app"]);
        Assert.Equal("invalid_request", QueryOf(location)["error"]);
    }

    [Fact]
    public async Task Unknown_client_and_wrong_redirect_stay_on_our_page()
    {
        var flow = await FlowAsync();

        using var unknown = await AuthorizeAsync(Api, flow.Parameters(("client_id", "kgt_client_" + new string('x', 22))));
        using var garbage = await AuthorizeAsync(Api, flow.Parameters(("client_id", "not a client")));
        using var noClient = await AuthorizeAsync(Api, flow.Parameters(("client_id", null)));
        using var evil = await AuthorizeAsync(Api, flow.Parameters(("redirect_uri", "https://evil.test/cb")));
        using var noRedirect = await AuthorizeAsync(Api, flow.Parameters(("redirect_uri", null)));
        // Even with every other parameter wrong too, nothing goes to an untrusted redirect URI.
        using var evilAndBroken = await AuthorizeAsync(Api, flow.Parameters(("redirect_uri", "https://evil.test/cb"), ("response_type", "token"), ("code_challenge", null)));

        foreach (var response in new[] { unknown, garbage, noClient })
        {
            Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
            Assert.Equal("/consent?error=unknown_client", Location(response));
        }

        foreach (var response in new[] { evil, noRedirect, evilAndBroken })
        {
            Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
            Assert.Equal("/consent?error=invalid_redirect_uri", Location(response));
        }
    }

    [Fact]
    public async Task Repeated_parameters_are_refused()
    {
        var flow = await FlowAsync();
        var parameters = flow.Parameters().Where(p => p.Value is not null).Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value!)}");

        async Task<HttpResponseMessage> WithTwice(string name, string value)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/oauth/authorize?" + string.Join('&', parameters) + $"&{name}={Uri.EscapeDataString(value)}");
            request.Headers.Add("X-Forwarded-For", Address());
            using var client = Api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
            return await client.SendAsync(request, Ct);
        }

        using var twoClients = await WithTwice("client_id", flow.ClientId);
        using var twoRedirects = await WithTwice("redirect_uri", "https://evil.test/cb");
        using var twoChallenges = await WithTwice("code_challenge", ChallengeOf(NewVerifier()));

        Assert.Equal("/consent?error=unknown_client", Location(twoClients));
        Assert.Equal("/consent?error=invalid_redirect_uri", Location(twoRedirects));
        Assert.Equal("invalid_request", QueryOf(Location(twoChallenges))["error"]);
    }

    [Theory]
    [InlineData("https://komogentic.test/mcp")]
    [InlineData(null)]
    [InlineData("https://komogentic.test/mcp/c/aaaaaaaaaaaaaaaa")]
    [InlineData("https://elsewhere.test/mcp/c/{id}")]
    public async Task A_resource_that_names_no_connection_goes_to_the_consent_page_as_a_problem(string? resource)
    {
        var flow = await FlowAsync();

        using var response = await AuthorizeAsync(Api, flow.Parameters(("resource", resource?.Replace("{id}", flow.ConnectionId, StringComparison.Ordinal))));
        var request = await PendingAsync(response);

        Assert.Equal(AuthorizationRequests.NotAConnection, request["problem"].AsString);
        Assert.False(request.Contains("connection"));
    }

    [Fact]
    public async Task The_canonical_forms_of_the_connection_url_are_the_connection()
    {
        var flow = await FlowAsync();

        using var response = await AuthorizeAsync(Api, flow.Parameters(("resource", $"HTTPS://KOMOGENTIC.TEST:443/mcp/c/{flow.ConnectionId}/")));
        var request = await PendingAsync(response);

        Assert.Equal(flow.ConnectionId, request["connection"].AsString);
        Assert.False(request.Contains("problem"));
    }

    [Theory]
    [InlineData("komodo:read", true)]
    [InlineData("komodo:read komodo:operate offline_access", false)]
    [InlineData("komodo:operate", false)]
    [InlineData("openid", false)]
    public async Task Read_scope_without_operate_makes_the_request_read_only(string scope, bool readOnly)
    {
        var flow = await FlowAsync(scope);

        using var response = await AuthorizeAsync(Api, flow.Parameters());

        Assert.Equal(readOnly, (await PendingAsync(response))["readOnly"].AsBoolean);
    }

    /// <summary>The public app, whose metadata fetches reach <paramref name="fetches"/> instead of the network.</summary>
    private WebApplicationFactory<Program> WithFetches(CountingHandler fetches) => Api.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        services.AddHttpClient(ClientMetadataServices.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => fetches)));

    /// <summary>Where <c>/oauth/authorize</c> sends a browser at <paramref name="address"/> for the metadata URL <paramref name="clientId"/>.</summary>
    private static async Task<string> AuthorizeLocationAsync(WebApplicationFactory<Program> api, string clientId, string address)
    {
        var url = QueryHelpers.AddQueryString("/oauth/authorize", new Dictionary<string, string?> { ["client_id"] = clientId, ["redirect_uri"] = Callback });
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Add("X-Forwarded-For", address);
        using var client = api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
        using var response = await client.SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        return Location(response);
    }

    private const string Unknown = "/consent?error=unknown_client";
    private const string Limited = "/consent?error=temporarily_unavailable";

    // Ten fetches a minute per address and ten per host of the client_id URL.
    private const int FetchesPerAddress = 10;
    private const int FetchesPerHost = 10;

    [Fact]
    public async Task Authorize_limits_metadata_fetches_per_address()
    {
        var fetches = new CountingHandler();
        var api = WithFetches(fetches);
        const string address = "198.27.1.1";

        // Spread over two hosts, so that neither host's own limit is reached.
        for (var i = 0; i < FetchesPerAddress; i++)
        {
            Assert.Equal(Unknown, await AuthorizeLocationAsync(api, $"https://{(i % 2 == 0 ? "a" : "b")}.example/client-{i}.json", address));
        }

        Assert.Equal(FetchesPerAddress, fetches.Total);
        Assert.Equal(Limited, await AuthorizeLocationAsync(api, "https://a.example/one-more.json", address));
        Assert.Equal(FetchesPerAddress, fetches.Total);

        // A document in the cache needs no fetch, so it isn't held back.
        Assert.Equal(Unknown, await AuthorizeLocationAsync(api, "https://a.example/client-0.json", address));
        // Another address still fetches.
        Assert.Equal(Unknown, await AuthorizeLocationAsync(api, "https://a.example/one-more.json", "198.27.1.2"));
        Assert.Equal(FetchesPerAddress + 1, fetches.Total);
    }

    [Fact]
    public async Task Authorize_limits_metadata_fetches_per_client_host()
    {
        var fetches = new CountingHandler();
        var api = WithFetches(fetches);

        for (var i = 0; i < FetchesPerHost; i++)
        {
            Assert.Equal(Unknown, await AuthorizeLocationAsync(api, $"https://a.example/client-{i}.json", $"198.28.1.{i + 1}"));
        }

        Assert.Equal(FetchesPerHost, fetches.Of("a.example"));
        Assert.Equal(Limited, await AuthorizeLocationAsync(api, "https://a.example/one-more.json", "198.28.2.1"));
        Assert.Equal(FetchesPerHost, fetches.Of("a.example"));

        // The same address may still fetch from another host.
        Assert.Equal(Unknown, await AuthorizeLocationAsync(api, "https://b.example/client.json", "198.28.2.1"));
        Assert.Equal(1, fetches.Of("b.example"));
    }

    [Fact]
    public async Task A_fetch_that_waits_too_long_for_its_turn_ends_on_the_unavailable_page()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new HoldingHandler(release.Task);
        // The fetcher on a clock of its own, so that its wait for a turn ends when the test says, not after 5 s of the held fetches' own.
        var time = new FakeTimeProvider();
        var api = Api.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            services.AddHttpClient(ClientMetadataServices.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => handler);
            services.RemoveAll<ClientMetadataFetcher>();
            services.AddSingleton(sp => new ClientMetadataFetcher(
                sp.GetRequiredService<IHttpClientFactory>(), sp.GetRequiredService<IOptions<KomogenticOptions>>(), time, sp.GetRequiredService<ILogger<ClientMetadataFetcher>>()));
        }));

        var held = Enumerable.Range(0, 8).Select(i => AuthorizeLocationAsync(api, $"https://c{i}.example/client.json", $"198.29.1.{i + 1}")).ToList();
        await handler.StartedAsync(8);
        var ninth = AuthorizeLocationAsync(api, "https://ninth.example/client.json", "198.29.2.1");
        await Task.Delay(100, Ct);
        Assert.False(ninth.IsCompleted);
        time.Advance(ClientMetadataFetcher.Timeout);

        Assert.Equal(Limited, await ninth.WaitAsync(TimeSpan.FromSeconds(4), Ct));
        Assert.Equal(8, handler.Started);

        release.SetResult();
        Assert.All(await Task.WhenAll(held), location => Assert.Equal(Unknown, location));
    }

    /// <summary>Stands in for the hosts of metadata documents: counts the requests per host and answers each with a 404.</summary>
    private sealed class CountingHandler : HttpMessageHandler
    {
        private readonly ConcurrentQueue<string> _hosts = new();

        public int Total => _hosts.Count;

        public int Of(string host) => _hosts.Count(h => h == host);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _hosts.Enqueue(request.RequestUri!.Host);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    [Fact]
    public async Task A_client_identified_by_its_metadata_document_reaches_the_consent_page()
    {
        await using var server = await MetadataServer.StartAsync(new MetadataResponse());
        server.Response = () => new MetadataResponse(
            $$"""{"client_id":"{{server.ClientId}}","client_name":"Claude","redirect_uris":["{{Callback}}"],"token_endpoint_auth_method":"none"}""");
        var api = Api.WithWebHostBuilder(b => b.UseSetting("Komogentic:OAuth:AllowLoopbackClients", "true"));
        var flow = (await FlowAsync(api: api)) with { ClientId = server.ClientId };

        using var response = await AuthorizeAsync(api, flow.Parameters());

        Assert.Equal(server.ClientId, (await PendingAsync(response))["client"].AsString);
        Assert.Equal(1, server.Requests);
    }

    [Fact]
    public async Task Authorize_needs_no_cookie()
    {
        var flow = await FlowAsync();

        // Without a cookie (as claude.ai's cross-site navigation arrives), and with a bogus one, alike.
        using var bogus = await AuthorizeAsync(Api, flow.Parameters(), cookie: "kgt_session=nonsense");

        Assert.Equal(HttpStatusCode.SeeOther, bogus.StatusCode);
        Assert.StartsWith("/consent?request=", Location(bogus), StringComparison.Ordinal);
        Assert.Equal("no-store", bogus.Headers.CacheControl?.ToString());
        Assert.Equal("no-referrer", bogus.Headers.GetValues("Referrer-Policy").Single());
        Assert.False(bogus.Headers.Contains("Set-Cookie"));
        Assert.False(bogus.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task Errors_carry_no_store_and_no_referrer_too()
    {
        var flow = await FlowAsync();

        using var page = await AuthorizeAsync(Api, flow.Parameters(("client_id", null)));
        using var redirected = await AuthorizeAsync(Api, flow.Parameters(("code_challenge", null)));

        foreach (var response in new[] { page, redirected })
        {
            Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
            Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        }
    }

    [Fact]
    public async Task The_request_is_logged_without_its_secrets()
    {
        var log = new CapturedLog();
        var api = Api.WithWebHostBuilder(b => b.ConfigureLogging(l => l.AddProvider(log)));
        var flow = await FlowAsync(api: api);

        using var response = await AuthorizeAsync(api, flow.Parameters());
        var requestId = (await PendingAsync(response))["_id"].AsString;

        var lines = log.Lines.Where(l => l.Contains("OAuth ", StringComparison.Ordinal)).ToList();
        Assert.Contains(lines, l => l.Contains("OAuth authorize pending", StringComparison.Ordinal) && l.Contains(flow.ConnectionId, StringComparison.Ordinal)
            && l.Contains("claude.test", StringComparison.Ordinal) && l.Contains(requestId, StringComparison.Ordinal));
        foreach (var line in log.Lines)
        {
            Assert.DoesNotContain(flow.State, line, StringComparison.Ordinal);
            Assert.DoesNotContain(ChallengeOf(flow.Verifier), line, StringComparison.Ordinal);
        }
    }
}
