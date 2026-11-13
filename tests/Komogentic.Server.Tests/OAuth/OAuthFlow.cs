// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Komogentic.Server.Accounts;
using Komogentic.Server.Tests.Api;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;

namespace Komogentic.Server.Tests.OAuth;

/// <summary>A Komodo user of the fake Core, signed in to the dashboard: the session cookie's value.</summary>
public sealed record Owner(string UserId, string Username, string Password, string Session)
{
    private static int _count;

    public KomodoUser User => new(UserId, Username);

    /// <summary>A new Komodo user, of this test alone, signed in to <paramref name="api"/>.</summary>
    public static async Task<Owner> NewAsync(AppFactory app, WebApplicationFactory<Program> api)
    {
        var n = Interlocked.Increment(ref _count);
        var suffix = $"{n}-{Guid.NewGuid().ToString("N")[..6]}";
        var (id, username, password) = ($"u-anna-oauth-{suffix}", $"anna-oauth-{suffix}", "anna-komodo-password");
        app.Komodo.AddUser(id, username, password);
        return new Owner(id, username, password, await api.SignInAsync(username, password));
    }

    /// <summary>A fresh session of the same user, on <paramref name="api"/>.</summary>
    public async Task<Owner> SignInAgainAsync(WebApplicationFactory<Program> api) => this with { Session = await api.SignInAsync(Username, Password) };
}

/// <summary>
/// One authorisation as an app and its user go through it on <see cref="AppFactory.PublicApi"/> (or a host derived
/// from it): the app sends the browser to <c>/oauth/authorize</c> (here without following the redirect), the user's
/// consent page reads the pending request and posts the decision with the user's session and our <c>Origin</c>, and
/// the app exchanges the code at <c>/oauth/token</c>. Each step is a method, so a test can stop at any of them or vary
/// one. <see cref="StartAsync"/> sends a fresh PKCE verifier and <c>state</c>, and <c>resource</c> = the connection's
/// URL; it asserts the 303 to <c>/consent?request={id}</c>.
/// </summary>
public sealed class OAuthFlow
{
    /// <summary>The issuer, as <c>iss</c> in every redirect: the public origin.</summary>
    public const string Issuer = AppFactory.PublicUrl;

    public const string Callback = "https://claude.test/cb";

    private const string Initialize =
        """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}""";

    private readonly WebApplicationFactory<Program> _api;

    private OAuthFlow(WebApplicationFactory<Program> api, Owner owner, string connectionId, string clientId, string redirectUri, string? scope)
    {
        _api = api;
        Owner = owner;
        ConnectionId = connectionId;
        ClientId = clientId;
        RedirectUri = redirectUri;
        Scope = scope;
        Resource = ResourceOf(connectionId);
        Verifier = NewVerifier();
        State = "st-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
    }

    private OAuthFlow(OAuthFlow other, Owner? owner = null)
    {
        _api = other._api;
        Owner = owner ?? other.Owner;
        ConnectionId = other.ConnectionId;
        ClientId = other.ClientId;
        RedirectUri = other.RedirectUri;
        Scope = other.Scope;
        Resource = other.Resource;
        Verifier = other.Verifier;
        State = other.State;
    }

    public Owner Owner { get; }

    public string ConnectionId { get; }

    public string ClientId { get; }

    public string RedirectUri { get; }

    public string? Scope { get; }

    /// <summary>The connection's URL, sent as <c>resource</c>.</summary>
    public string Resource { get; }

    /// <summary>The PKCE code verifier (43 characters of base64url); the challenge sent is <see cref="ChallengeOf"/> of it.</summary>
    public string Verifier { get; }

    public string State { get; }

    /// <summary>The pending request's id from the 303 to <c>/consent?request={id}</c>.</summary>
    public string RequestId { get; private set; } = "";

    /// <summary>The code of the last <see cref="AllowAsync"/>, or null before it.</summary>
    public string? Code { get; private set; }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static string ResourceOf(string connectionId) => $"{AppFactory.PublicUrl}/mcp/c/{connectionId}";

    /// <summary>A connection of <paramref name="owner"/>'s, made through the server's own service.</summary>
    public static async Task<string> ConnectionAsync(WebApplicationFactory<Program> api, Owner owner, string? name = null, int? expiresInDays = null) =>
        (await api.Services.GetRequiredService<Connections>().CreateAsync(owner.User, name ?? "Grok " + Guid.NewGuid().ToString("N")[..6], expiresInDays, Ct)).Id;

    /// <summary>Starts an authorisation for <paramref name="connectionId"/>'s URL and asserts it reaches the consent page.</summary>
    public static async Task<OAuthFlow> StartAsync(
        WebApplicationFactory<Program> api, Owner owner, string connectionId, string clientId, string redirectUri = Callback, string? scope = null)
    {
        var flow = new OAuthFlow(api, owner, connectionId, clientId, redirectUri, scope);
        flow.RequestId = await ConsentPageAsync(api, flow.Parameters());
        return flow;
    }

    /// <summary>A new user's connection, with a fresh registered client, at the consent page.</summary>
    public static async Task<OAuthFlow> NewAsync(AppFactory app, WebApplicationFactory<Program> api, int? expiresInDays = null, string? scope = null)
    {
        var owner = await Owner.NewAsync(app, api);
        var id = await ConnectionAsync(api, owner, expiresInDays: expiresInDays);
        return await StartAsync(api, owner, id, await RegisterAsync(api, Callback), Callback, scope);
    }

    /// <summary>Another authorisation request with this flow's parameters, changed as in <see cref="Parameters"/>
    /// (same verifier and state), by <paramref name="owner"/> if given; returns the flow of that request.</summary>
    public async Task<OAuthFlow> AgainAsync(Owner? owner = null, params (string Name, string? Value)[] changes)
    {
        var flow = new OAuthFlow(this, owner);
        flow.RequestId = await ConsentPageAsync(_api, Parameters(changes));
        return flow;
    }

    private static async Task<string> ConsentPageAsync(WebApplicationFactory<Program> api, Dictionary<string, string?> query)
    {
        using var response = await AuthorizeAsync(api, query);
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        var location = response.Headers.Location!.OriginalString;
        Assert.StartsWith("/consent?request=", location, StringComparison.Ordinal);
        return QueryOf(location)["request"];
    }

    /// <summary>The query this flow sends to <c>/oauth/authorize</c>; a change with a null value removes that parameter.</summary>
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

    /// <summary>A GET of <c>/oauth/authorize</c>, as a browser navigating there: no cookie, no redirect followed.</summary>
    public static async Task<HttpResponseMessage> AuthorizeAsync(WebApplicationFactory<Program> api, IEnumerable<KeyValuePair<string, string?>> query)
    {
        var url = QueryHelpers.AddQueryString("/oauth/authorize", query.Where(p => p.Value is not null));
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Add("X-Forwarded-For", Dashboard.NewAddress());
        using var client = api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
        return await client.SendAsync(request, Ct);
    }

    /// <summary>The consent page's read of the request, as <paramref name="user"/> (the owner by default).</summary>
    public Task<HttpResponseMessage> GetConsentAsync(Owner? user = null) =>
        _api.SendAsync(HttpMethod.Get, $"/api/oauth/requests/{RequestId}", session: (user ?? Owner).Session);

    public async Task<JsonElement> ConsentAsync(Owner? user = null)
    {
        using var response = await GetConsentAsync(user);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await Dashboard.JsonAsync(response);
    }

    /// <summary>The consent page's Allow or Deny, as <paramref name="user"/> (the owner by default), with the session and our <c>Origin</c>.</summary>
    public Task<HttpResponseMessage> DecideAsync(bool allow, Owner? user = null) =>
        _api.SendAsync(HttpMethod.Post, $"/api/oauth/requests/{RequestId}/decision", new { allow }, (user ?? Owner).Session);

    /// <summary>The URL the consent page navigates to after a decision that succeeded.</summary>
    public async Task<string> RedirectAfterAsync(bool allow, Owner? user = null)
    {
        using var response = await DecideAsync(allow, user);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await Dashboard.JsonAsync(response)).GetProperty("redirect").GetString()!;
    }

    /// <summary>Allows as the owner and returns the code from the redirect, asserting the redirect URI, <c>state</c> and <c>iss</c>.</summary>
    public async Task<string> AllowAsync()
    {
        var redirect = await RedirectAfterAsync(allow: true);
        Assert.StartsWith(RedirectUri + (RedirectUri.Contains('?', StringComparison.Ordinal) ? "&" : "?"), redirect, StringComparison.Ordinal);
        var query = QueryOf(redirect);
        Assert.Equal(State, query["state"]);
        Assert.Equal(Issuer, query["iss"]);
        Assert.False(query.ContainsKey("error"));
        Code = query["code"];
        return Code;
    }

    /// <summary>
    /// A POST to <c>/oauth/token</c>, form-encoded. Unless the form names another <c>grant_type</c>, it starts from the
    /// exchange of <see cref="Code"/>; entries in <paramref name="form"/> replace those of the same name, and a null
    /// value removes one.
    /// </summary>
    public async Task<HttpResponseMessage> TokenAsync(params (string Name, string? Value)[] form)
    {
        var fields = new Dictionary<string, string?>();
        var grant = form.LastOrDefault(f => f.Name == "grant_type").Value;
        if (grant is null or "authorization_code")
        {
            fields["grant_type"] = "authorization_code";
            fields["code"] = Code;
            fields["redirect_uri"] = RedirectUri;
            fields["client_id"] = ClientId;
            fields["code_verifier"] = Verifier;
            fields["resource"] = Resource;
        }

        foreach (var (name, value) in form) fields[name] = value;
        return await PostFormAsync(_api, "/oauth/token", Dashboard.NewAddress(), fields.Where(f => f.Value is not null).Select(f => (f.Key, f.Value!)).ToArray());
    }

    /// <summary><c>grant_type=refresh_token</c> with <paramref name="refreshToken"/> and this flow's client id;
    /// entries in <paramref name="form"/> are added or replace those, a null value removes one.</summary>
    public Task<HttpResponseMessage> RefreshAsync(string refreshToken, params (string Name, string? Value)[] form) =>
        TokenAsync([("grant_type", "refresh_token"), ("refresh_token", refreshToken), ("client_id", ClientId), .. form]);

    /// <summary>A POST to <c>/oauth/revoke</c> (RFC 7009) with <paramref name="token"/> and this flow's client id.</summary>
    public Task<HttpResponseMessage> RevokeAsync(string token, string? hint = null)
    {
        var fields = new List<(string, string)> { ("token", token), ("client_id", ClientId) };
        if (hint is not null) fields.Add(("token_type_hint", hint));
        return PostFormAsync(_api, "/oauth/revoke", Dashboard.NewAddress(), [.. fields]);
    }

    /// <summary>Exchanges <see cref="Code"/> and answers the pair.</summary>
    public async Task<Pair> ExchangeAsync()
    {
        using var response = await TokenAsync();
        return await PairOf(response);
    }

    public static async Task<Pair> PairOf(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl!.NoStore);
        var json = await Dashboard.JsonAsync(response);
        return new Pair(
            json.GetProperty("access_token").GetString()!, json.GetProperty("refresh_token").GetString()!, json.GetProperty("expires_in").GetInt32(),
            json.GetProperty("scope").GetString()!);
    }

    /// <summary>The OAuth error of a 400 answer.</summary>
    public static async Task<string> ErrorOf(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        return (await Dashboard.JsonAsync(response)).GetProperty("error").GetString()!;
    }

    public static async Task<HttpResponseMessage> PostFormAsync(WebApplicationFactory<Program> api, string path, string address, params (string Name, string Value)[] fields)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new FormUrlEncodedContent(fields.Select(f => new KeyValuePair<string, string>(f.Name, f.Value))),
        };
        request.Headers.Add("X-Forwarded-For", address);
        using var client = api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, AllowAutoRedirect = false, BaseAddress = new Uri(AppFactory.PublicUrl) });
        return await client.SendAsync(request, Ct);
    }

    /// <summary>An MCP <c>initialize</c> on <paramref name="path"/>, as a raw POST.</summary>
    public static async Task<HttpResponseMessage> InitializeAsync(
        WebApplicationFactory<Program> api, string path, string? bearer, string? address = null, string? cookie = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new StringContent(Initialize, Encoding.UTF8, "application/json") };
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        if (bearer is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (cookie is not null) request.Headers.Add("Cookie", $"{Dashboard.Cookie}={cookie}");
        request.Headers.Add("X-Forwarded-For", address ?? Dashboard.NewAddress());
        using var client = api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) });
        return await client.SendAsync(request, Ct);
    }

    /// <summary>The status of an MCP <c>initialize</c> on this flow's connection URL with <paramref name="access"/>.</summary>
    public async Task<HttpStatusCode> InitializeStatusAsync(string access, WebApplicationFactory<Program>? api = null)
    {
        using var response = await InitializeAsync(api ?? _api, $"/mcp/c/{ConnectionId}", access);
        return response.StatusCode;
    }

    /// <summary>The connection as its owner's dashboard lists it.</summary>
    public async Task<JsonElement> ListedAsync()
    {
        using var response = await _api.SendAsync(HttpMethod.Get, "/api/connections", session: Owner.Session);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await Dashboard.JsonAsync(response)).EnumerateArray().Single(c => c.GetProperty("id").GetString() == ConnectionId);
    }

    /// <summary>The connection's state and reason, from the owner's dashboard.</summary>
    public async Task<(string State, string? Reason)> StateAsync()
    {
        var listed = await ListedAsync();
        return (listed.GetProperty("state").GetString()!, listed.GetProperty("reason").GetString());
    }

    /// <summary>Registers a public client with one redirect URI (RFC 7591) and returns its client id.</summary>
    public static async Task<string> RegisterAsync(WebApplicationFactory<Program> api, string redirectUri = Callback, string name = "Test app")
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth/register")
        {
            Content = new StringContent(JsonSerializer.Serialize(new { client_name = name, redirect_uris = new[] { redirectUri } }), Encoding.UTF8, "application/json"),
        };
        request.Headers.Add("X-Forwarded-For", Dashboard.NewAddress());
        using var client = api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri("https://localhost") });
        using var response = await client.SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
        return body.RootElement.GetProperty("client_id").GetString()!;
    }

    /// <summary>A PKCE verifier: 32 random bytes in base64url, 43 characters (RFC 7636 §4.1).</summary>
    public static string NewVerifier() => Base64Url(RandomNumberGenerator.GetBytes(32));

    /// <summary>The S256 challenge of <paramref name="verifier"/>: <c>BASE64URL(SHA256(ASCII(verifier)))</c>.</summary>
    public static string ChallengeOf(string verifier) => Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    /// <summary>The query of a URL (absolute or relative), one value per name.</summary>
    public static Dictionary<string, string> QueryOf(string url)
    {
        var question = url.IndexOf('?', StringComparison.Ordinal);
        return question < 0 ? [] : QueryHelpers.ParseQuery(url[question..]).ToDictionary(p => p.Key, p => p.Value.ToString());
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>A pair from the token endpoint.</summary>
public sealed record Pair(string Access, string Refresh, int ExpiresIn, string Scope);
