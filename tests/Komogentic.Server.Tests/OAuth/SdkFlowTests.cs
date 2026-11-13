// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Komogentic.Server.Tests.Api;
using Komogentic.Server.Tests.Komodo;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using ModelContextProtocol.Authentication;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Komogentic.Server.Tests.OAuth;

/// <summary>
/// The whole flow as an app runs it, with the official SDK's OAuth client (spec §3 goals, §5): only the connection's
/// URL is given; from its 401 the client finds the metadata, registers itself (asking for <c>client_secret_post</c>,
/// answered <c>none</c>), authorises with PKCE and the owner's consent, exchanges the code, calls the tools, and
/// refreshes once the access token has expired.
/// </summary>
[Collection("app")]
public sealed class SdkFlowTests(AppFactory app) : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => app.Komodo.Time = TimeProvider.System;

    [Fact]
    public async Task Sdk_client_connects_with_only_the_url_and_lists_stacks()
    {
        var owner = await Owner.NewAsync(app, app.PublicApi);
        var stack = SdkConnector.AddStack(app, owner, "sdk", FakePermission.Read);
        var id = await SdkConnector.ConnectionAsync(app.PublicApi, owner, "Grok assistant");
        var sdk = new SdkConnector(app.PublicApi, owner, id);

        await using var client = await sdk.ConnectAsync();
        var text = await SdkConnector.OkAsync(client, "list_stacks");

        Assert.Contains($"{stack.Name} — server-1 — running — green", text, StringComparison.Ordinal);
        Assert.Equal(1, sdk.Authorisations);
        var lines = sdk.Lines.ToList();
        int At(string line)
        {
            var index = lines.IndexOf(line);
            Assert.True(index >= 0, $"Not seen: {line}; the server saw:\n" + string.Join('\n', lines));
            return index;
        }

        var challenge = At($"POST /mcp/c/{id} 401");
        var resource = At($"GET /.well-known/oauth-protected-resource/mcp/c/{id} 200");
        var server = At("GET /.well-known/oauth-authorization-server 200");
        var register = At("POST /oauth/register 201");
        var authorize = At("GET /oauth/authorize 303");
        var token = At("POST /oauth/token 200");
        var used = lines.LastIndexOf($"POST /mcp/c/{id} 200");
        Assert.True(challenge < resource && resource < server && server < register && register < authorize && authorize < token && token < used,
            string.Join('\n', lines));

        // The C# SDK asks for client_secret_post; a public client is all there is, and the answer says so.
        Assert.Equal("client_secret_post", sdk.RegistrationAsked);
        Assert.Equal("none", sdk.RegistrationAnswered);
        // PKCE with S256, for the connection's URL as the resource.
        Assert.Equal("S256", sdk.AuthorizeQuery["code_challenge_method"]);
        Assert.Matches("^[A-Za-z0-9_-]{43}$", sdk.AuthorizeQuery["code_challenge"]);
        Assert.Equal(OAuthFlow.ResourceOf(id), sdk.AuthorizeQuery["resource"]);
        Assert.Equal(["authorization_code"], sdk.Grants);
        Assert.Equal(("connected", (string?)null), await SdkConnector.StateAsync(app.PublicApi, owner, id));
    }

    [Fact]
    public async Task Sdk_client_refreshes_after_the_access_token_expires()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        app.Komodo.Time = time;
        using var api = app.PublicApi.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
        {
            s.RemoveAll<TimeProvider>();
            s.AddSingleton<TimeProvider>(time);
        }));
        var owner = await Owner.NewAsync(app, api);
        var stack = SdkConnector.AddStack(app, owner, "refresh", FakePermission.Read);
        var id = await SdkConnector.ConnectionAsync(api, owner, "claude.ai");
        var sdk = new SdkConnector(api, owner, id);
        await using var client = await sdk.ConnectAsync();
        Assert.Contains(stack.Name, await SdkConnector.OkAsync(client, "list_stacks"), StringComparison.Ordinal);

        // An hour later the access token has expired: the server refuses it, and the client refreshes on its own.
        time.Advance(TimeSpan.FromMinutes(61));
        var later = await SdkConnector.OkAsync(client, "list_stacks");

        Assert.Contains(stack.Name, later, StringComparison.Ordinal);
        Assert.Equal(["authorization_code", "refresh_token"], sdk.Grants);
        Assert.Equal(1, sdk.Authorisations);
        var lines = sdk.Lines.ToList();
        var refused = lines.LastIndexOf($"POST /mcp/c/{id} 401");
        var refreshed = lines.LastIndexOf("POST /oauth/token 200");
        Assert.True(refused >= 0 && refused < refreshed && refreshed < lines.LastIndexOf($"POST /mcp/c/{id} 200"), string.Join('\n', lines));
        // The dashboard session ended meanwhile (30 minutes idle); the connection did not.
        Assert.Equal(("connected", (string?)null), await SdkConnector.StateAsync(api, await owner.SignInAgainAsync(api), id));
    }

    [Fact]
    public async Task Both_handshakes_work_on_a_connection_url()
    {
        var flow = await OAuthFlow.NewAsync(app, app.PublicApi);
        await flow.AllowAsync();
        var pair = await flow.ExchangeAsync();
        var path = $"/mcp/c/{flow.ConnectionId}";

        var initialize = await SdkConnector.RawAsync(app.PublicApi, path, pair.Access,
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}""",
            []);
        var discover = await SdkConnector.RawAsync(app.PublicApi, path, pair.Access,
            """{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"raw","version":"0"}}}}""",
            [("MCP-Protocol-Version", "2026-07-28"), ("Mcp-Method", "server/discover")]);

        var result = initialize["result"] ?? throw new Xunit.Sdk.XunitException("No result in the initialize answer.");
        Assert.Equal("2025-11-25", result["protocolVersion"]?.GetValue<string>());
        Assert.Equal("komogentic", result["serverInfo"]?["name"]?.GetValue<string>());
        Assert.NotNull(result["capabilities"]?["tools"]);
        // 2026-07-28 carries the server's identity in the result's _meta rather than its body.
        var discovered = discover["result"] ?? throw new Xunit.Sdk.XunitException("No result in the server/discover answer.");
        var info = discovered["serverInfo"] ?? discovered["_meta"]?["io.modelcontextprotocol/serverInfo"];
        Assert.Equal("komogentic", info?["name"]?.GetValue<string>());
    }
}

/// <summary>
/// The MCP SDK's own client with OAuth on a connection's URL, as an app runs it: nothing but the URL and a redirect
/// URI is given, the client registers itself (DCR). Its authorisation handler plays the browser and the user: it GETs
/// the authorisation URL, follows the 303 to the consent page, has the owner allow (session and <c>Origin</c>) and
/// hands back what the redirect carries. Every request the app's server answers is recorded as <c>METHOD path status</c>
/// (no query: it carries the state and the challenge), each from an address of its own.
/// </summary>
internal sealed class SdkConnector(WebApplicationFactory<Program> api, Owner owner, string connectionId)
{
    public const string Callback = "http://127.0.0.1:1/callback";

    private readonly ConcurrentQueue<string> _lines = new();
    private readonly ConcurrentQueue<string> _grants = new();
    private int _authorisations;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public IReadOnlyCollection<string> Lines => _lines.ToArray();

    /// <summary>The <c>grant_type</c> of every successful token request, in order.</summary>
    public IReadOnlyList<string> Grants => [.. _grants];

    /// <summary>How often the client sent the user to consent.</summary>
    public int Authorisations => _authorisations;

    public string? RegistrationAsked { get; private set; }

    public string? RegistrationAnswered { get; private set; }

    /// <summary>The query of the last authorisation, without <c>state</c>.</summary>
    public Dictionary<string, string> AuthorizeQuery { get; private set; } = [];

    /// <summary>A stack of the test's own (its name ends in a fresh suffix) on server-1, with two healthy services.</summary>
    public static FakeStack AddStack(AppFactory app, Owner owner, string name, FakePermission permission)
    {
        var stack = app.Komodo.AddStack(
            Convert.ToHexStringLower(System.Security.Cryptography.RandomNumberGenerator.GetBytes(12)), $"{name}-{Guid.NewGuid().ToString("N")[..8]}",
            services: [new FakeService("web", "nginx:1", Status: "Up 5 minutes (healthy)"), new FakeService("backend", "app:latest")]);
        app.Komodo.Grant(owner.UserId, stack.Id, permission);
        return stack;
    }

    /// <summary>A connection made in the dashboard, as the user makes it.</summary>
    public static async Task<string> ConnectionAsync(WebApplicationFactory<Program> api, Owner owner, string name)
    {
        using var created = await api.SendAsync(HttpMethod.Post, "/api/connections", new { name, expiresInDays = 90 }, owner.Session);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        return (await Dashboard.JsonAsync(created)).GetProperty("id").GetString()!;
    }

    /// <summary>The connection's state and reason, as the owner's dashboard lists it.</summary>
    public static async Task<(string State, string? Reason)> StateAsync(WebApplicationFactory<Program> api, Owner owner, string id)
    {
        using var response = await api.SendAsync(HttpMethod.Get, "/api/connections", session: owner.Session);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var listed = (await Dashboard.JsonAsync(response)).EnumerateArray().Single(c => c.GetProperty("id").GetString() == id);
        return (listed.GetProperty("state").GetString()!, listed.GetProperty("reason").GetString());
    }

    public async Task<McpClient> ConnectAsync()
    {
        var http = api.CreateDefaultClient(new Uri(AppFactory.PublicUrl), new Recorder(this));
        var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(OAuthFlow.ResourceOf(connectionId)),
                OAuth = new ClientOAuthOptions
                {
                    RedirectUri = new Uri(Callback),
                    DynamicClientRegistration = new DynamicClientRegistrationOptions { ClientName = "Sdk Flow Probe" },
                    AuthorizationCallbackHandler = async (context, ct) =>
                    {
                        Interlocked.Increment(ref _authorisations);
                        using var authorize = await http.GetAsync(context.AuthorizationUri, ct);
                        Assert.Equal(HttpStatusCode.SeeOther, authorize.StatusCode);
                        var consent = authorize.Headers.Location!.OriginalString;
                        Assert.StartsWith("/consent?request=", consent, StringComparison.Ordinal);
                        var request = OAuthFlow.QueryOf(consent)["request"];

                        using var decided = await api.SendAsync(HttpMethod.Post, $"/api/oauth/requests/{request}/decision", new { allow = true }, owner.Session);
                        Assert.Equal(HttpStatusCode.OK, decided.StatusCode);
                        var redirect = (await Dashboard.JsonAsync(decided)).GetProperty("redirect").GetString()!;
                        Assert.StartsWith(Callback + "?", redirect, StringComparison.Ordinal);
                        var query = OAuthFlow.QueryOf(redirect);
                        return new AuthorizationResult { Code = query["code"], State = query["state"], Iss = query["iss"] };
                    },
                },
            },
            http,
            NullLoggerFactory.Instance,
            ownsHttpClient: true);
        return await McpClient.CreateAsync(transport, cancellationToken: Ct);
    }

    public static string Text(CallToolResult result) => string.Join("\n", result.Content.OfType<TextContentBlock>().Select(b => b.Text));

    public static Task<CallToolResult> CallAsync(McpClient client, string tool, object? arguments = null)
    {
        var args = arguments is null
            ? new Dictionary<string, object?>()
            : JsonSerializer.SerializeToElement(arguments).EnumerateObject().ToDictionary(p => p.Name, p => (object?)p.Value);
        return client.CallToolAsync(tool, args, cancellationToken: Ct).AsTask();
    }

    public static async Task<string> OkAsync(McpClient client, string tool, object? arguments = null)
    {
        var result = await CallAsync(client, tool, arguments);
        Assert.True(result.IsError != true, $"{tool} failed: {Text(result)}");
        return Text(result);
    }

    /// <summary>A raw JSON-RPC POST on <paramref name="path"/> with <paramref name="bearer"/>; asserts 200 and returns the message.</summary>
    public static async Task<JsonNode> RawAsync(WebApplicationFactory<Program> api, string path, string bearer, string body, (string Name, string Value)[] headers)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        request.Headers.Add("X-Forwarded-For", Dashboard.NewAddress());
        foreach (var (name, value) in headers) request.Headers.Add(name, value);
        using var client = api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) });
        using var response = await client.SendAsync(request, Ct);
        var raw = await response.Content.ReadAsStringAsync(Ct);
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode}: {raw}");
        // Either plain JSON or an SSE stream whose last data: line is the message.
        var json = response.Content.Headers.ContentType?.MediaType == "text/event-stream"
            ? raw.Split('\n').Select(l => l.TrimEnd('\r')).Last(l => l.StartsWith("data: ", StringComparison.Ordinal))["data: ".Length..]
            : raw;
        return JsonNode.Parse(json)!;
    }

    private sealed class Recorder(SdkConnector owner) : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.Add("X-Forwarded-For", Dashboard.NewAddress());
            var path = request.RequestUri!.AbsolutePath;
            string? sent = null;
            if (request.Content is not null && path is "/oauth/register" or "/oauth/token")
            {
                await request.Content.LoadIntoBufferAsync(cancellationToken);
                sent = await request.Content.ReadAsStringAsync(cancellationToken);
            }

            if (path == "/oauth/authorize")
            {
                owner.AuthorizeQuery = OAuthFlow.QueryOf(request.RequestUri.Query);
                owner.AuthorizeQuery.Remove("state");
            }

            var response = await base.SendAsync(request, cancellationToken);
            if (path == "/oauth/register")
            {
                await response.Content.LoadIntoBufferAsync(cancellationToken);
                owner.RegistrationAsked = JsonNode.Parse(sent!)?["token_endpoint_auth_method"]?.GetValue<string>();
                owner.RegistrationAnswered = JsonNode.Parse(await response.Content.ReadAsStringAsync(cancellationToken))?["token_endpoint_auth_method"]?.GetValue<string>();
            }
            else if (path == "/oauth/token" && response.IsSuccessStatusCode)
            {
                owner._grants.Enqueue(OAuthFlow.QueryOf("?" + sent).GetValueOrDefault("grant_type") ?? "");
            }

            owner._lines.Enqueue($"{request.Method} {path} {(int)response.StatusCode}");
            return response;
        }
    }
}
