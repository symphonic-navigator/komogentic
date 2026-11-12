// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
using Komogentic.Server.Accounts;
using Komogentic.Server.Auth;
using Komogentic.Server.Komodo;
using Komogentic.Server.Tests.Api;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Komogentic.Server.Tests.Tools;

/// <summary>Plain <c>/mcp</c> with an API key, on the wire: both handshakes, and the read-only filter.</summary>
[Collection("app")]
public sealed class McpApiKeyTests(AppFactory app)
{
    private static int _users;

    private const string Password = "anna-komodo-password";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Both_handshakes_work()
    {
        var key = await KeyAsync(app.PublicApi);

        var initialize = await RawAsync(app.PublicApi, key,
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}""",
            []);
        var discover = await RawAsync(app.PublicApi, key,
            """{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"raw","version":"0"}}}}""",
            [("MCP-Protocol-Version", "2026-07-28"), ("Mcp-Method", "server/discover")]);

        var result = initialize["result"] ?? throw new Xunit.Sdk.XunitException("No result: " + initialize.ToJsonString());
        Assert.Equal("2025-11-25", result["protocolVersion"]?.GetValue<string>());
        Assert.Equal("komogentic", result["serverInfo"]?["name"]?.GetValue<string>());
        Assert.Contains("Komodo", result["instructions"]?.GetValue<string>(), StringComparison.Ordinal);
        Assert.NotNull(result["capabilities"]?["tools"]);
        var discovered = discover["result"] ?? throw new Xunit.Sdk.XunitException("No result: " + discover.ToJsonString());
        var info = discovered["serverInfo"] ?? discovered["_meta"]?["io.modelcontextprotocol/serverInfo"];
        Assert.Equal("komogentic", info?["name"]?.GetValue<string>());
    }

    [Fact]
    public async Task Read_only_caller_gets_the_read_tools_only()
    {
        // API keys are never read-only; a connection granted komodo:read alone is (Task 8). Until then, a host whose
        // every caller is such a grant.
        var key = await KeyAsync(app.PublicApi);
        var resolved = (await app.PublicApi.Services.GetRequiredService<ApiKeys>().ResolveAsync(key, Ct)).Key
            ?? throw new InvalidOperationException("The key does not resolve.");
        var readOnly = ReadOnlyCaller(resolved);
        using var api = app.PublicApi.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
        {
            s.RemoveAll<RequestCaller>();
            s.AddScoped(_ => readOnly);
        }));

        var list = await RawAsync(api, key, """{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}""", []);
        var call = await RawAsync(api, key,
            """{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"deploy_stack","arguments":{"stack":"app"}}}""", []);

        var names = list["result"]!["tools"]!.AsArray().Select(t => t!["name"]!.GetValue<string>()).Order();
        Assert.Equal(["get_stack_logs", "get_stack_status", "list_stack_updates", "list_stacks"], names);
        Assert.True(call["result"]?["isError"]?.GetValue<bool>());
        Assert.Equal("this connection was granted read-only access", call["result"]!["content"]![0]!["text"]!.GetValue<string>());
    }

    /// <summary>A caller as a read-only grant would be, built past the middleware's private constructor.</summary>
    private static RequestCaller ReadOnlyCaller(ResolvedApiKey key) =>
        (RequestCaller)typeof(RequestCaller).GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance).Single()
            .Invoke([CallerKind.Connection, key.User, key.Komodo, "connection-id", "Grok assistant", "Grok", true, null]);

    private async Task<string> KeyAsync(WebApplicationFactory<Program> api)
    {
        var n = Interlocked.Increment(ref _users);
        app.Komodo.AddUser($"u-anna-mcp-{n}", $"anna-mcp-{n}", Password);
        var session = await api.SignInAsync($"anna-mcp-{n}", Password);
        using var created = await api.SendAsync(HttpMethod.Post, "/api/keys", new { name = "Hermes" }, session);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        return (await Dashboard.JsonAsync(created)).GetProperty("secret").GetString()!;
    }

    /// <summary>A raw JSON-RPC POST on <c>/mcp</c> with the key; asserts 200 and returns the message.</summary>
    private static async Task<JsonNode> RawAsync(WebApplicationFactory<Program> api, string key, string body, (string Name, string Value)[] headers)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key);
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        request.Headers.Add("X-Forwarded-For", Dashboard.NewAddress());
        foreach (var (name, value) in headers) request.Headers.Add(name, value);
        using var client = api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) });
        using var response = await client.SendAsync(request, Ct);
        var raw = await response.Content.ReadAsStringAsync(Ct);
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode}: {raw}");
        var json = response.Content.Headers.ContentType?.MediaType == "text/event-stream"
            ? raw.Split('\n').Select(l => l.TrimEnd('\r')).Last(l => l.StartsWith("data: ", StringComparison.Ordinal))["data: ".Length..]
            : raw;
        return JsonNode.Parse(json)!;
    }
}
