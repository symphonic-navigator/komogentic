// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Komogentic.Server.Komodo;
using Komogentic.Server.Tests.Api;
using Komogentic.Server.Tests.Komodo;
using Komogentic.Server.Tests.OAuth;
using Komogentic.Server.Tests.Tools;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Client;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Komogentic.Server.Tests.AntiGoals;

/// <summary>
/// The spec's anti-goals (§3, §8), each a failure even if everything else works: Komogentic acting beyond the closed
/// list of Komodo calls or beyond its user's rights, a credential opening another's URL, a secret in the logs or
/// readable from a database dump alone, and a connection that stops working without the dashboard saying why.
/// </summary>
[Collection("app")]
public sealed partial class AntiGoalTests(AppFactory app) : IDisposable
{
    /// <summary>The spec's closed list (§2 "The security boundary", the plan's Global Constraints), written out here
    /// rather than read from <see cref="KomodoCalls"/>, so that a call added there is caught here too.</summary>
    private static readonly Dictionary<string, string> SpecCalls = new()
    {
        ["LoginLocalUser"] = "/auth/login",
        ["CreateApiKey"] = "/auth/manage",
        ["DeleteApiKey"] = "/auth/manage",
        ["ListStacks"] = "/read",
        ["GetStack"] = "/read",
        ["ListStackServices"] = "/read",
        ["GetStackLog"] = "/read",
        ["SearchStackLog"] = "/read",
        ["ListUpdates"] = "/read",
        ["GetUpdate"] = "/read",
        ["DeployStack"] = "/execute",
        ["RestartStack"] = "/execute",
    };

    private const string Password = "anna-komodo-password";

    private static int _users;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        app.Komodo.Down = false;
        app.Komodo.RateLimited = false;
        app.Komodo.ClearFailures();
        app.Komodo.Delay("DeployStack", TimeSpan.Zero);
        app.Komodo.Delay("GetUpdate", TimeSpan.Zero);
    }

    private static string NewId() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(12));

    /// <summary>A new Komodo user (not an admin) of this test, signed in to <paramref name="api"/>.</summary>
    private async Task<Owner> UserAsync(WebApplicationFactory<Program> api, string name)
    {
        var n = Interlocked.Increment(ref _users);
        var (id, username) = ($"u-{name}-anti-{n}", $"{name}-anti-{n}-{Guid.NewGuid().ToString("N")[..6]}");
        app.Komodo.AddUser(id, username, Password);
        return new Owner(id, username, Password, await api.SignInAsync(username, Password));
    }

    private FakeStack AddStack(Owner owner, string name, FakePermission permission)
    {
        var stack = app.Komodo.AddStack(NewId(), $"{name}-{Guid.NewGuid().ToString("N")[..8]}",
            services: [new FakeService("web", "nginx:1", Status: "Up 5 minutes (healthy)"), new FakeService("backend", "app:latest")]);
        app.Komodo.Grant(owner.UserId, stack.Id, permission);
        return stack;
    }

    /// <summary>An API key made in the dashboard: its secret and id.</summary>
    private static async Task<(string Secret, string Id)> KeyAsync(WebApplicationFactory<Program> api, Owner owner, string name = "Hermes")
    {
        using var created = await api.SendAsync(HttpMethod.Post, "/api/keys", new { name }, owner.Session);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var body = await Dashboard.JsonAsync(created);
        return (body.GetProperty("secret").GetString()!, body.GetProperty("key").GetProperty("id").GetString()!);
    }

    /// <summary>A connection of <paramref name="owner"/>'s, allowed for a registered app and exchanged.</summary>
    private static async Task<(OAuthFlow Flow, Pair Pair)> ConnectedAsync(WebApplicationFactory<Program> api, Owner owner, string? scope = null)
    {
        var id = await OAuthFlow.ConnectionAsync(api, owner);
        var flow = await OAuthFlow.StartAsync(api, owner, id, await OAuthFlow.RegisterAsync(api), scope: scope);
        await flow.AllowAsync();
        return (flow, await flow.ExchangeAsync());
    }

    /// <summary>The SDK client on <paramref name="path"/> with a bearer of the test's choosing.</summary>
    private static async Task<McpClient> McpAsync(WebApplicationFactory<Program> api, string path, string bearer)
    {
        var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(new Uri(AppFactory.PublicUrl), path),
                AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = $"Bearer {bearer}", ["X-Forwarded-For"] = Dashboard.NewAddress() },
            },
            api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) }),
            NullLoggerFactory.Instance,
            ownsHttpClient: true);
        return await McpClient.CreateAsync(transport, cancellationToken: Ct);
    }

    private static async Task<string> ExpectAsync(McpClient client, string tool, object? arguments, bool error)
    {
        var result = await SdkConnector.CallAsync(client, tool, arguments);
        var text = SdkConnector.Text(result);
        Assert.True((result.IsError == true) == error, $"{tool} {(error ? "did not fail" : "failed")}: {text}");
        return text;
    }

    private static Task<string> OkAsync(McpClient client, string tool, object? arguments = null) => ExpectAsync(client, tool, arguments, error: false);

    private static Task<string> ErrorAsync(McpClient client, string tool, object? arguments = null) => ExpectAsync(client, tool, arguments, error: true);

    // ---------------------------------------------------------------------------------------------------------------
    // No destructive operation, no call outside the closed list.

    [Fact]
    public async Task No_tool_reaches_a_komodo_call_outside_the_closed_list()
    {
        // The tools' waits (2 s polls, 5 s deadlines) on a clock twenty times faster.
        using var api = app.PublicApi.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
        {
            s.RemoveAll<TimeProvider>();
            s.AddSingleton<TimeProvider>(new FastTime(20));
        }));
        var seen = app.Komodo.Requests.Count;
        var anna = await UserAsync(api, "anna");
        var key = await KeyAsync(api, anna);
        var (flow, pair) = await ConnectedAsync(api, anna);
        var (readOnlyFlow, readOnlyPair) = await ConnectedAsync(api, anna, scope: "komodo:read");

        await using (var client = await McpAsync(api, "/mcp", key.Secret)) await ExerciseAsync(client, anna);
        await using (var client = await McpAsync(api, $"/mcp/c/{flow.ConnectionId}", pair.Access)) await ExerciseAsync(client, anna);
        await using (var client = await McpAsync(api, $"/mcp/c/{readOnlyFlow.ConnectionId}", readOnlyPair.Access))
        {
            var stack = AddStack(anna, "ro-grant", FakePermission.Execute | FakePermission.Logs);
            var deploys = app.Komodo.Requests.Count(r => r.Type is "DeployStack" or "RestartStack");
            await OkAsync(client, "list_stacks");
            await OkAsync(client, "get_stack_status", new { stack = stack.Name });
            await ErrorAsync(client, "deploy_stack", new { stack = stack.Name });
            await ErrorAsync(client, "restart_stack", new { stack = stack.Name, services = new[] { "web" } });
            Assert.Equal(deploys, app.Komodo.Requests.Count(r => r.Type is "DeployStack" or "RestartStack"));
        }

        // Last: a Komodo key deleted behind Komogentic's back, for each credential.
        foreach (var (path, bearer, collection, id) in new[] { ("/mcp", key.Secret, "api_keys", key.Id), ($"/mcp/c/{flow.ConnectionId}", pair.Access, "connections", flow.ConnectionId) })
        {
            await using var client = await McpAsync(api, path, bearer);
            app.Komodo.DeleteKey(await KomodoKeyAsync(collection, id));
            await ErrorAsync(client, "deploy_stack", new { stack = "anything" });
        }

        // Revoking deletes the Komodo keys with the user's JWT: DeleteApiKey on the path.
        using (var revoked = await api.SendAsync(HttpMethod.Delete, $"/api/connections/{readOnlyFlow.ConnectionId}", session: anna.Session))
            Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);

        var requests = app.Komodo.Requests.Skip(seen).ToList();
        Assert.Empty(app.Komodo.Violations);
        var closedList = KomodoCalls.All.Select(c => c.Name).ToHashSet();
        foreach (var request in requests)
        {
            Assert.True(closedList.Contains(request.Type), $"{request.Type} is not in KomodoCalls");
            Assert.True(SpecCalls.TryGetValue(request.Type, out var route), $"{request.Type} is not in the spec's closed list");
            Assert.True(route == request.Path, $"{request.Type} was sent to {request.Path}, not {route}");
        }

        // Every call of the closed list was reached, so the drive above covers what the tools and the dashboard do.
        Assert.Equal(SpecCalls.Keys.Order(StringComparer.Ordinal), requests.Select(r => r.Type).Distinct().Order(StringComparer.Ordinal));
        // Outside the sign-in and the dashboard's key management, every call is made with a key of the user's.
        Assert.All(requests.Where(r => r.Path is "/read" or "/execute"), r => Assert.Equal("key", r.AuthKind));
    }

    /// <summary>The Komodo key id an API key's or a connection's record names (not secret, stored in the clear).</summary>
    private async Task<string> KomodoKeyAsync(string collection, string id) =>
        (await app.Database.GetCollection<BsonDocument>(collection).Find(new BsonDocument("_id", id)).SingleAsync(Ct))["komodoKey"].AsString;

    /// <summary>Every tool with every option, on success and failure paths, through <paramref name="client"/>.</summary>
    private async Task ExerciseAsync(McpClient client, Owner owner)
    {
        var run = AddStack(owner, "app", FakePermission.Execute | FakePermission.Logs);
        run.LogText = "starting\nERROR: Null Ref EXCEPTION in save\nan exception only\nready";
        var readOnly = AddStack(owner, "ro", FakePermission.Read);
        var swarm = AddStack(owner, "swarm", FakePermission.Read | FakePermission.Logs);
        swarm.SwarmId = "swarm-1";
        swarm.LogText = "swarm line";
        var hidden = app.Komodo.AddStack(NewId(), $"billing-{Guid.NewGuid().ToString("N")[..8]}", services: [new FakeService("web", "billing:1")]);
        var update = app.Komodo.AddUpdate(run.Id, owner.UserId, "DeployStack", false, 1_000, 2_000,
            new FakeLog("Compose Up", Stderr: "backend exited with code 1", Success: false, Command: "docker compose up -d"));
        var foreign = app.Komodo.AddUpdate(readOnly.Id, owner.UserId, "RestartStack", true, 3_000, 4_000);

        await OkAsync(client, "list_stacks");

        await OkAsync(client, "get_stack_status", new { stack = run.Name });
        await OkAsync(client, "get_stack_status", new { stack = run.Id });
        await ErrorAsync(client, "get_stack_status", new { stack = hidden.Name });
        await ErrorAsync(client, "get_stack_status", new { stack = "nope-" + NewId() });

        await OkAsync(client, "get_stack_logs", new { stack = run.Name });
        await OkAsync(client, "get_stack_logs", new { stack = run.Name, services = new[] { "web" }, tail = 7, timestamps = true });
        await OkAsync(client, "get_stack_logs", new { stack = run.Name, search = new[] { "exception" } });
        await OkAsync(client, "get_stack_logs", new { stack = run.Name, search = new[] { "exception", "null ref" }, match_all = true, timestamps = true });
        await OkAsync(client, "get_stack_logs", new { stack = run.Name, services = new[] { "backend" }, search = new[] { "ready" } });
        await ErrorAsync(client, "get_stack_logs", new { stack = run.Name, services = new[] { "nope" } });
        await ErrorAsync(client, "get_stack_logs", new { stack = run.Name, services = new[] { "-f" } });
        await ErrorAsync(client, "get_stack_logs", new { stack = run.Name, tail = 0 });
        await ErrorAsync(client, "get_stack_logs", new { stack = run.Name, tail = 5001 });
        await ErrorAsync(client, "get_stack_logs", new { stack = readOnly.Name });
        await ErrorAsync(client, "get_stack_logs", new { stack = readOnly.Name, search = new[] { "x" } });
        await ErrorAsync(client, "get_stack_logs", new { stack = swarm.Name });
        await OkAsync(client, "get_stack_logs", new { stack = swarm.Name, services = new[] { "web" } });
        await OkAsync(client, "get_stack_logs", new { stack = swarm.Name, services = new[] { "web" }, search = new[] { "swarm" } });
        await ErrorAsync(client, "get_stack_logs", new { stack = hidden.Name });

        await OkAsync(client, "list_stack_updates", new { stack = run.Name });
        await OkAsync(client, "list_stack_updates", new { stack = run.Name, limit = 1 });
        await OkAsync(client, "list_stack_updates", new { stack = run.Name, update_id = update.Id });
        await ErrorAsync(client, "list_stack_updates", new { stack = run.Name, update_id = foreign.Id });
        await ErrorAsync(client, "list_stack_updates", new { stack = run.Name, update_id = "0123456789abcdef01234567" });
        await ErrorAsync(client, "list_stack_updates", new { stack = run.Name, update_id = "not an id" });
        await ErrorAsync(client, "list_stack_updates", new { stack = run.Name, limit = 0 });
        await ErrorAsync(client, "list_stack_updates", new { stack = hidden.Name });

        foreach (var tool in new[] { "deploy_stack", "restart_stack" })
        {
            run.DeployOutcome = new DeployOutcome.Succeeds(AfterPolls: 2);
            await OkAsync(client, tool, new { stack = run.Name });
            await OkAsync(client, tool, new { stack = run.Id, services = new[] { "backend" }, wait_seconds = 30 });
            run.DeployOutcome = new DeployOutcome.Fails();
            await ErrorAsync(client, tool, new { stack = run.Name });
            run.DeployOutcome = new DeployOutcome.NeverCompletes();
            await OkAsync(client, tool, new { stack = run.Name, wait_seconds = 5 });
            run.DeployOutcome = new DeployOutcome.Succeeds();
            await ErrorAsync(client, tool, new { stack = readOnly.Name });
            await ErrorAsync(client, tool, new { stack = hidden.Name });
            await ErrorAsync(client, tool, new { stack = run.Name, services = new[] { "nope" } });
            await ErrorAsync(client, tool, new { stack = run.Name, services = new[] { "web --all" } });
            await ErrorAsync(client, tool, new { stack = run.Name, wait_seconds = 4 });
            await ErrorAsync(client, tool, new { stack = run.Name, wait_seconds = 601 });

            // Komodo slow to accept, then slow to report.
            app.Komodo.Delay(tool == "deploy_stack" ? "DeployStack" : "RestartStack", TimeSpan.FromSeconds(1));
            await ErrorAsync(client, tool, new { stack = run.Name, wait_seconds = 5 });
            app.Komodo.Delay(tool == "deploy_stack" ? "DeployStack" : "RestartStack", TimeSpan.Zero);
            app.Komodo.Delay("GetUpdate", TimeSpan.FromSeconds(1));
            await OkAsync(client, tool, new { stack = run.Name, wait_seconds = 5 });
            app.Komodo.Delay("GetUpdate", TimeSpan.Zero);
        }

        // Komodo down, refusing for a moment, or failing one call.
        app.Komodo.Down = true;
        await ErrorAsync(client, "list_stacks");
        await ErrorAsync(client, "get_stack_status", new { stack = run.Name });
        await ErrorAsync(client, "deploy_stack", new { stack = run.Name });
        app.Komodo.Down = false;
        app.Komodo.RateLimited = true;
        await ErrorAsync(client, "list_stacks");
        await ErrorAsync(client, "restart_stack", new { stack = run.Name });
        app.Komodo.RateLimited = false;
        app.Komodo.FailNext("GetStack", 500, FakeKomodo.ErrorBody("database unavailable"));
        await ErrorAsync(client, "get_stack_status", new { stack = run.Name });
        app.Komodo.FailNext("ListStacks", 502, "<html>bad gateway</html>");
        await ErrorAsync(client, "list_stacks");
        app.Komodo.FailNext("GetUpdate", 500, FakeKomodo.ErrorBody("boom"));
        await ErrorAsync(client, "list_stack_updates", new { stack = run.Name, update_id = update.Id });
        app.Komodo.ClearFailures();
        await OkAsync(client, "list_stacks");
    }

    // ---------------------------------------------------------------------------------------------------------------
    // A credential opens its own URL only.

    [Fact]
    public async Task Token_for_connection_A_fails_on_connection_B()
    {
        var api = app.PublicApi;
        var anna = await UserAsync(api, "anna");
        var ben = await UserAsync(api, "ben");
        AddStack(anna, "anna", FakePermission.Read);
        var bens = AddStack(ben, "ben", FakePermission.Read);
        var (a, pairA) = await ConnectedAsync(api, anna);
        var (b, pairB) = await ConnectedAsync(api, ben);
        // A second connection of Anna's own, connected too.
        var (a2, _) = await ConnectedAsync(api, anna);

        foreach (var (token, path) in new[] { (pairA.Access, $"/mcp/c/{b.ConnectionId}"), (pairA.Access, $"/mcp/c/{a2.ConnectionId}"), (pairB.Access, $"/mcp/c/{a.ConnectionId}") })
        {
            using var response = await OAuthFlow.InitializeAsync(api, path, token);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Contains("error=\"invalid_token\"", response.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
        }

        // Nor through the SDK's client, for a tool call: and Ben's stacks never reach Anna's token.
        var ex = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await using var client = await McpAsync(api, $"/mcp/c/{b.ConnectionId}", pairA.Access);
            await SdkConnector.CallAsync(client, "list_stacks");
        });
        Assert.Contains("401", ex.Message, StringComparison.Ordinal);

        // Each still opens its own.
        Assert.Equal(HttpStatusCode.OK, await a.InitializeStatusAsync(pairA.Access));
        Assert.Equal(HttpStatusCode.OK, await b.InitializeStatusAsync(pairB.Access));
        await using (var client = await McpAsync(api, $"/mcp/c/{a.ConnectionId}", pairA.Access))
            Assert.DoesNotContain(bens.Name, await OkAsync(client, "list_stacks"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Api_key_fails_on_a_connection_url()
    {
        var api = app.PublicApi;
        var anna = await UserAsync(api, "anna");
        var key = await KeyAsync(api, anna);
        var (flow, _) = await ConnectedAsync(api, anna);
        var waiting = await OAuthFlow.ConnectionAsync(api, anna);

        foreach (var id in new[] { flow.ConnectionId, waiting })
        {
            using var response = await OAuthFlow.InitializeAsync(api, $"/mcp/c/{id}", key.Secret);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.StartsWith("Bearer resource_metadata=", response.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
        }

        // The key still works where it belongs.
        using var own = await OAuthFlow.InitializeAsync(api, "/mcp", key.Secret);
        Assert.Equal(HttpStatusCode.OK, own.StatusCode);
    }

    [Fact]
    public async Task Access_token_fails_on_mcp()
    {
        var api = app.PublicApi;
        var anna = await UserAsync(api, "anna");
        var (flow, pair) = await ConnectedAsync(api, anna);

        foreach (var token in new[] { pair.Access, pair.Refresh })
        {
            using var response = await OAuthFlow.InitializeAsync(api, "/mcp", token);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("Bearer", response.Headers.WwwAuthenticate.ToString());
            using var dashboard = await api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) })
                .SendAsync(new HttpRequestMessage(HttpMethod.Get, "/api/connections") { Headers = { Authorization = new("Bearer", token) } }, Ct);
            Assert.Equal(HttpStatusCode.Unauthorized, dashboard.StatusCode);
        }

        Assert.Equal(HttpStatusCode.OK, await flow.InitializeStatusAsync(pair.Access));
    }

    [Fact]
    public async Task Session_cookie_opens_neither_mcp_url()
    {
        var api = app.PublicApi;
        var anna = await UserAsync(api, "anna");
        var (flow, _) = await ConnectedAsync(api, anna);

        foreach (var path in new[] { "/mcp", $"/mcp/c/{flow.ConnectionId}", "/MCP", $"/Mcp/C/{flow.ConnectionId}" })
        {
            using var response = await OAuthFlow.InitializeAsync(api, path, bearer: null, cookie: anna.Session);
            Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, $"{path}: {(int)response.StatusCode}");
            // Not even with the session as the bearer.
            using var asBearer = await OAuthFlow.InitializeAsync(api, path, bearer: anna.Session);
            Assert.True(asBearer.StatusCode == HttpStatusCode.Unauthorized, $"{path} with the session as bearer: {(int)asBearer.StatusCode}");
        }

        // The cookie is a live one: it opens the dashboard.
        using var dashboard = await api.SendAsync(HttpMethod.Get, "/api/connections", session: anna.Session);
        Assert.Equal(HttpStatusCode.OK, dashboard.StatusCode);
    }

    // ---------------------------------------------------------------------------------------------------------------
    // The user's rights and no more.

    [Fact]
    public async Task Agent_sees_exactly_the_stacks_its_user_sees()
    {
        var api = app.PublicApi;
        var anna = await UserAsync(api, "anna");
        var ben = await UserAsync(api, "ben");
        var annaApp = AddStack(anna, "anna-app", FakePermission.Execute | FakePermission.Logs);
        var annaDocs = AddStack(anna, "anna-docs", FakePermission.Read);
        var bensApp = AddStack(ben, "ben-app", FakePermission.Execute | FakePermission.Logs);
        var nobodys = app.Komodo.AddStack(NewId(), $"nobody-{Guid.NewGuid().ToString("N")[..8]}", services: [new FakeService("web", "x:1")]);
        var id = await SdkConnector.ConnectionAsync(api, anna, "Grok assistant");
        var deploys = app.Komodo.Requests.Count(r => r.Type == "DeployStack");

        await using var client = await new SdkConnector(api, anna, id).ConnectAsync();
        var listed = await OkAsync(client, "list_stacks");

        Assert.Contains(annaApp.Name, listed, StringComparison.Ordinal);
        Assert.Contains(annaDocs.Name, listed, StringComparison.Ordinal);
        Assert.DoesNotContain(bensApp.Name, listed, StringComparison.Ordinal);
        Assert.DoesNotContain(nobodys.Name, listed, StringComparison.Ordinal);
        foreach (var hidden in new[] { bensApp, nobodys })
        {
            foreach (var stack in new[] { hidden.Name, hidden.Id })
            {
                var answer = $"no such stack: {stack} (or your Komodo user may not see it)";
                Assert.Equal(answer, await ErrorAsync(client, "get_stack_status", new { stack }));
                Assert.Equal(answer, await ErrorAsync(client, "get_stack_logs", new { stack }));
                Assert.Equal(answer, await ErrorAsync(client, "list_stack_updates", new { stack }));
                Assert.Equal(answer, await ErrorAsync(client, "deploy_stack", new { stack, wait_seconds = 5 }));
                Assert.Equal(answer, await ErrorAsync(client, "restart_stack", new { stack, wait_seconds = 5 }));
            }
        }

        Assert.Equal(deploys, app.Komodo.Requests.Count(r => r.Type == "DeployStack"));
        Assert.Equal($"your Komodo user lacks Execute on stack {annaDocs.Name}", await ErrorAsync(client, "deploy_stack", new { stack = annaDocs.Name }));
        Assert.StartsWith("deploy succeeded in ", await OkAsync(client, "deploy_stack", new { stack = annaApp.Name }), StringComparison.Ordinal);
        // Komodo saw Anna as the operator, through the connection's own key.
        var deploy = app.Komodo.Requests.Last(r => r.Type == "DeployStack");
        Assert.Equal("key", deploy.AuthKind);
        Assert.Equal(anna.UserId, app.Komodo.ApiKeys.Single(k => k.Key == deploy.ApiKey).UserId);
        Assert.All(annaApp.Updates, u => Assert.Equal(anna.UserId, u.Operator));
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Secrets: never in the logs, never readable from the database alone.

    /// <summary>Everything secret one full flow produced, and what it opens with.</summary>
    private sealed record FlowSecrets(Owner Owner, string ConnectionId, string ApiKeyId, IReadOnlyList<string> Values);

    /// <summary>
    /// The whole life of a user's credentials on <paramref name="api"/>: a failed and a good sign-in, an API key, a
    /// connection with consent, the code exchange and a refresh, tools through both, a sign-out.
    /// </summary>
    private async Task<FlowSecrets> FullFlowAsync(WebApplicationFactory<Program> api)
    {
        var n = Interlocked.Increment(ref _users);
        var (userId, username) = ($"u-anna-secret-{n}", $"anna-secret-{n}-{Guid.NewGuid().ToString("N")[..6]}");
        var password = "pw-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(12));
        var wrongPassword = "wrong-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(12));
        app.Komodo.AddUser(userId, username, password);
        using (var refused = await api.PostSessionAsync(username, wrongPassword)) Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        var owner = new Owner(userId, username, password, await api.SignInAsync(username, password));
        var stack = AddStack(owner, "secret", FakePermission.Execute | FakePermission.Logs);
        stack.LogText = "a log line";

        var key = await KeyAsync(api, owner);
        var id = await SdkConnector.ConnectionAsync(api, owner, "Grok assistant");
        var flow = await OAuthFlow.StartAsync(api, owner, id, await OAuthFlow.RegisterAsync(api));
        var code = await flow.AllowAsync();
        var first = await flow.ExchangeAsync();
        using var refreshed = await flow.RefreshAsync(first.Refresh);
        var second = await OAuthFlow.PairOf(refreshed);
        using (var wrong = await OAuthFlow.InitializeAsync(api, "/mcp", key.Secret[..^4] + "AAAA")) Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        using (var wrong = await OAuthFlow.InitializeAsync(api, $"/mcp/c/{id}", first.Access[..^4] + "AAAA")) Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);

        foreach (var (path, bearer) in new[] { ("/mcp", key.Secret), ($"/mcp/c/{id}", second.Access) })
        {
            await using var client = await McpAsync(api, path, bearer);
            await OkAsync(client, "list_stacks");
            await OkAsync(client, "get_stack_status", new { stack = stack.Name });
            await OkAsync(client, "get_stack_logs", new { stack = stack.Name, search = new[] { "log" } });
            await OkAsync(client, "deploy_stack", new { stack = stack.Name });
            await ErrorAsync(client, "deploy_stack", new { stack = "nope-" + NewId() });
        }

        // The code once more: refused, and it revokes what it issued.
        using (var reused = await flow.TokenAsync()) Assert.Equal(HttpStatusCode.BadRequest, reused.StatusCode);
        var otherSession = await api.SignInAsync(username, password);
        using (var signedOut = await api.SendAsync(HttpMethod.Delete, "/api/session", session: otherSession))
            Assert.True(signedOut.IsSuccessStatusCode, $"sign-out: {(int)signedOut.StatusCode}");

        var values = new List<string>
        {
            password, wrongPassword, owner.Session, otherSession, key.Secret, code, flow.Verifier,
            first.Access, first.Refresh, second.Access, second.Refresh,
        };
        values.AddRange(app.Komodo.IssuedJwts);
        values.AddRange(app.Komodo.ApiKeys.Select(k => k.Secret));
        return new FlowSecrets(owner, id, key.Id, values);
    }

    [GeneratedRegex(@"kgt_(?:at_|rt_|ac_)?[0-9A-Za-z]{43}(?![0-9A-Za-z])")]
    private static partial Regex KgtSecret();

    [GeneratedRegex(@"S_[0-9A-Za-z]{40}_S")]
    private static partial Regex KomodoSecret();

    [GeneratedRegex(@"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")]
    private static partial Regex Jwt();

    /// <summary>Asserts <paramref name="text"/> holds no secret, without ever printing one.</summary>
    private static void AssertNoSecret(string text, IReadOnlyList<string> secrets, string where)
    {
        for (var i = 0; i < secrets.Count; i++)
        {
            Assert.False(text.Contains(secrets[i], StringComparison.Ordinal), $"{where} holds secret #{i} of the flow.");
            Assert.False(text.Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes(secrets[i])), StringComparison.Ordinal), $"{where} holds secret #{i} in base64.");
        }

        Assert.False(KgtSecret().IsMatch(text), $"{where} holds something shaped like a kgt_ secret.");
        Assert.False(KomodoSecret().IsMatch(text), $"{where} holds something shaped like a Komodo secret.");
        Assert.False(Jwt().IsMatch(text), $"{where} holds something shaped like a JWT.");
        Assert.False(text.Contains(Dashboard.Cookie + "=", StringComparison.Ordinal), $"{where} holds a session cookie.");
    }

    [Fact]
    public async Task Nothing_secret_in_the_logs()
    {
        var log = new CapturedLog(scopes: true);
        using var api = app.PublicApi.WithWebHostBuilder(b => b.ConfigureLogging(l => l.AddProvider(log)));

        var flow = await FullFlowAsync(api);

        var lines = log.Lines.ToList();
        // The flow was logged: sign-in, consent, tokens and the tools' audit.
        Assert.Contains(lines, l => l.Contains($"User {flow.Owner.UserId} signed in", StringComparison.Ordinal));
        Assert.Contains(lines, l => l.Contains(flow.ConnectionId, StringComparison.Ordinal));
        Assert.Contains(lines, l => l.Contains(" Komogentic.Audit: ", StringComparison.Ordinal) && l.Contains(flow.ApiKeyId, StringComparison.Ordinal));
        Assert.Contains(lines, l => l.Contains(" Komogentic.Audit: ", StringComparison.Ordinal) && l.Contains(flow.ConnectionId, StringComparison.Ordinal));
        for (var i = 0; i < lines.Count; i++) AssertNoSecret(lines[i], flow.Values, $"Log line #{i}");
    }

    [Fact]
    public async Task Database_dump_alone_opens_nothing()
    {
        var api = app.PublicApi;
        var flow = await FullFlowAsync(api);

        var dump = new List<(string Collection, BsonDocument Document)>();
        foreach (var name in await (await app.Database.ListCollectionNamesAsync(cancellationToken: Ct)).ToListAsync(Ct))
            dump.AddRange((await app.Database.GetCollection<BsonDocument>(name).Find(FilterDefinition<BsonDocument>.Empty).ToListAsync(Ct)).Select(d => (name, d)));
        Assert.Contains(dump, d => d.Collection == "connections" && d.Document["_id"] == flow.ConnectionId);
        Assert.Contains(dump, d => d.Collection == "oauth_tokens");
        Assert.Contains(dump, d => d.Collection == "sessions");

        for (var i = 0; i < dump.Count; i++) AssertNoSecret(dump[i].Document.ToJson(), flow.Values, $"Document #{i} of {dump[i].Collection}");

        // What the dump holds of this user, presented as a credential, opens neither URL.
        var mine = dump.Where(d => d.Document.ToJson().Contains(flow.Owner.UserId, StringComparison.Ordinal)).ToList();
        Assert.Contains(mine, d => d.Collection == "api_keys" || d.Document.ToJson().Contains(flow.ApiKeyId, StringComparison.Ordinal));
        var candidates = mine.SelectMany(d => Values(d.Document)).Where(v => v.Length >= 8).Distinct().ToList();
        Assert.NotEmpty(candidates);
        foreach (var candidate in candidates)
        {
            foreach (var bearer in new[] { candidate, "kgt_" + candidate, "kgt_at_" + candidate })
            {
                using var mcp = await OAuthFlow.InitializeAsync(api, "/mcp", bearer);
                Assert.True(mcp.StatusCode == HttpStatusCode.Unauthorized, $"A stored value opened /mcp: {(int)mcp.StatusCode}");
                using var connection = await OAuthFlow.InitializeAsync(api, $"/mcp/c/{flow.ConnectionId}", bearer);
                Assert.True(connection.StatusCode == HttpStatusCode.Unauthorized, $"A stored value opened the connection's URL: {(int)connection.StatusCode}");
            }

            using var session = await api.SendAsync(HttpMethod.Get, "/api/connections", session: candidate);
            Assert.True(session.StatusCode == HttpStatusCode.Unauthorized, $"A stored value opened the dashboard: {(int)session.StatusCode}");
        }
    }

    /// <summary>Every string of a document, and every binary as base64 and base64url.</summary>
    private static IEnumerable<string> Values(BsonValue value) => value switch
    {
        BsonDocument d => d.Elements.SelectMany(e => Values(e.Value)),
        BsonArray a => a.SelectMany(Values),
        BsonString s => [s.Value],
        BsonBinaryData b => [Convert.ToBase64String(b.Bytes), Convert.ToBase64String(b.Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')],
        _ => [],
    };

    // ---------------------------------------------------------------------------------------------------------------
    // A connection never stops silently.

    [Fact]
    public async Task Deleted_komodo_key_marks_the_connection_dead()
    {
        var api = app.PublicApi;
        var anna = await UserAsync(api, "anna");
        var stack = AddStack(anna, "app", FakePermission.Read);
        var id = await SdkConnector.ConnectionAsync(api, anna, "Grok assistant");
        var sdk = new SdkConnector(api, anna, id);
        await using var client = await sdk.ConnectAsync();
        Assert.Contains(stack.Name, await OkAsync(client, "list_stacks"), StringComparison.Ordinal);
        var komodoKey = await KomodoKeyAsync("connections", id);

        // Anna deletes the key in Komodo.
        app.Komodo.DeleteKey(komodoKey);
        var text = await ErrorAsync(client, "list_stacks");

        Assert.StartsWith("Komodo rejected this credential's API key", text, StringComparison.Ordinal);
        Assert.Equal(("needs_reconnect", "komodo_key_rejected"), await SdkConnector.StateAsync(api, anna, id));

        // The app, refused on its next request, goes through consent on the same URL again, and that reconnects it.
        var after = await OkAsync(client, "list_stacks");

        Assert.Contains(stack.Name, after, StringComparison.Ordinal);
        Assert.Equal(2, sdk.Authorisations);
        Assert.Equal(("connected", (string?)null), await SdkConnector.StateAsync(api, anna, id));
        var renewed = await KomodoKeyAsync("connections", id);
        Assert.NotEqual(komodoKey, renewed);
        Assert.False(app.Komodo.ApiKeys.Single(k => k.Key == renewed).Deleted);
    }
}
