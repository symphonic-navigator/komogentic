// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Komogentic.Server.Komodo;
using Komogentic.Server.Tests.Api;
using Komogentic.Server.Tests.Komodo;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Komogentic.Server.Tests.Tools;

/// <summary>
/// The six stack tools end to end (spec §4), as an agent with an API key calls them through the MCP SDK's client,
/// against the fake Core. Each test has a Komodo user and stacks of its own; the host's clock runs a hundred times
/// faster, so that polls and deadlines take milliseconds.
/// </summary>
[Collection("app")]
public sealed class StackToolsTests : IAsyncLifetime
{
    private static int _runs;

    private const string Password = "anna-komodo-password";

    private readonly AppFactory _app;
    private readonly CapturedLog _log = new();
    private readonly WebApplicationFactory<Program> _api;
    private readonly string _userId;
    private readonly string _username;
    private readonly int _n;

    private string _session = "";
    private string _key = "";
    private string _keyId = "";

    public StackToolsTests(AppFactory app)
    {
        _app = app;
        _n = Interlocked.Increment(ref _runs);
        _userId = $"u-anna-tools-{_n}";
        _username = $"anna-tools-{_n}";
        app.Komodo.AddUser(_userId, _username, Password);
        _api = app.PublicApi.WithWebHostBuilder(b => b
            .ConfigureLogging(l => l.AddProvider(_log))
            .ConfigureTestServices(s =>
            {
                s.RemoveAll<TimeProvider>();
                s.AddSingleton<TimeProvider>(new FastTime(100));
            }));
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private string App => $"app-{_n}";

    private string Billing => $"billing-{_n}";

    public async ValueTask InitializeAsync()
    {
        _session = await _api.SignInAsync(_username, Password);
        using var created = await _api.SendAsync(HttpMethod.Post, "/api/keys", new { name = "Hermes" }, _session);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var body = await Dashboard.JsonAsync(created);
        _key = body.GetProperty("secret").GetString()!;
        _keyId = body.GetProperty("key").GetProperty("id").GetString()!;
    }

    public async ValueTask DisposeAsync()
    {
        await _api.DisposeAsync();
        _app.Komodo.Down = false;
        _app.Komodo.RateLimited = false;
        _app.Komodo.ClearFailures();
        _app.Komodo.Delay("DeployStack", TimeSpan.Zero);
        _app.Komodo.Delay("GetUpdate", TimeSpan.Zero);
    }

    private static string NewId() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(12));

    /// <summary>The test's stack <c>app-n</c> with a web and a backend service, and what Anna may do on it.</summary>
    private FakeStack AddApp(FakePermission permission = FakePermission.Read, string state = "running", params FakeService[] services)
    {
        var stack = _app.Komodo.AddStack(NewId(), App, state: state, services: services.Length > 0
            ? services
            : [new FakeService("web", "nginx:1", Status: "Up 5 minutes (healthy)"), new FakeService("backend", "app:latest")]);
        _app.Komodo.Grant(_userId, stack.Id, permission);
        return stack;
    }

    /// <summary>A stack Anna may not see.</summary>
    private FakeStack AddBilling() => _app.Komodo.AddStack(NewId(), Billing, services: [new FakeService("web", "billing:1")]);

    private async Task<McpClient> ConnectAsync()
    {
        var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(new Uri(AppFactory.PublicUrl), "/mcp"),
                AdditionalHeaders = new Dictionary<string, string>
                {
                    ["Authorization"] = $"Bearer {_key}",
                    ["X-Forwarded-For"] = Dashboard.NewAddress(),
                },
            },
            _api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) }),
            NullLoggerFactory.Instance,
            ownsHttpClient: true);
        return await McpClient.CreateAsync(transport, cancellationToken: Ct);
    }

    private async Task<CallToolResult> CallAsync(string tool, object? arguments = null)
    {
        await using var client = await ConnectAsync();
        var args = arguments is null
            ? new Dictionary<string, object?>()
            : JsonSerializer.SerializeToElement(arguments).EnumerateObject().ToDictionary(p => p.Name, p => (object?)p.Value);
        return await client.CallToolAsync(tool, args, cancellationToken: Ct);
    }

    private static string Text(CallToolResult result) => string.Join("\n", result.Content.OfType<TextContentBlock>().Select(b => b.Text));

    private async Task<string> OkAsync(string tool, object? arguments = null)
    {
        var result = await CallAsync(tool, arguments);
        Assert.True(result.IsError != true, $"{tool} failed: {Text(result)}");
        return Text(result);
    }

    private async Task<string> ErrorAsync(string tool, object? arguments = null)
    {
        var result = await CallAsync(tool, arguments);
        Assert.True(result.IsError == true, $"{tool} did not fail: {Text(result)}");
        return Text(result);
    }

    private List<FakeRequest> Requests(string type) => _app.Komodo.Requests.Where(r => r.Type == type).ToList();

    private FakeRequest Last(string type) => Requests(type).Last();

    [Fact]
    public async Task List_stacks_shows_only_what_the_user_sees()
    {
        AddApp();
        AddBilling();

        var text = await OkAsync("list_stacks");

        Assert.Contains($"{App} — server-1 — running — green", text, StringComparison.Ordinal);
        Assert.DoesNotContain(Billing, text, StringComparison.Ordinal);
        Assert.EndsWith("1 green, 0 yellow, 0 red", text.TrimEnd(), StringComparison.Ordinal);
        Assert.All(_app.Komodo.Requests.Where(r => r.Type is "ListStacks" or "ListStackServices"), r => Assert.Equal("key", r.AuthKind));
    }

    [Fact]
    public async Task List_stacks_judges_health_and_shows_updates()
    {
        AddApp(services: [new FakeService("web", "nginx:1", Status: "Up 1 minute (unhealthy)", UpdateAvailable: true)]);

        var text = await OkAsync("list_stacks");

        Assert.Contains($"{App} — server-1 — running — red, update available", text, StringComparison.Ordinal);
        Assert.EndsWith("0 green, 0 yellow, 1 red", text.TrimEnd(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Stack_is_found_by_id_too()
    {
        var stack = AddApp();

        var text = await OkAsync("get_stack_status", new { stack = stack.Id });

        Assert.StartsWith($"{App} — server-1 — running — green", text, StringComparison.Ordinal);
        Assert.Contains("web: Running", text, StringComparison.Ordinal);
        Assert.Contains("health: healthy", text, StringComparison.Ordinal);
        Assert.Contains("image app:latest", text, StringComparison.Ordinal);
        // The canonical name from GetStack is what the later calls use.
        Assert.Equal(App, Last("ListStackServices").Params.GetProperty("stack").GetString());
    }

    [Fact]
    public async Task Unknown_and_invisible_stacks_get_the_same_answer()
    {
        AddApp(FakePermission.Execute | FakePermission.Logs);
        AddBilling();
        var deploysBefore = Requests("DeployStack").Count + Requests("RestartStack").Count;

        foreach (var name in new[] { $"nope-{_n}", Billing })
        {
            foreach (var (tool, args) in new (string, object)[]
                     {
                         ("get_stack_status", new { stack = name }),
                         ("get_stack_logs", new { stack = name }),
                         ("list_stack_updates", new { stack = name }),
                         ("deploy_stack", new { stack = name, wait_seconds = 5 }),
                         ("restart_stack", new { stack = name, wait_seconds = 5 }),
                     })
            {
                Assert.Equal($"no such stack: {name} (or your Komodo user may not see it)", await ErrorAsync(tool, args));
            }
        }

        // Komodo would have accepted a deploy of the invisible stack and failed it only later.
        Assert.Equal(deploysBefore, Requests("DeployStack").Count + Requests("RestartStack").Count);
    }

    [Fact]
    public async Task Logs_pass_tail_services_and_timestamps()
    {
        var stack = AddApp(FakePermission.Read | FakePermission.Logs);
        stack.LogText = string.Join("\n", Enumerable.Range(1, 20).Select(i => $"line {i}"));

        var text = await OkAsync("get_stack_logs", new { stack = App, services = new[] { "web" }, tail = 7, timestamps = true });

        var request = Last("GetStackLog").Params;
        Assert.Equal(["web"], request.GetProperty("services").EnumerateArray().Select(s => s.GetString()));
        Assert.Equal(7, request.GetProperty("tail").GetInt32());
        Assert.True(request.GetProperty("timestamps").GetBoolean());
        Assert.Contains("line 20", text, StringComparison.Ordinal);
        Assert.Contains("line 14", text, StringComparison.Ordinal);
        Assert.DoesNotContain("line 13\n", text + "\n", StringComparison.Ordinal);
        Assert.Equal("key", Last("GetStackLog").AuthKind);
    }

    [Fact]
    public async Task Search_uses_search_stack_log_with_the_combinator()
    {
        var stack = AddApp(FakePermission.Read | FakePermission.Logs);
        stack.LogText = "ok line\nERROR: Null Ref EXCEPTION in save\nan exception only\nnull ref alone";

        var both = await OkAsync("get_stack_logs", new { stack = App, search = new[] { "exception", "null ref" }, match_all = true });
        var and = Last("SearchStackLog").Params;
        var either = await OkAsync("get_stack_logs", new { stack = App, search = new[] { "exception", "null ref" } });
        var or = Last("SearchStackLog").Params;

        Assert.Equal("And", and.GetProperty("combinator").GetString());
        Assert.Equal("Or", or.GetProperty("combinator").GetString());
        Assert.Equal(["[eE][xX][cC][eE][pP][tT][iI][oO][nN]", "[nN][uU][lL][lL] [rR][eE][fF]"], and.GetProperty("terms").EnumerateArray().Select(t => t.GetString()));
        Assert.Contains("Null Ref EXCEPTION", both, StringComparison.Ordinal);
        Assert.DoesNotContain("exception only", both, StringComparison.Ordinal);
        Assert.Contains("Null Ref EXCEPTION", either, StringComparison.Ordinal);
        Assert.Contains("an exception only", either, StringComparison.Ordinal);
        Assert.Contains("null ref alone", either, StringComparison.Ordinal);
        Assert.DoesNotContain(Requests("GetStackLog"), r => r.Params.GetProperty("stack").GetString() == App);
    }

    [Fact]
    public async Task Logs_are_trimmed_with_a_note()
    {
        var stack = AddApp(FakePermission.Read | FakePermission.Logs);
        stack.LogText = string.Join("\n", Enumerable.Range(1, 6000).Select(i => $"{i:D6} " + new string('x', 93)));

        var text = await OkAsync("get_stack_logs", new { stack = App, tail = 5000 });

        Assert.InRange(text.Length, 150_000, 200_500);
        Assert.Contains("trimmed", text, StringComparison.Ordinal);
        Assert.Contains("006000 ", text, StringComparison.Ordinal);
        Assert.DoesNotContain("002000 ", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Tail_out_of_range_is_refused()
    {
        AddApp(FakePermission.Read | FakePermission.Logs);

        Assert.Contains("tail", await ErrorAsync("get_stack_logs", new { stack = App, tail = 5001 }), StringComparison.Ordinal);
        Assert.Contains("tail", await ErrorAsync("get_stack_logs", new { stack = App, tail = 0 }), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Logs_without_logs_permission_say_so()
    {
        AddApp(FakePermission.Read);

        Assert.Equal($"your Komodo user lacks the Logs permission on stack {App}", await ErrorAsync("get_stack_logs", new { stack = App }));
        Assert.Equal($"your Komodo user lacks the Logs permission on stack {App}", await ErrorAsync("get_stack_logs", new { stack = App, search = new[] { "x" } }));
    }

    [Fact]
    public async Task Swarm_logs_need_one_service()
    {
        var stack = AddApp(FakePermission.Read | FakePermission.Logs);
        stack.SwarmId = "swarm-1";
        stack.LogText = "swarm line";
        var before = Requests("GetStackLog").Count;

        var none = await ErrorAsync("get_stack_logs", new { stack = App });
        var two = await ErrorAsync("get_stack_logs", new { stack = App, services = new[] { "web", "backend" } });
        Assert.Equal(before, Requests("GetStackLog").Count);
        var one = await OkAsync("get_stack_logs", new { stack = App, services = new[] { "web" } });

        Assert.Contains("Swarm", none, StringComparison.Ordinal);
        Assert.Contains("exactly one service", none, StringComparison.Ordinal);
        Assert.Contains("web, backend", none, StringComparison.Ordinal);
        Assert.Equal(none, two);
        Assert.Contains("swarm line", one, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unknown_or_malformed_service_is_refused()
    {
        AddApp(FakePermission.Execute | FakePermission.Logs);
        var before = Requests("GetStackLog").Count + Requests("DeployStack").Count + Requests("RestartStack").Count + Requests("SearchStackLog").Count;

        var unknown = await ErrorAsync("get_stack_logs", new { stack = App, services = new[] { "nope" } });
        Assert.Equal(unknown, await ErrorAsync("deploy_stack", new { stack = App, services = new[] { "nope" } }));
        Assert.Equal(unknown, await ErrorAsync("restart_stack", new { stack = App, services = new[] { "nope" } }));
        Assert.Equal(unknown, await ErrorAsync("get_stack_logs", new { stack = App, services = new[] { "nope" }, search = new[] { "x" } }));
        var malformed = await ErrorAsync("deploy_stack", new { stack = App, services = new[] { "web --all" } });
        var dash = await ErrorAsync("get_stack_logs", new { stack = App, services = new[] { "-f" } });

        Assert.Equal($"stack {App} has no service nope; its services are web, backend", unknown);
        Assert.StartsWith("not a service name: web --all", malformed, StringComparison.Ordinal);
        Assert.StartsWith("not a service name: -f", dash, StringComparison.Ordinal);
        Assert.Equal(before, Requests("GetStackLog").Count + Requests("DeployStack").Count + Requests("RestartStack").Count + Requests("SearchStackLog").Count);
    }

    [Fact]
    public async Task Updates_list_is_filtered_by_stack()
    {
        var app = AddApp();
        var other = _app.Komodo.AddStack(NewId(), $"other-{_n}", services: [new FakeService("web", "x:1")]);
        _app.Komodo.Grant(_userId, other.Id, FakePermission.Read);
        var start = DateTimeOffset.Parse("2026-11-12T08:00:00Z").ToUnixTimeMilliseconds();
        var first = _app.Komodo.AddUpdate(app.Id, _userId, "DeployStack", true, start, start + 48_000);
        var second = _app.Komodo.AddUpdate(app.Id, _userId, "RestartStack", false, start + 3_600_000, start + 3_610_000);
        var third = _app.Komodo.AddUpdate(app.Id, _userId, "DeployStack", true, start + 7_200_000, start + 7_230_000);
        var others = _app.Komodo.AddUpdate(other.Id, _userId, "DeployStack", true, start + 100, start + 200);
        var gets = Requests("GetUpdate").Count;

        var text = await OkAsync("list_stack_updates", new { stack = App, limit = 2 });

        Assert.Contains(third.Id, text, StringComparison.Ordinal);
        Assert.Contains(second.Id, text, StringComparison.Ordinal);
        Assert.DoesNotContain(first.Id, text, StringComparison.Ordinal);
        Assert.DoesNotContain(others.Id, text, StringComparison.Ordinal);
        Assert.Contains($"{second.Id} — RestartStack — {_username} — started 2026-11-12 09:00:00Z — ended 2026-11-12 09:00:10Z — failed", text, StringComparison.Ordinal);
        Assert.Contains("ended 2026-11-12 10:00:30Z — succeeded", text, StringComparison.Ordinal);
        // The end time comes from GetUpdate, one per update shown.
        Assert.Equal(2, Requests("GetUpdate").Count - gets);
        Assert.Equal(app.Id, Last("ListUpdates").Params.GetProperty("query").GetProperty("target.id").GetString());
    }

    [Fact]
    public async Task Update_logs_by_id()
    {
        var app = AddApp();
        var update = _app.Komodo.AddUpdate(app.Id, _userId, "DeployStack", false, 1_000, 2_000,
            new FakeLog("Compose Pull", Stdout: "pulled app:latest", Command: "docker compose pull"),
            new FakeLog("Compose Up", Stderr: "backend exited with code 1", Success: false, Command: "docker compose up -d"));

        var text = await OkAsync("list_stack_updates", new { stack = App, update_id = update.Id });

        foreach (var part in new[] { "Compose Pull", "docker compose pull", "pulled app:latest", "Compose Up", "docker compose up -d", "backend exited with code 1", "failed" })
            Assert.Contains(part, text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Update_of_another_target_is_refused()
    {
        AddApp();
        var other = _app.Komodo.AddStack(NewId(), $"other-{_n}", services: [new FakeService("web", "x:1")]);
        _app.Komodo.Grant(_userId, other.Id, FakePermission.Read);
        var update = _app.Komodo.AddUpdate(other.Id, _userId, "DeployStack", true, 1_000, 2_000, new FakeLog("Compose Up", Stdout: "the other stack's log"));

        var text = await ErrorAsync("list_stack_updates", new { stack = App, update_id = update.Id });

        Assert.Equal($"no update {update.Id} of stack {App}", text);
        Assert.Equal(text.Replace(update.Id, "0123456789abcdef01234567", StringComparison.Ordinal),
            await ErrorAsync("list_stack_updates", new { stack = App, update_id = "0123456789abcdef01234567" }));
    }

    [Fact]
    public async Task Deploy_waits_and_reports_success_and_verdict()
    {
        var stack = AddApp(FakePermission.Execute);
        stack.DeployOutcome = new DeployOutcome.Succeeds(AfterPolls: 2, Stdout: "Container app-backend-1 Started");

        var text = await OkAsync("deploy_stack", new { stack = App });

        Assert.StartsWith("deploy succeeded in ", text, StringComparison.Ordinal);
        Assert.Contains($" s; {App} is green", text, StringComparison.Ordinal);
        Assert.Contains("Container app-backend-1 Started", text, StringComparison.Ordinal);
        Assert.Equal("key", Last("DeployStack").AuthKind);
        Assert.Equal(App, Last("DeployStack").Params.GetProperty("stack").GetString());
        Assert.True(Requests("GetUpdate").Count >= 2);
    }

    [Fact]
    public async Task Deploy_of_services_passes_them()
    {
        AddApp(FakePermission.Execute);

        await OkAsync("deploy_stack", new { stack = App, services = new[] { "backend" } });

        Assert.Equal(["backend"], Last("DeployStack").Params.GetProperty("services").EnumerateArray().Select(s => s.GetString()));
    }

    [Fact]
    public async Task Deploy_failure_reports_the_log()
    {
        var stack = AddApp(FakePermission.Execute);
        stack.DeployOutcome = new DeployOutcome.Fails(Stderr: "service backend failed to start: port is already allocated");

        var text = await ErrorAsync("deploy_stack", new { stack = App });

        Assert.StartsWith("deploy failed", text, StringComparison.Ordinal);
        Assert.Contains("Compose Up", text, StringComparison.Ordinal);
        Assert.Contains("port is already allocated", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Deploy_without_execute_says_so()
    {
        AddApp(FakePermission.Read);

        Assert.Equal($"your Komodo user lacks Execute on stack {App}", await ErrorAsync("deploy_stack", new { stack = App }));
    }

    [Fact]
    public async Task Deploy_timeout_returns_the_update_id()
    {
        var stack = AddApp(FakePermission.Execute);
        stack.DeployOutcome = new DeployOutcome.NeverCompletes();

        var text = await OkAsync("deploy_stack", new { stack = App, wait_seconds = 5 });

        var update = stack.Updates.Last();
        Assert.Equal($"still running after 5 s; update id {update.Id} — follow it with list_stack_updates", text);
    }

    [Fact]
    public async Task Wait_out_of_range_is_refused()
    {
        AddApp(FakePermission.Execute);
        var before = Requests("DeployStack").Count;

        Assert.Contains("wait_seconds", await ErrorAsync("deploy_stack", new { stack = App, wait_seconds = 4 }), StringComparison.Ordinal);
        Assert.Contains("wait_seconds", await ErrorAsync("restart_stack", new { stack = App, wait_seconds = 601 }), StringComparison.Ordinal);
        Assert.Equal(before, Requests("DeployStack").Count);
    }

    [Fact]
    public async Task Slow_komodo_does_not_exceed_the_wait()
    {
        AddApp(FakePermission.Execute);
        // Three real seconds: three hundred on the host's clock, far beyond the 5 s wait.
        _app.Komodo.Delay("DeployStack", TimeSpan.FromSeconds(3));
        var watch = Stopwatch.StartNew();

        var text = await ErrorAsync("deploy_stack", new { stack = App, wait_seconds = 5 });

        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2), $"the call took {watch.Elapsed}");
        Assert.StartsWith("Komodo did not answer within 5 s", text, StringComparison.Ordinal);

        // A slow poll is cut at the same deadline, and the update id is known by then.
        _app.Komodo.Delay("DeployStack", TimeSpan.Zero);
        _app.Komodo.Delay("GetUpdate", TimeSpan.FromSeconds(3));
        watch.Restart();
        var polling = await OkAsync("restart_stack", new { stack = App, wait_seconds = 5 });
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2), $"the call took {watch.Elapsed}");
        Assert.StartsWith("still running after 5 s; update id ", polling, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Restart_reports_like_deploy()
    {
        AddApp(FakePermission.Execute);

        var text = await OkAsync("restart_stack", new { stack = App });

        Assert.StartsWith("restart succeeded in ", text, StringComparison.Ordinal);
        Assert.Contains($" s; {App} is green", text, StringComparison.Ordinal);
        Assert.Equal(App, Last("RestartStack").Params.GetProperty("stack").GetString());
        Assert.Equal($"your Komodo user lacks Execute on stack {Billing}",
            await AfterGrantAsync());

        async Task<string> AfterGrantAsync()
        {
            var billing = AddBilling();
            _app.Komodo.Grant(_userId, billing.Id, FakePermission.Read);
            return await ErrorAsync("restart_stack", new { stack = Billing });
        }
    }

    [Fact]
    public async Task Deleted_komodo_key_marks_the_api_key_dead()
    {
        AddApp();
        var komodoKey = _app.Komodo.ApiKeys.Single(k => k.UserId == _userId && !k.Deleted);
        _app.Komodo.DeleteKey(komodoKey.Key);

        var text = await ErrorAsync("list_stacks");

        Assert.Equal("Komodo rejected this credential's API key (it was probably deleted in Komodo). Reconnect it in Komogentic's dashboard.", text);
        using (var list = await _api.SendAsync(HttpMethod.Get, "/api/keys", session: _session))
        {
            var key = (await Dashboard.JsonAsync(list)).EnumerateArray().Single(k => k.GetProperty("id").GetString() == _keyId);
            Assert.Equal(("dead", "komodo_key_rejected"), (key.GetProperty("state").GetString(), key.GetProperty("reason").GetString()));
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}""", Encoding.UTF8, "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _key);
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        request.Headers.Add("X-Forwarded-For", Dashboard.NewAddress());
        using var refused = await _api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) })
            .SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
    }

    [Fact]
    public async Task Rate_limited_does_not_kill_the_key()
    {
        AddApp();
        _app.Komodo.RateLimited = true;

        var text = await ErrorAsync("list_stacks");

        Assert.StartsWith(KomodoClient.RateLimitedMessage, text, StringComparison.Ordinal);
        _app.Komodo.RateLimited = false;
        using var list = await _api.SendAsync(HttpMethod.Get, "/api/keys", session: _session);
        var key = (await Dashboard.JsonAsync(list)).EnumerateArray().Single(k => k.GetProperty("id").GetString() == _keyId);
        Assert.Equal("active", key.GetProperty("state").GetString());
        Assert.Contains($"{App} — ", await OkAsync("list_stacks"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Komodo_down_is_a_clear_error()
    {
        AddApp();
        _app.Komodo.Down = true;

        Assert.Equal("Komodo could not be reached; try again in a minute.", await ErrorAsync("get_stack_status", new { stack = App }));
    }

    [Fact]
    public async Task Tool_annotations_are_as_specified()
    {
        await using var client = await ConnectAsync();

        var tools = (await client.ListToolsAsync(cancellationToken: Ct)).ToDictionary(t => t.Name);

        Assert.Equal(["deploy_stack", "get_stack_logs", "get_stack_status", "list_stack_updates", "list_stacks", "restart_stack"], tools.Keys.Order());
        foreach (var name in new[] { "deploy_stack", "restart_stack" })
        {
            var a = tools[name].ProtocolTool.Annotations!;
            Assert.Equal((false, false, false, false), (a.ReadOnlyHint, a.DestructiveHint, a.IdempotentHint, a.OpenWorldHint));
        }

        foreach (var name in new[] { "list_stacks", "get_stack_status", "get_stack_logs", "list_stack_updates" })
        {
            var a = tools[name].ProtocolTool.Annotations!;
            Assert.Equal((true, false, false), (a.ReadOnlyHint, a.DestructiveHint, a.OpenWorldHint));
        }

        Assert.Contains("wait_seconds", tools["deploy_stack"].ProtocolTool.InputSchema.GetProperty("properties").EnumerateObject().Select(p => p.Name));
        Assert.Contains("match_all", tools["get_stack_logs"].ProtocolTool.InputSchema.GetProperty("properties").EnumerateObject().Select(p => p.Name));
    }

    [Fact]
    public async Task Audit_line_names_user_tool_stack_and_outcome()
    {
        AddApp(FakePermission.Execute | FakePermission.Logs);
        AddBilling();

        await OkAsync("deploy_stack", new { stack = App });
        await ErrorAsync("get_stack_status", new { stack = Billing });
        await OkAsync("get_stack_logs", new { stack = App, search = new[] { "secret-search-term" } });

        var audit = _log.Lines.Where(l => l.Contains(" Komogentic.Audit: ", StringComparison.Ordinal)).ToList();
        Assert.Contains(audit, l => l.Contains($"Tool deploy_stack on {App} by {_username} via api key Hermes ({_keyId}), client -: succeeded", StringComparison.Ordinal));
        Assert.Contains(audit, l => l.Contains($"Tool get_stack_status on {Billing} by {_username} via api key Hermes ({_keyId}), client -: no such stack", StringComparison.Ordinal));
        Assert.Contains(audit, l => l.Contains($"Tool get_stack_logs on {App} by {_username}", StringComparison.Ordinal) && l.EndsWith(": ok ", StringComparison.Ordinal));
        var komodoKey = _app.Komodo.ApiKeys.Single(k => k.UserId == _userId && !k.Deleted);
        foreach (var line in _log.Lines)
        {
            Assert.False(line.Contains(_key, StringComparison.Ordinal), "A log line holds the API key.");
            Assert.False(line.Contains(komodoKey.Secret, StringComparison.Ordinal), "A log line holds the Komodo secret.");
            Assert.False(line.Contains("secret-search-term", StringComparison.Ordinal), "A log line holds the search terms.");
        }
    }
}
