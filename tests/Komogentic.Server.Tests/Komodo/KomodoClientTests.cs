// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Diagnostics;
using System.Text;
using Komogentic.Server.Komodo;
using Microsoft.Extensions.DependencyInjection;

namespace Komogentic.Server.Tests.Komodo;

public sealed class KomodoClientTests : IAsyncLifetime
{
    private FakeKomodo _fake = null!;
    private KomodoClient _komodo = null!;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public async ValueTask InitializeAsync()
    {
        _fake = await FakeKomodo.StartAsync();
        _fake.AddUser("u-anna", "anna", "anna-password");
        _fake.AddUser("u-ben", "ben", "ben-password", twoFactor: true);
        _fake.AddStack("65f0c0ffee0000000000a001", "app", "server-1", "running",
            new FakeService("web", "nginx:1.27", Status: "Up 5 minutes (healthy)"));
        _fake.AddStack("65f0c0ffee0000000000b002", "billing", "server-2", "running");
        _fake.Grant("u-anna", "65f0c0ffee0000000000a001", FakePermission.Read);
        _komodo = _fake.CreateClient();
    }

    public async ValueTask DisposeAsync() => await _fake.DisposeAsync();

    [Fact]
    public async Task Login_returns_the_jwt()
    {
        var result = await _komodo.LoginLocalUserAsync("anna", "anna-password", Ct);

        Assert.False(result.TwoFactor);
        Assert.NotNull(result.Jwt);
        Assert.Equal("u-anna", KomodoJwt.Read(result.Jwt)?.UserId);
        Assert.Equal(("/auth/login", "LoginLocalUser", "none"), Last());
    }

    [Fact]
    public async Task Login_with_wrong_password_is_unauthorized()
    {
        var e = await Assert.ThrowsAsync<KomodoException>(() => _komodo.LoginLocalUserAsync("anna", "wrong", Ct));

        Assert.Equal(KomodoErrorKind.Unauthorized, e.Kind);
        Assert.Equal(401, e.Status);
        Assert.Contains("Invalid login credentials", e.Message);
        Assert.DoesNotContain("wrong", e.Message);
    }

    [Fact]
    public async Task Login_with_totp_reports_two_factor()
    {
        var result = await _komodo.LoginLocalUserAsync("ben", "ben-password", Ct);

        Assert.True(result.TwoFactor);
        Assert.Null(result.Jwt);
    }

    [Fact]
    public async Task Create_and_delete_api_key_with_the_jwt()
    {
        var jwt = new KomodoAuth.Jwt(_fake.IssueJwt("u-anna"));
        var expires = new DateTime(2027, 2, 10, 12, 0, 0, DateTimeKind.Utc);

        var created = await _komodo.CreateApiKeyAsync(jwt, "komogentic/Hermes", expires, Ct);

        Assert.Matches("^K_[A-Za-z0-9]{40}_K$", created.Key);
        Assert.Matches("^S_[A-Za-z0-9]{40}_S$", created.Secret);
        var stored = Assert.Single(_fake.ApiKeys);
        Assert.Equal(("u-anna", "komogentic/Hermes", new DateTimeOffset(expires).ToUnixTimeMilliseconds()), (stored.UserId, stored.Name, stored.Expires));
        var create = _fake.Requests[^1];
        Assert.Equal(("/auth/manage", "CreateApiKey", "jwt", null), (create.Path, create.Type, create.AuthKind, create.ApiKey));

        await _komodo.DeleteApiKeyAsync(jwt, created.Key, Ct);

        Assert.True(Assert.Single(_fake.ApiKeys).Deleted);
        Assert.Equal(("/auth/manage", "DeleteApiKey", "jwt"), Last());
        Assert.Equal(created.Key, _fake.Requests[^1].Params.GetProperty("key").GetString());
    }

    [Fact]
    public async Task Create_api_key_without_expiry_sends_zero()
    {
        await _komodo.CreateApiKeyAsync(new KomodoAuth.Jwt(_fake.IssueJwt("u-anna")), "komogentic/Grok", null, Ct);

        Assert.Equal(0, _fake.Requests[^1].Params.GetProperty("expires").GetInt64());
    }

    [Fact]
    public async Task Delete_unknown_key_counts_as_done()
    {
        await _komodo.DeleteApiKeyAsync(new KomodoAuth.Jwt(_fake.IssueJwt("u-anna")), "K_gone_K", Ct);

        Assert.Equal(("/auth/manage", "DeleteApiKey", "jwt"), Last());
    }

    [Fact]
    public async Task List_stacks_with_a_key_sends_both_headers()
    {
        var key = _fake.IssueKey("u-anna", "komogentic/Hermes");

        var stacks = await _komodo.ListStacksAsync(new KomodoAuth.Key(key.Key, key.Secret), Ct);

        var stack = Assert.Single(stacks);
        Assert.Equal(("65f0c0ffee0000000000a001", "app", "server-1", "running"), (stack.Id, stack.Name, stack.Info.ServerName, stack.Info.State));
        Assert.Equal("web", Assert.Single(stack.Info.Services).Service);
        var request = _fake.Requests[^1];
        Assert.Equal(("/read", "ListStacks", "key", key.Key), (request.Path, request.Type, request.AuthKind, request.ApiKey));
    }

    [Fact]
    public async Task List_stacks_asks_for_all_pages()
    {
        _fake.DefaultPaginationLimit = 1;
        _fake.Grant("u-anna", "65f0c0ffee0000000000b002", FakePermission.Read);

        var stacks = await _komodo.ListStacksAsync(new KomodoAuth.Jwt(_fake.IssueJwt("u-anna")), Ct);

        Assert.Equal(["app", "billing"], stacks.Select(s => s.Name));
    }

    [Fact]
    public async Task Find_stack_asks_for_the_name()
    {
        var jwt = new KomodoAuth.Jwt(_fake.IssueJwt("u-anna"));

        Assert.Equal("65f0c0ffee0000000000a001", (await _komodo.FindStackAsync(jwt, "app", Ct))?.Id);
        Assert.Equal("app", _fake.Requests[^1].Params.GetProperty("query").GetProperty("names")[0].GetString());
        Assert.Null(await _komodo.FindStackAsync(jwt, "billing", Ct));
    }

    [Fact]
    public async Task Get_stack_by_id_or_name_gives_the_canonical_pair()
    {
        var jwt = new KomodoAuth.Jwt(_fake.IssueJwt("u-anna"));

        Assert.Equal(new StackRef("65f0c0ffee0000000000a001", "app"), await _komodo.GetStackAsync(jwt, "app", Ct));
        Assert.Equal(new StackRef("65f0c0ffee0000000000a001", "app"), await _komodo.GetStackAsync(jwt, "65f0c0ffee0000000000a001", Ct));
    }

    [Fact]
    public async Task Get_stack_unknown_is_not_found_or_forbidden()
    {
        var e = await Assert.ThrowsAsync<KomodoException>(() =>
            _komodo.GetStackAsync(new KomodoAuth.Jwt(_fake.IssueJwt("u-anna")), "x", Ct));

        Assert.Equal(KomodoErrorKind.NotFoundOrForbidden, e.Kind);
        Assert.Equal(500, e.Status);
        Assert.Contains("Did not find any Stack matching x", e.Message);
    }

    [Fact]
    public async Task Get_stack_without_permission_is_not_found_or_forbidden()
    {
        var e = await Assert.ThrowsAsync<KomodoException>(() =>
            _komodo.GetStackAsync(new KomodoAuth.Jwt(_fake.IssueJwt("u-anna")), "billing", Ct));

        Assert.Equal(KomodoErrorKind.NotFoundOrForbidden, e.Kind);
        Assert.Contains("does not have required permissions", e.Message);
    }

    [Fact]
    public async Task Permission_message_in_the_trace_counts_too()
    {
        _fake.FailNext("GetStack", 500,
            """{"error":"Failed to get stack","trace":["User does not have required permissions on this Stack. Must have at least Read permissions"]}""");

        var e = await Assert.ThrowsAsync<KomodoException>(() =>
            _komodo.GetStackAsync(new KomodoAuth.Jwt(_fake.IssueJwt("u-anna")), "app", Ct));

        Assert.Equal(KomodoErrorKind.NotFoundOrForbidden, e.Kind);
    }

    [Fact]
    public async Task Deleted_key_is_unauthorized()
    {
        var key = _fake.IssueKey("u-anna", "komogentic/Hermes");
        _fake.DeleteKey(key.Key);

        var e = await Assert.ThrowsAsync<KomodoException>(() =>
            _komodo.ListStacksAsync(new KomodoAuth.Key(key.Key, key.Secret), Ct));

        Assert.Equal(KomodoErrorKind.Unauthorized, e.Kind);
        Assert.Equal(401, e.Status);
        Assert.DoesNotContain(key.Secret, e.Message);
        Assert.DoesNotContain(key.Secret, e.ToString());
    }

    [Fact]
    public async Task Expired_jwt_is_unauthorized_although_komodo_answers_500()
    {
        _fake.JwtLifetime = TimeSpan.FromMilliseconds(-1);
        var jwt = _fake.IssueJwt("u-anna");

        var e = await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(new KomodoAuth.Jwt(jwt), Ct));

        Assert.Equal(KomodoErrorKind.Unauthorized, e.Kind);
        Assert.Equal(500, e.Status);
        Assert.DoesNotContain(jwt, e.ToString());
    }

    [Fact]
    public async Task Rate_limited_is_its_own_kind()
    {
        _fake.RateLimited = true;

        var e = await Assert.ThrowsAsync<KomodoException>(() => _komodo.LoginLocalUserAsync("anna", "anna-password", Ct));

        Assert.Equal(KomodoErrorKind.RateLimited, e.Kind);
        Assert.Equal(429, e.Status);
        Assert.Equal("Komodo is refusing sign-ins for a moment after several failures; try again in a minute.", e.Message);
    }

    [Fact]
    public async Task Unreachable_core_is_a_clear_error()
    {
        var jwt = new KomodoAuth.Jwt(_fake.IssueJwt("u-anna"));
        var slow = _fake.CreateClient(TimeSpan.FromSeconds(1));
        _fake.Delay(null, TimeSpan.FromSeconds(30));

        var watch = Stopwatch.StartNew();
        var timedOut = await Assert.ThrowsAsync<KomodoException>(() => slow.ListStacksAsync(jwt, Ct));
        watch.Stop();

        Assert.Equal((KomodoErrorKind.Unreachable, "Komodo could not be reached"), (timedOut.Kind, timedOut.Message));
        Assert.InRange(watch.Elapsed, TimeSpan.FromSeconds(0.5), TimeSpan.FromSeconds(10));

        _fake.Delay(null, TimeSpan.Zero);
        _fake.Down = true;
        var dropped = await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(jwt, Ct));
        Assert.Equal((KomodoErrorKind.Unreachable, "Komodo could not be reached"), (dropped.Kind, dropped.Message));

        await _fake.StopAsync();
        var stopped = await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(jwt, Ct));
        Assert.Equal((KomodoErrorKind.Unreachable, "Komodo could not be reached"), (stopped.Kind, stopped.Message));
        Assert.DoesNotContain(jwt.Token, stopped.ToString());
    }

    [Fact]
    public async Task Cancellation_by_the_caller_is_not_unreachable()
    {
        _fake.Delay(null, TimeSpan.FromSeconds(30));
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        cts.CancelAfter(TimeSpan.FromMilliseconds(200));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _komodo.ListStacksAsync(new KomodoAuth.Jwt(_fake.IssueJwt("u-anna")), cts.Token));
    }

    [Fact]
    public async Task Bad_request_and_other_failures_are_classified()
    {
        var jwt = new KomodoAuth.Jwt(_fake.IssueJwt("u-anna"));
        _fake.FailNext("ListStacks", 400, FakeKomodo.ErrorBody("Failed to deserialize the JSON body"));
        _fake.FailNext("ListStacks", 500, FakeKomodo.ErrorBody("Failed to query db"));
        _fake.FailNext("ListStacks", 502, "<html>Bad Gateway</html>");

        Assert.Equal(KomodoErrorKind.BadRequest, (await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(jwt, Ct))).Kind);
        var failed = await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(jwt, Ct));
        Assert.Equal((KomodoErrorKind.Failed, 500), (failed.Kind, failed.Status));
        Assert.Contains("Failed to query db", failed.Message);
        Assert.Equal(KomodoErrorKind.Unreachable, (await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(jwt, Ct))).Kind);
    }

    [Fact]
    public async Task Services_logs_and_updates_are_read()
    {
        var key = _fake.IssueKey("u-anna", "komogentic/Hermes");
        var auth = new KomodoAuth.Key(key.Key, key.Secret);
        _fake.Grant("u-anna", "65f0c0ffee0000000000a001", FakePermission.Read | FakePermission.Logs);
        _fake.Stack("app").LogText = "web-1 | starting\nweb-1 | ready\nweb-1 | GET /";
        var old = _fake.AddUpdate("65f0c0ffee0000000000a001", "u-anna", "DeployStack", true, 1_700_000_000_000, 1_700_000_048_000,
            new FakeLog("Compose Up", "done"));

        var service = Assert.Single(await _komodo.ListStackServicesAsync(auth, "app", Ct));
        Assert.Equal(("web", "Running", "running", "Up 5 minutes (healthy)"), (service.Service, service.State, service.Container?.State, service.Container?.Status));

        var log = await _komodo.GetStackLogAsync(auth, "app", ["web"], 2, true, Ct);
        Assert.Equal("web-1 | ready\nweb-1 | GET /", log.Stdout);
        var logParams = _fake.Requests[^1].Params;
        Assert.Equal((2, true, "web"), (logParams.GetProperty("tail").GetInt32(), logParams.GetProperty("timestamps").GetBoolean(), logParams.GetProperty("services")[0].GetString()));

        var found = await _komodo.SearchStackLogAsync(auth, "app", [], ["web", "ready"], all: true, timestamps: false, Ct);
        Assert.Equal("web-1 | ready", found.Stdout);
        Assert.Equal("And", _fake.Requests[^1].Params.GetProperty("combinator").GetString());
        await _komodo.SearchStackLogAsync(auth, "app", [], ["ready"], all: false, timestamps: false, Ct);
        Assert.Equal("Or", _fake.Requests[^1].Params.GetProperty("combinator").GetString());

        var listed = Assert.Single(await _komodo.ListUpdatesAsync(auth, "65f0c0ffee0000000000a001", Ct));
        Assert.Equal((old.Id, "DeployStack", "anna", "Complete", true), (listed.Id, listed.Operation, listed.Username, listed.Status, listed.Success));
        var query = _fake.Requests[^1].Params.GetProperty("query");
        Assert.Equal(("Stack", "65f0c0ffee0000000000a001"), (query.GetProperty("target.type").GetString(), query.GetProperty("target.id").GetString()));

        var update = await _komodo.GetUpdateAsync(auth, old.Id, Ct);
        Assert.Equal((old.Id, 1_700_000_048_000L, "done"), (update.Id, update.EndTs, Assert.Single(update.Logs).Stdout));
    }

    [Fact]
    public async Task Deploy_answers_at_once_and_completes_when_polled()
    {
        _fake.Grant("u-anna", "65f0c0ffee0000000000a001", FakePermission.Execute);
        _fake.Stack("app").DeployOutcome = new DeployOutcome.Succeeds(AfterPolls: 2);
        var jwt = new KomodoAuth.Jwt(_fake.IssueJwt("u-anna"));

        var started = await _komodo.DeployStackAsync(jwt, "app", [], Ct);
        Assert.Equal(("InProgress", "DeployStack"), (started.Status, started.Operation));
        Assert.Equal("InProgress", (await _komodo.GetUpdateAsync(jwt, started.Id, Ct)).Status);
        var done = await _komodo.GetUpdateAsync(jwt, started.Id, Ct);
        Assert.Equal(("Complete", true), (done.Status, done.Success));
        Assert.NotNull(done.EndTs);

        var restart = await _komodo.RestartStackAsync(jwt, "app", ["web"], Ct);
        Assert.Equal("RestartStackService", restart.Operation);
        Assert.Equal(("/execute", "RestartStack", "jwt"), Last());
    }

    [Fact]
    public async Task Deploy_without_execute_fails_later_with_a_task_error()
    {
        var jwt = new KomodoAuth.Jwt(_fake.IssueJwt("u-anna"));

        var started = await _komodo.DeployStackAsync(jwt, "app", [], Ct);
        var done = await _komodo.GetUpdateAsync(jwt, started.Id, Ct);

        Assert.Equal(("Complete", false), (done.Status, done.Success));
        var log = Assert.Single(done.Logs);
        Assert.Equal("Task Error", log.Stage);
        Assert.Contains("does not have required permissions", log.Stderr);
    }

    [Fact]
    public async Task Calls_outside_the_closed_list_are_violations()
    {
        using var http = _fake.CreateHttpClient();

        using var response = await http.PostAsync("/execute",
            new StringContent("""{"type":"DestroyStack","params":{"stack":"app"}}""", Encoding.UTF8, "application/json"), Ct);

        Assert.Equal(400, (int)response.StatusCode);
        Assert.Equal(["/execute DestroyStack"], _fake.Violations);
    }

    [Fact]
    public void Jwt_payload_gives_user_and_expiry()
    {
        // {"sub":"u-anna","iat":1767225600000,"exp":1767312000000}: 2026-01-01 and 2026-01-02, in milliseconds.
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes("""{"sub":"u-anna","iat":1767225600000,"exp":1767312000000}"""))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var read = KomodoJwt.Read($"eyJhbGciOiJIUzI1NiJ9.{payload}.c2lnbmF0dXJl");

        Assert.Equal(("u-anna", new DateTime(2026, 1, 2, 0, 0, 0, DateTimeKind.Utc)), read);
        Assert.Equal(DateTimeKind.Utc, read!.Value.ExpiresAt.Kind);
        Assert.Null(KomodoJwt.Read("not-a-jwt"));
        Assert.Null(KomodoJwt.Read("a.!!!.c"));
    }

    [Fact]
    public void Auth_to_string_hides_the_secrets()
    {
        Assert.DoesNotContain("S_secret_S", new KomodoAuth.Key("K_key_K", "S_secret_S").ToString());
        Assert.DoesNotContain("eyJ.jwt.sig", new KomodoAuth.Jwt("eyJ.jwt.sig").ToString());
    }

    private (string Path, string Type, string AuthKind) Last()
    {
        var last = _fake.Requests[^1];
        return (last.Path, last.Type, last.AuthKind);
    }
}

[Collection("app")]
public sealed class KomodoRegistrationTests(AppFactory app)
{
    [Fact]
    public async Task Client_is_registered_against_the_configured_core()
    {
        app.Komodo.AddUser("u-reg", "registered", "registered-password");
        using var scope = app.Services.CreateScope();
        var komodo = scope.ServiceProvider.GetRequiredService<KomodoClient>();

        var result = await komodo.LoginLocalUserAsync("registered", "registered-password", TestContext.Current.CancellationToken);

        Assert.Equal("u-reg", KomodoJwt.Read(result.Jwt!)?.UserId);
    }
}
