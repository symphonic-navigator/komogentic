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

    public async ValueTask DisposeAsync()
    {
        var violations = _fake.Violations;
        await _fake.DisposeAsync();
        Assert.True(violations.Count == 0, "The fake Core saw calls outside the closed list: " + string.Join(", ", violations));
    }

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
        var expires = new DateTimeOffset(2027, 2, 10, 12, 0, 0, TimeSpan.Zero);

        var created = await _komodo.CreateApiKeyAsync(jwt, "komogentic/Hermes", expires, Ct);

        Assert.Matches("^K_[A-Za-z0-9]{40}_K$", created.Key);
        Assert.Matches("^S_[A-Za-z0-9]{40}_S$", created.Secret);
        var stored = Assert.Single(_fake.ApiKeys);
        Assert.Equal(("u-anna", "komogentic/Hermes", expires.ToUnixTimeMilliseconds()), (stored.UserId, stored.Name, stored.Expires));
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
    public async Task Create_api_key_expiry_is_sent_in_utc_milliseconds()
    {
        var expires = new DateTimeOffset(2027, 2, 10, 14, 0, 0, TimeSpan.FromHours(2));

        await _komodo.CreateApiKeyAsync(new KomodoAuth.Jwt(_fake.IssueJwt("u-anna")), "komogentic/Hermes", expires, Ct);

        Assert.Equal(1_802_260_800_000, _fake.Requests[^1].Params.GetProperty("expires").GetInt64());
    }

    [Fact]
    public async Task Delete_with_any_other_404_is_a_failure()
    {
        var jwt = new KomodoAuth.Jwt(_fake.IssueJwt("u-anna"));
        // A proxy in front of Komodo that doesn't know the route, and a 404 of Komodo's that isn't about the key.
        _fake.FailNext("DeleteApiKey", 404, "<html>404 page not found</html>");
        _fake.FailNext("DeleteApiKey", 404, FakeKomodo.ErrorBody("Failed to find user"));

        var proxy = await Assert.ThrowsAsync<KomodoException>(() => _komodo.DeleteApiKeyAsync(jwt, "K_gone_K", Ct));
        var other = await Assert.ThrowsAsync<KomodoException>(() => _komodo.DeleteApiKeyAsync(jwt, "K_gone_K", Ct));

        Assert.Equal((KomodoErrorKind.NotFoundOrForbidden, 404), (proxy.Kind, proxy.Status));
        Assert.Equal((KomodoErrorKind.NotFoundOrForbidden, 404), (other.Kind, other.Status));
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
    public async Task Only_komodos_credential_errors_are_unauthorized()
    {
        var jwt = new KomodoAuth.Jwt(_fake.IssueJwt("u-anna"));
        // An auth proxy in front of Komodo, and a 401 of Komodo's that says nothing about the credentials.
        _fake.FailNext("ListStacks", 401, "");
        _fake.FailNext("ListStacks", 401, FakeKomodo.ErrorBody("Local auth is not enabled"));
        _fake.FailNext("ListStacks", 401, FakeKomodo.ErrorBody("Invalid client credentials"));
        _fake.FailNext("ListStacks", 500, FakeKomodo.ErrorBody("Invalid user credentials | You have 4 attempts remaining"));
        _fake.FailNext("ListStacks", 403, FakeKomodo.ErrorBody("Invalid user credentials"));

        Assert.Equal((KomodoErrorKind.Failed, 401), Classified(await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(jwt, Ct))));
        Assert.Equal((KomodoErrorKind.Failed, 401), Classified(await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(jwt, Ct))));
        Assert.Equal((KomodoErrorKind.Unauthorized, 401), Classified(await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(jwt, Ct))));
        Assert.Equal((KomodoErrorKind.Unauthorized, 500), Classified(await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(jwt, Ct))));
        Assert.NotEqual(KomodoErrorKind.Unauthorized, (await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(jwt, Ct))).Kind);

        static (KomodoErrorKind, int) Classified(KomodoException e) => (e.Kind, e.Status);
    }

    [Fact]
    public async Task Rate_limited_is_its_own_kind()
    {
        _fake.RateLimited = true;

        var e = await Assert.ThrowsAsync<KomodoException>(() => _komodo.LoginLocalUserAsync("anna", "anna-password", Ct));

        Assert.Equal(KomodoErrorKind.RateLimited, e.Kind);
        Assert.Equal(429, e.Status);
        Assert.StartsWith(
            "Komodo is refusing requests from Komogentic for a moment after several failed authentications; try again in a minute.", e.Message);
        Assert.Contains("Try again in 15s", e.Message);

        _fake.RateLimited = false;
        _fake.FailNext("ListStacks", 429, "");
        var bare = await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(new KomodoAuth.Jwt(_fake.IssueJwt("u-anna")), Ct));
        Assert.Equal(
            "Komodo is refusing requests from Komogentic for a moment after several failed authentications; try again in a minute.", bare.Message);
    }

    [Fact]
    public async Task Failed_authentications_trip_komodos_limit_for_valid_requests_too()
    {
        _fake.AuthRateLimit = (5, TimeSpan.FromSeconds(15));
        var key = _fake.IssueKey("u-anna", "komogentic/Hermes");
        var valid = new KomodoAuth.Key(key.Key, key.Secret);
        var wrong = new KomodoAuth.Key(key.Key, "S_wrong_S");

        await _komodo.ListStacksAsync(valid, Ct);
        for (var i = 0; i < 5; i++)
        {
            var refused = await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(wrong, Ct));
            Assert.Equal(KomodoErrorKind.Unauthorized, refused.Kind);
        }

        var limited = await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(valid, Ct));
        Assert.Equal((KomodoErrorKind.RateLimited, 429), (limited.Kind, limited.Status));
        Assert.Equal(KomodoErrorKind.RateLimited,
            (await Assert.ThrowsAsync<KomodoException>(() => _komodo.GetStackAsync(new KomodoAuth.Jwt(_fake.IssueJwt("u-anna")), "app", Ct))).Kind);
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
    public async Task Answer_without_a_required_field_is_an_unknown_shape()
    {
        var jwt = new KomodoAuth.Jwt(_fake.IssueJwt("u-anna"));
        _fake.FailNext("ListStacks", 200, """[{"id":"65f0c0ffee0000000000a001","type":"Stack","name":"app","template":false,"tags":[]}]""");
        _fake.FailNext("ListStacks", 200, """[{"id":"65f0c0ffee0000000000a001","type":"Stack","name":null,"template":false,"tags":[],"info":{}}]""");

        var missing = await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(jwt, Ct));
        var nulled = await Assert.ThrowsAsync<KomodoException>(() => _komodo.ListStacksAsync(jwt, Ct));

        Assert.Equal((KomodoErrorKind.Failed, "Komodo answered in a shape Komogentic does not know (ListStacks)."), (missing.Kind, missing.Message));
        Assert.Equal((KomodoErrorKind.Failed, "Komodo answered in a shape Komogentic does not know (ListStacks)."), (nulled.Kind, nulled.Message));
    }

    [Fact]
    public async Task Answer_larger_than_komogentic_reads_is_a_failure()
    {
        _fake.FailNext("GetStackLog", 200, "\"" + new string('x', KomodoClient.MaxAnswerBytes) + "\"");

        var e = await Assert.ThrowsAsync<KomodoException>(() =>
            _komodo.GetStackLogAsync(new KomodoAuth.Jwt(_fake.IssueJwt("u-anna")), "app", [], 5000, false, Ct));

        Assert.Equal((KomodoErrorKind.Failed, "Komodo's answer to GetStackLog is larger than Komogentic reads."), (e.Kind, e.Message));
    }

    [Fact]
    public async Task Fields_komodo_leaves_out_when_empty_may_be_missing()
    {
        // ContainerListItem's status is skip_serializing_if = "Option::is_none" (entities/docker/container.rs).
        _fake.Stack("app").Services[0] = new FakeService("web", "nginx:1.27", Status: null);

        var service = Assert.Single(await _komodo.ListStackServicesAsync(new KomodoAuth.Jwt(_fake.IssueJwt("u-anna")), "app", Ct));

        Assert.Equal(("running", null), (service.Container?.State, service.Container?.Status));
    }

    [Fact]
    public async Task List_stacks_leaves_out_templates()
    {
        _fake.AddStack("65f0c0ffee0000000000c003", "app-template", "server-1", "unknown").Template = true;
        _fake.Grant("u-anna", "65f0c0ffee0000000000c003", FakePermission.Read);
        var jwt = new KomodoAuth.Jwt(_fake.IssueJwt("u-anna"));

        Assert.Equal(["app"], (await _komodo.ListStacksAsync(jwt, Ct)).Select(s => s.Name));
        Assert.Equal("Exclude", _fake.Requests[^1].Params.GetProperty("query").GetProperty("templates").GetString());
        Assert.Null(await _komodo.FindStackAsync(jwt, "app-template", Ct));
        Assert.Equal("Exclude", _fake.Requests[^1].Params.GetProperty("query").GetProperty("templates").GetString());
    }

    [Fact]
    public async Task Get_update_refuses_a_malformed_id_without_asking()
    {
        var jwt = new KomodoAuth.Jwt(_fake.IssueJwt("u-anna"));
        var before = _fake.Requests.Count;

        foreach (var id in (string[])["", "../read", "65F0C0FFEE0000000000A001", "65f0c0ffee0000000000a0011", "{\"$ne\":null}"])
        {
            var e = await Assert.ThrowsAsync<KomodoException>(() => _komodo.GetUpdateAsync(jwt, id, Ct));
            Assert.Equal(KomodoErrorKind.NotFoundOrForbidden, e.Kind);
        }

        Assert.Equal(before, _fake.Requests.Count);
    }

    [Fact]
    public async Task Update_komodo_does_not_show_is_not_found_or_forbidden()
    {
        var jwt = new KomodoAuth.Jwt(_fake.IssueJwt("u-anna"));
        _fake.FailNext("GetUpdate", 500, FakeKomodo.ErrorBody("user must be admin to view system updates"));

        var system = await Assert.ThrowsAsync<KomodoException>(() => _komodo.GetUpdateAsync(jwt, "65f0c0ffee0000000000d004", Ct));
        var unknown = await Assert.ThrowsAsync<KomodoException>(() => _komodo.GetUpdateAsync(jwt, "65f0c0ffee0000000000d004", Ct));

        Assert.Equal(KomodoErrorKind.NotFoundOrForbidden, system.Kind);
        Assert.Equal(KomodoErrorKind.NotFoundOrForbidden, unknown.Kind);
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
        // A fake of its own: this test's violation is meant, and the shared one must end without any.
        await using var fake = await FakeKomodo.StartAsync();
        using var http = fake.CreateHttpClient();

        using var response = await http.PostAsync("/execute",
            new StringContent("""{"type":"DestroyStack","params":{"stack":"app"}}""", Encoding.UTF8, "application/json"), Ct);

        Assert.Equal(400, (int)response.StatusCode);
        Assert.Equal(["/execute DestroyStack"], fake.Violations);
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

    [Fact]
    public void Client_buffers_at_most_16_mb_of_an_answer()
    {
        var http = app.Services.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(KomodoClient));

        Assert.Equal(16 * 1024 * 1024, http.MaxResponseContentBufferSize);
    }
}
