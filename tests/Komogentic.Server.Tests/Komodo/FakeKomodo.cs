// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Komogentic.Server.Komodo;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Komogentic.Server.Tests.Komodo;

[Flags]
public enum FakePermission
{
    None = 0,
    Read = 1,
    /// <summary>A permission level above Read: it includes Read, as in Komodo.</summary>
    Execute = 2,
    /// <summary>A "specific" permission on top of the level (Komodo's <c>PermissionLevel::Read.logs()</c>).</summary>
    Logs = 4,
}

/// <summary>One request the fake saw. <c>AuthKind</c> is <c>jwt</c>, <c>key</c> or <c>none</c>.</summary>
public sealed record FakeRequest(string Path, string Type, string AuthKind, string? ApiKey, JsonElement Params);

public sealed class FakeUser(string id, string username, string password, bool admin, bool twoFactor)
{
    public string Id { get; } = id;
    public string Username { get; } = username;
    public string Password { get; set; } = password;
    public bool Admin { get; set; } = admin;
    public bool TwoFactor { get; set; } = twoFactor;
    public Dictionary<string, FakePermission> Permissions { get; } = [];
}

public sealed class FakeApiKey(string key, string secret, string userId, string name, long expires)
{
    public string Key { get; } = key;
    public string Secret { get; } = secret;
    public string UserId { get; } = userId;
    public string Name { get; } = name;
    /// <summary>Unix milliseconds; 0 for none.</summary>
    public long Expires { get; } = expires;
    public bool Deleted { get; set; }
}

public sealed record FakeService(
    string Service,
    string Image,
    string State = "Running",
    string ContainerState = "running",
    string? Status = "Up 5 minutes",
    bool UpdateAvailable = false,
    string? LatestImage = null);

public sealed record FakeLog(string Stage, string Stdout = "", string Stderr = "", bool Success = true, string Command = "");

/// <summary>What a deploy or restart of a stack does once it has been accepted.</summary>
public abstract record DeployOutcome
{
    private DeployOutcome() { }

    /// <summary>The update completes on the given <c>GetUpdate</c> poll (1 = the first) with these logs.</summary>
    public sealed record Succeeds(int AfterPolls = 1, string Stdout = "Deployed.") : DeployOutcome;

    public sealed record Fails(int AfterPolls = 1, string Stage = "Compose Up", string Stderr = "service app failed to start") : DeployOutcome;

    public sealed record NeverCompletes : DeployOutcome;
}

public sealed class FakeUpdate
{
    public string Id { get; } = RandomNumberGenerator.GetHexString(24, lowercase: true);
    public required string Operation { get; init; }
    public required long StartTs { get; init; }
    public long? EndTs { get; set; }
    public bool Success { get; set; } = true;
    public required string Operator { get; init; }
    public required string Username { get; init; }
    public required string StackId { get; init; }
    public string Status { get; set; } = "Complete";
    public List<FakeLog> Logs { get; } = [];

    internal int Polls;
    internal int CompletesAfterPolls;
    internal Action? Complete;
}

public sealed class FakeStack(string id, string name, string serverName, string state)
{
    public string Id { get; } = id;
    public string Name { get; } = name;
    public string ServerId { get; set; } = "server-" + serverName;
    public string ServerName { get; set; } = serverName;
    public string SwarmId { get; set; } = "";
    public string SwarmName { get; set; } = "";
    public string State { get; set; } = state;
    public string? Status { get; set; }
    /// <summary>A template (Komodo's <c>template: true</c>), which <c>ListStacks</c> leaves out on <c>templates: Exclude</c>.</summary>
    public bool Template { get; set; }
    public List<FakeService> Services { get; } = [];
    /// <summary>What <c>GetStackLog</c> and <c>SearchStackLog</c> read, one line per log line.</summary>
    public string LogText { get; set; } = "";
    public List<FakeUpdate> Updates { get; } = [];
    public DeployOutcome DeployOutcome { get; set; } = new DeployOutcome.Succeeds();
}

/// <summary>
/// Komodo Core 2.3.4 as far as Komogentic uses it, in process on a loopback port: users, JWTs, API keys, stacks,
/// permissions, updates and the twelve calls of the closed list. Shapes follow Komodo's and the mogh crates' sources;
/// what could not be confirmed from them is marked <c>Unconfirmed:</c>.
/// </summary>
public sealed class FakeKomodo : IAsyncDisposable
{
    private static readonly HashSet<string> ClosedList = KomodoCalls.All.Select(c => c.Name).ToHashSet();

    private readonly object _gate = new();
    private readonly byte[] _jwtKey = RandomNumberGenerator.GetBytes(32);
    private readonly Dictionary<string, FakeUser> _users = [];
    private readonly Dictionary<string, FakeStack> _stacks = [];
    private readonly Dictionary<string, FakeApiKey> _keys = [];
    private readonly Dictionary<string, Queue<(int Status, string Body)>> _failNext = [];
    private readonly Dictionary<string, (int Status, string Body)> _failAlways = [];
    private readonly ConcurrentDictionary<string, TimeSpan> _delays = [];
    private readonly List<FakeRequest> _requests = [];
    private readonly List<string> _violations = [];
    private readonly List<string> _jwts = [];
    private readonly Dictionary<string, List<DateTimeOffset>> _generalFailures = [];
    private readonly Dictionary<string, List<DateTimeOffset>> _loginFailures = [];
    private readonly WebApplication _app;

    private FakeKomodo(WebApplication app)
    {
        _app = app;
        _app.Run(HandleAsync);
    }

    public static async Task<FakeKomodo> StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var fake = new FakeKomodo(builder.Build());
        await fake._app.StartAsync();
        fake.Url = new Uri(fake._app.Urls.First());
        return fake;
    }

    public Uri Url { get; private set; } = null!;

    /// <summary>The clock for JWT and API key expiry; tests share theirs with the app.</summary>
    public TimeProvider Time { get; set; } = TimeProvider.System;

    /// <summary>Komodo's <c>jwt_ttl</c> (default one day).</summary>
    public TimeSpan JwtLifetime { get; set; } = TimeSpan.FromDays(1);

    /// <summary>Every connection is dropped without an answer.</summary>
    public bool Down { get; set; }

    /// <summary>Every request is answered 429, as Komodo's auth rate limiter does after too many failures.</summary>
    public bool RateLimited { get; set; }

    /// <summary>
    /// Komodo's auth rate limiters (<c>KOMODO_AUTH_RATE_LIMIT_MAX_ATTEMPTS</c>, <c>…_WINDOW_SECONDS</c>; Komodo's
    /// default is 5 per 15 s); null, the default here, for none. As in mogh_rate_limit 1.0.1, failures are counted per
    /// client address (here every client is Komogentic's one), and once there are as many as allowed in the window,
    /// every request from that address is refused with 429 before its credentials are checked, valid ones too. Komodo
    /// keeps two: <c>GENERAL_RATE_LIMITER</c> for the authenticated routes and <c>LOCAL_LOGIN_RATE_LIMITER</c> for
    /// <c>LoginLocalUser</c> (komodo bin/core/src/auth/mod.rs).
    /// </summary>
    public (int MaxAttempts, TimeSpan Window)? AuthRateLimit { get; set; }

    /// <summary>Komodo's <c>default_pagination_limit</c>, applied to <c>ListStacks</c> without a <c>limit</c>.</summary>
    public int DefaultPaginationLimit { get; set; } = 30;

    public IReadOnlyList<FakeRequest> Requests { get { lock (_gate) return [.. _requests]; } }

    /// <summary>Requests outside the closed list (or on the wrong path); each was answered 400.</summary>
    public IReadOnlyList<string> Violations { get { lock (_gate) return [.. _violations]; } }

    public IReadOnlyList<FakeApiKey> ApiKeys { get { lock (_gate) return [.. _keys.Values]; } }

    /// <summary>Every JWT the fake issued, oldest first: for tests that check where one must not show up.</summary>
    public IReadOnlyList<string> IssuedJwts { get { lock (_gate) return [.. _jwts]; } }

    public HttpClient CreateHttpClient(TimeSpan? timeout = null) =>
        new(new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false })
        {
            BaseAddress = Url,
            Timeout = timeout ?? TimeSpan.FromSeconds(10),
            MaxResponseContentBufferSize = KomodoClient.MaxAnswerBytes,
        };

    public KomodoClient CreateClient(TimeSpan? timeout = null) => new(CreateHttpClient(timeout));

    public FakeUser AddUser(string id, string username, string password, bool admin = false, bool twoFactor = false)
    {
        var user = new FakeUser(id, username, password, admin, twoFactor);
        lock (_gate) _users[id] = user;
        return user;
    }

    public FakeStack AddStack(string id, string name, string server = "server-1", string state = "running", params FakeService[] services)
    {
        var stack = new FakeStack(id, name, server, state);
        stack.Services.AddRange(services);
        lock (_gate) _stacks[id] = stack;
        return stack;
    }

    public FakeStack Stack(string idOrName)
    {
        lock (_gate) return Find(idOrName) ?? throw new KeyNotFoundException(idOrName);
    }

    public void Grant(string userId, string stackId, FakePermission permission)
    {
        lock (_gate) _users[userId].Permissions[stackId] = permission;
    }

    public FakeUpdate AddUpdate(string stackId, string userId, string operation, bool success, long startTs, long? endTs, params FakeLog[] logs)
    {
        lock (_gate)
        {
            var update = new FakeUpdate
            {
                Operation = operation, StartTs = startTs, Operator = userId, Username = _users[userId].Username, StackId = stackId,
            };
            update.Success = success;
            update.EndTs = endTs;
            update.Logs.AddRange(logs);
            _stacks[stackId].Updates.Add(update);
            return update;
        }
    }

    public string IssueJwt(string userId)
    {
        var iat = Now();
        var exp = iat + (long)JwtLifetime.TotalMilliseconds;
        static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var header = B64(Encoding.UTF8.GetBytes("""{"alg":"HS256","typ":"JWT"}"""));
        var payload = B64(JsonSerializer.SerializeToUtf8Bytes(new { sub = userId, iat, exp }));
        var signature = B64(HMACSHA256.HashData(_jwtKey, Encoding.ASCII.GetBytes(header + "." + payload)));
        var jwt = $"{header}.{payload}.{signature}";
        lock (_gate) _jwts.Add(jwt);
        return jwt;
    }

    public FakeApiKey IssueKey(string userId, string name, long expires = 0)
    {
        // Komodo: format!("K_{}_K", random_string(40)) (mogh_auth_server api/manage/api_key.rs).
        var key = new FakeApiKey(
            "K_" + RandomNumberGenerator.GetString(Alphanumeric, 40) + "_K",
            "S_" + RandomNumberGenerator.GetString(Alphanumeric, 40) + "_S",
            userId, name, expires);
        lock (_gate) _keys[key.Key] = key;
        return key;
    }

    /// <summary>The key is deleted in Komodo behind Komogentic's back.</summary>
    public void DeleteKey(string key)
    {
        lock (_gate) _keys[key].Deleted = true;
    }

    /// <summary>The next request of <paramref name="type"/> is answered with this status and body instead.</summary>
    public void FailNext(string type, int status, string body)
    {
        lock (_gate)
        {
            if (!_failNext.TryGetValue(type, out var queue)) _failNext[type] = queue = new();
            queue.Enqueue((status, body));
        }
    }

    /// <summary>Every request of <paramref name="type"/> is answered with this status and body until <see cref="ClearFailures"/>.</summary>
    public void Fail(string type, int status, string body)
    {
        lock (_gate) _failAlways[type] = (status, body);
    }

    public void ClearFailures()
    {
        lock (_gate)
        {
            _failNext.Clear();
            _failAlways.Clear();
        }
    }

    /// <summary>Requests of <paramref name="type"/> (or of every type, with null) wait this long before being answered.</summary>
    public void Delay(string? type, TimeSpan delay) => _delays[type ?? "*"] = delay;

    public static string ErrorBody(string error) => JsonSerializer.Serialize(new { error, trace = Array.Empty<string>() });

    public Task StopAsync() => _app.StopAsync();

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();

    private const string Alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private long Now() => Time.GetUtcNow().ToUnixTimeMilliseconds();

    private sealed class Answer(int status, object? body)
    {
        public int Status { get; } = status;
        public object? Body { get; } = body;
        public string? Raw { get; init; }
    }

    private static Answer Error(int status, string error) => new(status, new { error, trace = Array.Empty<string>() });

    private async Task HandleAsync(HttpContext ctx)
    {
        if (Down)
        {
            ctx.Abort();
            return;
        }

        var path = ctx.Request.Path.Value ?? "";
        JsonElement body;
        try
        {
            body = (await JsonDocument.ParseAsync(ctx.Request.Body, cancellationToken: ctx.RequestAborted)).RootElement.Clone();
        }
        catch (JsonException)
        {
            await WriteAsync(ctx, Error(400, "Failed to parse the request body as JSON"));
            return;
        }

        var type = body.TryGetProperty("type", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString()! : "";
        var parameters = body.TryGetProperty("params", out var p) ? p.Clone() : default;
        var authKind = ctx.Request.Headers.ContainsKey("Authorization") ? "jwt"
            : ctx.Request.Headers.ContainsKey("X-Api-Key") ? "key"
            : "none";
        var apiKey = ctx.Request.Headers.TryGetValue("X-Api-Key", out var k) ? k.ToString() : null;
        lock (_gate) _requests.Add(new FakeRequest(path, type, authKind, apiKey, parameters));

        if (_delays.TryGetValue(type, out var delay) || _delays.TryGetValue("*", out delay))
        {
            try
            {
                await Task.Delay(delay, ctx.RequestAborted);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }

        await WriteAsync(ctx, Respond(ctx, path, type, parameters));
    }

    private Answer Respond(HttpContext ctx, string path, string type, JsonElement parameters)
    {
        lock (_gate)
        {
            if (!ClosedList.Contains(type) || KomodoCalls.Paths[type] != path)
            {
                _violations.Add($"{path} {type}");
                return Error(400, $"The fake Core refuses {type} on {path}: it is not in Komogentic's closed list.");
            }

            if (RateLimited)
                // mogh_rate_limit 1.0.1 lib.rs: anyhow!("Too many attempts | Try again in {:.0?}", …).status_code(429).
                return Error(429, "Too many attempts | Try again in 15s");

            if (_failNext.TryGetValue(type, out var queue) && queue.TryDequeue(out var once))
                return new Answer(once.Status, null) { Raw = once.Body };
            if (_failAlways.TryGetValue(type, out var always))
                return new Answer(always.Status, null) { Raw = always.Body };

            var address = ctx.Connection.RemoteIpAddress?.ToString() ?? "";
            if (type == "LoginLocalUser")
                return Limited(_loginFailures, address, () => Login(parameters));

            // mogh_auth_server 1.8.0 middleware.rs authenticate_request: the credentials are read first (a JWT that
            // doesn't decode fails there, before the limiter, and isn't counted), then the limiter decides whether
            // they are checked at all.
            var (credentials, unreadable) = ReadCredentials(ctx);
            if (unreadable is not null) return unreadable;
            FakeUser? user = null;
            var authenticated = Limited(_generalFailures, address, () =>
            {
                (user, var failure) = Check(credentials!);
                return failure ?? Authenticated;
            });
            if (authenticated != Authenticated) return authenticated;

            return type switch
            {
                "CreateApiKey" => CreateApiKey(user!, parameters),
                "DeleteApiKey" => DeleteApiKey(user!, parameters),
                "ListStacks" => ListStacks(user!, parameters),
                "GetStack" => WithStack(user!, parameters, FakePermission.Read, s => new Answer(200, StackJson(s))),
                "ListStackServices" => WithStack(user!, parameters, FakePermission.Read, s => new Answer(200, s.Services.Select(v => ServiceJson(s, v)).ToArray())),
                "GetStackLog" => WithStack(user!, parameters, FakePermission.Read | FakePermission.Logs, s => GetStackLog(s, parameters)),
                "SearchStackLog" => WithStack(user!, parameters, FakePermission.Read | FakePermission.Logs, s => SearchStackLog(s, parameters)),
                "ListUpdates" => ListUpdates(user!, parameters),
                "GetUpdate" => GetUpdate(user!, parameters),
                "DeployStack" => Execute(user!, parameters, "DeployStack", "DeployStackService"),
                "RestartStack" => Execute(user!, parameters, "RestartStack", "RestartStackService"),
                _ => throw new InvalidOperationException(type),
            };
        }
    }

    private static async Task WriteAsync(HttpContext ctx, Answer answer)
    {
        ctx.Response.StatusCode = answer.Status;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(answer.Raw ?? JsonSerializer.Serialize(answer.Body), ctx.RequestAborted);
    }

    private static readonly Answer Authenticated = new(200, null);

    // mogh_rate_limit 1.0.1 lib.rs with_failure_rate_limit_using_ip: refused once the address has max_attempts failures
    // in the window; otherwise run, and a failure is recorded and told how many attempts remain.
    private Answer Limited(Dictionary<string, List<DateTimeOffset>> failures, string address, Func<Answer> run)
    {
        if (AuthRateLimit is not var (max, window)) return run();
        var now = Time.GetUtcNow();
        if (!failures.TryGetValue(address, out var times)) failures[address] = times = [];
        times.RemoveAll(t => t <= now - window);
        if (times.Count >= max)
            return Error(429, $"Too many attempts | Try again in {Math.Ceiling((window - (now - times[0])).TotalSeconds)}s");

        var answer = run();
        if (answer.Status is >= 200 and < 300) return answer;
        times.Add(now);
        var error = answer.Body is null ? "" : JsonSerializer.SerializeToElement(answer.Body).GetProperty("error").GetString();
        return Error(answer.Status, $"{error} | You have {max - times.Count} attempts remaining");
    }

    private abstract record Credentials
    {
        public sealed record Jwt(string UserId) : Credentials;

        public sealed record Key(string ApiKey, string Secret) : Credentials;
    }

    // mogh_auth_server 1.8.0 middleware.rs extract_request_authentication: a JWT in Authorization ("Bearer " optional)
    // comes first, then X-Api-Key with X-Api-Secret. A JWT that fails to decode or has expired is a plain anyhow error
    // there, so HTTP 500, not 401; no credentials at all is a 401.
    private (Credentials? Credentials, Answer? Failure) ReadCredentials(HttpContext ctx)
    {
        if (ctx.Request.Headers.TryGetValue("Authorization", out var authorization))
        {
            var jwt = authorization.ToString().Trim();
            if (jwt.StartsWith("Bearer ", StringComparison.Ordinal)) jwt = jwt["Bearer ".Length..];
            return ReadJwt(jwt) is { } id ? (new Credentials.Jwt(id), null) : (null, Error(500, "Invalid user credentials"));
        }

        if (ctx.Request.Headers.TryGetValue("X-Api-Key", out var keyHeader))
        {
            if (!ctx.Request.Headers.TryGetValue("X-Api-Secret", out var secretHeader))
                return (null, Error(500, "Request headers have X-API-KEY but missing X-API-SECRET"));
            return (new Credentials.Key(keyHeader.ToString().Trim(), secretHeader.ToString().Trim()), null);
        }

        return (null, Error(401, "Invalid client credentials"));
    }

    // komodo bin/core/src/auth/middleware.rs extract_user_from_auth: a key's expiry with 5 minutes of clock skew
    // tolerance, then its secret; the user must exist. Mapped to 401 in bin/core/src/auth/mod.rs (handle_request_authentication).
    private (FakeUser? User, Answer? Failure) Check(Credentials credentials)
    {
        var userId = credentials switch
        {
            Credentials.Jwt jwt => jwt.UserId,
            Credentials.Key k when _keys.TryGetValue(k.ApiKey, out var key)
                && !key.Deleted
                && (key.Expires == 0 || key.Expires >= Now() - 5 * 60 * 1000)
                && key.Secret == k.Secret => key.UserId,
            _ => null,
        };
        return userId is not null && _users.TryGetValue(userId, out var user) ? (user, null) : (null, Error(401, "Invalid user credentials"));
    }

    private string? ReadJwt(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) return null;
        static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        if (B64(HMACSHA256.HashData(_jwtKey, Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]))) != parts[2]) return null;
        try
        {
            return Subject(parts[1]);
        }
        catch (Exception e) when (e is FormatException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return null;
        }
    }

    private string? Subject(string encodedPayload)
    {
        var padded = encodedPayload.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        using var payload = JsonDocument.Parse(Convert.FromBase64String(padded));
        // mogh_auth_server provider/jwt.rs: exp in ms, accepted until exp plus a clock skew tolerance, which the
        // fake leaves out so that a test's clock decides exactly.
        return payload.RootElement.GetProperty("exp").GetInt64() > Now() ? payload.RootElement.GetProperty("sub").GetString() : null;
    }

    // mogh_auth_server api/login/local.rs and mogh_auth_client api/login.rs: JwtOrTwoFactor, tag "type", content "data".
    private Answer Login(JsonElement p)
    {
        var username = p.GetProperty("username").GetString();
        var password = p.GetProperty("password").GetString();
        var user = _users.Values.FirstOrDefault(u => u.Username == username);
        if (user is null || user.Password != password)
            return Error(401, "Invalid login credentials");
        if (user.TwoFactor)
            return new Answer(200, new { type = "Totp", data = new { } });
        return new Answer(200, new { type = "Jwt", data = new { jwt = IssueJwt(user.Id) } });
    }

    // mogh_auth_client api/manage.rs CreateApiKey {name, expires} → CreateApiKeyResponse {key, secret}.
    private Answer CreateApiKey(FakeUser user, JsonElement p)
    {
        var expires = p.TryGetProperty("expires", out var e) ? e.GetInt64() : 0;
        var key = IssueKey(user.Id, p.GetProperty("name").GetString()!, expires);
        return new Answer(200, new { key = key.Key, secret = key.Secret });
    }

    // mogh_auth_server api/manage/api_key.rs delete_api_key; komodo bin/core/src/auth/mod.rs get_api_key_user_id (404).
    private Answer DeleteApiKey(FakeUser user, JsonElement p)
    {
        if (!_keys.TryGetValue(p.GetProperty("key").GetString()!, out var key) || key.Deleted)
            return Error(404, "No api key with key found");
        if (key.UserId != user.Id)
            return Error(403, "Api key does not belong to user");
        key.Deleted = true;
        return new Answer(200, new { });
    }

    private bool Has(FakeUser user, FakeStack stack, FakePermission needed)
    {
        if (user.Admin) return true;
        var granted = user.Permissions.GetValueOrDefault(stack.Id);
        if (granted.HasFlag(FakePermission.Execute)) granted |= FakePermission.Read;
        return (granted & needed) == needed;
    }

    private FakeStack? Find(string idOrName) =>
        _stacks.GetValueOrDefault(idOrName) ?? _stacks.Values.FirstOrDefault(s => s.Name == idOrName);

    // komodo bin/core/src/resource/mod.rs get (not found) and bin/core/src/permission.rs get_check_permissions;
    // both plain anyhow errors, so HTTP 500.
    private Answer WithStack(FakeUser user, JsonElement p, FakePermission needed, Func<FakeStack, Answer> then)
    {
        var name = p.GetProperty("stack").GetString()!;
        if (Find(name) is not { } stack)
            return Error(500, $"Did not find any Stack matching {name}");
        if (!Has(user, stack, needed))
        {
            var level = needed.HasFlag(FakePermission.Execute) ? "Execute" : "Read";
            var specifics = needed.HasFlag(FakePermission.Logs) ? ", as well as these specific permissions: [Logs]" : "";
            return Error(500, $"User does not have required permissions on this Stack. Must have at least {level} permissions{specifics}");
        }
        return then(stack);
    }

    // komodo bin/core/src/api/read/stack.rs ListStacks: Read-visible stacks, query.names, limit (absent →
    // default_pagination_limit, 0 → all) and page. StackListItem = ResourceListItem<StackListItemInfo>
    // (client/core/rs/src/entities/resource.rs, entities/stack.rs).
    private Answer ListStacks(FakeUser user, JsonElement p)
    {
        var names = p.TryGetProperty("query", out var q) && q.TryGetProperty("names", out var n)
            ? n.EnumerateArray().Select(x => x.GetString()).ToHashSet()
            : null;
        // entities/resource.rs TemplatesQueryBehavior: Include (the default), Exclude or Only.
        var templates = q.ValueKind == JsonValueKind.Object && q.TryGetProperty("templates", out var tq) ? tq.GetString() : "Include";
        var limit = p.TryGetProperty("limit", out var l) && l.ValueKind == JsonValueKind.Number ? l.GetInt32() : DefaultPaginationLimit;
        var page = p.TryGetProperty("page", out var pg) ? pg.GetInt32() : 0;
        var visible = _stacks.Values
            .Where(s => Has(user, s, FakePermission.Read))
            .Where(s => names is null || names.Count == 0 || names.Contains(s.Name))
            .Where(s => templates switch { "Exclude" => !s.Template, "Only" => s.Template, _ => true })
            .OrderBy(s => s.Name, StringComparer.Ordinal)
            .Skip(limit == 0 ? 0 : page * limit);
        if (limit != 0) visible = visible.Take(limit);
        return new Answer(200, visible.Select(s => new
        {
            id = s.Id,
            type = "Stack",
            name = s.Name,
            template = s.Template,
            tags = Array.Empty<string>(),
            info = new
            {
                swarm_id = s.SwarmId,
                swarm_name = s.SwarmName,
                server_id = s.ServerId,
                server_name = s.ServerName,
                files_on_host = false,
                file_contents = true,
                linked_repo = "",
                linked_repo_name = "",
                git_provider = "",
                repo = "",
                branch = "",
                repo_link = "",
                state = s.State,
                status = s.Status,
                services = s.Services.Select(v => new
                {
                    service = v.Service,
                    image = v.Image,
                    latest_image = v.LatestImage,
                    update_available = v.UpdateAvailable,
                }).ToArray(),
                auto_update_all_services = false,
                project_missing = false,
                missing_files = Array.Empty<string>(),
                deployed_hash = (string?)null,
                latest_hash = (string?)null,
            },
        }).ToArray());
    }

    // client/core/rs/src/entities/mod.rs Resource<Config, Info>; the id is bson's ObjectId as {"$oid": hex}.
    // Config and info carry many more fields; only the ones Komogentic could read are here.
    // Unconfirmed: the serialised shape of base_permission.
    private static Dictionary<string, object?> StackJson(FakeStack s) => new()
    {
        ["_id"] = new Dictionary<string, string> { ["$oid"] = s.Id },
        ["name"] = s.Name,
        ["description"] = "",
        ["template"] = s.Template,
        ["tags"] = Array.Empty<string>(),
        ["info"] = new { missing_files = Array.Empty<string>() },
        ["config"] = new { server_id = s.ServerId, swarm_id = s.SwarmId },
        ["base_permission"] = "None",
    };

    // client/core/rs/src/entities/stack.rs StackService; entities/docker/container.rs ContainerListItem (state lowercase).
    // A Swarm stack's swarm_service (SwarmServiceListItem, PascalCase fields) is reduced to ID, Name and Image.
    private static object ServiceJson(FakeStack s, FakeService v) => new
    {
        stack_id = s.Id,
        stack_name = s.Name,
        service = v.Service,
        image = v.Image,
        container = s.SwarmId == "" ? ContainerJson(s, v) : null,
        swarm_service = s.SwarmId == "" ? null : new { ID = v.Service, Name = $"{s.Name}_{v.Service}", Image = v.Image },
        state = v.State,
        image_digests = (string[]?)null,
    };

    // entities/docker/container.rs ContainerListItem: its Option fields are skip_serializing_if = "Option::is_none".
    private static Dictionary<string, object> ContainerJson(FakeStack s, FakeService v)
    {
        var container = new Dictionary<string, object> { ["name"] = $"{s.Name}-{v.Service}-1", ["image"] = v.Image, ["state"] = v.ContainerState };
        if (v.Status is { } status) container["status"] = status;
        return container;
    }

    // client/core/rs/src/entities/update.rs Log.
    private object LogJson(FakeLog log, long ts) => new
    {
        stage = log.Stage,
        command = log.Command,
        stdout = log.Stdout,
        stderr = log.Stderr,
        success = log.Success,
        start_ts = ts,
        end_ts = ts,
    };

    // client/core/rs/src/api/read/stack.rs GetStackLog {stack, services, tail, timestamps} → Log.
    // Unconfirmed: the log's stage and the exact command Periphery runs; the fake's are only illustrative.
    private Answer GetStackLog(FakeStack s, JsonElement p)
    {
        var tail = p.TryGetProperty("tail", out var t) ? t.GetInt32() : 50;
        var services = p.GetProperty("services").EnumerateArray().Select(x => x.GetString()).ToArray();
        var lines = Lines(s.LogText);
        var stdout = string.Join("\n", lines.Skip(Math.Max(0, lines.Length - tail)));
        var command = $"docker compose -p {s.Name} logs --tail {tail} {string.Join(" ", services)}".TrimEnd();
        return new Answer(200, LogJson(new FakeLog("get stack log", stdout, Command: command), Now()));
    }

    // client/core/rs/src/api/read/stack.rs SearchStackLog; bin/periphery/src/helpers.rs: the last 5000 lines through
    // grep -E 'a|b' (Or) or grep -P '^(?=.*a)(?=.*b)' (And), terms as regular expressions, case-sensitive.
    private Answer SearchStackLog(FakeStack s, JsonElement p)
    {
        var terms = p.GetProperty("terms").EnumerateArray().Select(x => new Regex(x.GetString()!)).ToArray();
        var and = p.TryGetProperty("combinator", out var c) && c.GetString() == "And";
        var invert = p.TryGetProperty("invert", out var i) && i.GetBoolean();
        var lines = Lines(s.LogText);
        var matching = lines.Skip(Math.Max(0, lines.Length - 5000))
            .Where(line => (and ? terms.All(r => r.IsMatch(line)) : terms.Any(r => r.IsMatch(line))) != invert);
        return new Answer(200, LogJson(new FakeLog("search stack log", string.Join("\n", matching), Command: "grep"), Now()));
    }

    private static string[] Lines(string text) => text.Length == 0 ? [] : text.Split('\n');

    // client/core/rs/src/entities/update.rs UpdateListItem; bin/core/src/api/read/update.rs ListUpdates: newest first,
    // 100 per page, next_page; a non-admin sees only updates of what they can read.
    // The query is a full Mongo filter in Komodo; the fake reads only target.type and target.id.
    private Answer ListUpdates(FakeUser user, JsonElement p)
    {
        string? targetType = null, targetId = null;
        if (p.TryGetProperty("query", out var q) && q.ValueKind == JsonValueKind.Object)
        {
            if (q.TryGetProperty("target.type", out var tt)) targetType = tt.GetString();
            if (q.TryGetProperty("target.id", out var ti)) targetId = ti.GetString();
        }
        var page = p.TryGetProperty("page", out var pg) ? pg.GetInt32() : 0;
        var all = _stacks.Values
            .Where(s => targetType is null or "Stack")
            .Where(s => targetId is null || s.Id == targetId)
            .Where(s => Has(user, s, FakePermission.Read))
            .SelectMany(s => s.Updates)
            .OrderByDescending(u => u.StartTs)
            .ToList();
        var items = all.Skip(page * 100).Take(100).Select(u => new
        {
            id = u.Id,
            operation = u.Operation,
            start_ts = u.StartTs,
            success = u.Success,
            username = u.Username,
            @operator = u.Operator,
            target = new { type = "Stack", id = u.StackId },
            status = u.Status,
        }).ToArray();
        return new Answer(200, new { updates = items, next_page = all.Count > (page + 1) * 100 ? page + 1 : (int?)null });
    }

    // client/core/rs/src/entities/update.rs Update; bin/core/src/api/read/update.rs GetUpdate (Read on the target).
    private Answer GetUpdate(FakeUser user, JsonElement p)
    {
        var id = p.GetProperty("id").GetString();
        var found = _stacks.Values.SelectMany(s => s.Updates.Select(u => (Stack: s, Update: u))).FirstOrDefault(x => x.Update.Id == id);
        if (found.Update is null)
            return Error(500, "no update exists with given id");
        if (!Has(user, found.Stack, FakePermission.Read))
            return Error(500, "User does not have required permissions on this Stack. Must have at least Read permissions");
        var update = found.Update;
        if (update.Complete is not null && ++update.Polls >= update.CompletesAfterPolls)
        {
            update.Complete();
            update.Complete = null;
        }
        return new Answer(200, UpdateJson(update));
    }

    private Dictionary<string, object?> UpdateJson(FakeUpdate u) => new()
    {
        ["_id"] = new Dictionary<string, string> { ["$oid"] = u.Id },
        ["operation"] = u.Operation,
        ["start_ts"] = u.StartTs,
        ["success"] = u.Success,
        ["operator"] = u.Operator,
        ["target"] = new { type = "Stack", id = u.StackId },
        ["logs"] = u.Logs.Select(l => LogJson(l, u.StartTs)).ToArray(),
        ["end_ts"] = u.EndTs,
        ["status"] = u.Status,
    };

    // komodo bin/core/src/api/execute/mod.rs inner_handler and helpers/update.rs init_execution_update: the stack is
    // looked up without a permission check (unknown → 500), an Update is stored InProgress (operation …Service when
    // services are given) and returned at once; the permission check runs in the task, and its failure is a
    // "Task Error" log whose stderr is format_serror (lib/formatting) of the error, then the update completes.
    private Answer Execute(FakeUser user, JsonElement p, string operation, string serviceOperation)
    {
        var name = p.GetProperty("stack").GetString()!;
        if (Find(name) is not { } stack)
            return Error(500, $"Did not find any Stack matching {name}");
        var services = p.TryGetProperty("services", out var sv) ? sv.GetArrayLength() : 0;
        var update = new FakeUpdate
        {
            Operation = services > 0 ? serviceOperation : operation,
            StartTs = Now(),
            Operator = user.Id,
            Username = user.Username,
            StackId = stack.Id,
            Status = "InProgress",
        };
        var now = Now;

        if (!Has(user, stack, FakePermission.Execute))
        {
            update.CompletesAfterPolls = 1;
            update.Complete = () =>
            {
                // bin/core/src/stack/mod.rs setup_stack_execution adds no context, so the message has no TRACE part.
                update.Logs.Add(new FakeLog("Task Error",
                    Stderr: "<span style=\"color: var(--mantine-color-red-6)\">ERROR</span>: User does not have required permissions on this Stack. Must have at least Execute permissions",
                    Success: false));
                update.Success = false;
                update.Status = "Complete";
                update.EndTs = now();
            };
        }
        else
        {
            switch (stack.DeployOutcome)
            {
                // Unconfirmed: the stages and commands of a real deploy's logs; only "Task Error" is from the source.
                case DeployOutcome.Succeeds ok:
                    update.CompletesAfterPolls = ok.AfterPolls;
                    update.Complete = () =>
                    {
                        update.Logs.Add(new FakeLog("Compose Up", ok.Stdout, Command: $"docker compose -p {stack.Name} up -d"));
                        update.Status = "Complete";
                        update.EndTs = now();
                    };
                    break;
                case DeployOutcome.Fails failed:
                    update.CompletesAfterPolls = failed.AfterPolls;
                    update.Complete = () =>
                    {
                        update.Logs.Add(new FakeLog(failed.Stage, Stderr: failed.Stderr, Success: false, Command: $"docker compose -p {stack.Name} up -d"));
                        update.Success = false;
                        update.Status = "Complete";
                        update.EndTs = now();
                    };
                    break;
                case DeployOutcome.NeverCompletes:
                    break;
            }
        }

        stack.Updates.Add(update);
        return new Answer(200, UpdateJson(update));
    }
}
