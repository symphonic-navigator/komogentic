// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net.Http.Headers;
using System.Text.Json;

namespace Komogentic.Server.Komodo;

/// <summary>How a call authenticates to Komodo (mogh_auth_server 1.8.0, <c>middleware.rs</c>).</summary>
public abstract record KomodoAuth
{
    private KomodoAuth() { }

    /// <summary>A JWT from <c>LoginLocalUser</c>, sent raw in <c>Authorization</c>.</summary>
    public sealed record Jwt(string Token) : KomodoAuth
    {
        public override string ToString() => "KomodoAuth.Jwt";
    }

    /// <summary>A Komodo API key of the calling user, sent as <c>X-Api-Key</c> and <c>X-Api-Secret</c>.</summary>
    public sealed record Key(string ApiKey, string Secret) : KomodoAuth
    {
        public override string ToString() => $"KomodoAuth.Key {{ ApiKey = {ApiKey} }}";
    }
}

/// <summary>
/// Komodo Core's API, limited to the calls of <see cref="KomodoCall"/>. Every request goes through
/// <see cref="SendAsync"/>, the only member that builds one (ClosedListTests checks this).
/// </summary>
public sealed class KomodoClient(HttpClient http)
{
    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public async Task<LoginResult> LoginLocalUserAsync(string username, string password, CancellationToken ct)
    {
        var answer = await SendAsync(KomodoCall.LoginLocalUser, null, new { username, password }, ct);
        return Parse(KomodoCall.LoginLocalUser.Name, answer, a => a.GetProperty("type").GetString() switch
        {
            "Jwt" => new LoginResult(a.GetProperty("data").GetProperty("jwt").GetString() ?? throw new JsonException(), false),
            "Totp" or "Passkey" => new LoginResult(null, true),
            _ => throw new JsonException(),
        });
    }

    /// <summary><paramref name="expiresAt"/> null for a key without expiry (<c>expires: 0</c>).</summary>
    public async Task<CreatedKey> CreateApiKeyAsync(KomodoAuth.Jwt auth, string name, DateTime? expiresAt, CancellationToken ct)
    {
        var expires = expiresAt is { } at ? new DateTimeOffset(at.ToUniversalTime()).ToUnixTimeMilliseconds() : 0;
        var answer = await SendAsync(KomodoCall.CreateApiKey, auth, new { name, expires }, ct);
        return Read<CreatedKey>(KomodoCall.CreateApiKey.Name, answer);
    }

    /// <summary>A key Komodo no longer has counts as deleted.</summary>
    public async Task DeleteApiKeyAsync(KomodoAuth.Jwt auth, string key, CancellationToken ct)
    {
        try
        {
            await SendAsync(KomodoCall.DeleteApiKey, auth, new { key }, ct);
        }
        catch (KomodoException e) when (e.Status == 404)
        {
            // "No api key with key found" (komodo bin/core/src/auth/mod.rs, get_api_key_user_id).
        }
    }

    /// <summary>Every stack the user may read. Without <c>limit: 0</c> Komodo returns one page of <c>default_pagination_limit</c> (30).</summary>
    public async Task<IReadOnlyList<StackListItem>> ListStacksAsync(KomodoAuth auth, CancellationToken ct)
    {
        var answer = await SendAsync(KomodoCall.ListStacks, auth, new { query = new { }, limit = 0 }, ct);
        return Read<List<StackListItem>>(KomodoCall.ListStacks.Name, answer);
    }

    public async Task<StackListItem?> FindStackAsync(KomodoAuth auth, string name, CancellationToken ct)
    {
        var answer = await SendAsync(KomodoCall.ListStacks, auth, new { query = new { names = new[] { name } } }, ct);
        return Read<List<StackListItem>>(KomodoCall.ListStacks.Name, answer).FirstOrDefault(s => s.Name == name);
    }

    /// <summary>Komodo accepts an id or a name; the answer gives both, canonical.</summary>
    public async Task<StackRef> GetStackAsync(KomodoAuth auth, string idOrName, CancellationToken ct)
    {
        var answer = await SendAsync(KomodoCall.GetStack, auth, new { stack = idOrName }, ct);
        return Parse(KomodoCall.GetStack.Name, answer, a => new StackRef(
            a.GetProperty("_id").GetProperty("$oid").GetString() ?? throw new JsonException(),
            a.GetProperty("name").GetString() ?? throw new JsonException()));
    }

    public async Task<IReadOnlyList<StackService>> ListStackServicesAsync(KomodoAuth auth, string stack, CancellationToken ct)
    {
        var answer = await SendAsync(KomodoCall.ListStackServices, auth, new { stack }, ct);
        return Read<List<StackService>>(KomodoCall.ListStackServices.Name, answer);
    }

    public async Task<KomodoLog> GetStackLogAsync(
        KomodoAuth auth, string stack, IReadOnlyList<string> services, int tail, bool timestamps, CancellationToken ct)
    {
        var answer = await SendAsync(KomodoCall.GetStackLog, auth, new { stack, services, tail, timestamps }, ct);
        return Read<KomodoLog>(KomodoCall.GetStackLog.Name, answer);
    }

    /// <summary><paramref name="all"/>: every term must match (<c>And</c>); otherwise any (<c>Or</c>). Komodo reads terms as regular expressions.</summary>
    public async Task<KomodoLog> SearchStackLogAsync(
        KomodoAuth auth, string stack, IReadOnlyList<string> services, IReadOnlyList<string> terms, bool all, bool timestamps, CancellationToken ct)
    {
        var combinator = all ? "And" : "Or";
        var answer = await SendAsync(KomodoCall.SearchStackLog, auth, new { stack, services, terms, combinator, invert = false, timestamps }, ct);
        return Read<KomodoLog>(KomodoCall.SearchStackLog.Name, answer);
    }

    /// <summary>The newest 100 updates of the stack (Komodo's first page).</summary>
    public async Task<IReadOnlyList<UpdateListItem>> ListUpdatesAsync(KomodoAuth auth, string stackId, CancellationToken ct)
    {
        var query = new Dictionary<string, string> { ["target.type"] = "Stack", ["target.id"] = stackId };
        var answer = await SendAsync(KomodoCall.ListUpdates, auth, new { query, page = 0 }, ct);
        return Read<UpdateListPage>(KomodoCall.ListUpdates.Name, answer).Updates;
    }

    public async Task<Update> GetUpdateAsync(KomodoAuth auth, string id, CancellationToken ct)
    {
        var answer = await SendAsync(KomodoCall.GetUpdate, auth, new { id }, ct);
        return Read<Update>(KomodoCall.GetUpdate.Name, answer);
    }

    /// <summary>
    /// Komodo answers at once with the update, in progress; a missing Execute permission shows only later, as the
    /// update completing unsuccessfully with a "Task Error" log.
    /// </summary>
    public async Task<Update> DeployStackAsync(KomodoAuth auth, string stack, IReadOnlyList<string> services, CancellationToken ct)
    {
        var answer = await SendAsync(KomodoCall.DeployStack, auth, new { stack, services }, ct);
        return Read<Update>(KomodoCall.DeployStack.Name, answer);
    }

    /// <inheritdoc cref="DeployStackAsync"/>
    public async Task<Update> RestartStackAsync(KomodoAuth auth, string stack, IReadOnlyList<string> services, CancellationToken ct)
    {
        var answer = await SendAsync(KomodoCall.RestartStack, auth, new { stack, services }, ct);
        return Read<Update>(KomodoCall.RestartStack.Name, answer);
    }

    private async Task<JsonElement> SendAsync(KomodoCall call, KomodoAuth? auth, object parameters, CancellationToken ct)
    {
        // Relative to BaseAddress, so that a Komodo behind a path prefix keeps it.
        using var request = new HttpRequestMessage(HttpMethod.Post, call.Path.TrimStart('/'));
        var body = JsonSerializer.SerializeToUtf8Bytes(new { type = call.Name, @params = parameters }, Json);
        request.Content = new ByteArrayContent(body) { Headers = { ContentType = new MediaTypeHeaderValue("application/json") } };
        switch (auth)
        {
            case KomodoAuth.Jwt jwt:
                request.Headers.TryAddWithoutValidation("Authorization", jwt.Token);
                break;
            case KomodoAuth.Key key:
                request.Headers.TryAddWithoutValidation("X-Api-Key", key.ApiKey);
                request.Headers.TryAddWithoutValidation("X-Api-Secret", key.Secret);
                break;
        }

        int status;
        byte[] answer;
        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseContentRead, ct);
            status = (int)response.StatusCode;
            answer = await response.Content.ReadAsByteArrayAsync(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException or IOException)
        {
            // HttpClient.Timeout surfaces as a TaskCanceledException that the caller's token did not cause.
            throw new KomodoException(KomodoErrorKind.Unreachable, 0, "Komodo could not be reached");
        }

        if (status is >= 200 and < 300)
            return Parse(call.Name, answer, a => a);
        throw Classify(call.Name, status, answer);
    }

    private static KomodoException Classify(string call, int status, byte[] answer)
    {
        // mogh_error 1.0.4 Serror {error, trace}; plain anyhow errors (not found, no permission) default to 500.
        string error = "", trace = "";
        try
        {
            using var doc = JsonDocument.Parse(answer);
            if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                if (doc.RootElement.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.String) error = e.GetString()!;
                if (doc.RootElement.TryGetProperty("trace", out var t) && t.ValueKind == JsonValueKind.Array)
                    trace = string.Join("; ", t.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()));
            }
        }
        catch (JsonException)
        {
        }

        var text = (error, trace) switch
        {
            ("", "") => $"Komodo answered {call} with HTTP {status}",
            (_, "") => $"{call}: {error}",
            _ => $"{call}: {error} ({trace})",
        };
        if (text.Length > 2000) text = text[..2000] + "…";
        var both = error + "\n" + trace;

        if (status == 429)
            return new KomodoException(KomodoErrorKind.RateLimited, status,
                "Komodo is refusing sign-ins for a moment after several failures; try again in a minute.");
        if (status == 401
            // A JWT that is expired or not Komodo's is a plain anyhow error in mogh_auth_server's middleware.rs: 500.
            || error.StartsWith("Invalid user credentials", StringComparison.Ordinal))
            return new KomodoException(KomodoErrorKind.Unauthorized, status, text);
        if (status is 502 or 503 or 504)
            return new KomodoException(KomodoErrorKind.Unreachable, status, "Komodo could not be reached");
        if (status is 403 or 404
            || both.Contains("Did not find any Stack matching", StringComparison.Ordinal)
            || both.Contains("does not have required permissions", StringComparison.Ordinal)
            || both.Contains("no update exists with given id", StringComparison.Ordinal))
            return new KomodoException(KomodoErrorKind.NotFoundOrForbidden, status, text);
        if (status is 400 or 415 or 422)
            return new KomodoException(KomodoErrorKind.BadRequest, status, text);
        return new KomodoException(KomodoErrorKind.Failed, status, text);
    }

    private static T Read<T>(string call, JsonElement answer) =>
        Parse(call, answer, a => a.Deserialize<T>(Json) ?? throw new JsonException());

    private static T Parse<T>(string call, byte[] answer, Func<JsonElement, T> read)
    {
        try
        {
            using var doc = JsonDocument.Parse(answer.Length == 0 ? "{}"u8.ToArray() : answer);
            return read(doc.RootElement.Clone());
        }
        catch (JsonException)
        {
            throw Unexpected(call);
        }
    }

    private static T Parse<T>(string call, JsonElement answer, Func<JsonElement, T> read)
    {
        try
        {
            return read(answer);
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            throw Unexpected(call);
        }
    }

    private static KomodoException Unexpected(string call) =>
        new(KomodoErrorKind.Failed, 200, $"Komodo answered {call} in a shape Komogentic does not know (is it Komodo 2.3?).");
}
