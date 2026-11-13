// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Komogentic.Server.Net;
using Microsoft.Extensions.Options;

namespace Komogentic.Server.OAuth;

/// <summary>A client as the authorisation page shows it. CIMD: <see cref="Host"/> is the host of the <c>client_id</c> URL
/// and <see cref="Verified"/> is true; DCR: the host of the first redirect URI, not verified. Verified says only that the
/// document came from that host; the name is the client's own choice either way. The host is in its IDN (punycode) form,
/// so that a look-alike such as <c>claudе.ai</c> with a Cyrillic е shows as what it is.</summary>
public sealed record OAuthClient(string ClientId, string Name, string Host, IReadOnlyList<string> RedirectUris, bool Verified);

/// <summary><paramref name="Error"/> is one of <c>unreachable</c>, <c>not_public</c>, <c>too_large</c>, <c>not_json</c>,
/// <c>client_id_mismatch</c>, <c>no_redirect_uris</c>, <c>bad_redirect_uri</c>, <c>not_public_client</c>, <c>redirected</c>,
/// or <see cref="ClientMetadataFetcher.Unavailable"/>, which says nothing about the client and is not cached.</summary>
public sealed record ClientMetadataResult(OAuthClient? Client, string? Error);

/// <summary>A client's metadata document waited too long for its turn to be fetched (<see cref="ClientMetadataFetcher.Unavailable"/>).</summary>
public sealed class ClientMetadataUnavailableException() : Exception("Too many apps are being identified right now; try again in a minute.");

public static class ClientMetadataServices
{
    public const string HttpClientName = "cimd";

    /// <summary>The fetcher and the one HTTP client it uses. The client refuses redirects, cookies and proxies, and
    /// connects only to a public address it resolved itself, so a hostname cannot be re-resolved to an
    /// internal address between the check and the connection.</summary>
    public static IServiceCollection AddClientMetadataFetcher(this IServiceCollection services)
    {
        services.AddHttpClient(HttpClientName).ConfigurePrimaryHttpMessageHandler(sp =>
        {
            var options = sp.GetRequiredService<IOptions<KomogenticOptions>>();
            return new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                UseProxy = false,
                ConnectTimeout = ClientMetadataFetcher.Timeout,
                ConnectCallback = (context, ct) => ClientMetadataFetcher.ConnectAsync(context, options.Value.OAuth.AllowLoopbackClients, ct),
            };
        });
        services.AddSingleton<ClientMetadataFetcher>();
        return services;
    }
}

/// <summary>Fetches and validates a client's metadata document (draft-ietf-oauth-client-id-metadata-document). The URL is
/// chosen by whoever starts an authorisation, so this is the server's one request to an address a stranger picks.</summary>
public sealed class ClientMetadataFetcher(IHttpClientFactory http, IOptions<KomogenticOptions> options, TimeProvider time, ILogger<ClientMetadataFetcher> log)
{
    public const int MaxBytes = 16 * 1024;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    /// <summary>The error of a fetch that waited <see cref="Timeout"/> for one of the fetches at once and didn't get it.</summary>
    public const string Unavailable = "unavailable";

    private const int MaxEntries = 1000;
    private const int MaxConcurrentFetches = 8;
    private const int MaxUrlLength = 2048;
    private const int MaxNameLength = 100;
    private static readonly TimeSpan MinAge = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaxAge = TimeSpan.FromHours(24);
    private static readonly TimeSpan DefaultAge = TimeSpan.FromHours(1);
    private static readonly TimeSpan FailureAge = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.Ordinal);

    /// <summary>At most this many fetches at once, whoever starts them; the rest wait their turn, for <see cref="Timeout"/> at most.</summary>
    private readonly SemaphoreSlim _fetches = new(MaxConcurrentFetches);

    private sealed record CacheEntry(ClientMetadataResult Result, DateTimeOffset Stored, DateTimeOffset Expires);

    /// <summary>Whether this client id is to be fetched as a metadata document: an http(s) URL with a path.</summary>
    public static bool IsMetadataUrl(string? clientId) =>
        clientId is { Length: > 0 and <= MaxUrlLength }
        && Uri.TryCreate(clientId, UriKind.Absolute, out var uri)
        && uri.Scheme is "https" or "http"
        && uri.AbsolutePath.Length > 1
        && uri.UserInfo.Length == 0
        && !clientId.Contains('#', StringComparison.Ordinal);

    /// <summary>Whether <see cref="FetchAsync"/> would answer from the cache, without a request.</summary>
    public bool IsCached(string clientId) => _cache.TryGetValue(clientId, out var cached) && time.GetUtcNow() < cached.Expires;

    public async Task<ClientMetadataResult> FetchAsync(string clientId, CancellationToken ct)
    {
        if (_cache.TryGetValue(clientId, out var cached) && time.GetUtcNow() < cached.Expires) return cached.Result;

        if (!await TurnAsync(ct))
        {
            log.LogInformation("Client metadata not fetched: too many fetches at once");
            return new ClientMetadataResult(null, Unavailable);
        }

        try
        {
            // Another request may have fetched it while this one waited.
            var now = time.GetUtcNow();
            if (_cache.TryGetValue(clientId, out cached) && now < cached.Expires) return cached.Result;
            var allowLoopback = options.Value.OAuth.AllowLoopbackClients;
            var (result, maxAge) = await FetchUncachedAsync(clientId, allowLoopback, ct);
            Store(clientId, result, now, result.Error is null ? maxAge : FailureAge);
            return result;
        }
        finally
        {
            _fetches.Release();
        }
    }

    /// <summary>Waits for one of the fetches at once, on <see cref="TimeProvider"/>'s clock; false after <see cref="Timeout"/>.</summary>
    private async Task<bool> TurnAsync(CancellationToken ct)
    {
        using var waited = new CancellationTokenSource(Timeout, time);
        using var either = CancellationTokenSource.CreateLinkedTokenSource(ct, waited.Token);
        try
        {
            await _fetches.WaitAsync(either.Token);
            return true;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return false;
        }
    }

    private void Store(string clientId, ClientMetadataResult result, DateTimeOffset now, TimeSpan age)
    {
        _cache[clientId] = new CacheEntry(result, now, now + age);
        while (_cache.Count > MaxEntries)
        {
            var oldest = _cache.MinBy(e => e.Value.Stored).Key;
            _cache.TryRemove(oldest, out _);
        }
    }

    private async Task<(ClientMetadataResult, TimeSpan)> FetchUncachedAsync(string clientId, bool allowLoopback, CancellationToken ct)
    {
        if (!IsMetadataUrl(clientId)) return (Fail(clientId, "unreachable"), default);
        var url = new Uri(clientId);
        var loopbackAllowed = allowLoopback && IsLoopbackHost(url);
        if (url.Scheme != "https" && !loopbackAllowed) return (Fail(clientId, "not_public"), default);
        // A literal address needs no lookup; the connection check would refuse it too, but this saves the attempt.
        if (IPAddress.TryParse(url.Host.Trim('[', ']'), out var literal) && !PublicAddresses.AddressAllowed(literal, loopbackAllowed))
            return (Fail(clientId, "not_public"), default);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(Timeout);
        try
        {
            using var client = http.CreateClient(ClientMetadataServices.HttpClientName);
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Accept.ParseAdd("application/json");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);

            var status = (int)response.StatusCode;
            if (status is >= 300 and < 400) return (Fail(clientId, "redirected"), default);
            if (status is < 200 or >= 300) return (Fail(clientId, "unreachable"), default);
            if (response.Content.Headers.ContentLength > MaxBytes) return (Fail(clientId, "too_large"), default);

            var body = await ReadCappedAsync(await response.Content.ReadAsStreamAsync(timeout.Token), timeout.Token);
            if (body is null) return (Fail(clientId, "too_large"), default);

            var parsed = Parse(clientId, url.IdnHost, body);
            if (parsed.Error is not null) return (Fail(clientId, parsed.Error), default);
            log.LogInformation("Client metadata of {Host} accepted", url.IdnHost);
            var maxAge = response.Headers.CacheControl?.MaxAge ?? DefaultAge;
            return (parsed, Clamp(maxAge));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return (Fail(clientId, "unreachable"), default);
        }
        catch (HttpRequestException e) when (IsNotPublic(e))
        {
            return (Fail(clientId, "not_public"), default);
        }
        catch (Exception e) when (e is HttpRequestException or IOException)
        {
            // The type only: a message could carry the address or part of the response.
            log.LogInformation("Client metadata of {Host} unreachable ({Type})", url.IdnHost, e.GetType().Name);
            return (new ClientMetadataResult(null, "unreachable"), default);
        }
    }

    private ClientMetadataResult Fail(string clientId, string error)
    {
        // Only the host and the reason: the document and the rest of the URL are the client's to choose.
        var host = Uri.TryCreate(clientId, UriKind.Absolute, out var uri) ? uri.IdnHost : "(not a URL)";
        log.LogInformation("Client metadata of {Host} refused: {Error}", host, error);
        return new ClientMetadataResult(null, error);
    }

    private static TimeSpan Clamp(TimeSpan age) => age < MinAge ? MinAge : age > MaxAge ? MaxAge : age;

    private static bool IsNotPublic(Exception e)
    {
        for (var inner = e; inner is not null; inner = inner.InnerException)
            if (inner is NotPublicAddressException) return true;
        return false;
    }

    /// <summary>The body, or null once it is longer than <see cref="MaxBytes"/> (stops after one byte too many).</summary>
    private static async Task<byte[]?> ReadCappedAsync(Stream stream, CancellationToken ct)
    {
        await using var _ = stream;
        var buffer = new byte[MaxBytes + 1];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), ct);
            if (read == 0) return buffer[..length];
            length += read;
        }

        return null;
    }

    private static ClientMetadataResult Parse(string clientId, string host, byte[] body)
    {
        try
        {
            return ParseDocument(clientId, host, body);
        }
        catch (InvalidOperationException)
        {
            // GetString() throws on a string holding an unpaired surrogate escape (\ud800): not a usable document.
            return new ClientMetadataResult(null, "not_json");
        }
    }

    private static ClientMetadataResult ParseDocument(string clientId, string host, byte[] body)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 8 });
        }
        catch (JsonException)
        {
            return new ClientMetadataResult(null, "not_json");
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return new ClientMetadataResult(null, "not_json");

            if (!Text(root, "client_id", out var id)) return new ClientMetadataResult(null, "not_json");
            if (!string.Equals(id, clientId, StringComparison.Ordinal)) return new ClientMetadataResult(null, "client_id_mismatch");

            if (root.TryGetProperty("token_endpoint_auth_method", out var method)
                && !(method.ValueKind == JsonValueKind.String && method.GetString() == "none"))
                return new ClientMetadataResult(null, "not_public_client");

            if (!Text(root, "client_name", out var rawName)) return new ClientMetadataResult(null, "not_json");
            var name = CleanName(rawName);
            if (name.Length == 0) return new ClientMetadataResult(null, "not_json");

            if (!root.TryGetProperty("redirect_uris", out var uris) || uris.ValueKind != JsonValueKind.Array || uris.GetArrayLength() == 0)
                return new ClientMetadataResult(null, "no_redirect_uris");
            var redirects = new List<string>();
            foreach (var element in uris.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.String || !IsAcceptableRedirect(element.GetString()!))
                    return new ClientMetadataResult(null, "bad_redirect_uri");
                redirects.Add(element.GetString()!);
            }

            // Unknown members (logo_uri, client_uri, grant_types such as jwt-bearer…) are ignored on purpose.
            return new ClientMetadataResult(new OAuthClient(clientId, name, host, redirects, Verified: true), null);
        }
    }

    private static bool Text(JsonElement root, string member, out string value)
    {
        value = "";
        if (!root.TryGetProperty(member, out var element) || element.ValueKind != JsonValueKind.String) return false;
        value = element.GetString()!;
        return value.Length > 0;
    }

    /// <summary>Absolute, no fragment, no credentials; https, or http to a loopback host (a native app's listener).</summary>
    internal static bool IsAcceptableRedirect(string value) =>
        value.Length <= MaxUrlLength
        && !value.Contains('#', StringComparison.Ordinal)
        && Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && uri.UserInfo.Length == 0
        && (uri.Scheme == "https" || (uri.Scheme == "http" && IsLoopbackHost(uri)));

    internal static bool IsLoopbackHost(Uri uri) => uri.Host is "localhost" or "127.0.0.1" or "[::1]";

    /// <summary>Trimmed, without control or format characters (they could hide or reorder text on the consent page), at most 100 characters.</summary>
    internal static string CleanName(string raw)
    {
        var sb = new StringBuilder(raw.Length);
        for (var i = 0; i < raw.Length; i++)
        {
            var c = raw[i];
            if (char.IsHighSurrogate(c) && i + 1 < raw.Length && char.IsLowSurrogate(raw[i + 1]))
            {
                sb.Append(c).Append(raw[++i]);
                continue;
            }

            // Unpaired surrogates fall in the Surrogate category and go with the rest.
            var category = char.GetUnicodeCategory(c);
            if (category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.LineSeparator
                or UnicodeCategory.ParagraphSeparator or UnicodeCategory.Surrogate) continue;
            sb.Append(c);
        }

        var name = sb.ToString().Trim();
        if (name.Length <= MaxNameLength) return name;
        // Never cut a surrogate pair in half.
        var cut = char.IsHighSurrogate(name[MaxNameLength - 1]) ? MaxNameLength - 1 : MaxNameLength;
        return name[..cut].TrimEnd();
    }

    /// <summary>See <see cref="PublicAddresses.ConnectAsync"/>.</summary>
    internal static ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, bool allowLoopback, CancellationToken ct) =>
        PublicAddresses.ConnectAsync(context, allowLoopback, ct);

    /// <summary>See <see cref="PublicAddresses.IsPublicAddress"/>.</summary>
    internal static bool IsPublicAddress(IPAddress address) => PublicAddresses.IsPublicAddress(address);
}
