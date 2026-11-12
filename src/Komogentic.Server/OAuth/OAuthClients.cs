// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Security.Cryptography;
using System.Text.Json;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace Komogentic.Server.OAuth;

/// <summary>
/// Finds the client an authorisation request names: a metadata document for a URL, else a registered one (RFC 7591).
/// Registered clients are public, unverified, and expire after a day unless an authorisation succeeds.
/// </summary>
public sealed class OAuthClients(IMongoDatabase db, ClientMetadataFetcher fetcher, TimeProvider time)
{
    public const string RegisteredPrefix = "kgt_client_";

    internal const string CollectionName = "oauth_clients";

    public static readonly TimeSpan UnusedLifetime = TimeSpan.FromHours(24);

    private const int RandomLength = 22;
    private const int MaxRedirectUris = 10;
    private const string Base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    private IMongoCollection<OAuthClientDocument> Docs => db.GetCollection<OAuthClientDocument>(CollectionName);

    private volatile bool _ready;

    /// <summary>Null when the client is unknown or its document unusable; <see cref="ClientMetadataFetcher.FetchAsync"/> says why when that matters.</summary>
    /// <exception cref="ClientMetadataUnavailableException">The document couldn't be fetched now; that says nothing about the client.</exception>
    public async Task<OAuthClient?> ResolveAsync(string clientId, CancellationToken ct)
    {
        if (ClientMetadataFetcher.IsMetadataUrl(clientId))
        {
            var fetched = await fetcher.FetchAsync(clientId, ct);
            return fetched.Error == ClientMetadataFetcher.Unavailable ? throw new ClientMetadataUnavailableException() : fetched.Client;
        }

        if (!IsRegisteredId(clientId)) return null;

        await EnsureReadyAsync(ct);
        var doc = await Docs.Find(d => d.Id == clientId).FirstOrDefaultAsync(ct);
        // The TTL index only tidies up, and runs about once a minute: expiry is decided here.
        if (doc is null || doc.ExpiresAt is { } expiresAt && expiresAt <= Now) return null;
        return new OAuthClient(doc.Id, doc.Name, HostOf(doc.RedirectUris[0]), doc.RedirectUris, Verified: false);
    }

    /// <summary>Whether resolving <paramref name="clientId"/> would fetch a metadata document, rather than read the cache or the store.</summary>
    public bool WouldFetch(string clientId) => ClientMetadataFetcher.IsMetadataUrl(clientId) && !fetcher.IsCached(clientId);

    /// <summary>
    /// Registers a public client from RFC 7591 client metadata. Only what Komogentic uses is read; the rest is ignored.
    /// </summary>
    /// <exception cref="RegistrationException">The metadata is unusable; carries the RFC 7591 error code.</exception>
    public async Task<OAuthClient> RegisterAsync(JsonElement body, CancellationToken ct)
    {
        if (body.ValueKind != JsonValueKind.Object) throw new RegistrationException("invalid_client_metadata", "The client metadata must be a JSON object.");

        // Public clients only (PKCE protects the code); a secret would need storing and guarding for nothing. A requested
        // secret method is replaced by "none" in the answer (RFC 7591 §3.2.1) rather than refused: the MCP SDK asks for
        // client_secret_post whatever the metadata advertises, and no secret is ever issued, so nothing is weakened.
        if (body.TryGetProperty("token_endpoint_auth_method", out var method) && method.ValueKind != JsonValueKind.String)
            throw new RegistrationException("invalid_client_metadata", "token_endpoint_auth_method must be a string.");

        var redirects = RedirectUris(body);
        var name = "";
        if (body.TryGetProperty("client_name", out var rawName) && rawName.ValueKind == JsonValueKind.String)
        {
            try
            {
                name = ClientMetadataFetcher.CleanName(rawName.GetString()!);
            }
            catch (InvalidOperationException)
            {
                // An unpaired surrogate escape (\ud800): not text.
                throw new RegistrationException("invalid_client_metadata", "client_name is not valid text.");
            }
        }

        var host = HostOf(redirects[0]);
        if (name.Length == 0) name = host;

        await EnsureReadyAsync(ct);
        var now = Now;
        var doc = new OAuthClientDocument
        {
            Id = RegisteredPrefix + RandomString(),
            Name = name,
            RedirectUris = redirects,
            CreatedAt = now,
            ExpiresAt = now + UnusedLifetime,
        };
        await Docs.InsertOneAsync(doc, cancellationToken: ct);
        return new OAuthClient(doc.Id, name, host, redirects, Verified: false);
    }

    /// <summary>
    /// For the log: the host of a client id that is a URL (its metadata document is not fetched for this), else the
    /// host of a registered client's first redirect URI, else null.
    /// </summary>
    public async Task<string?> HostAsync(string clientId, CancellationToken ct)
    {
        if (ClientMetadataFetcher.IsMetadataUrl(clientId)) return new Uri(clientId).IdnHost;
        if (!IsRegisteredId(clientId)) return null;
        await EnsureReadyAsync(ct);
        var redirects = await Docs.Find(d => d.Id == clientId).Project(d => d.RedirectUris).FirstOrDefaultAsync(ct);
        return redirects is [var first, ..] ? new Uri(first).IdnHost : null;
    }

    /// <summary>An authorisation succeeded: the client stays.</summary>
    public async Task MarkAuthorisedAsync(string clientId, CancellationToken ct)
    {
        if (!IsRegisteredId(clientId)) return;
        await EnsureReadyAsync(ct);
        await Docs.UpdateOneAsync(d => d.Id == clientId, Builders<OAuthClientDocument>.Update.Unset(d => d.ExpiresAt), cancellationToken: ct);
    }

    private static List<string> RedirectUris(JsonElement body)
    {
        if (!body.TryGetProperty("redirect_uris", out var uris) || uris.ValueKind != JsonValueKind.Array || uris.GetArrayLength() == 0)
            throw new RegistrationException("invalid_redirect_uri", "redirect_uris must list at least one URI.");
        if (uris.GetArrayLength() > MaxRedirectUris)
            throw new RegistrationException("invalid_redirect_uri", $"At most {MaxRedirectUris} redirect URIs.");

        var redirects = new List<string>();
        foreach (var element in uris.EnumerateArray())
        {
            string? value;
            try
            {
                value = element.ValueKind == JsonValueKind.String ? element.GetString() : null;
            }
            catch (InvalidOperationException)
            {
                value = null;
            }

            // The same rule as for a metadata document: https, or http to a loopback host; no fragment, no credentials.
            if (value is null || !ClientMetadataFetcher.IsAcceptableRedirect(value))
                throw new RegistrationException("invalid_redirect_uri", "Each redirect URI must be absolute, without fragment or credentials, and https (or http to localhost).");
            if (!redirects.Contains(value, StringComparer.Ordinal)) redirects.Add(value);
        }

        return redirects;
    }

    private static string HostOf(string redirectUri) => new Uri(redirectUri).Host;

    private static bool IsRegisteredId(string id) =>
        id.Length == RegisteredPrefix.Length + RandomLength
        && id.StartsWith(RegisteredPrefix, StringComparison.Ordinal)
        && id.AsSpan(RegisteredPrefix.Length).IndexOfAnyExcept(Base62) < 0;

    // 22 characters of 62: about 131 bits. GetItems picks without modulo bias.
    private static string RandomString() => new(RandomNumberGenerator.GetItems<char>(Base62, RandomLength));

    private DateTime Now => time.GetUtcNow().UtcDateTime;

    /// <summary>Creates the TTL index once per process; lazy, so the server starts before MongoDB is reachable.</summary>
    private async Task EnsureReadyAsync(CancellationToken ct)
    {
        if (_ready) return;
        // Unused registrations are tidied away; the ones that were authorised have no expiresAt and stay.
        await Docs.Indexes.CreateOneAsync(
            new CreateIndexModel<OAuthClientDocument>(
                Builders<OAuthClientDocument>.IndexKeys.Ascending(d => d.ExpiresAt),
                new CreateIndexOptions { ExpireAfter = TimeSpan.Zero }),
            cancellationToken: ct);
        _ready = true;
    }

    /// <summary>Exact, except an http loopback redirect whose port is ignored (RFC 8252 §7.3).</summary>
    public static bool RedirectMatches(OAuthClient client, string redirectUri)
    {
        if (client.RedirectUris.Contains(redirectUri, StringComparer.Ordinal)) return true;
        if (!TryLoopback(redirectUri, out var asked)) return false;

        foreach (var registered in client.RedirectUris)
        {
            if (TryLoopback(registered, out var known)
                && asked.Host == known.Host
                && string.Equals(asked.PathAndQuery, known.PathAndQuery, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    private static bool TryLoopback(string value, out Uri uri) =>
        Uri.TryCreate(value, UriKind.Absolute, out uri!) && uri.Scheme == "http" && ClientMetadataFetcher.IsLoopbackHost(uri) && uri.Fragment.Length == 0;
}

/// <summary>Registration was refused; <see cref="Code"/> is the RFC 7591 error and the message its description.</summary>
public sealed class RegistrationException(string code, string description) : ArgumentException(description)
{
    public string Code { get; } = code;
}

/// <summary>A self-registered client (collection <c>oauth_clients</c>): what it said about itself, in the clear.</summary>
[BsonIgnoreExtraElements]
public sealed class OAuthClientDocument
{
    [BsonId]
    public string Id { get; set; } = "";

    [BsonElement("name")]
    public string Name { get; set; } = "";

    [BsonElement("redirectUris")]
    public List<string> RedirectUris { get; set; } = [];

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; }

    /// <summary>24 h after creation; unset once an authorisation succeeded. A TTL index removes the rest.</summary>
    [BsonElement("expiresAt"), BsonIgnoreIfNull]
    public DateTime? ExpiresAt { get; set; }
}
