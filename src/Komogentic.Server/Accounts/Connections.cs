// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Komogentic.Server.Komodo;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace Komogentic.Server.Accounts;

/// <summary>
/// Where a connection stands. <see cref="Revoked"/> and <see cref="Expired"/> are final; <see cref="NeedsReconnect"/>
/// is an authorised connection that lost its tokens or whose Komodo key was rejected, which the app renews on the same
/// URL after a fresh consent.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<ConnectionState>))]
public enum ConnectionState
{
    [JsonStringEnumMemberName("waiting")] Waiting,
    [JsonStringEnumMemberName("connected")] Connected,
    [JsonStringEnumMemberName("needs_reconnect")] NeedsReconnect,
    [JsonStringEnumMemberName("revoked")] Revoked,
    [JsonStringEnumMemberName("expired")] Expired,
}

/// <summary>Why a connection's tokens were revoked, as stored and as the web app shows it (<c>reason</c>).</summary>
public static class ConnectionReasons
{
    public const string Revoked = "revoked";
    public const string Expired = "expired";
    public const string ClientRevoked = "client_revoked";
    public const string RefreshReused = "refresh_reused";
    public const string CodeReused = "code_reused";
    public const string KomodoKeyRejected = "komodo_key_rejected";

    /// <summary>A consent made a Komodo key whose code was never exchanged, and the code expired.</summary>
    public const string CodeUnused = "code_unused";

    /// <summary>A new consent replaced the tokens; shown only until the new code is exchanged.</summary>
    public const string Reconnected = "reconnected";
}

/// <summary>The app a connection was authorised for. <c>Verified</c>: identified by a client metadata document,
/// not self-registered.</summary>
public sealed record ConnectedClient(
    [property: JsonPropertyName("name"), BsonElement("name")] string Name,
    [property: JsonPropertyName("host"), BsonElement("host")] string Host,
    [property: JsonPropertyName("verified"), BsonElement("verified")] bool Verified);

/// <summary>A connection as its owner sees it in a list. <c>Reason</c> goes with <c>Revoked</c>, <c>Expired</c> and
/// <c>NeedsReconnect</c>; <c>Client</c> is null until an app was authorised.</summary>
public sealed record ConnectionInfo(
    string Id, string Name, DateTime CreatedAt, DateTime? LastUsedAt, DateTime? ExpiresAt, DateTime? RevokedAt,
    ConnectionState State, string? Reason, ConnectedClient? Client);

/// <summary>
/// Connections: each has its own URL <c>/mcp/c/{id}</c>, for which an app such as claude.ai obtains tokens through
/// OAuth, and on consent a Komodo API key of its own (collection <c>connections</c>). Nothing here is secret: the
/// Komodo key's secret is sealed under the tokens, never stored with the connection.
/// </summary>
public sealed class Connections(IMongoDatabase db, KomodoClient komodo, PendingDeletions pending, TimeProvider time, ILogger<Connections> log)
{
    internal const string CollectionName = "connections";

    public const int MaxNameLength = CredentialRules.MaxNameLength;

    /// <summary>RFC 4648 Base32, lower-cased: an id that survives a URL, a host's case folding and being read aloud.</summary>
    private const string Base32 = "abcdefghijklmnopqrstuvwxyz234567";

    /// <summary>80 bits, 16 Base32 characters without padding.</summary>
    private const int IdBytes = 10;

    private const string Noun = "A connection";

    private volatile bool _ready;

    private IMongoCollection<ConnectionDocument> Docs { get; } = db.GetCollection<ConnectionDocument>(CollectionName);

    private DateTime Now => time.GetUtcNow().UtcDateTime;

    /// <summary>
    /// Creates a connection that waits for an app to authorise it. <see cref="UserInputException"/> for a name that is
    /// empty, longer than <see cref="MaxNameLength"/> or holds control or invisible formatting characters, or an expiry
    /// other than <see cref="CredentialRules.ExpiryDays"/> or never; <see cref="ConnectionNameTakenException"/> if another of the
    /// user's connections that is neither revoked nor expired has that name (case aside).
    /// </summary>
    public async Task<ConnectionInfo> CreateAsync(KomodoUser user, string name, int? expiresInDays, CancellationToken ct)
    {
        var clean = CredentialRules.Name(name, Noun);
        var now = Now;
        var expiresAt = CredentialRules.ExpiresAt(now, expiresInDays, Noun);

        await EnsureReadyAsync(ct);
        // An expired connection's name is free again: it gives up its name key, which the unique index covers.
        await Docs.UpdateManyAsync(
            c => c.User == user.Id && c.NameKey != null && c.ExpiresAt <= now,
            Builders<ConnectionDocument>.Update.Unset(c => c.NameKey),
            cancellationToken: ct);

        var doc = new ConnectionDocument
        {
            Id = NewId(),
            User = user.Id,
            Username = user.Username,
            Name = clean,
            NameKey = clean.ToLowerInvariant(),
            CreatedAt = CredentialRules.Milliseconds(now),
            // Whole milliseconds, as MongoDB keeps them, so the expiry the tokens get reads back equal.
            ExpiresAt = expiresAt,
        };
        try
        {
            await Docs.InsertOneAsync(doc, cancellationToken: ct);
        }
        catch (MongoWriteException e) when (e.WriteError.Category == ServerErrorCategory.DuplicateKey)
        {
            throw new ConnectionNameTakenException(clean);
        }

        return new ConnectionInfo(doc.Id, doc.Name, doc.CreatedAt, null, doc.ExpiresAt, null, ConnectionState.Waiting, null, null);
    }

    /// <summary>The connection with this id, whoever's it is and whatever its state; null if there is none.</summary>
    public async Task<ConnectionDocument?> FindAsync(string id, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        return await Docs.Find(c => c.Id == id).FirstOrDefaultAsync(ct);
    }

    /// <summary>The user's connections, revoked and expired ones included, the newest first.</summary>
    public async Task<IReadOnlyList<ConnectionInfo>> ListAsync(string userId, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        var now = Now;
        var docs = await Docs.Find(c => c.User == userId).SortByDescending(c => c.CreatedAt).ToListAsync(ct);
        return docs.Select(d => Info(d, now)).ToList();
    }

    internal static ConnectionInfo Info(ConnectionDocument d, DateTime now)
    {
        var (state, reason) = StateOf(d, now);
        return new ConnectionInfo(d.Id, d.Name, d.CreatedAt, d.LastUsedAt, d.ExpiresAt, d.RevokedAt, state, reason, d.Client);
    }

    /// <summary>
    /// Revoked and expired are final. Otherwise: never allowed (no Komodo key), waiting; a Komodo key whose code expired
    /// without being exchanged, needs a reconnect (<see cref="ConnectionReasons.CodeUnused"/>); never exchanged, waiting
    /// for the code; else connected while its tokens are, and needs a reconnect for the reason they were revoked: the
    /// token endpoint unsets <c>tokensRevokedAt</c> when it issues a pair, every revocation of the tokens sets it, and
    /// the refresh token lives as long as the connection.
    /// </summary>
    internal static (ConnectionState State, string? Reason) StateOf(ConnectionDocument doc, DateTime now)
    {
        if (doc.RevokedAt is not null) return (ConnectionState.Revoked, ConnectionReasons.Revoked);
        if (now >= doc.ExpiresAt) return (ConnectionState.Expired, ConnectionReasons.Expired);
        if (doc.KomodoKey is null) return (ConnectionState.Waiting, null);
        if (doc.CodeExpiresAt is { } codeExpiresAt && now >= codeExpiresAt) return (ConnectionState.NeedsReconnect, ConnectionReasons.CodeUnused);
        if (doc.AuthorisedAt is null) return (ConnectionState.Waiting, null);
        return doc.TokensRevokedAt is null ? (ConnectionState.Connected, null) : (ConnectionState.NeedsReconnect, doc.TokensRevokedReason);
    }

    /// <summary>
    /// The owner's Revoke, final: marked revoked, name freed, its codes and tokens tombstones and its pending
    /// authorisation requests deleted, in one transaction; then its Komodo key is deleted with <paramref name="jwt"/>,
    /// or queued for the user's next JWT if Komodo doesn't. False if the user has no such connection that isn't revoked.
    /// Komodo refusing the JWT is thrown after all that (the session has ended; the revoke stands).
    /// </summary>
    public async Task<bool> RevokeAsync(KomodoUser user, KomodoAuth.Jwt jwt, string id, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        await pending.EnsureReadyAsync(ct);
        ConnectionDocument? doc;
        using (var session = await db.Client.StartSessionAsync(cancellationToken: ct))
        {
            // Retried on a write conflict: a token in use writes lastUsedAt on this document outside any transaction.
            doc = await session.WithTransactionAsync(
                async (s, token) =>
                {
                    var now = Now;
                    var marked = await Docs.FindOneAndUpdateAsync(
                        s,
                        c => c.Id == id && c.User == user.Id && c.RevokedAt == null,
                        Builders<ConnectionDocument>.Update.Set(c => c.RevokedAt, CredentialRules.Milliseconds(now)).Unset(c => c.NameKey),
                        cancellationToken: token);
                    if (marked is null) return null;
                    await ConnectionRevocation.RevokeTokensAsync(db, s, id, ConnectionReasons.Revoked, now, token);
                    await db.GetCollection<BsonDocument>(OAuth.AuthorizationRequests.CollectionName)
                        .DeleteManyAsync(s, Builders<BsonDocument>.Filter.Eq("connection", id), cancellationToken: token);
                    return marked;
                },
                cancellationToken: ct);
        }

        if (doc is null) return false;
        log.LogInformation("User {UserId} revoked connection {ConnectionId}", user.Id, id);
        if (doc.KomodoKey is not { } komodoKey) return true;

        // Not the request's token: the connection is revoked now, and its Komodo key must go whatever the client does.
        try
        {
            await komodo.DeleteApiKeyAsync(jwt, komodoKey, CancellationToken.None);
            // A code's key waited for its minute (amendment R6): it is gone now.
            await pending.RemoveAsync(null, user.Id, komodoKey, CancellationToken.None);
        }
        catch (KomodoException e)
        {
            log.LogWarning("A Komodo key of user {UserId} is queued for deletion: Komodo answered {Kind} (HTTP {Status})", user.Id, e.Kind, e.Status);
            await pending.AddAsync(null, user.Id, komodoKey, ConnectionReasons.Revoked, CancellationToken.None);
            if (e.Kind == KomodoErrorKind.Unauthorized) throw;
        }

        return true;
    }

    /// <summary>
    /// Komodo rejected <paramref name="komodoKey"/> during a tool call (deleted in Komodo, say): the connection's tokens
    /// are revoked (<see cref="ConnectionReasons.KomodoKeyRejected"/>, needs a reconnect) and the key is queued for
    /// deletion. Only if it is still the connection's current Komodo key and the connection isn't revoked (amendment
    /// R1): a late answer for a key a reconnect replaced changes nothing.
    /// </summary>
    public async Task MarkKomodoKeyRejectedAsync(string id, string komodoKey, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        await pending.EnsureReadyAsync(ct);
        using var session = await db.Client.StartSessionAsync(cancellationToken: CancellationToken.None);
        var user = await session.WithTransactionAsync(
            async (s, token) =>
            {
                var doc = await Docs.Find(s, c => c.Id == id && c.KomodoKey == komodoKey && c.RevokedAt == null).FirstOrDefaultAsync(token);
                if (doc is null) return null;
                await ConnectionRevocation.RevokeTokensAsync(db, s, id, ConnectionReasons.KomodoKeyRejected, Now, token);
                await pending.AddAsync(s, doc.User, komodoKey, ConnectionReasons.KomodoKeyRejected, token);
                return doc.User;
            },
            cancellationToken: CancellationToken.None);
        if (user is not null) log.LogWarning("Connection {ConnectionId} of user {UserId} needs a reconnect: Komodo rejected its Komodo key", id, user);
    }

    /// <summary>10 random bytes in lower-case Base32 without padding: 16 characters.</summary>
    public static string NewId()
    {
        var bytes = RandomNumberGenerator.GetBytes(IdBytes);
        var chars = new char[IdBytes * 8 / 5];
        int buffer = 0, bits = 0, next = 0;
        foreach (var b in bytes)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                chars[next++] = Base32[(buffer >> bits) & 31];
            }
        }

        return new string(chars);
    }

    /// <summary>Creates the indexes once per process, outside any transaction; lazy, so the server starts before MongoDB is reachable.</summary>
    internal async Task EnsureReadyAsync(CancellationToken ct)
    {
        if (_ready) return;
        var keys = Builders<ConnectionDocument>.IndexKeys;
        await Docs.Indexes.CreateManyAsync(
            [
                new CreateIndexModel<ConnectionDocument>(keys.Ascending(c => c.User).Ascending(c => c.CreatedAt)),
                // One name per user among connections that are neither revoked nor expired: both give up the name key.
                new CreateIndexModel<ConnectionDocument>(
                    keys.Ascending(c => c.User).Ascending(c => c.NameKey),
                    new CreateIndexOptions<ConnectionDocument>
                    {
                        Unique = true,
                        PartialFilterExpression = new BsonDocument("nameKey", new BsonDocument("$type", "string")),
                    }),
            ],
            ct);
        _ready = true;
    }
}

/// <summary>A connection as stored (collection <c>connections</c>).</summary>
[BsonIgnoreExtraElements]
public sealed class ConnectionDocument
{
    [BsonId]
    public string Id { get; set; } = "";

    /// <summary>The Komodo user id of the owner.</summary>
    [BsonElement("user")]
    public string User { get; set; } = "";

    [BsonElement("username")]
    public string Username { get; set; } = "";

    [BsonElement("name")]
    public string Name { get; set; } = "";

    /// <summary>The name lower-cased while the connection is live, for the unique index; unset when it is revoked or
    /// has expired, which frees the name.</summary>
    [BsonElement("nameKey"), BsonIgnoreIfNull]
    public string? NameKey { get; set; }

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; }

    [BsonElement("expiresAt"), BsonIgnoreIfNull]
    public DateTime? ExpiresAt { get; set; }

    [BsonElement("revokedAt"), BsonIgnoreIfNull]
    public DateTime? RevokedAt { get; set; }

    /// <summary>When a code was first exchanged for tokens: from then on, a connection without tokens needs a reconnect.</summary>
    [BsonElement("authorisedAt"), BsonIgnoreIfNull]
    public DateTime? AuthorisedAt { get; set; }

    [BsonElement("lastUsedAt"), BsonIgnoreIfNull]
    public DateTime? LastUsedAt { get; set; }

    /// <summary>The app of the latest consent; null until then.</summary>
    [BsonElement("client"), BsonIgnoreIfNull]
    public ConnectedClient? Client { get; set; }

    /// <summary>The id of the connection's current Komodo API key, in the clear: it opens nothing without its secret.</summary>
    [BsonElement("komodoKey"), BsonIgnoreIfNull]
    public string? KomodoKey { get; set; }

    /// <summary>Until the code of the latest consent is exchanged: when it expires. Past it, the Komodo key was never
    /// used and the connection needs a reconnect (<see cref="ConnectionReasons.CodeUnused"/>).</summary>
    [BsonElement("codeExpiresAt"), BsonIgnoreIfNull]
    public DateTime? CodeExpiresAt { get; set; }

    [BsonElement("tokensRevokedAt"), BsonIgnoreIfNull]
    public DateTime? TokensRevokedAt { get; set; }

    [BsonElement("tokensRevokedReason"), BsonIgnoreIfNull]
    public string? TokensRevokedReason { get; set; }

    /// <summary>How many times the Komodo secret was sealed for its codes and tokens. Incremented in every issuing
    /// transaction, a write that always changes the document, so that issuing conflicts with a revocation.</summary>
    [BsonElement("wraps")]
    public long Wraps { get; set; }
}

/// <summary>
/// Revoking connections' tokens, on the collections directly, inside the caller's transaction: <see cref="Connections"/>
/// and <c>OAuthTokens</c> both call it.
/// </summary>
internal static class ConnectionRevocation
{
    internal const string TokensCollection = "oauth_tokens";

    /// <summary>How long a revoked code's or token's record stays as a tombstone: long enough for an app to give up on
    /// it, and for a reused code to be recognised.</summary>
    internal static readonly TimeSpan TombstoneRetention = TimeSpan.FromHours(24);

    /// <summary>
    /// Revokes the tokens of the connection <paramref name="connectionId"/>: its codes and tokens become tombstones
    /// (<see cref="TombstoneAsync"/>), and <c>tokensRevokedAt</c> and <c>tokensRevokedReason</c> are stamped.
    /// </summary>
    public static async Task RevokeTokensAsync(IMongoDatabase db, IClientSessionHandle session, string connectionId, string reason, DateTime now, CancellationToken ct)
    {
        await TombstoneAsync(db, session, Builders<BsonDocument>.Filter.Eq("connection", connectionId), now, ct);
        await db.GetCollection<ConnectionDocument>(Connections.CollectionName).UpdateOneAsync(
            session,
            c => c.Id == connectionId,
            Builders<ConnectionDocument>.Update.Set(c => c.TokensRevokedAt, now).Set(c => c.TokensRevokedReason, reason).Inc(c => c.Wraps, 1),
            cancellationToken: ct);
    }

    /// <summary>
    /// Turns the code and token records <paramref name="which"/> selects, unless already revoked, into tombstones:
    /// <c>revokedAt</c> set, the lookup kept, the grant, the sealed Komodo key and a used refresh token's kept pair
    /// dropped, gone after <see cref="TombstoneRetention"/>, or later for a used refresh token whose record was to stay
    /// longer to recognise its reuse. A revoked token stays recognised: from Anthropic's shared range a revoked token
    /// counted as a wrong key would lock every claude.ai user of the instance out. A tombstone opens nothing.
    /// </summary>
    internal static async Task TombstoneAsync(IMongoDatabase db, IClientSessionHandle session, FilterDefinition<BsonDocument> which, DateTime now, CancellationToken ct)
    {
        var tokens = db.GetCollection<BsonDocument>(TokensCollection);
        var f = Builders<BsonDocument>.Filter;
        var live = which & f.Exists("revokedAt", false);
        var used = f.Eq("kind", "refresh") & f.Exists("usedAt");
        var update = Builders<BsonDocument>.Update.Set("revokedAt", now).Unset("grant").Unset("sealed").Unset("successor");
        await tokens.UpdateManyAsync(session, live & used, update.Max("purgeAt", now + TombstoneRetention), cancellationToken: ct);
        await tokens.UpdateManyAsync(session, live & !used, update.Set("purgeAt", now + TombstoneRetention), cancellationToken: ct);
    }
}

public sealed class ConnectionNameTakenException(string name) : CredentialNameTakenException($"You already have a connection named '{name}'.");
