// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace Komogentic.Server.Accounts;

/// <summary>
/// Where a connection stands. <see cref="Revoked"/> and <see cref="Expired"/> are final; <see cref="NeedsReconnect"/>
/// is an authorised connection that lost its tokens or whose Komodo key was rejected, which the app renews on the same
/// URL after a fresh consent.
/// </summary>
public enum ConnectionState
{
    Waiting,
    Connected,
    NeedsReconnect,
    Revoked,
    Expired,
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
public sealed class Connections(IMongoDatabase db, TimeProvider time)
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

    /// <summary>Creates the indexes once per process; lazy, so the server starts before MongoDB is reachable.</summary>
    private async Task EnsureReadyAsync(CancellationToken ct)
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

    [BsonElement("tokensRevokedAt"), BsonIgnoreIfNull]
    public DateTime? TokensRevokedAt { get; set; }

    [BsonElement("tokensRevokedReason"), BsonIgnoreIfNull]
    public string? TokensRevokedReason { get; set; }

    /// <summary>How many times the Komodo secret was sealed for its codes and tokens. Incremented in every issuing
    /// transaction, a write that always changes the document, so that issuing conflicts with a revocation.</summary>
    [BsonElement("wraps")]
    public long Wraps { get; set; }
}

public sealed class ConnectionNameTakenException(string name) : CredentialNameTakenException($"You already have a connection named '{name}'.");
