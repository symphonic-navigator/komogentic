// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Komogentic.Server.Komodo;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace Komogentic.Server.Accounts;

/// <summary>Where an API key stands. Only <see cref="Active"/> opens <c>/mcp</c>; the others are final.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ApiKeyState>))]
public enum ApiKeyState
{
    [JsonStringEnumMemberName("active")] Active,
    [JsonStringEnumMemberName("revoked")] Revoked,
    [JsonStringEnumMemberName("expired")] Expired,
    /// <summary>Komodo rejected its Komodo key (deleted in Komodo, say); <c>Reason</c> says why.</summary>
    [JsonStringEnumMemberName("dead")] Dead,
}

/// <summary>An API key as its owner sees it in the dashboard: never its secret, nor its Komodo key.</summary>
public sealed record ApiKeyInfo(
    string Id, string Name, DateTime CreatedAt, DateTime? LastUsedAt, DateTime? ExpiresAt, DateTime? RevokedAt,
    ApiKeyState State, string? Reason);

/// <summary>A presented API key that opens <c>/mcp</c>: whose it is, and its Komodo key, unsealed for this request.</summary>
public sealed record ResolvedApiKey(string Id, KomodoUser User, string Name, KomodoAuth.Key Komodo, DateTime? ExpiresAt);

/// <summary>
/// API keys for agents that can't do MCP OAuth (spec §2, step 4): a <c>kgt_</c> bearer for plain <c>/mcp</c>, and with
/// each a Komodo API key of its user, created with the session's JWT when the key is (spec §2, "How rights work"). The
/// Komodo key's secret is sealed under the API key (collection <c>api_keys</c>), which only the agent holds: the server
/// keeps its HKDF lookup, never the key itself. A revoked or dead key's Komodo key is deleted with a JWT, at once or
/// with the user's next one (<see cref="PendingDeletions"/>); an expired key's with the user's next sign-in.
/// </summary>
public sealed class ApiKeys(IMongoDatabase db, KomodoClient komodo, PendingDeletions pending, TimeProvider time, ILogger<ApiKeys> log)
{
    internal const string CollectionName = "api_keys";

    public const string Prefix = "kgt_";

    /// <summary>The Komodo key of an API key is named after it, with this before, so it is recognisable in Komodo.</summary>
    public const string KomodoNamePrefix = "komogentic/";

    private const string Noun = "An API key";
    private const string LookupLabel = "kgt/v1/api-key";
    private const string SealLabel = "kgt/v1/api-key-komodo";

    /// <summary>A burst of requests shouldn't write on each; <c>lastUsedAt</c> may therefore be up to this much behind.</summary>
    private static readonly TimeSpan LastUsedGranularity = TimeSpan.FromMinutes(1);

    private volatile bool _ready;

    private IMongoCollection<ApiKeyDocument> Docs { get; } = db.GetCollection<ApiKeyDocument>(CollectionName);

    private DateTime Now => time.GetUtcNow().UtcDateTime;

    /// <summary>
    /// Creates an API key for <paramref name="user"/> and, with <paramref name="jwt"/>, its Komodo key
    /// <c>komogentic/{name}</c> with the same expiry. <see cref="UserInputException"/> for a name or expiry that
    /// <see cref="CredentialRules"/> refuses; <see cref="ApiKeyNameTakenException"/> if another of the user's keys that
    /// is neither revoked, expired nor dead has the name (case aside), checked before Komodo is asked. The key is stored
    /// only once Komodo made its Komodo key; if storing fails, that Komodo key is deleted again, or queued for deletion.
    /// Komodo's refusals are thrown as they are.
    /// </summary>
    public async Task<(ApiKeyInfo Info, string Key)> CreateAsync(KomodoUser user, KomodoAuth.Jwt jwt, string name, int? expiresInDays, CancellationToken ct)
    {
        var clean = CredentialRules.Name(name, Noun);
        var now = CredentialRules.Milliseconds(Now);
        var expiresAt = CredentialRules.ExpiresAt(now, expiresInDays, Noun);

        await EnsureReadyAsync(ct);
        // An expired key's name is free again: it gives up its name key, which the unique index covers.
        await Docs.UpdateManyAsync(
            k => k.User == user.Id && k.NameKey != null && k.ExpiresAt <= now,
            Builders<ApiKeyDocument>.Update.Unset(k => k.NameKey),
            cancellationToken: ct);
        var nameKey = clean.ToLowerInvariant();
        if (await Docs.Find(k => k.User == user.Id && k.NameKey == nameKey).AnyAsync(ct)) throw new ApiKeyNameTakenException(clean);

        // From here on not the request's token: a client that hangs up once Komodo made the key must not leave it
        // made and untracked. Komodo's answer is awaited and the key stored, or deleted again, whatever the client does.
        var created = await komodo.CreateApiKeyAsync(jwt, KomodoNamePrefix + clean, expiresAt is { } at ? new DateTimeOffset(at) : null, CancellationToken.None);

        var id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var key = Secrets.New(Prefix);
        var doc = new ApiKeyDocument
        {
            Id = id,
            User = user.Id,
            Username = user.Username,
            Name = clean,
            NameKey = nameKey,
            Lookup = Lookup(key),
            Sealed = Sealing.Seal(Sealing.Derive(key, SealLabel), JsonSerializer.SerializeToUtf8Bytes(new SealedKomodoKey(created.Key, created.Secret)), Context(id, expiresAt)),
            KomodoKey = created.Key,
            CreatedAt = now,
            ExpiresAt = expiresAt,
        };
        try
        {
            await Docs.InsertOneAsync(doc, cancellationToken: CancellationToken.None);
        }
        catch (Exception e)
        {
            // Nobody will ever hold this Komodo key's secret: away with it, whatever went wrong (the request aborted too).
            await DiscardAsync(user.Id, jwt, created.Key, "unstored");
            if (e is MongoWriteException { WriteError.Category: ServerErrorCategory.DuplicateKey }) throw new ApiKeyNameTakenException(clean);
            throw;
        }

        log.LogInformation("User {UserId} created API key {KeyId}", user.Id, id);
        return (Info(doc, now), key);
    }

    /// <summary>Every key of the user, the newest first, revoked, expired and dead ones too.</summary>
    public async Task<IReadOnlyList<ApiKeyInfo>> ListAsync(string userId, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        var now = Now;
        var docs = await Docs.Find(k => k.User == userId).SortByDescending(k => k.CreatedAt).ToListAsync(ct);
        return docs.Select(d => Info(d, now)).ToList();
    }

    /// <summary>
    /// Revokes one of the user's keys and deletes its Komodo key with <paramref name="jwt"/>; false if the user has no
    /// such key that isn't revoked already. If Komodo doesn't delete it, the key is queued for the user's next JWT, and
    /// the key is revoked all the same; Komodo refusing the JWT is thrown after that (the session has ended).
    /// </summary>
    public async Task<bool> RevokeAsync(KomodoUser user, KomodoAuth.Jwt jwt, string id, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        var doc = await Docs.FindOneAndUpdateAsync(
            k => k.Id == id && k.User == user.Id && k.RevokedAt == null,
            Builders<ApiKeyDocument>.Update.Set(k => k.RevokedAt, CredentialRules.Milliseconds(Now)).Unset(k => k.NameKey),
            cancellationToken: ct);
        if (doc is null) return false;
        log.LogInformation("User {UserId} revoked API key {KeyId}", user.Id, id);

        // A dead key's Komodo key was queued when it died, and may still exist (an unreadable key's does): deleting it
        // again is harmless, as Komodo's "no such key" counts as done.
        await DiscardAsync(user.Id, jwt, doc.KomodoKey, "revoked", rethrowUnauthorized: true);
        return true;
    }

    /// <summary>
    /// The key behind a presented bearer, or null if it isn't one, is unknown, revoked, expired or dead, or its Komodo key
    /// doesn't open; <c>Known</c> whether it is one of the keys at all (a revoked one too), so that an agent retrying an
    /// old key is not taken for someone guessing. A key whose Komodo key no longer opens (its document changed: its
    /// expiry is part of the seal's context) becomes dead with the reason <c>unreadable</c>. Never calls Komodo, never
    /// logs anything of the key. Notes the use at most once a minute.
    /// </summary>
    public async Task<(ResolvedApiKey? Key, bool Known)> ResolveAsync(string presented, CancellationToken ct)
    {
        if (!Secrets.IsWellFormed(presented, Prefix)) return (null, false);
        await EnsureReadyAsync(ct);
        var lookup = Lookup(presented);
        var doc = await Docs.Find(k => k.Lookup == lookup).FirstOrDefaultAsync(ct);
        var now = Now;
        if (doc is null) return (null, false);
        if (doc.RevokedAt is not null || doc.DeadAt is not null || now >= doc.ExpiresAt) return (null, true);

        SealedKomodoKey? komodoKey;
        try
        {
            komodoKey = JsonSerializer.Deserialize<SealedKomodoKey>(Sealing.Open(Sealing.Derive(presented, SealLabel), doc.Sealed, Context(doc.Id, doc.ExpiresAt)));
        }
        catch (Exception e) when (e is CryptographicException or JsonException)
        {
            komodoKey = null;
        }

        if (komodoKey is null)
        {
            log.LogWarning("API key {KeyId} matched but its Komodo key does not open: it is marked dead", doc.Id);
            await MarkDeadAsync(doc.Id, doc.KomodoKey, "unreadable", CancellationToken.None);
            return (null, true);
        }

        if (doc.LastUsedAt is not { } lastUsed || now - lastUsed >= LastUsedGranularity)
        {
            // Conditional, so of concurrent requests only one writes.
            var stale = now - LastUsedGranularity;
            await Docs.UpdateOneAsync(
                k => k.Id == doc.Id && (k.LastUsedAt == null || k.LastUsedAt <= stale),
                Builders<ApiKeyDocument>.Update.Set(k => k.LastUsedAt, CredentialRules.Milliseconds(now)),
                cancellationToken: ct);
        }

        return (new ResolvedApiKey(doc.Id, new KomodoUser(doc.User, doc.Username), doc.Name, new KomodoAuth.Key(komodoKey.Key, komodoKey.Secret), doc.ExpiresAt), true);
    }

    /// <summary>
    /// Komodo rejected <paramref name="komodoKey"/>: the key becomes dead with <paramref name="reason"/>, and the Komodo
    /// key is queued for deletion. Only if it is still the key's current Komodo key and the key is neither revoked nor
    /// dead already (amendment R1): a late answer for an earlier Komodo key changes nothing.
    /// </summary>
    public async Task MarkDeadAsync(string id, string komodoKey, string reason, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        var doc = await Docs.FindOneAndUpdateAsync(
            k => k.Id == id && k.KomodoKey == komodoKey && k.RevokedAt == null && k.DeadAt == null,
            Builders<ApiKeyDocument>.Update.Set(k => k.DeadAt, CredentialRules.Milliseconds(Now)).Set(k => k.Reason, reason).Unset(k => k.NameKey),
            cancellationToken: ct);
        if (doc is null) return;
        log.LogWarning("API key {KeyId} of user {UserId} is dead: {Reason}", id, doc.User, reason);
        // Not the request's token: the key is dead now, and its Komodo key must be queued whatever the caller does.
        await pending.AddAsync(null, doc.User, komodoKey, "dead", CancellationToken.None);
    }

    /// <summary>
    /// Queues the Komodo keys of the user's keys that have expired, neither revoked nor dead (those were queued then),
    /// for deletion (reason <c>expired</c>), each once: a key queued is marked so. Called at sign-in, before the queue is
    /// drained with the new JWT.
    /// </summary>
    public async Task QueueExpiredAsync(string userId, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        var now = Now;
        var expired = await Docs.Find(k => k.User == userId && k.ExpiresAt <= now && k.RevokedAt == null && k.DeadAt == null && k.ExpiredQueuedAt == null)
            .ToListAsync(ct);
        foreach (var doc in expired)
        {
            // Queued before it is marked: a failure in between queues it again next time, which only updates its time.
            await pending.AddAsync(null, userId, doc.KomodoKey, "expired", ct);
            await Docs.UpdateOneAsync(k => k.Id == doc.Id, Builders<ApiKeyDocument>.Update.Set(k => k.ExpiredQueuedAt, CredentialRules.Milliseconds(now)), cancellationToken: ct);
        }
    }

    /// <summary>
    /// Deletes a Komodo key nobody will use again with <paramref name="jwt"/>, else queues it for the user's next JWT.
    /// Never fails over Komodo, except that with <paramref name="rethrowUnauthorized"/> Komodo refusing the JWT is
    /// thrown, once the key is queued, so that the session ends.
    /// </summary>
    private async Task DiscardAsync(string userId, KomodoAuth.Jwt jwt, string komodoKey, string reason, bool rethrowUnauthorized = false)
    {
        // Not the request's token: an aborted request must still leave the key deleted or queued.
        try
        {
            await komodo.DeleteApiKeyAsync(jwt, komodoKey, CancellationToken.None);
            return;
        }
        catch (KomodoException e)
        {
            log.LogWarning("A Komodo key of user {UserId} is queued for deletion: Komodo answered {Kind} (HTTP {Status})", userId, e.Kind, e.Status);
            await pending.AddAsync(null, userId, komodoKey, reason, CancellationToken.None);
            if (rethrowUnauthorized && e.Kind == KomodoErrorKind.Unauthorized) throw;
        }
    }

    private static ApiKeyInfo Info(ApiKeyDocument d, DateTime now)
    {
        var state = d.RevokedAt is not null ? ApiKeyState.Revoked
            : d.DeadAt is not null ? ApiKeyState.Dead
            : now >= d.ExpiresAt ? ApiKeyState.Expired
            : ApiKeyState.Active;
        return new ApiKeyInfo(d.Id, d.Name, d.CreatedAt, d.LastUsedAt, d.ExpiresAt, d.RevokedAt, state, state == ApiKeyState.Dead ? d.Reason : null);
    }

    /// <summary>Finds the key without storing it; HKDF suffices, as the key is random.</summary>
    private static string Lookup(string key) => Convert.ToHexStringLower(Sealing.Lookup(key, LookupLabel));

    /// <summary>The associated data: the sealed Komodo key opens only as this API key's, and only with the expiry it was
    /// made with, so that whoever may write the database can't extend a key.</summary>
    private static string Context(string id, DateTime? expiresAt) =>
        $"api-key:{id}:{(expiresAt is { } at ? new DateTimeOffset(DateTime.SpecifyKind(at, DateTimeKind.Utc)).ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture) : "none")}";

    /// <summary>Creates the indexes once per process; lazy, so the server starts before MongoDB is reachable.</summary>
    private async Task EnsureReadyAsync(CancellationToken ct)
    {
        if (_ready) return;
        var keys = Builders<ApiKeyDocument>.IndexKeys;
        await Docs.Indexes.CreateManyAsync(
            [
                new CreateIndexModel<ApiKeyDocument>(keys.Ascending(k => k.Lookup), new CreateIndexOptions { Unique = true }),
                new CreateIndexModel<ApiKeyDocument>(keys.Ascending(k => k.User).Ascending(k => k.CreatedAt)),
                // One name per user among keys that are neither revoked, expired nor dead: each gives up the name key.
                new CreateIndexModel<ApiKeyDocument>(
                    keys.Ascending(k => k.User).Ascending(k => k.NameKey),
                    new CreateIndexOptions<ApiKeyDocument>
                    {
                        Unique = true,
                        PartialFilterExpression = new BsonDocument("nameKey", new BsonDocument("$type", "string")),
                    }),
            ],
            ct);
        _ready = true;
    }

    /// <summary>What is sealed under the API key: its Komodo key and that key's secret.</summary>
    private sealed record SealedKomodoKey(
        [property: JsonPropertyName("key")] string Key,
        [property: JsonPropertyName("secret")] string Secret)
    {
        public override string ToString() => $"SealedKomodoKey {{ Key = {Key} }}";
    }
}

/// <summary>An API key as stored (collection <c>api_keys</c>).</summary>
[BsonIgnoreExtraElements]
public sealed class ApiKeyDocument
{
    /// <summary>16 random bytes in hex.</summary>
    [BsonId]
    public string Id { get; set; } = "";

    /// <summary>The Komodo user id of the owner.</summary>
    [BsonElement("user")]
    public string User { get; set; } = "";

    [BsonElement("username")]
    public string Username { get; set; } = "";

    [BsonElement("name")]
    public string Name { get; set; } = "";

    /// <summary>The name lower-cased while the key is live, for the unique index; unset when it is revoked, dead or has
    /// expired, which frees the name.</summary>
    [BsonElement("nameKey"), BsonIgnoreIfNull]
    public string? NameKey { get; set; }

    /// <summary>The hex of the key's HKDF lookup: it finds the key, but opens nothing.</summary>
    [BsonElement("lookup")]
    public string Lookup { get; set; } = "";

    /// <summary>The Komodo key and its secret as JSON, AES-256-GCM under <c>HKDF(key, "kgt/v1/api-key-komodo")</c>,
    /// context <c>api-key:{id}</c>.</summary>
    [BsonElement("sealed")]
    public byte[] Sealed { get; set; } = [];

    /// <summary>The Komodo key's id, in the clear (spec §2): it opens nothing without its secret, and deletes the key
    /// with a JWT.</summary>
    [BsonElement("komodoKey")]
    public string KomodoKey { get; set; } = "";

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; }

    [BsonElement("lastUsedAt"), BsonIgnoreIfNull]
    public DateTime? LastUsedAt { get; set; }

    [BsonElement("expiresAt"), BsonIgnoreIfNull]
    public DateTime? ExpiresAt { get; set; }

    [BsonElement("revokedAt"), BsonIgnoreIfNull]
    public DateTime? RevokedAt { get; set; }

    [BsonElement("deadAt"), BsonIgnoreIfNull]
    public DateTime? DeadAt { get; set; }

    /// <summary>Why the key is dead: <c>komodo_key_rejected</c>, <c>unreadable</c>.</summary>
    [BsonElement("reason"), BsonIgnoreIfNull]
    public string? Reason { get; set; }

    /// <summary>When its Komodo key was queued for deletion because the key had expired.</summary>
    [BsonElement("expiredQueuedAt"), BsonIgnoreIfNull]
    public DateTime? ExpiredQueuedAt { get; set; }
}

public sealed class ApiKeyNameTakenException(string name) : CredentialNameTakenException($"You already have an API key named '{name}'.");
