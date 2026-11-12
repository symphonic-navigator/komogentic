// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace Komogentic.Server.Accounts;

/// <summary>A live dashboard session: whose it is, the Komodo JWT it holds and when it ends at the latest.</summary>
public sealed record ResolvedSession(KomodoUser User, string Jwt, DateTime ExpiresAt);

/// <summary>
/// Dashboard sessions (spec §5, "What is different from Kumbu²"): a random secret in the browser's cookie and, in
/// <c>sessions</c>, the Komodo JWT of the sign-in sealed under a key derived from that secret. The server keeps neither
/// the secret nor the JWT in the clear, so a database dump opens no Komodo session. A session ends after
/// <see cref="IdleTimeout"/> unused, after <see cref="AbsoluteTimeout"/>, and never later than the JWT's own expiry.
/// </summary>
public sealed class Sessions(IMongoDatabase db, TimeProvider time)
{
    internal const string CollectionName = "sessions";

    public static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(30);
    public static readonly TimeSpan AbsoluteTimeout = TimeSpan.FromHours(12);

    /// <summary>A burst of requests shouldn't write on each; the idle clock may therefore run up to this much early.</summary>
    private static readonly TimeSpan LastUsedGranularity = TimeSpan.FromMinutes(1);

    private const int SecretBytes = 32;
    private const string LookupLabel = "kgt/v1/session";
    private const string JwtLabel = "kgt/v1/session-jwt";

    private volatile bool _ready;

    private IMongoCollection<SessionDocument> Docs { get; } = db.GetCollection<SessionDocument>(CollectionName);

    private DateTime Now => time.GetUtcNow().UtcDateTime;

    /// <summary>
    /// Starts a session for <paramref name="user"/>, whose Komodo sign-in just answered <paramref name="jwt"/>, and
    /// returns its secret (Base64Url of 32 random bytes) for the cookie. The session ends at
    /// <paramref name="jwtExpiresAt"/> at the latest.
    /// </summary>
    public async Task<string> StartAsync(KomodoUser user, string jwt, DateTime jwtExpiresAt, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        var secret = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(SecretBytes));
        var now = Milliseconds(Now);
        var limit = now + AbsoluteTimeout;
        await Docs.InsertOneAsync(
            new SessionDocument
            {
                Id = Lookup(secret),
                User = user.Id,
                Username = user.Username,
                Jwt = Sealing.Seal(Sealing.Derive(secret, JwtLabel), Encoding.UTF8.GetBytes(jwt), Context(user.Id)),
                CreatedAt = now,
                LastUsedAt = now,
                // Milliseconds down, as MongoDB keeps them: the session never outlives the JWT by a fraction.
                ExpiresAt = Milliseconds(jwtExpiresAt.ToUniversalTime() < limit ? jwtExpiresAt.ToUniversalTime() : limit),
            },
            cancellationToken: ct);
        return secret;
    }

    /// <summary>
    /// The session of <paramref name="secret"/>, or null if it is unknown, ended, idle too long or past its end. A
    /// session found dead is deleted. Using it moves its idle clock on.
    /// </summary>
    public async Task<ResolvedSession?> ResolveAsync(string secret, CancellationToken ct)
    {
        if (!IsWellFormed(secret)) return null;
        await EnsureReadyAsync(ct);
        var id = Lookup(secret);
        var doc = await Docs.Find(s => s.Id == id).FirstOrDefaultAsync(ct);
        if (doc is null) return null;

        // The TTL index removes expired sessions only eventually (MongoDB's sweep runs once a minute), and idle ones
        // not at all before their end, so the times are checked here.
        var now = Now;
        if (now >= doc.ExpiresAt || now - doc.LastUsedAt > IdleTimeout)
        {
            await Docs.DeleteOneAsync(s => s.Id == id, ct);
            return null;
        }

        string jwt;
        try
        {
            jwt = Encoding.UTF8.GetString(Sealing.Open(Sealing.Derive(secret, JwtLabel), doc.Jwt, Context(doc.User)));
        }
        catch (CryptographicException)
        {
            return null;
        }

        if (now - doc.LastUsedAt >= LastUsedGranularity)
        {
            // Conditional on the value read, so of concurrent requests only one writes.
            await Docs.UpdateOneAsync(
                s => s.Id == id && s.LastUsedAt == doc.LastUsedAt, Builders<SessionDocument>.Update.Set(s => s.LastUsedAt, Milliseconds(now)), cancellationToken: ct);
        }

        return new ResolvedSession(new KomodoUser(doc.User, doc.Username), jwt, doc.ExpiresAt);
    }

    /// <summary>
    /// Ends the session of <paramref name="secret"/>: signing out, signing in again in the same browser, and a JWT
    /// that Komodo refused (<see cref="Api.ApiErrors.Filter"/>). Nothing happens for an unknown secret.
    /// </summary>
    public async Task EndAsync(string secret, CancellationToken ct)
    {
        if (!IsWellFormed(secret)) return;
        await EnsureReadyAsync(ct);
        var id = Lookup(secret);
        await Docs.DeleteOneAsync(s => s.Id == id, ct);
    }

    /// <summary>Checked before any lookup: anything else can't be a secret of <see cref="StartAsync"/>.</summary>
    private static bool IsWellFormed(string secret) =>
        secret.Length == Base64Url.GetEncodedLength(SecretBytes) && Base64Url.IsValid(secret);

    /// <summary>Finds the session without storing the secret; HKDF suffices, as the secret is random.</summary>
    private static string Lookup(string secret) => Convert.ToHexStringLower(Sealing.Lookup(secret, LookupLabel));

    /// <summary>The associated data: the sealed JWT opens only as this user's session.</summary>
    private static string Context(string userId) => $"session:{userId}";

    private static DateTime Milliseconds(DateTime t) => new(t.Ticks - (t.Ticks % TimeSpan.TicksPerMillisecond), DateTimeKind.Utc);

    /// <summary>Creates the indexes once per process; lazy, so the server starts before MongoDB is reachable.</summary>
    private async Task EnsureReadyAsync(CancellationToken ct)
    {
        if (_ready) return;
        var keys = Builders<SessionDocument>.IndexKeys;
        await Docs.Indexes.CreateManyAsync(
            [
                // MongoDB deletes a session once its expiresAt has passed.
                new CreateIndexModel<SessionDocument>(keys.Ascending(s => s.ExpiresAt), new CreateIndexOptions { ExpireAfter = TimeSpan.Zero }),
                new CreateIndexModel<SessionDocument>(keys.Ascending(s => s.User)),
            ],
            ct);
        _ready = true;
    }
}

/// <summary>A dashboard session as stored (collection <c>sessions</c>).</summary>
[BsonIgnoreExtraElements]
public sealed class SessionDocument
{
    /// <summary>The hex of the secret's HKDF lookup: it finds the session, but opens nothing.</summary>
    [BsonId]
    public string Id { get; set; } = "";

    /// <summary>The Komodo user id.</summary>
    [BsonElement("user")]
    public string User { get; set; } = "";

    [BsonElement("username")]
    public string Username { get; set; } = "";

    /// <summary>The Komodo JWT, AES-256-GCM under <c>HKDF(secret, "kgt/v1/session-jwt")</c>, context <c>session:{user}</c>.</summary>
    [BsonElement("jwt")]
    public byte[] Jwt { get; set; } = [];

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; }

    [BsonElement("lastUsedAt")]
    public DateTime LastUsedAt { get; set; }

    /// <summary>The earlier of 12 hours after the sign-in and the JWT's expiry.</summary>
    [BsonElement("expiresAt")]
    public DateTime ExpiresAt { get; set; }
}
