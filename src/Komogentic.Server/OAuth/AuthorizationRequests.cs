// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Security.Cryptography;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace Komogentic.Server.OAuth;

/// <summary>
/// An authorisation request that passed <c>/oauth/authorize</c>, waiting for the user's decision on the consent page
///. Everything here came from the app's request, checked: the client resolved, the redirect URI one of
/// its own, PKCE S256. <see cref="ConnectionId"/> is the connection <see cref="Resource"/> names, or null with
/// <see cref="Problem"/> <c>"not_a_connection"</c>. <see cref="ReadOnly"/>: the scopes asked for
/// <c>komodo:read</c> and not <c>komodo:operate</c>, which limits the grant to the read tools.
/// </summary>
public sealed record PendingAuthorisation(
    string Id, string ClientId, string RedirectUri, string? State, string CodeChallenge, string Resource, string? ConnectionId, bool ReadOnly, string? Problem,
    DateTime ExpiresAt);

/// <summary>
/// The pending authorisation requests (collection <c>oauth_requests</c>), for <see cref="Lifetime"/>. Expiry is
/// checked here; the TTL index only tidies up. A request is decided once: <see cref="TakeAsync"/> deletes it as it
/// reads it, so of two decisions at once exactly one gets it.
/// </summary>
public sealed class AuthorizationRequests(IMongoDatabase db, TimeProvider time)
{
    internal const string CollectionName = "oauth_requests";

    public const string NotAConnection = "not_a_connection";

    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    private IMongoCollection<PendingDocument> Docs => db.GetCollection<PendingDocument>(CollectionName);

    private volatile bool _ready;

    private DateTime Now => time.GetUtcNow().UtcDateTime;

    /// <summary>16 random bytes in hex: the request's id, in the consent page's URL. Not a secret (the decision
    /// needs the owner's session), but not guessable either.</summary>
    public static string NewId() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

    public async Task CreateAsync(PendingAuthorisation request, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        await Docs.InsertOneAsync(PendingDocument.From(request), cancellationToken: ct);
    }

    /// <summary>The request, or null if there is none or it expired.</summary>
    public async Task<PendingAuthorisation?> GetAsync(string id, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        var now = Now;
        var doc = await Docs.Find(d => d.Id == id && d.ExpiresAt > now).FirstOrDefaultAsync(ct);
        return doc?.ToRecord();
    }

    /// <summary>The request, deleted in the same step (single use); null if there is none, it expired or another
    /// decision took it first.</summary>
    public async Task<PendingAuthorisation?> TakeAsync(string id, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        var doc = await Docs.FindOneAndDeleteAsync(d => d.Id == id, cancellationToken: ct);
        // Deleted whether or not it expired: an expired one is of no use to anyone.
        return doc is not null && doc.ExpiresAt > Now ? doc.ToRecord() : null;
    }

    /// <summary>
    /// Puts back a request that <see cref="TakeAsync"/> took for a decision that issued nothing (Komodo could
    /// not be reached), so that the user can decide again; one that expired meanwhile stays gone.
    /// </summary>
    public async Task PutBackAsync(PendingAuthorisation request, CancellationToken ct)
    {
        if (request.ExpiresAt <= Now) return;
        await EnsureReadyAsync(ct);
        try
        {
            await Docs.InsertOneAsync(PendingDocument.From(request), cancellationToken: ct);
        }
        catch (MongoWriteException e) when (e.WriteError.Category == ServerErrorCategory.DuplicateKey)
        {
        }
    }

    /// <summary>Creates the TTL index once per process; lazy, so the server starts before MongoDB is reachable.</summary>
    private async Task EnsureReadyAsync(CancellationToken ct)
    {
        if (_ready) return;
        var keys = Builders<PendingDocument>.IndexKeys;
        await Docs.Indexes.CreateManyAsync(
            [
                new CreateIndexModel<PendingDocument>(keys.Ascending(d => d.ExpiresAt), new CreateIndexOptions { ExpireAfter = TimeSpan.Zero }),
                // A connection's revocation finds its requests.
                new CreateIndexModel<PendingDocument>(keys.Ascending(d => d.ConnectionId)),
            ],
            ct);
        _ready = true;
    }

    /// <summary>A pending request as stored. Nothing secret: a code challenge is a hash, the state the app's own.</summary>
    [BsonIgnoreExtraElements]
    internal sealed class PendingDocument
    {
        [BsonId]
        public string Id { get; set; } = "";

        [BsonElement("client")]
        public string ClientId { get; set; } = "";

        [BsonElement("redirectUri")]
        public string RedirectUri { get; set; } = "";

        [BsonElement("state"), BsonIgnoreIfNull]
        public string? State { get; set; }

        [BsonElement("codeChallenge")]
        public string CodeChallenge { get; set; } = "";

        [BsonElement("resource")]
        public string Resource { get; set; } = "";

        [BsonElement("connection"), BsonIgnoreIfNull]
        public string? ConnectionId { get; set; }

        [BsonElement("readOnly")]
        public bool ReadOnly { get; set; }

        [BsonElement("problem"), BsonIgnoreIfNull]
        public string? Problem { get; set; }

        [BsonElement("expiresAt")]
        public DateTime ExpiresAt { get; set; }

        public static PendingDocument From(PendingAuthorisation r) => new()
        {
            Id = r.Id,
            ClientId = r.ClientId,
            RedirectUri = r.RedirectUri,
            State = r.State,
            CodeChallenge = r.CodeChallenge,
            Resource = r.Resource,
            ConnectionId = r.ConnectionId,
            ReadOnly = r.ReadOnly,
            Problem = r.Problem,
            ExpiresAt = r.ExpiresAt,
        };

        public PendingAuthorisation ToRecord() =>
            new(Id, ClientId, RedirectUri, State, CodeChallenge, Resource, ConnectionId, ReadOnly, Problem, DateTime.SpecifyKind(ExpiresAt, DateTimeKind.Utc));
    }
}
