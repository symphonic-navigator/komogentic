// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Komodo;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace Komogentic.Server.Accounts;

/// <summary>
/// Komodo API keys that Komogentic created for a user and no longer uses (a revoked or dead API key or connection, a
/// replaced connection key, a code never exchanged), waiting to be deleted in Komodo (spec §5). Deleting one needs the
/// user's JWT, which only a sign-in or a consent brings, so they wait in <c>pending_deletions</c> until then. Until it
/// is deleted such a key is useless (nobody holds its secret) and recognisable by its <c>komogentic/</c> name prefix.
/// </summary>
public sealed class PendingDeletions(IMongoDatabase db, KomodoClient komodo, TimeProvider time, ILogger<PendingDeletions> log)
{
    internal const string CollectionName = "pending_deletions";

    private volatile bool _ready;

    private IMongoCollection<PendingDeletionDocument> Docs { get; } = db.GetCollection<PendingDeletionDocument>(CollectionName);

    /// <summary>
    /// Queues <paramref name="komodoKey"/> of <paramref name="userId"/> for deletion, in the transaction of
    /// <paramref name="s"/> if given. With <paramref name="notBefore"/> it is not deleted before then: the key of a code
    /// not yet exchanged, which may still be (amendment R6). Queuing a key again only updates its time.
    /// </summary>
    public async Task AddAsync(IClientSessionHandle? s, string userId, string komodoKey, string reason, CancellationToken ct, DateTime? notBefore = null)
    {
        // Outside the transaction: indexes can't be created inside one.
        await EnsureReadyAsync(ct);
        var filter = Builders<PendingDeletionDocument>.Filter.Where(d => d.User == userId && d.KomodoKey == komodoKey);
        var update = Builders<PendingDeletionDocument>.Update
            .SetOnInsert(d => d.Reason, reason)
            .SetOnInsert(d => d.CreatedAt, time.GetUtcNow().UtcDateTime)
            .Set(d => d.NotBefore, notBefore?.ToUniversalTime());
        var options = new UpdateOptions { IsUpsert = true };
        if (s is null) await Docs.UpdateOneAsync(filter, update, options, ct);
        else await Docs.UpdateOneAsync(s, filter, update, options, ct);
    }

    /// <summary>Takes <paramref name="komodoKey"/> off the list again: the code it waited for was exchanged after all.</summary>
    public async Task RemoveAsync(IClientSessionHandle? s, string userId, string komodoKey, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        if (s is null) await Docs.DeleteOneAsync(d => d.User == userId && d.KomodoKey == komodoKey, ct);
        else await Docs.DeleteOneAsync(s, d => d.User == userId && d.KomodoKey == komodoKey, cancellationToken: ct);
    }

    /// <summary>
    /// Deletes each of the user's queued keys whose time has come in Komodo with <paramref name="jwt"/>, and takes it
    /// off the list once Komodo deleted it or no longer has it. Any other failure keeps it for the next time; Komodo's
    /// failures never throw, so a sign-in or consent never fails over a key nobody can use anyway.
    /// </summary>
    public async Task DrainAsync(string userId, KomodoAuth.Jwt jwt, CancellationToken ct)
    {
        await EnsureReadyAsync(ct);
        var now = time.GetUtcNow().UtcDateTime;
        var due = await Docs.Find(d => d.User == userId && (d.NotBefore == null || d.NotBefore <= now)).ToListAsync(ct);
        var deleted = 0;
        foreach (var doc in due)
        {
            try
            {
                await komodo.DeleteApiKeyAsync(jwt, doc.KomodoKey, ct);
            }
            catch (KomodoException e)
            {
                log.LogWarning("A Komodo key pending deletion for user {UserId} stays queued: Komodo answered {Kind} (HTTP {Status})", userId, e.Kind, e.Status);
                // Each of the others would be refused alike.
                if (e.Kind is KomodoErrorKind.Unauthorized or KomodoErrorKind.Unreachable or KomodoErrorKind.RateLimited) break;
                continue;
            }

            await Docs.DeleteOneAsync(d => d.Id == doc.Id, ct);
            deleted++;
        }

        if (deleted > 0) log.LogInformation("Deleted {Count} Komodo key(s) pending deletion for user {UserId}", deleted, userId);
    }

    /// <summary>Creates the indexes once per process; lazy, so the server starts before MongoDB is reachable.</summary>
    private async Task EnsureReadyAsync(CancellationToken ct)
    {
        if (_ready) return;
        var keys = Builders<PendingDeletionDocument>.IndexKeys;
        await Docs.Indexes.CreateOneAsync(
            new CreateIndexModel<PendingDeletionDocument>(keys.Ascending(d => d.User).Ascending(d => d.KomodoKey), new CreateIndexOptions { Unique = true }),
            cancellationToken: ct);
        _ready = true;
    }
}

/// <summary>A Komodo key waiting to be deleted (collection <c>pending_deletions</c>). The key id opens nothing without its secret.</summary>
[BsonIgnoreExtraElements]
public sealed class PendingDeletionDocument
{
    [BsonId]
    public ObjectId Id { get; set; }

    /// <summary>The Komodo user id of the key's owner.</summary>
    [BsonElement("user")]
    public string User { get; set; } = "";

    [BsonElement("komodoKey")]
    public string KomodoKey { get; set; } = "";

    /// <summary>Why it is no longer used: <c>revoked</c>, <c>dead</c>, <c>replaced</c>, <c>code_unused</c>, …</summary>
    [BsonElement("reason")]
    public string Reason { get; set; } = "";

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; }

    /// <summary>Not deleted before this time; null for at once.</summary>
    [BsonElement("notBefore")]
    public DateTime? NotBefore { get; set; }
}
