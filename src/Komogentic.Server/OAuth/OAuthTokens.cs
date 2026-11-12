// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Komogentic.Server.Accounts;
using Komogentic.Server.Komodo;
using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace Komogentic.Server.OAuth;

/// <summary>The kinds of <c>oauth_tokens</c> records.</summary>
public static class OAuthTokenKinds
{
    public const string Code = "code";
    public const string Access = "access";
    public const string Refresh = "refresh";
}

/// <summary>What the token endpoint passes on for <c>grant_type=authorization_code</c>; <c>Resource</c> is optional.</summary>
public sealed record CodeExchange(string Code, string ClientId, string RedirectUri, string CodeVerifier, string? Resource)
{
    public override string ToString() => $"CodeExchange {{ ClientId = {ClientId}, RedirectUri = {RedirectUri}, Resource = {Resource} }}";
}

/// <summary>A connection's tokens as the token endpoint answers them. Not logged: <see cref="ToString"/> hides them.</summary>
public sealed record TokenPair(string AccessToken, string RefreshToken, int ExpiresIn, string Scope)
{
    public override string ToString() => $"TokenPair {{ ExpiresIn = {ExpiresIn}, Scope = {Scope} }}";
}

/// <summary>The token endpoint's answer: a pair, or an RFC 6749 §5.2 error (<c>invalid_request</c>, <c>invalid_grant</c>,
/// <c>invalid_client</c>, <c>invalid_target</c>, <c>unsupported_grant_type</c>) with a description.</summary>
public sealed record TokenResult(TokenPair? Pair, string? Error, string? Description)
{
    public static TokenResult Failure(string error, string description) => new(null, error, description);
}

/// <summary>The connection an access token opens, as <see cref="OAuthTokens.ResolveAccessAsync"/> found it valid: its
/// owner, the name and client sealed into the grant, whether the grant is read-only, and the connection's Komodo key,
/// unsealed for this request.</summary>
public sealed record ResolvedConnection(KomodoUser User, string ConnectionId, string Name, string? ClientName, bool ReadOnly, KomodoAuth.Key Komodo, DateTime? ExpiresAt);

/// <summary>An access token's resolution: <c>Connection</c> if valid here; else <c>Known</c> if a record with its lookup
/// exists (expired, of another connection, revoked meanwhile), which isn't a guess and isn't counted as a wrong key.</summary>
public sealed record AccessResolution(ResolvedConnection? Connection, bool Known);

/// <summary>Allowing could not go ahead: the connection is no longer the user's to authorise (revoked, expired, gone,
/// another user's) or the client no longer resolves. The consent API answers 409.</summary>
public sealed class ConnectionUnavailableException(string message) : Exception(message);

/// <summary>
/// A connection's OAuth codes and tokens (spec §5): random secrets with a prefix (<see cref="Secrets"/>), stored only as
/// an HKDF lookup. Each record seals, under a key derived from its own token, the connection's Komodo key and secret
/// (<c>sealed</c>) and the grant (<c>grant</c>: name, resource, expiries, read-only, client), so a token opens exactly
/// its connection's Komodo key and a database dump alone opens nothing. A code is exchanged once for an access token
/// (an hour) and a refresh token (until the connection expires); a connection has one family of tokens at a time.
/// </summary>
public sealed class OAuthTokens(
    IMongoDatabase db, Connections connections, OAuthClients clients, KomodoClient komodo, PendingDeletions pending, IOptions<KomogenticOptions> options,
    TimeProvider time, ILogger<OAuthTokens> log)
{
    public const string CodePrefix = "kgt_ac_";
    public const string AccessPrefix = "kgt_at_";
    public const string RefreshPrefix = "kgt_rt_";

    internal const string CollectionName = ConnectionRevocation.TokensCollection;

    /// <summary>A code is exchanged within seconds by the app's server; a minute leaves room and little else.</summary>
    public static readonly TimeSpan CodeLifetime = TimeSpan.FromSeconds(60);

    /// <summary>A code's record outlives the code by this much (its Komodo key doesn't), so that a reuse is recognised
    /// as one and revokes what the code issued.</summary>
    public static readonly TimeSpan CodeRetention = TimeSpan.FromMinutes(10);

    /// <summary>An access token's record outlives the token by this much, so that an expired token is recognised as
    /// one: it answers <c>invalid_token</c> and isn't counted as a wrong key.</summary>
    public static readonly TimeSpan AccessRetention = TimeSpan.FromHours(24);

    /// <summary>How long a retried refresh gets the same pair back: Claude's refresh times out after 30 s, so a retry
    /// comes within that; a used refresh token presented later revokes the connection's tokens.</summary>
    public static readonly TimeSpan GracePeriod = TimeSpan.FromSeconds(30);

    /// <summary>A used refresh token's record outlives its use by this much, so that a reuse is recognised as one.</summary>
    public static readonly TimeSpan UsedRetention = TimeSpan.FromDays(30);

    /// <summary>How often a connection's <c>lastUsedAt</c> is written at most, as an API key's (amendment R14).</summary>
    private static readonly TimeSpan LastUsedGranularity = TimeSpan.FromMinutes(1);

    private const string InvalidCode = "The code is invalid, expired or already used.";
    private const string InvalidRefresh = "The refresh token is invalid, expired, revoked or already used.";
    private const string ConnectionGone = "This connection is revoked or expired.";

    private const string LookupLabel = "kgt/v1/oauth-token";
    private const string GrantLabel = "kgt/v1/oauth-grant";
    private const string KomodoLabel = "kgt/v1/oauth-komodo";
    private const string SuccessorLabel = "kgt/v1/oauth-successor";

    private volatile bool _ready;

    private IMongoCollection<OAuthTokenDocument> Docs => db.GetCollection<OAuthTokenDocument>(CollectionName);

    private IMongoCollection<ConnectionDocument> ConnectionDocs => db.GetCollection<ConnectionDocument>(Connections.CollectionName);

    private DateTime Now => time.GetUtcNow().UtcDateTime;

    /// <summary>The access token's lifetime, from <c>Komogentic:OAuth:AccessTokenMinutes</c>.</summary>
    internal TimeSpan AccessLifetime => TimeSpan.FromMinutes(options.Value.OAuth.AccessTokenMinutes);

    /// <summary>
    /// The user's Allow on <paramref name="request"/>: a one-time code for <see cref="CodeLifetime"/>. The connection
    /// must be the user's, neither revoked nor expired, and the client must still resolve. With <paramref name="jwt"/>,
    /// Komodo creates the connection's Komodo key <c>komogentic/{name}</c> with the connection's expiry, sealed under the
    /// code with the grant; from that call on the request's token is not used, so a client that hangs up leaves nothing
    /// untracked. In one transaction the code is stored and the connection gets the client and the Komodo key. Should
    /// the transaction fail, the new Komodo key is deleted again, or queued for deletion.
    /// </summary>
    /// <exception cref="ConnectionUnavailableException">The connection or the client can't be authorised (any more).</exception>
    /// <exception cref="KomodoException">Komodo refused or did not answer; nothing was stored.</exception>
    /// <exception cref="ClientMetadataUnavailableException">The client's metadata document couldn't be fetched now.</exception>
    public async Task<string> IssueCodeAsync(KomodoUser user, KomodoAuth.Jwt jwt, PendingAuthorisation request, CancellationToken ct)
    {
        if (request.ConnectionId is not { } connectionId || request.Problem is not null) throw new ConnectionUnavailableException("This request names no connection.");
        await EnsureReadyAsync(ct);

        var doc = await connections.FindAsync(connectionId, ct);
        if (doc is null || !IsLive(doc, user.Id, Now)) throw new ConnectionUnavailableException(ConnectionGone);
        var client = await clients.ResolveAsync(request.ClientId, ct)
            ?? throw new ConnectionUnavailableException("The app could not be identified any more; start the connection again in the app.");

        // From here on not the request's token: once Komodo made the key, it is stored, or deleted again, whatever the
        // client does.
        var created = await komodo.CreateApiKeyAsync(jwt, ApiKeys.KomodoNamePrefix + doc.Name, doc.ExpiresAt is { } at ? new DateTimeOffset(at) : null, CancellationToken.None);

        var code = Secrets.New(CodePrefix);
        var tokenId = NewTokenId();
        var now = Now;
        var expiresAt = CredentialRules.Milliseconds(now + CodeLifetime);
        var record = new OAuthTokenDocument
        {
            Id = tokenId,
            Kind = OAuthTokenKinds.Code,
            ConnectionId = connectionId,
            User = user.Id,
            ClientId = request.ClientId,
            Lookup = Lookup(code),
            Grant = SealGrant(code, tokenId, OAuthTokenKinds.Code, new OAuthGrant(doc.Name, request.Resource, doc.ExpiresAt, expiresAt, request.ReadOnly, client.Name)),
            Sealed = SealKomodo(code, tokenId, OAuthTokenKinds.Code, new SealedKomodoKey(created.Key, created.Secret)),
            RedirectUri = request.RedirectUri,
            CodeChallenge = request.CodeChallenge,
            ReadOnly = request.ReadOnly,
            CreatedAt = now,
            ExpiresAt = expiresAt,
            PurgeAt = expiresAt + CodeRetention,
        };
        var connected = new ConnectedClient(client.Name, client.Host, client.Verified);

        try
        {
            using var session = await db.Client.StartSessionAsync(cancellationToken: CancellationToken.None);
            await session.WithTransactionAsync(
                async (s, token) =>
                {
                    // Read in the transaction, and written in it: the owner's Revoke and every revocation of the
                    // connection's tokens write this document too, so one of the two conflicts and the retry sees the other.
                    var current = await ConnectionDocs.Find(s, c => c.Id == connectionId).FirstOrDefaultAsync(token);
                    if (current is null || !IsLive(current, user.Id, Now)) throw new ConnectionUnavailableException(ConnectionGone);
                    // The earlier codes and tokens go: they carry the Komodo key this consent replaces, and a late
                    // rejection of that key must not reach the new grant (amendment R1). Before the new code is stored,
                    // which they would take with them.
                    await ConnectionRevocation.RevokeTokensAsync(db, s, connectionId, ConnectionReasons.Reconnected, now, token);
                    if (current.KomodoKey is { } previous && previous != created.Key)
                        await pending.AddAsync(s, user.Id, previous, ConnectionReasons.Reconnected, token);
                    // Should the code never be exchanged, its key is deleted once the code has expired (amendment R6);
                    // the exchange takes it off the list.
                    await pending.AddAsync(s, user.Id, created.Key, ConnectionReasons.CodeUnused, token, notBefore: expiresAt);
                    await Docs.InsertOneAsync(s, record, cancellationToken: token);
                    await ConnectionDocs.UpdateOneAsync(
                        s,
                        c => c.Id == connectionId,
                        Wrapped.Set(c => c.Client, connected).Set(c => c.KomodoKey, created.Key).Set(c => c.CodeExpiresAt, expiresAt),
                        cancellationToken: token);
                    return true;
                },
                cancellationToken: CancellationToken.None);
        }
        catch
        {
            // Nobody will ever hold this Komodo key's secret: away with it, whatever went wrong.
            await DiscardAsync(user.Id, jwt, created.Key, "unstored");
            throw;
        }

        log.LogDebug("OAuth code {TokenId} issued for connection {ConnectionId}, expiring {ExpiresAt:u}", tokenId, connectionId, expiresAt);
        // The key this consent replaced, and whatever else waited for a JWT of the user's. Never fails over Komodo.
        await pending.DrainAsync(user.Id, jwt, CancellationToken.None);
        return code;
    }

    /// <summary>Deletes a Komodo key nobody will use with <paramref name="jwt"/>, else queues it for the user's next JWT.
    /// Never fails over Komodo.</summary>
    private async Task DiscardAsync(string userId, KomodoAuth.Jwt jwt, string komodoKey, string reason)
    {
        try
        {
            await komodo.DeleteApiKeyAsync(jwt, komodoKey, CancellationToken.None);
        }
        catch (KomodoException e)
        {
            log.LogWarning("A Komodo key of user {UserId} is queued for deletion: Komodo answered {Kind} (HTTP {Status})", userId, e.Kind, e.Status);
            await pending.AddAsync(null, userId, komodoKey, reason, CancellationToken.None);
        }
    }

    /// <summary>
    /// Exchanges a code for the connection's tokens (spec §5), in one transaction. The code is spent by the first
    /// request that presents it, whatever the outcome, so a code intercepted and tried is burnt; a code presented again
    /// after it issued tokens revokes the connection's tokens (<see cref="ConnectionReasons.CodeReused"/>). The code must
    /// be unexpired, for this client and redirect URI (exactly as stored), its PKCE challenge must be
    /// <c>BASE64URL(SHA256(verifier))</c> (compared in fixed time), and a <c>resource</c>, if sent, must name the
    /// connection the code is for. The connection must still be live, and its Komodo key still the code's. Then the
    /// connection's earlier tokens become tombstones (one family per connection), and a refresh token (until the
    /// connection expires) and an access token (<see cref="AccessLifetime"/>, at most until the connection expires) get
    /// the Komodo key sealed under each.
    /// </summary>
    public async Task<TokenResult> ExchangeCodeAsync(CodeExchange exchange, CancellationToken ct)
    {
        if (!Secrets.IsWellFormed(exchange.Code, CodePrefix)) return Refused("token", null, null, "invalid_grant", InvalidCode);
        await EnsureReadyAsync(ct);
        var lookup = Lookup(exchange.Code);

        var found = await Docs.Find(d => d.Lookup == lookup).FirstOrDefaultAsync(ct);
        if (found is null || found.Kind != OAuthTokenKinds.Code) return Refused("token", null, null, "invalid_grant", InvalidCode);

        var access = Secrets.New(AccessPrefix);
        var refresh = Secrets.New(RefreshPrefix);
        var accessId = NewTokenId();
        var refreshId = NewTokenId();
        var reused = false;
        using var session = await db.Client.StartSessionAsync(cancellationToken: ct);
        var result = await session.WithTransactionAsync(
            async (s, token) =>
            {
                reused = false;
                var code = await Docs.Find(s, d => d.Id == found.Id).FirstOrDefaultAsync(token);
                // A tombstone: the connection's tokens were revoked, this code with them; there is nothing left to revoke.
                if (code is null || code.RevokedAt is not null) return TokenResult.Failure("invalid_grant", InvalidCode);
                var now = Now;
                if (code.UsedAt is not null)
                {
                    // Only a code that issued tokens has something to revoke; one burnt by a failed attempt issued nothing.
                    if (code.Issued is not null)
                    {
                        await RevokeFamilyAsync(s, code.ConnectionId, ConnectionReasons.CodeReused, now, token);
                        reused = true;
                    }

                    return TokenResult.Failure("invalid_grant", InvalidCode);
                }

                // Spent now, whatever comes next; committed with the answer. Its grant and Komodo key go with it.
                await Docs.UpdateOneAsync(
                    s, d => d.Id == code.Id, Builders<OAuthTokenDocument>.Update.Set(d => d.UsedAt, now).Unset(d => d.Grant).Unset(d => d.Sealed), cancellationToken: token);
                if (!(now < code.ExpiresAt)) return TokenResult.Failure("invalid_grant", InvalidCode);
                if (!string.Equals(exchange.ClientId, code.ClientId, StringComparison.Ordinal)
                    || !string.Equals(exchange.RedirectUri, code.RedirectUri, StringComparison.Ordinal)
                    || !PkceMatches(exchange.CodeVerifier, code.CodeChallenge))
                {
                    return TokenResult.Failure("invalid_grant", "The code was issued to another client, redirect URI or code verifier.");
                }

                OAuthGrant grant;
                SealedKomodoKey komodoKey;
                try
                {
                    grant = OpenGrant(exchange.Code, code);
                    komodoKey = OpenKomodo(exchange.Code, code);
                }
                catch (Exception e) when (e is CryptographicException or JsonException)
                {
                    log.LogWarning("The grant of OAuth code {TokenId} does not open", code.Id);
                    return TokenResult.Failure("invalid_grant", InvalidCode);
                }

                // The code's expiry as sealed into its grant: a changed expiresAt in the database extends nothing.
                if (!(now < grant.ExpiresAt)) return TokenResult.Failure("invalid_grant", InvalidCode);
                if (exchange.Resource is { } resource && OAuthUrls.Canonical(resource) != OAuthUrls.Canonical(grant.Resource))
                    return TokenResult.Failure("invalid_target", "The resource is not the connection this code was issued for.");

                var connection = await ConnectionDocs.Find(s, c => c.Id == code.ConnectionId).FirstOrDefaultAsync(token);
                if (connection is null || !IsLive(connection, code.User, now) || now >= grant.ConnectionExpiresAt)
                    return TokenResult.Failure("invalid_grant", ConnectionGone);
                // A later consent replaced the Komodo key this code carries: the code issued nothing usable.
                if (connection.KomodoKey != komodoKey.Key) return TokenResult.Failure("invalid_grant", InvalidCode);

                // The connection's expiry as sealed into the grant: a changed expiresAt in the database extends nothing.
                var connectionExpiresAt = grant.ConnectionExpiresAt;
                var accessExpiresAt = AccessExpiry(now, connectionExpiresAt);

                // One family per connection: the earlier tokens become tombstones, still recognised but opening nothing.
                var earlier = await Docs.Find(
                        s, d => d.ConnectionId == code.ConnectionId && d.RevokedAt == null && (d.Kind == OAuthTokenKinds.Access || d.Kind == OAuthTokenKinds.Refresh))
                    .Project(d => d.Id).ToListAsync(token);
                if (earlier.Count > 0) await ConnectionRevocation.TombstoneAsync(db, s, Builders<BsonDocument>.Filter.In("_id", earlier), now, token);

                await Docs.InsertManyAsync(
                    s,
                    [
                        Record(refreshId, OAuthTokenKinds.Refresh, refresh, code, grant with { ExpiresAt = connectionExpiresAt }, komodoKey, now, connectionExpiresAt, connectionExpiresAt),
                        Record(accessId, OAuthTokenKinds.Access, access, code, grant with { ExpiresAt = accessExpiresAt }, komodoKey, now, accessExpiresAt, accessExpiresAt + AccessRetention),
                    ],
                    cancellationToken: token);
                await Docs.UpdateOneAsync(s, d => d.Id == code.Id, Builders<OAuthTokenDocument>.Update.Set(d => d.Issued, refreshId), cancellationToken: token);
                var update = Wrapped.Unset(c => c.TokensRevokedAt).Unset(c => c.TokensRevokedReason).Unset(c => c.CodeExpiresAt);
                if (connection.AuthorisedAt is null) update = update.Set(c => c.AuthorisedAt, now);
                await ConnectionDocs.UpdateOneAsync(s, c => c.Id == code.ConnectionId, update, cancellationToken: token);
                // Its Komodo key is in use now: no longer waiting to be deleted (amendment R6).
                await pending.RemoveAsync(s, code.User, komodoKey.Key, token);

                return new TokenResult(new TokenPair(access, refresh, ExpiresIn(accessExpiresAt, now), ScopeOf(grant.ReadOnly)), null, null);
            },
            cancellationToken: ct);

        var clientHost = found.RedirectUri is { } redirect ? OAuthEndpoints.ClientHost(found.ClientId, redirect) : null;
        if (reused) log.LogWarning("OAuth code {TokenId} was presented again: the tokens of connection {ConnectionId} are revoked", found.Id, found.ConnectionId);
        return result.Pair is not null
            ? Logged(result, "token", found.ConnectionId, clientHost, "issued")
            : Refused("token", found.ConnectionId, clientHost, result.Error!, result.Description!);
    }

    /// <summary>
    /// The <c>refresh_token</c> grant (spec §5), in one transaction. An unused refresh token, unexpired (its record's
    /// expiry and the one sealed into its grant), of this client, a <c>resource</c> if sent naming its connection, the
    /// connection live and its Komodo key still the token's, is rotated: it is marked used (conditionally, so of
    /// parallel refreshes one wins and the others conflict and retry), its grant and Komodo key go, a new refresh and
    /// access token get the Komodo key sealed under each, and the new pair is sealed into its record under a key derived
    /// from it for <see cref="GracePeriod"/>'s retries; its parent's kept pair is dropped, since that is this token, now
    /// used. The used record stays <see cref="UsedRetention"/> to recognise a reuse. A used token presented again within
    /// the grace period gets the same pair while its refresh token is unused and live, else <c>invalid_grant</c>; after
    /// it, the connection's tokens are revoked (<see cref="ConnectionReasons.RefreshReused"/>). A revoked token (a
    /// tombstone) is <c>invalid_grant</c>, and also revokes the connection's tokens if the connection has a live family
    /// again and the token was spent more than the grace period ago: an old family's token turning up beside a new one
    /// is a reuse too. A token of another client is refused and changes nothing.
    /// </summary>
    public Task<TokenResult> RefreshAsync(string refreshToken, string clientId, string? resource, CancellationToken ct) =>
        RefreshAsync(refreshToken, clientId, resource, retry: true, ct);

    private async Task<TokenResult> RefreshAsync(string refreshToken, string clientId, string? resource, bool retry, CancellationToken ct)
    {
        if (!Secrets.IsWellFormed(refreshToken, RefreshPrefix)) return Refused("refresh", null, null, "invalid_grant", InvalidRefresh);
        await EnsureReadyAsync(ct);
        var lookup = Lookup(refreshToken);

        var found = await Docs.Find(d => d.Lookup == lookup).FirstOrDefaultAsync(ct);
        if (found is null || found.Kind != OAuthTokenKinds.Refresh) return Refused("refresh", null, null, "invalid_grant", InvalidRefresh);
        // For the log only; resolved before the transaction, so that nothing can fail between its commit and the answer.
        var clientHost = await clients.HostAsync(found.ClientId, ct);

        var access = Secrets.New(AccessPrefix);
        var refresh = Secrets.New(RefreshPrefix);
        var accessId = NewTokenId();
        var refreshId = NewTokenId();
        var reused = false;
        var retried = false;
        using var session = await db.Client.StartSessionAsync(cancellationToken: ct);
        var result = await session.WithTransactionAsync<TokenResult?>(
            async (s, token) =>
            {
                reused = false;
                retried = false;
                var old = await Docs.Find(s, d => d.Id == found.Id).FirstOrDefaultAsync(token);
                if (old is null) return TokenResult.Failure("invalid_grant", InvalidRefresh);
                // Another client presenting it gets nothing, and revokes nothing.
                if (!string.Equals(clientId, old.ClientId, StringComparison.Ordinal)) return TokenResult.Failure("invalid_grant", "The refresh token was issued to another client.");
                var now = Now;

                if (old.RevokedAt is { } revokedAt)
                {
                    // Revoked with its family, or replaced by a new consent. Nothing to revoke unless a family is live
                    // again; then an old token turning up beyond the grace period is a reuse like any other.
                    var spentAt = old.UsedAt is { } u && u < revokedAt ? u : revokedAt;
                    if (now - spentAt > GracePeriod && await LiveFamilyAsync(s, old.ConnectionId, token))
                    {
                        await RevokeFamilyAsync(s, old.ConnectionId, ConnectionReasons.RefreshReused, now, token);
                        reused = true;
                    }

                    return TokenResult.Failure("invalid_grant", InvalidRefresh);
                }

                if (old.UsedAt is { } usedAt)
                {
                    if (now - usedAt > GracePeriod)
                    {
                        await RevokeFamilyAsync(s, old.ConnectionId, ConnectionReasons.RefreshReused, now, token);
                        reused = true;
                        return TokenResult.Failure("invalid_grant", InvalidRefresh);
                    }

                    retried = true;
                    return await RetriedAsync(s, old, refreshToken, resource, now, token);
                }

                if (now >= old.ExpiresAt) return TokenResult.Failure("invalid_grant", InvalidRefresh);
                OAuthGrant grant;
                SealedKomodoKey komodoKey;
                try
                {
                    grant = OpenGrant(refreshToken, old);
                    komodoKey = OpenKomodo(refreshToken, old);
                }
                catch (Exception e) when (e is CryptographicException or JsonException)
                {
                    log.LogWarning("The grant of OAuth refresh token {TokenId} does not open", old.Id);
                    return TokenResult.Failure("invalid_grant", InvalidRefresh);
                }

                if (Unusable(grant, resource, now) is { } refused) return refused;
                if (await LiveAsync(s, old, komodoKey.Key, now, token) is null) return TokenResult.Failure("invalid_grant", ConnectionGone);

                var connectionExpiresAt = grant.ConnectionExpiresAt;
                var accessExpiresAt = AccessExpiry(now, connectionExpiresAt);
                var kept = new KeptPair(access, refresh, accessExpiresAt, ScopeOf(grant.ReadOnly));

                // Spent now, only if still unused: a parallel refresh that got here first makes this one conflict and
                // retry, and the retry takes the used branch above and gets that refresh's pair.
                var spent = await Docs.UpdateOneAsync(
                    s,
                    d => d.Id == old.Id && d.UsedAt == null && d.RevokedAt == null,
                    Builders<OAuthTokenDocument>.Update
                        .Set(d => d.UsedAt, now)
                        .Set(d => d.PurgeAt, now + UsedRetention)
                        .Set(d => d.Successor, SealKept(refreshToken, old.Id, kept))
                        .Unset(d => d.Grant)
                        .Unset(d => d.Sealed),
                    cancellationToken: token);
                if (spent.ModifiedCount == 0) return null;

                await Docs.InsertManyAsync(
                    s,
                    [
                        Record(refreshId, OAuthTokenKinds.Refresh, refresh, old, grant with { ExpiresAt = connectionExpiresAt }, komodoKey, now, connectionExpiresAt, connectionExpiresAt),
                        Record(accessId, OAuthTokenKinds.Access, access, old, grant with { ExpiresAt = accessExpiresAt }, komodoKey, now, accessExpiresAt, accessExpiresAt + AccessRetention),
                    ],
                    cancellationToken: token);
                // The parent's kept pair is this token's: used now, a retry of the parent has nothing to get back.
                if (old.Parent is { } parent)
                    await Docs.UpdateOneAsync(s, d => d.Id == parent && d.Kind == OAuthTokenKinds.Refresh, Builders<OAuthTokenDocument>.Update.Unset(d => d.Successor), cancellationToken: token);
                // Written here too, so that this conflicts with any revocation of the connection's tokens, which write it.
                await ConnectionDocs.UpdateOneAsync(s, c => c.Id == old.ConnectionId, Wrapped, cancellationToken: token);

                return new TokenResult(new TokenPair(access, refresh, ExpiresIn(accessExpiresAt, now), kept.Scope), null, null);
            },
            cancellationToken: ct);

        // Under snapshot isolation a lost race conflicts rather than matching nothing; should it match nothing, it was
        // still lost, and the next attempt sees the winner's pair. Once only: a second miss is refused, not looped on.
        if (result is null)
        {
            return retry
                ? await RefreshAsync(refreshToken, clientId, resource, retry: false, ct)
                : Refused("refresh", found.ConnectionId, clientHost, "invalid_grant", InvalidRefresh);
        }

        if (reused) log.LogWarning("OAuth refresh token {TokenId} was presented again: the tokens of connection {ConnectionId} are revoked", found.Id, found.ConnectionId);
        return result.Pair is not null
            ? Logged(result, "refresh", found.ConnectionId, clientHost, retried ? "retried" : "issued")
            : Refused("refresh", found.ConnectionId, clientHost, result.Error!, result.Description!);
    }

    /// <summary>A retry of a refresh within the grace period: the pair it was rotated into, while that pair's refresh
    /// token is unused and live and its access token not revoked; else <c>invalid_grant</c>. The checks of a refresh
    /// apply to the new pair's grant (resource, expiries) and to the connection.</summary>
    private async Task<TokenResult> RetriedAsync(IClientSessionHandle s, OAuthTokenDocument old, string oldRefresh, string? resource, DateTime now, CancellationToken ct)
    {
        if (old.Successor is null) return TokenResult.Failure("invalid_grant", InvalidRefresh);
        KeptPair kept;
        try
        {
            kept = OpenKept(oldRefresh, old);
        }
        catch (Exception e) when (e is CryptographicException or JsonException)
        {
            log.LogWarning("The kept pair of OAuth refresh token {TokenId} does not open", old.Id);
            return TokenResult.Failure("invalid_grant", InvalidRefresh);
        }

        var refreshLookup = Lookup(kept.Refresh);
        var accessLookup = Lookup(kept.Access);
        var next = await Docs.Find(s, d => d.Lookup == refreshLookup).FirstOrDefaultAsync(ct);
        var nextAccess = await Docs.Find(s, d => d.Lookup == accessLookup).FirstOrDefaultAsync(ct);
        if (next is null || next.Kind != OAuthTokenKinds.Refresh || next.Parent != old.Id || next.UsedAt is not null || next.RevokedAt is not null || now >= next.ExpiresAt
            || nextAccess is null || nextAccess.Kind != OAuthTokenKinds.Access || nextAccess.RevokedAt is not null || !(now < kept.AccessExpiresAt))
        {
            return TokenResult.Failure("invalid_grant", InvalidRefresh);
        }

        OAuthGrant grant;
        SealedKomodoKey komodoKey;
        try
        {
            grant = OpenGrant(kept.Refresh, next);
            komodoKey = OpenKomodo(kept.Refresh, next);
        }
        catch (Exception e) when (e is CryptographicException or JsonException)
        {
            log.LogWarning("The grant of OAuth refresh token {TokenId} does not open", next.Id);
            return TokenResult.Failure("invalid_grant", InvalidRefresh);
        }

        if (Unusable(grant, resource, now) is { } refused) return refused;
        if (await LiveAsync(s, old, komodoKey.Key, now, ct) is null) return TokenResult.Failure("invalid_grant", ConnectionGone);
        return new TokenResult(new TokenPair(kept.Access, kept.Refresh, ExpiresIn(kept.AccessExpiresAt, now), kept.Scope), null, null);
    }

    /// <summary>A refresh token's grant can't be used now: expired (as sealed), its connection expired (as sealed), or a
    /// sent <c>resource</c> that isn't its connection's URL (canonically).</summary>
    private static TokenResult? Unusable(OAuthGrant grant, string? resource, DateTime now)
    {
        if (now >= grant.ExpiresAt || now >= grant.ConnectionExpiresAt) return TokenResult.Failure("invalid_grant", InvalidRefresh);
        if (resource is not null && OAuthUrls.Canonical(resource) != OAuthUrls.Canonical(grant.Resource))
            return TokenResult.Failure("invalid_target", "The resource is not the connection this refresh token was issued for.");
        return null;
    }

    /// <summary>
    /// The write every issuing transaction makes on the connection's document: a counter, so that it always changes the
    /// document. MongoDB writes nothing for an update that changes nothing (an <c>$unset</c> of absent fields), and such
    /// an update conflicts with nothing, so a revocation under way would not stop tokens being issued.
    /// </summary>
    private static UpdateDefinition<ConnectionDocument> Wrapped => Builders<ConnectionDocument>.Update.Inc(c => c.Wraps, 1);

    /// <summary>The token's connection if it is live and <paramref name="komodoKey"/> is still its Komodo key, read in the
    /// transaction; else null.</summary>
    private async Task<ConnectionDocument?> LiveAsync(IClientSessionHandle s, OAuthTokenDocument record, string komodoKey, DateTime now, CancellationToken ct)
    {
        var connection = await ConnectionDocs.Find(s, c => c.Id == record.ConnectionId).FirstOrDefaultAsync(ct);
        return connection is not null && IsLive(connection, record.User, now) && connection.KomodoKey == komodoKey ? connection : null;
    }

    /// <summary>The connection has a refresh token that is neither used nor revoked: a family issued after any tombstone
    /// of it, since every revocation and every new family turns all earlier records into tombstones.</summary>
    private Task<bool> LiveFamilyAsync(IClientSessionHandle s, string connectionId, CancellationToken ct) =>
        Docs.Find(s, d => d.ConnectionId == connectionId && d.Kind == OAuthTokenKinds.Refresh && d.UsedAt == null && d.RevokedAt == null).AnyAsync(ct);

    /// <summary>
    /// Every token of the connection is revoked for <paramref name="reason"/>, inside the caller's transaction. Nobody
    /// holds the Komodo key's secret any more, so the key is queued for deletion with the owner's next JWT (spec §5).
    /// </summary>
    private async Task RevokeFamilyAsync(IClientSessionHandle s, string connectionId, string reason, DateTime now, CancellationToken ct)
    {
        await ConnectionRevocation.RevokeTokensAsync(db, s, connectionId, reason, now, ct);
        var connection = await ConnectionDocs.Find(s, c => c.Id == connectionId).FirstOrDefaultAsync(ct);
        if (connection?.KomodoKey is { } komodoKey) await pending.AddAsync(s, connection.User, komodoKey, reason, ct);
    }

    /// <summary>
    /// Revocation by the client (RFC 7009), whatever the result: a refresh token, used or not, revokes all of its
    /// connection's tokens (<see cref="ConnectionReasons.ClientRevoked"/>), so the connection needs a reconnect; an
    /// access token becomes a tombstone, the refresh token stays; anything else, a code, a revoked token or a string that
    /// is no token, changes nothing. Holding the token is the proof: clients are public, their id is no secret.
    /// </summary>
    public async Task RevokeAsync(string token, CancellationToken ct)
    {
        var kind = Secrets.IsWellFormed(token, RefreshPrefix) ? OAuthTokenKinds.Refresh : Secrets.IsWellFormed(token, AccessPrefix) ? OAuthTokenKinds.Access : null;
        if (kind is null) return;
        await EnsureReadyAsync(ct);
        var lookup = Lookup(token);
        var found = await Docs.Find(d => d.Lookup == lookup).FirstOrDefaultAsync(ct);
        if (found is null || found.Kind != kind || found.RevokedAt is not null) return;
        // For the log only; resolved before the transaction, so that nothing can fail between its commit and the answer.
        var clientHost = await clients.HostAsync(found.ClientId, ct);

        using var session = await db.Client.StartSessionAsync(cancellationToken: ct);
        var revoked = await session.WithTransactionAsync(
            async (s, t) =>
            {
                var current = await Docs.Find(s, d => d.Id == found.Id).FirstOrDefaultAsync(t);
                if (current is null || current.RevokedAt is not null) return false;
                if (kind == OAuthTokenKinds.Refresh) await RevokeFamilyAsync(s, current.ConnectionId, ConnectionReasons.ClientRevoked, Now, t);
                else await ConnectionRevocation.TombstoneAsync(db, s, Builders<BsonDocument>.Filter.Eq("_id", current.Id), Now, t);
                return true;
            },
            cancellationToken: ct);

        if (revoked)
        {
            OAuthEndpoints.LogStep(log, "revoke", kind == OAuthTokenKinds.Refresh ? ConnectionReasons.ClientRevoked : "access_revoked", found.ConnectionId, clientHost, null);
        }
    }

    /// <summary>
    /// The connection an access token presented on <c>/mcp/c/{connectionId}</c> opens (spec §5): a record of kind
    /// <c>access</c> with its lookup, unexpired (checked here; the TTL index only tidies up), of exactly this connection,
    /// its grant and Komodo key opening with the token, the grant bound to <paramref name="resource"/> (canonically
    /// equal), the connection neither revoked nor expired and its Komodo key still the token's. Writes the connection's
    /// <c>lastUsedAt</c> at most once a minute. Never calls Komodo, never logs anything of the token.
    /// </summary>
    public async Task<AccessResolution> ResolveAccessAsync(string presented, string connectionId, string resource, CancellationToken ct)
    {
        if (!Secrets.IsWellFormed(presented, AccessPrefix)) return new(null, false);
        await EnsureReadyAsync(ct);
        var lookup = Lookup(presented);
        var record = await Docs.Find(d => d.Lookup == lookup).FirstOrDefaultAsync(ct);
        if (record is null) return new(null, false);
        var known = new AccessResolution(null, true);
        var now = Now;
        // A tombstone (revoked) is known too: refused, but not counted as a wrong key.
        if (record.RevokedAt is not null || record.Kind != OAuthTokenKinds.Access || record.ConnectionId != connectionId || !(now < record.ExpiresAt)) return known;

        OAuthGrant grant;
        SealedKomodoKey komodoKey;
        try
        {
            grant = OpenGrant(presented, record);
            komodoKey = OpenKomodo(presented, record);
        }
        catch (Exception e) when (e is CryptographicException or JsonException)
        {
            log.LogWarning("The grant of OAuth access token {TokenId} does not open", record.Id);
            return known;
        }

        // The expiry sealed into the grant, not only the record's: a changed expiresAt in the database extends nothing.
        if (!(now < grant.ExpiresAt) || OAuthUrls.Canonical(grant.Resource) != OAuthUrls.Canonical(resource) || now >= grant.ConnectionExpiresAt) return known;
        var connection = await ConnectionDocs.Find(c => c.Id == connectionId).FirstOrDefaultAsync(ct);
        if (connection is null || !IsLive(connection, record.User, now) || connection.KomodoKey != komodoKey.Key) return known;

        if (connection.LastUsedAt is not { } lastUsed || now - lastUsed >= LastUsedGranularity)
        {
            // Conditional, so of concurrent requests only one writes.
            var stale = now - LastUsedGranularity;
            await ConnectionDocs.UpdateOneAsync(
                c => c.Id == connectionId && (c.LastUsedAt == null || c.LastUsedAt <= stale),
                Builders<ConnectionDocument>.Update.Set(c => c.LastUsedAt, CredentialRules.Milliseconds(now)),
                cancellationToken: ct);
        }

        return new(
            new ResolvedConnection(
                new KomodoUser(connection.User, connection.Username), connectionId, grant.Name, grant.ClientName, grant.ReadOnly,
                new KomodoAuth.Key(komodoKey.Key, komodoKey.Secret), grant.ConnectionExpiresAt),
            true);
    }

    /// <summary>A failure, logged as <paramref name="step"/> (<c>token</c> for a code exchange, <c>refresh</c>).</summary>
    private TokenResult Refused(string step, string? connectionId, string? clientHost, string error, string description) =>
        Logged(TokenResult.Failure(error, description), step, connectionId, clientHost, error);

    private TokenResult Logged(TokenResult result, string step, string? connectionId, string? clientHost, string outcome)
    {
        OAuthEndpoints.LogStep(log, step, outcome, connectionId, clientHost, null);
        return result;
    }

    /// <summary>A token's record, issued from <paramref name="parent"/> (the code, or the refresh token it rotates).</summary>
    private static OAuthTokenDocument Record(
        string id, string kind, string token, OAuthTokenDocument parent, OAuthGrant grant, SealedKomodoKey komodoKey, DateTime now, DateTime? expiresAt, DateTime? purgeAt) => new()
        {
            Id = id,
            Kind = kind,
            ConnectionId = parent.ConnectionId,
            User = parent.User,
            ClientId = parent.ClientId,
            Lookup = Lookup(token),
            Grant = SealGrant(token, id, kind, grant),
            Sealed = SealKomodo(token, id, kind, komodoKey),
            Parent = parent.Id,
            CreatedAt = now,
            ExpiresAt = expiresAt,
            PurgeAt = purgeAt,
        };

    /// <summary>An access token lives <see cref="AccessLifetime"/>, never past the connection's expiry; whole milliseconds,
    /// as MongoDB keeps them.</summary>
    private DateTime AccessExpiry(DateTime now, DateTime? connectionExpiresAt) =>
        CredentialRules.Milliseconds(connectionExpiresAt is { } c && c < now + AccessLifetime ? c : now + AccessLifetime);

    private static int ExpiresIn(DateTime expiresAt, DateTime now) => (int)Math.Ceiling((expiresAt - now).TotalSeconds);

    /// <summary><c>komodo:read</c> for a read-only grant, else both scopes.</summary>
    private static string ScopeOf(bool readOnly) => readOnly ? OAuthScopes.Read : OAuthScopes.Challenge;

    /// <summary>The pair a refresh token was rotated into, sealed under a key derived from that (old) token and bound to
    /// its record, so only its holder opens it and it can't be moved to another record.</summary>
    private static byte[] SealKept(string oldRefresh, string oldId, KeptPair kept) =>
        Sealing.Seal(Sealing.Derive(oldRefresh, SuccessorLabel), JsonSerializer.SerializeToUtf8Bytes(kept), SuccessorContext(oldId));

    private static KeptPair OpenKept(string oldRefresh, OAuthTokenDocument old) =>
        JsonSerializer.Deserialize<KeptPair>(Sealing.Open(Sealing.Derive(oldRefresh, SuccessorLabel), old.Successor!, SuccessorContext(old.Id)))
        ?? throw new JsonException("empty pair");

    private static string SuccessorContext(string oldId) => $"oauth:{oldId}:successor";

    /// <summary>RFC 7636 S256: <c>BASE64URL(SHA256(ASCII(verifier))) == challenge</c>, in fixed time.</summary>
    private static bool PkceMatches(string verifier, string? challenge)
    {
        if (challenge is null) return false;
        var computed = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(computed), Encoding.ASCII.GetBytes(challenge));
    }

    /// <summary>The user's own connection, neither revoked nor expired.</summary>
    private static bool IsLive(ConnectionDocument doc, string userId, DateTime now) => doc.User == userId && doc.RevokedAt is null && !(now >= doc.ExpiresAt);

    /// <summary>16 random bytes in hex, as API key ids.</summary>
    private static string NewTokenId() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

    /// <summary>Finds a token's record without storing the token; HKDF suffices, as the token is random.</summary>
    internal static byte[] Lookup(string token) => Sealing.Lookup(token, LookupLabel);

    private static byte[] SealGrant(string token, string tokenId, string kind, OAuthGrant grant) =>
        Sealing.Seal(Sealing.Derive(token, GrantLabel), JsonSerializer.SerializeToUtf8Bytes(grant), GrantContext(tokenId, kind));

    /// <summary>The grant of a record, opened with its token; <see cref="CryptographicException"/> or <see cref="JsonException"/> if it doesn't open.</summary>
    private static OAuthGrant OpenGrant(string token, OAuthTokenDocument record) =>
        JsonSerializer.Deserialize<OAuthGrant>(Sealing.Open(Sealing.Derive(token, GrantLabel), record.Grant ?? [], GrantContext(record.Id, record.Kind)))
        ?? throw new JsonException("empty grant");

    private static byte[] SealKomodo(string token, string tokenId, string kind, SealedKomodoKey key) =>
        Sealing.Seal(Sealing.Derive(token, KomodoLabel), JsonSerializer.SerializeToUtf8Bytes(key), KomodoContext(tokenId, kind));

    private static SealedKomodoKey OpenKomodo(string token, OAuthTokenDocument record) =>
        JsonSerializer.Deserialize<SealedKomodoKey>(Sealing.Open(Sealing.Derive(token, KomodoLabel), record.Sealed ?? [], KomodoContext(record.Id, record.Kind)))
        ?? throw new JsonException("empty key");

    /// <summary>Bound to the record's id and kind: a grant can't be moved to another record, nor a code's read as a token's.</summary>
    private static string GrantContext(string tokenId, string kind) => $"oauth:{tokenId}:{kind}";

    private static string KomodoContext(string tokenId, string kind) => $"oauth:{tokenId}:{kind}:komodo";

    /// <summary>Creates the indexes once per process, outside any transaction (those of the collections the
    /// transactions here write too); lazy, so the server starts before MongoDB is reachable.</summary>
    private async Task EnsureReadyAsync(CancellationToken ct)
    {
        if (_ready) return;
        var keys = Builders<OAuthTokenDocument>.IndexKeys;
        await Docs.Indexes.CreateManyAsync(
            [
                new CreateIndexModel<OAuthTokenDocument>(keys.Ascending(d => d.Lookup), new CreateIndexOptions { Unique = true }),
                // A connection's revocation finds its tokens by the connection, and so does a reuse of a revoked refresh token.
                new CreateIndexModel<OAuthTokenDocument>(keys.Ascending(d => d.ConnectionId)),
                // Records go some time after their token expired, was used or was revoked, so that a reuse is recognised.
                new CreateIndexModel<OAuthTokenDocument>(keys.Ascending(d => d.PurgeAt), new CreateIndexOptions { ExpireAfter = TimeSpan.Zero }),
            ],
            ct);
        await connections.EnsureReadyAsync(ct);
        await pending.EnsureReadyAsync(ct);
        _ready = true;
    }

    /// <summary>What a token's grant seals under the token: the connection's name, the resource it is bound to, the
    /// connection's expiry and the code's or token's own (null for a refresh token of a connection that doesn't
    /// expire), whether it is read-only and the client's name, so a request with the token knows them and a changed
    /// expiry in the database extends nothing.</summary>
    internal sealed record OAuthGrant(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("resource")] string Resource,
        [property: JsonPropertyName("connectionExpiresAt")] DateTime? ConnectionExpiresAt,
        [property: JsonPropertyName("expiresAt")] DateTime? ExpiresAt,
        [property: JsonPropertyName("readOnly")] bool ReadOnly,
        [property: JsonPropertyName("clientName")] string? ClientName);

    /// <summary>What is sealed under each code and token: the connection's Komodo key and its secret.</summary>
    internal sealed record SealedKomodoKey(
        [property: JsonPropertyName("key")] string Key,
        [property: JsonPropertyName("secret")] string Secret)
    {
        public override string ToString() => $"SealedKomodoKey {{ Key = {Key} }}";
    }

    /// <summary>What a used refresh token's record keeps sealed for a retry: the pair it was rotated into, the access
    /// token's expiry and the scope. Not logged: <see cref="ToString"/> hides the tokens.</summary>
    internal sealed record KeptPair(
        [property: JsonPropertyName("access")] string Access,
        [property: JsonPropertyName("refresh")] string Refresh,
        [property: JsonPropertyName("accessExpiresAt")] DateTime AccessExpiresAt,
        [property: JsonPropertyName("scope")] string Scope)
    {
        public override string ToString() => $"KeptPair {{ AccessExpiresAt = {AccessExpiresAt:u}, Scope = {Scope} }}";
    }
}

/// <summary>
/// A code or token of a connection (collection <c>oauth_tokens</c>). Never the token itself: <see cref="Lookup"/> is
/// derived from it, and <see cref="Grant"/> and <see cref="Sealed"/> are sealed under keys derived from it. In the
/// clear: whose, for which connection and client, the PKCE challenge and redirect URI a code is bound to, and the times.
/// </summary>
[BsonIgnoreExtraElements]
public sealed class OAuthTokenDocument
{
    /// <summary>16 random bytes in hex.</summary>
    [BsonId]
    public string Id { get; set; } = "";

    /// <summary><see cref="OAuthTokenKinds"/>: <c>code</c>, <c>access</c> or <c>refresh</c>.</summary>
    [BsonElement("kind")]
    public string Kind { get; set; } = "";

    [BsonElement("connection")]
    public string ConnectionId { get; set; } = "";

    [BsonElement("user")]
    public string User { get; set; } = "";

    [BsonElement("client")]
    public string ClientId { get; set; } = "";

    /// <summary><c>HKDF(token, "kgt/v1/oauth-token/lookup")</c>, unique.</summary>
    [BsonElement("lookup")]
    public byte[] Lookup { get; set; } = [];

    /// <summary>Name, resource, expiries, read-only and client, sealed under <c>HKDF(token, "kgt/v1/oauth-grant")</c>;
    /// gone once the code or refresh token is spent, and from a tombstone.</summary>
    [BsonElement("grant"), BsonIgnoreIfNull]
    public byte[]? Grant { get; set; }

    /// <summary>The connection's Komodo key and secret, sealed under <c>HKDF(token, "kgt/v1/oauth-komodo")</c> with the
    /// associated data <c>oauth:{id}:{kind}:komodo</c>; gone with the grant.</summary>
    [BsonElement("sealed"), BsonIgnoreIfNull]
    public byte[]? Sealed { get; set; }

    /// <summary>Codes only: the redirect URI the exchange must name again, exactly.</summary>
    [BsonElement("redirectUri"), BsonIgnoreIfNull]
    public string? RedirectUri { get; set; }

    /// <summary>Codes only: <c>BASE64URL(SHA256(code_verifier))</c> as the app sent it (S256 only).</summary>
    [BsonElement("codeChallenge"), BsonIgnoreIfNull]
    public string? CodeChallenge { get; set; }

    /// <summary>Codes only: the grant is limited to the read tools (also sealed into the grant, which decides).</summary>
    [BsonElement("readOnly"), BsonIgnoreIfNull]
    public bool? ReadOnly { get; set; }

    /// <summary>The id of the record this one was issued from (a code for the first pair, a refresh token for the next).</summary>
    [BsonElement("parent"), BsonIgnoreIfNull]
    public string? Parent { get; set; }

    [BsonElement("createdAt")]
    public DateTime CreatedAt { get; set; }

    /// <summary>Expiry, checked in code; null for a refresh token of a connection that doesn't expire.</summary>
    [BsonElement("expiresAt"), BsonIgnoreIfNull]
    public DateTime? ExpiresAt { get; set; }

    /// <summary>A tombstone: when its connection's tokens were revoked or replaced. Its lookup stays, so it is still
    /// recognised, but it has no grant and no Komodo key (<see cref="ConnectionRevocation.TombstoneAsync"/>).</summary>
    [BsonElement("revokedAt"), BsonIgnoreIfNull]
    public DateTime? RevokedAt { get; set; }

    /// <summary>Codes and refresh tokens: when it was spent. A second use is a reuse.</summary>
    [BsonElement("usedAt"), BsonIgnoreIfNull]
    public DateTime? UsedAt { get; set; }

    /// <summary>Codes: the id of the refresh token they issued (a reuse then revokes the connection's tokens).</summary>
    [BsonElement("issued"), BsonIgnoreIfNull]
    public string? Issued { get; set; }

    /// <summary>Refresh tokens, once used: the pair they were rotated into, sealed under
    /// <c>HKDF(token, "kgt/v1/oauth-successor")</c> with the associated data <c>oauth:{id}:successor</c>, so that only
    /// the old token's holder gets it back, on a retry within <see cref="OAuthTokens.GracePeriod"/>. Unset once that
    /// pair's refresh token is used in turn, and by a revocation.</summary>
    [BsonElement("successor"), BsonIgnoreIfNull]
    public byte[]? Successor { get; set; }

    /// <summary>When MongoDB's TTL index removes the record.</summary>
    [BsonElement("purgeAt"), BsonIgnoreIfNull]
    public DateTime? PurgeAt { get; set; }
}
