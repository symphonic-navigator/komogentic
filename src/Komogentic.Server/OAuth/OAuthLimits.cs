// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Threading.RateLimiting;
using Komogentic.Server.Auth;

namespace Komogentic.Server.OAuth;

/// <summary>
/// The OAuth endpoints' rate limits, in memory like <see cref="WrongKeyLimiter"/>: registrations per network,
/// metadata document fetches per address and per host, failed token requests per client id and network together.
/// Not per client id alone: anyone can name claude.ai's client id, and 20 bogus requests would then stop every real claude.ai exchange for a minute. Not per
/// network alone either: Anthropic's connectors all come from one egress range, so its users would share
/// one budget with every other client calling from there.
/// </summary>
public sealed class OAuthLimits : IDisposable
{
    public const int RegistrationsPerHour = 30;

    /// <summary>A client id longer than this is cut, so a caller can't fill the memory with long keys.</summary>
    public const int MaxClientIdKey = 256;

    /// <summary>
    /// Fetches of a client's metadata document that an anonymous <c>/oauth/authorize</c> starts, a minute per address
    /// and per host of the <c>client_id</c> URL: each is a request to an address a stranger picks. A document in the
    /// cache needs no fetch and isn't counted, so a known app keeps working while a host is held back.
    /// </summary>
    public const int MetadataFetchesPerAddress = 10;

    public const int MetadataFetchesPerHost = 10;

    private static readonly TimeSpan RegistrationWindow = TimeSpan.FromHours(1);

    private static readonly TimeSpan MetadataFetchWindow = TimeSpan.FromMinutes(1);

    private readonly PartitionedRateLimiter<string> _metadataFetchByAddress = MetadataFetchLimiter(MetadataFetchesPerAddress);

    private readonly PartitionedRateLimiter<string> _metadataFetchByHost = MetadataFetchLimiter(MetadataFetchesPerHost);

    // Every attempt counts, successful or not: registering is what costs a row.
    private readonly PartitionedRateLimiter<string> _registrations = PartitionedRateLimiter.Create<string, string>(partition =>
        RateLimitPartition.GetSlidingWindowLimiter(partition, _ => new SlidingWindowRateLimiterOptions
        {
            PermitLimit = RegistrationsPerHour,
            Window = RegistrationWindow,
            SegmentsPerWindow = 12,
            QueueLimit = 0,
            AutoReplenishment = true,
        }));

    // 20 failures a minute, with the reserve/fail/release protocol of wrong API keys: same budget, other key.
    private readonly WrongKeyLimiter _tokens = new();

    /// <summary>Null if this caller may register; else how long it has to wait.</summary>
    public TimeSpan? Registration(HttpContext http)
    {
        using var lease = _registrations.AttemptAcquire(WrongKeyLimiter.Partition(http.Connection.RemoteIpAddress));
        if (lease.IsAcquired) return null;
        return lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter) ? retryAfter : RegistrationWindow;
    }

    /// <summary>A fetch of a client's metadata document from <paramref name="host"/>: null if it may go ahead, else how
    /// long to wait. The address is asked first, so one over its own limit uses up nothing of the host's.</summary>
    public TimeSpan? MetadataFetch(HttpContext http, string host) =>
        Take(_metadataFetchByAddress, WrongKeyLimiter.Partition(http.Connection.RemoteIpAddress)) ?? Take(_metadataFetchByHost, host.ToLowerInvariant());

    /// <summary>Null if a token request for the client from this caller's network may be checked (a permit is then held
    /// until <see cref="TokenFailed"/> or <see cref="TokenRelease"/>); else how long to wait.</summary>
    public TimeSpan? TokenReserve(HttpContext http, string clientId) => _tokens.TryReserve(Key(http, clientId));

    public void TokenFailed(HttpContext http, string clientId) => _tokens.Failed(Key(http, clientId));

    public void TokenRelease(HttpContext http, string clientId) => _tokens.Release(Key(http, clientId));

    /// <summary>The network (<see cref="WrongKeyLimiter.Partition"/>, IPv6 per /64) and the client id, cut to <see cref="MaxClientIdKey"/>.</summary>
    private static string Key(HttpContext http, string clientId) =>
        WrongKeyLimiter.Partition(http.Connection.RemoteIpAddress) + " " + (clientId.Length <= MaxClientIdKey ? clientId : clientId[..MaxClientIdKey]);

    private static TimeSpan? Take(PartitionedRateLimiter<string> limiter, string key)
    {
        using var lease = limiter.AttemptAcquire(key);
        if (lease.IsAcquired) return null;
        return lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter) ? retryAfter : MetadataFetchWindow;
    }

    private static PartitionedRateLimiter<string> MetadataFetchLimiter(int permits) => PartitionedRateLimiter.Create<string, string>(key =>
        RateLimitPartition.GetSlidingWindowLimiter(key, _ => new SlidingWindowRateLimiterOptions
        {
            PermitLimit = permits,
            Window = MetadataFetchWindow,
            SegmentsPerWindow = 6,
            QueueLimit = 0,
            AutoReplenishment = true,
        }));

    public void Dispose()
    {
        _registrations.Dispose();
        _metadataFetchByAddress.Dispose();
        _metadataFetchByHost.Dispose();
        _tokens.Dispose();
    }
}
