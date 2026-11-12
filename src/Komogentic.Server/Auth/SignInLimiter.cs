// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Threading.RateLimiting;

namespace Komogentic.Server.Auth;

/// <summary>
/// Dashboard sign-ins, in memory (one instance): at most <see cref="PerUsername"/> a minute per username (case aside)
/// and <see cref="PerAddress"/> per client address. Every attempt counts, successful or not, so that Komogentic can't be
/// used to guess Komodo passwords. Komodo limits failures too (5 per 15 s per address by default), but it sees only
/// Komogentic's address, so its limit holds everyone back at once (amendment R2); these keep one guesser from reaching
/// it alone. Sliding windows, as in <see cref="WrongKeyLimiter"/>.
/// </summary>
public sealed class SignInLimiter : IDisposable
{
    public const int PerUsername = 3;

    public const int PerAddress = 5;

    public static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    /// <summary>A username longer than this is cut, so a caller can't fill the memory with long keys.</summary>
    private const int MaxUsernameKey = 64;

    private readonly PartitionedRateLimiter<string> _byUsername = Limiter(PerUsername);

    private readonly PartitionedRateLimiter<string> _byAddress = Limiter(PerAddress);

    /// <summary>Null if this attempt may go ahead; else how long to wait. The address is asked first, so an address
    /// over its own limit uses up nothing of the username's.</summary>
    public TimeSpan? Attempt(HttpContext http, string username) =>
        Take(_byAddress, WrongKeyLimiter.Partition(http.Connection.RemoteIpAddress)) ?? Take(_byUsername, UsernameKey(username));

    private static string UsernameKey(string username)
    {
        var key = username.ToLowerInvariant();
        return key.Length > MaxUsernameKey ? key[..MaxUsernameKey] : key;
    }

    private static TimeSpan? Take(PartitionedRateLimiter<string> limiter, string key)
    {
        using var lease = limiter.AttemptAcquire(key);
        if (lease.IsAcquired) return null;
        return lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter) ? retryAfter : Window;
    }

    private static PartitionedRateLimiter<string> Limiter(int permits) => PartitionedRateLimiter.Create<string, string>(key =>
        RateLimitPartition.GetSlidingWindowLimiter(key, _ => new SlidingWindowRateLimiterOptions
        {
            PermitLimit = permits,
            Window = Window,
            SegmentsPerWindow = 6,
            QueueLimit = 0,
            AutoReplenishment = true,
        }));

    public void Dispose()
    {
        _byUsername.Dispose();
        _byAddress.Dispose();
    }
}
