// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using System.Net.Sockets;
using System.Threading.RateLimiting;

namespace Komogentic.Server.Auth;

/// <summary>
/// Dashboard sign-ins, in memory (one instance): at most <see cref="PerUsername"/> a minute per username (case aside),
/// and per client address at most <see cref="PerAddressShort"/> in <see cref="ShortWindow"/> and <see cref="PerAddress"/>
/// a minute. Every attempt counts, successful or not, so that Komogentic can't be used to guess Komodo passwords. Komodo
/// limits failures too (its local login refuses an address with 5 failures in 15 s, by default), but it sees only
/// Komogentic's address, so its limit holds everyone back at once (amendment R2); these keep one guesser from reaching it
/// alone: 4 in 15 s from one address never trip it. An IPv6 address counts by its /48 (<see cref="WrongKeyLimiter.Network"/>),
/// so that a guesser's many /64s count as one; IPv4 by the address. Sliding windows, as in <see cref="WrongKeyLimiter"/>.
/// </summary>
public sealed class SignInLimiter : IDisposable
{
    public const int PerUsername = 3;

    public const int PerAddress = 5;

    /// <summary>One fewer than the failures Komodo's local login takes from one address in <see cref="ShortWindow"/>.</summary>
    public const int PerAddressShort = 4;

    public static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    public static readonly TimeSpan ShortWindow = TimeSpan.FromSeconds(15);

    /// <summary>A username longer than this is cut, so a caller can't fill the memory with long keys.</summary>
    private const int MaxUsernameKey = 64;

    private readonly PartitionedRateLimiter<string> _byUsername = Limiter(PerUsername, Window);

    private readonly PartitionedRateLimiter<string> _byAddress = Limiter(PerAddress, Window);

    private readonly PartitionedRateLimiter<string> _byAddressShort = Limiter(PerAddressShort, ShortWindow);

    /// <summary>Null if this attempt may go ahead; else how long to wait. The address is asked first, its short window
    /// before its minute, so an attempt refused by one uses up nothing of those after it.</summary>
    public TimeSpan? Attempt(HttpContext http, string username)
    {
        var address = AddressKey(http.Connection.RemoteIpAddress);
        return Take(_byAddressShort, address, ShortWindow) ?? Take(_byAddress, address, Window) ?? Take(_byUsername, UsernameKey(username), Window);
    }

    /// <summary>IPv4 by the address (<see cref="WrongKeyLimiter.Partition"/>), IPv6 by its /48 (<see cref="WrongKeyLimiter.Network"/>).</summary>
    private static string AddressKey(IPAddress? address) =>
        address is { AddressFamily: AddressFamily.InterNetworkV6, IsIPv4MappedToIPv6: false } ? WrongKeyLimiter.Network(address) : WrongKeyLimiter.Partition(address);

    private static string UsernameKey(string username)
    {
        var key = username.ToLowerInvariant();
        return key.Length > MaxUsernameKey ? key[..MaxUsernameKey] : key;
    }

    private static TimeSpan? Take(PartitionedRateLimiter<string> limiter, string key, TimeSpan window)
    {
        using var lease = limiter.AttemptAcquire(key);
        if (lease.IsAcquired) return null;
        return lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter) ? retryAfter : window;
    }

    private static PartitionedRateLimiter<string> Limiter(int permits, TimeSpan window) => PartitionedRateLimiter.Create<string, string>(key =>
        RateLimitPartition.GetSlidingWindowLimiter(key, _ => new SlidingWindowRateLimiterOptions
        {
            PermitLimit = permits,
            Window = window,
            SegmentsPerWindow = 6,
            QueueLimit = 0,
            AutoReplenishment = true,
        }));

    public void Dispose()
    {
        _byUsername.Dispose();
        _byAddress.Dispose();
        _byAddressShort.Dispose();
    }
}
