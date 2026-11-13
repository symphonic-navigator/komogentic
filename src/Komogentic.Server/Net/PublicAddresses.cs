// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using System.Net.Sockets;

namespace Komogentic.Server.Net;

/// <summary>A connection attempt found no acceptable address for the host.</summary>
internal sealed class NotPublicAddressException : IOException
{
    public NotPublicAddressException() : base("The host resolves to no public address.")
    {
    }
}

/// <summary>The checks for every client that fetches from an address a stranger may choose (OAuth client metadata
/// documents): only unicast addresses on the public internet, resolved and checked by the connection itself.</summary>
internal static class PublicAddresses
{
    internal static bool AddressAllowed(IPAddress address, bool allowLoopback) =>
        IsPublicAddress(address) || (allowLoopback && IPAddress.IsLoopback(address));

    /// <summary>Resolves the host itself and connects to the first acceptable address, so the address that was checked is the
    /// one that is used.</summary>
    internal static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, bool allowLoopback, CancellationToken ct)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, ct);
        var address = addresses.FirstOrDefault(a => AddressAllowed(a, allowLoopback)) ?? throw new NotPublicAddressException();
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>False for every address that is not a unicast address on the public internet.</summary>
    internal static bool IsPublicAddress(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork) return IsPublicV4(address.GetAddressBytes());
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return false;

        var b = address.GetAddressBytes();
        // IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d) and NAT64 (64:ff9b::a.b.c.d) forms are judged by the IPv4 address inside.
        if (address.IsIPv4MappedToIPv6) return IsPublicV4(b[12..]);
        if (b[..12].All(x => x == 0)) return b[12..].Any(x => x != 0) && !(b[12] == 0 && b[13] == 0 && b[14] == 0 && b[15] <= 1) && IsPublicV4(b[12..]);
        if (b[0] == 0 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b[4..12].All(x => x == 0)) return IsPublicV4(b[12..]);
        // SIIT (::ffff:0:a.b.c.d) and 6to4 (2002:a.b.c.d::) carry an IPv4 address too.
        if (b[..8].All(x => x == 0) && b[8] == 0xff && b[9] == 0xff && b[10] == 0 && b[11] == 0) return IsPublicV4(b[12..]);
        if (b[0] == 0x20 && b[1] == 0x02) return IsPublicV4(b[2..6]);
        // Teredo (2001::/32) tunnels through arbitrary relays and local-use NAT64 (64:ff9b:1::/48) is for the local network: refused outright.
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0 && b[3] == 0) return false;
        if (b[0] == 0 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b[4] == 0 && b[5] == 1) return false;

        if (address.IsIPv6Multicast || address.IsIPv6LinkLocal || address.IsIPv6SiteLocal) return false;
        if ((b[0] & 0xfe) == 0xfc) return false; // fc00::/7 unique local
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return false; // 2001:db8::/32 documentation
        return true;
    }

    private static bool IsPublicV4(ReadOnlySpan<byte> b) => !(
        b[0] == 0                                         // 0.0.0.0/8
        || b[0] == 10                                     // 10/8
        || (b[0] == 100 && (b[1] & 0xc0) == 64)           // 100.64/10 carrier-grade NAT
        || b[0] == 127                                    // loopback
        || (b[0] == 169 && b[1] == 254)                   // link-local
        || (b[0] == 172 && (b[1] & 0xf0) == 16)           // 172.16/12
        || (b[0] == 192 && b[1] == 0 && b[2] is 0 or 2)   // 192.0.0/24, 192.0.2/24
        || (b[0] == 192 && b[1] == 168)                   // 192.168/16
        || (b[0] == 198 && (b[1] & 0xfe) == 18)           // 198.18/15 benchmarking
        || (b[0] == 198 && b[1] == 51 && b[2] == 100)     // 198.51.100/24
        || (b[0] == 203 && b[1] == 0 && b[2] == 113)      // 203.0.113/24
        || b[0] >= 224);                                  // multicast, reserved, broadcast
}
