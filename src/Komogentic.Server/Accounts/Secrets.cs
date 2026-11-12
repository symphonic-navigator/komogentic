// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Numerics;
using System.Security.Cryptography;

namespace Komogentic.Server.Accounts;

/// <summary>
/// Bearer secrets: API keys, OAuth codes and tokens: a recognisable prefix and 32 random bytes in Base62,
/// 43 characters.
/// </summary>
internal static class Secrets
{
    private const int SecretBytes = 32;

    /// <summary>62^43 > 2^256 > 62^42: every 32 bytes fit in 43 digits.</summary>
    private const int Base62Length = 43;

    private const string Base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    public static string New(string prefix) => prefix + EncodeBase62(RandomNumberGenerator.GetBytes(SecretBytes));

    /// <summary>The shape of a secret from <see cref="New"/> with <paramref name="prefix"/>: checked before any lookup.</summary>
    public static bool IsWellFormed(string presented, string prefix) =>
        presented.Length == prefix.Length + Base62Length
        && presented.StartsWith(prefix, StringComparison.Ordinal)
        && presented.AsSpan(prefix.Length).IndexOfAnyExcept(Base62) < 0;

    private static string EncodeBase62(byte[] bytes)
    {
        var value = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        var digits = new char[Base62Length];
        for (var i = Base62Length - 1; i >= 0; i--)
        {
            value = BigInteger.DivRem(value, 62, out var digit);
            digits[i] = Base62[(int)digit];
        }

        return new string(digits);
    }
}
