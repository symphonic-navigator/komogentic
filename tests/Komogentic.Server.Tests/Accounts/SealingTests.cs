// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Security.Cryptography;
using System.Text;
using Komogentic.Server.Accounts;

namespace Komogentic.Server.Tests.Accounts;

public sealed class SealingTests
{
    private static readonly byte[] Plain = Encoding.UTF8.GetBytes("S_secret_S");

    [Fact]
    public void Seal_then_open_round_trips()
    {
        var key = Sealing.Derive("kgt_token", "kgt/v1/test");
        var sealedBytes = Sealing.Seal(key, Plain, "test:1");

        Assert.Equal(Plain, Sealing.Open(key, sealedBytes, "test:1"));
        Assert.Equal(12 + Plain.Length + 16, sealedBytes.Length);
    }

    [Fact]
    public void Open_with_another_context_throws()
    {
        var key = Sealing.Derive("kgt_token", "kgt/v1/test");
        var sealedBytes = Sealing.Seal(key, Plain, "test:1");

        Assert.ThrowsAny<CryptographicException>(() => Sealing.Open(key, sealedBytes, "test:2"));
    }

    [Fact]
    public void Open_with_another_key_throws()
    {
        var sealedBytes = Sealing.Seal(Sealing.Derive("kgt_token", "kgt/v1/test"), Plain, "test:1");

        Assert.ThrowsAny<CryptographicException>(() => Sealing.Open(Sealing.Derive("kgt_other", "kgt/v1/test"), sealedBytes, "test:1"));
    }

    [Fact]
    public void Tampered_ciphertext_throws()
    {
        var key = Sealing.Derive("kgt_token", "kgt/v1/test");
        var sealedBytes = Sealing.Seal(key, Plain, "test:1");
        sealedBytes[14] ^= 1;

        Assert.ThrowsAny<CryptographicException>(() => Sealing.Open(key, sealedBytes, "test:1"));
    }

    [Fact]
    public void Lookup_is_deterministic_and_differs_by_label()
    {
        Assert.Equal(Sealing.Lookup("kgt_token", "kgt/v1/a"), Sealing.Lookup("kgt_token", "kgt/v1/a"));
        Assert.NotEqual(Sealing.Lookup("kgt_token", "kgt/v1/a"), Sealing.Lookup("kgt_token", "kgt/v1/b"));
        Assert.NotEqual(Sealing.Lookup("kgt_token", "kgt/v1/a"), Sealing.Derive("kgt_token", "kgt/v1/a"));
    }
}
