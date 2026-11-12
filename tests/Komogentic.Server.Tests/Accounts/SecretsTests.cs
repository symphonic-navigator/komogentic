// SPDX-License-Identifier: AGPL-3.0-or-later
using Komogentic.Server.Accounts;

namespace Komogentic.Server.Tests.Accounts;

public sealed class SecretsTests
{
    [Fact]
    public void New_has_the_prefix_and_43_base62_characters()
    {
        var secret = Secrets.New("kgt_at_");

        Assert.StartsWith("kgt_at_", secret);
        Assert.Equal("kgt_at_".Length + 43, secret.Length);
        Assert.Matches("^kgt_at_[0-9A-Za-z]{43}$", secret);
        Assert.NotEqual(secret, Secrets.New("kgt_at_"));
    }

    [Fact]
    public void IsWellFormed_refuses_wrong_length_prefix_and_alphabet()
    {
        var secret = Secrets.New("kgt_");

        Assert.True(Secrets.IsWellFormed(secret, "kgt_"));
        Assert.False(Secrets.IsWellFormed(secret[..^1], "kgt_"));
        Assert.False(Secrets.IsWellFormed(secret + "A", "kgt_"));
        Assert.False(Secrets.IsWellFormed("kgx_" + secret[4..], "kgt_"));
        Assert.False(Secrets.IsWellFormed(secret[..^1] + "-", "kgt_"));
        // An access token is not an API key, although both start with kgt_.
        Assert.False(Secrets.IsWellFormed(Secrets.New("kgt_at_"), "kgt_"));
    }
}
