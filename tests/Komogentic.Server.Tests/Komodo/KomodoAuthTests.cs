// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Text.Json;
using Komogentic.Server.Accounts;
using Komogentic.Server.Komodo;

namespace Komogentic.Server.Tests.Komodo;

/// <summary>A Komodo secret never ends up in a JSON dump of what holds it.</summary>
public sealed class KomodoAuthTests
{
    private const string Secret = "S_not_to_be_serialised_S";

    [Fact]
    public void Key_secret_is_not_serialised()
    {
        var key = new KomodoAuth.Key("K_key_K", Secret);
        var resolved = new ResolvedApiKey("id", new KomodoUser("u-anna", "anna"), "Hermes", key, null);

        Assert.DoesNotContain(Secret, JsonSerializer.Serialize(key), StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, JsonSerializer.Serialize(resolved), StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, JsonSerializer.Serialize(key, KomodoClient.Json), StringComparison.Ordinal);
        Assert.Contains("K_key_K", JsonSerializer.Serialize(key), StringComparison.Ordinal);
    }
}
