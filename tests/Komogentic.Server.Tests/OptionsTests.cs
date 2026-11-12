// SPDX-License-Identifier: AGPL-3.0-or-later
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;

namespace Komogentic.Server.Tests;

[Collection("app")]
public sealed class OptionsTests(AppFactory app)
{
    [Fact]
    public void Missing_komodo_url_fails_start()
    {
        using var broken = app.WithWebHostBuilder(b => b.UseSetting("Komogentic:Komodo:Url", ""));

        var e = Assert.ThrowsAny<Exception>(() => broken.CreateClient());
        Assert.Contains("Komodo:Url", Unwrap(e).Message);
    }

    [Theory]
    [InlineData("4")]
    [InlineData("1441")]
    public void Access_token_minutes_out_of_range_fails_start(string minutes)
    {
        using var broken = app.WithWebHostBuilder(b => b.UseSetting("Komogentic:OAuth:AccessTokenMinutes", minutes));

        var e = Assert.ThrowsAny<Exception>(() => broken.CreateClient());
        Assert.Contains("AccessTokenMinutes", Unwrap(e).Message);
    }

    [Fact]
    public void Public_url_with_a_path_fails_start()
    {
        using var broken = app.WithWebHostBuilder(b => b.UseSetting("Komogentic:PublicUrl", "https://komogentic.example.org/app"));

        var e = Assert.ThrowsAny<Exception>(() => broken.CreateClient());
        Assert.Contains("PublicUrl", Unwrap(e).Message);
    }

    private static Exception Unwrap(Exception e)
    {
        for (var inner = e; inner is not null; inner = inner.InnerException)
            if (inner is OptionsValidationException) return inner;
        return e;
    }
}
