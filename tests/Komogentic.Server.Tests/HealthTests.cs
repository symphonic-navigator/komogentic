// SPDX-License-Identifier: AGPL-3.0-or-later
namespace Komogentic.Server.Tests;

[Collection("app")]
public sealed class HealthTests(AppFactory app)
{
    [Fact]
    public async Task Healthz_answers_ok()
    {
        var response = await app.CreateClient().GetAsync("/healthz", TestContext.Current.CancellationToken);

        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("ok", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
}
