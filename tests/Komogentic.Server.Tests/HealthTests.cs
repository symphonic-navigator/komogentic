// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using Komogentic.Server.Tests.Api;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Komogentic.Server.Tests;

[Collection("app")]
public sealed class HealthTests(AppFactory app)
{
    private const string Index = "<!doctype html><title>Komogentic</title><div id=\"root\" data-test=\"spa-index\"></div>";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Healthz_answers_ok()
    {
        var response = await app.CreateClient().GetAsync("/healthz", Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("ok", await response.Content.ReadAsStringAsync(Ct));
    }

    /// <summary>The app with a web app build of the test's own in its web root (a real build lands in wwwroot).</summary>
    private static WebApplicationFactory<Program> WithWebApp(WebApplicationFactory<Program> api, out DirectoryInfo root)
    {
        var dir = Directory.CreateTempSubdirectory("komogentic-webroot-");
        File.WriteAllText(Path.Combine(dir.FullName, "index.html"), Index);
        Directory.CreateDirectory(Path.Combine(dir.FullName, "assets"));
        File.WriteAllText(Path.Combine(dir.FullName, "assets", "index-abc123.js"), "console.log('app');");
        root = dir;
        return api.WithWebHostBuilder(b => b.UseWebRoot(dir.FullName));
    }

    [Fact]
    public async Task Spa_fallback_serves_index_for_consent()
    {
        using var api = WithWebApp(app.PublicApi, out var root);
        try
        {
            foreach (var path in new[] { "/", "/consent?request=0123456789abcdef0123456789abcdef", "/consent?error=unknown_client", "/connections" })
            {
                using var response = await api.SendAsync(HttpMethod.Get, path, origin: null);
                Assert.True(response.StatusCode == HttpStatusCode.OK, $"{path}: {(int)response.StatusCode}");
                Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
                Assert.Equal(Index, await response.Content.ReadAsStringAsync(Ct));
                Assert.True(response.Headers.CacheControl?.NoCache, $"{path}: index.html must be revalidated");
            }

            using var asset = await api.SendAsync(HttpMethod.Get, "/assets/index-abc123.js", origin: null);
            Assert.Equal(HttpStatusCode.OK, asset.StatusCode);
            Assert.True(asset.Headers.CacheControl is { Public: true, MaxAge.TotalDays: 365 }, $"assets: {asset.Headers.CacheControl}");
            // A chunk of an older build is a plain 404, not the shell in its place.
            using var missing = await api.SendAsync(HttpMethod.Get, "/assets/index-old.js", origin: null);
            Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
            Assert.NotEqual(Index, await missing.Content.ReadAsStringAsync(Ct));
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Unknown_mcp_path_is_not_the_spa()
    {
        using var api = WithWebApp(app.PublicApi, out var root);
        try
        {
            var n = Guid.NewGuid().ToString("N")[..8];
            app.Komodo.AddUser($"u-anna-spa-{n}", $"anna-spa-{n}", "anna-komodo-password");
            var session = await api.SignInAsync($"anna-spa-{n}", "anna-komodo-password");
            using var created = await api.SendAsync(HttpMethod.Post, "/api/keys", new { name = "Hermes" }, session);
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
            var key = (await Dashboard.JsonAsync(created)).GetProperty("secret").GetString()!;

            foreach (var path in new[] { "/mcp/nope", "/mcp/nope/deeper", "/MCP/nope", "/mcp/c", "/mcp/c/", "/mcp/c/nope", "/api/nope" })
            {
                // Without a credential: refused, never the web app.
                using var anonymous = await api.SendAsync(HttpMethod.Get, path, origin: null);
                Assert.True(anonymous.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound, $"{path}: {(int)anonymous.StatusCode}");
                Assert.NotEqual(Index, await anonymous.Content.ReadAsStringAsync(Ct));
            }

            foreach (var path in new[] { "/mcp/nope", "/mcp/nope/deeper", "/MCP/nope" })
            {
                // With a valid key: the JSON 404, not index.html.
                using var request = Dashboard.Request(HttpMethod.Get, path, origin: null);
                request.Headers.Authorization = new("Bearer", key);
                using var response = await api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) })
                    .SendAsync(request, Ct);
                Assert.True(response.StatusCode == HttpStatusCode.NotFound, $"{path}: {(int)response.StatusCode}");
                Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
                Assert.Equal("Not found.", await Dashboard.ErrorAsync(response));
            }

            using var unknownApi = await api.SendAsync(HttpMethod.Get, "/api/nope", session: session, origin: null);
            Assert.Equal(HttpStatusCode.NotFound, unknownApi.StatusCode);
            Assert.Equal("Not found.", await Dashboard.ErrorAsync(unknownApi));
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }
}
