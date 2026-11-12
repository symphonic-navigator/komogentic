// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Komogentic.Server.Tests.Api;

/// <summary>What every answer carries, and what guards <c>/api</c> and <c>/mcp</c> before any endpoint runs.</summary>
[Collection("app")]
public sealed class SecurityTests(AppFactory app)
{
    private const string SignIn = "Sign in with your Komodo username and password.";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private WebApplicationFactory<Program> Api => app.PublicApi;

    private async Task<string> SessionAsync()
    {
        // Its own username, so the sign-in limit per username leaves the other tests alone.
        var name = "anna-" + Guid.NewGuid().ToString("N")[..8];
        app.Komodo.AddUser("u-" + name, name, "anna-komodo-password");
        return await Api.SignInAsync(name, "anna-komodo-password");
    }

    [Fact]
    public async Task Post_without_origin_is_403()
    {
        app.Komodo.AddUser("u-origin", "origin-user", "origin-password");
        var body = new { username = "origin-user", password = "origin-password" };
        var before = app.Komodo.Requests.Count;

        using var none = await Api.SendAsync(HttpMethod.Post, "/api/session", body, origin: null);
        using var other = await Api.SendAsync(HttpMethod.Post, "/api/session", body, origin: "https://elsewhere.example.org");

        Assert.Equal(HttpStatusCode.Forbidden, none.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, other.StatusCode);
        Assert.Null(Dashboard.SetCookie(none));
        Assert.Equal(before, app.Komodo.Requests.Count);

        // With a session too: a forged sign-out doesn't end it.
        var session = await SessionAsync();
        using var signOut = await Api.SendAsync(HttpMethod.Delete, "/api/session", session: session, origin: null);
        using var still = await Api.SendAsync(HttpMethod.Get, "/api/session", session: session);
        Assert.Equal(HttpStatusCode.Forbidden, signOut.StatusCode);
        Assert.Equal(HttpStatusCode.OK, still.StatusCode);
    }

    [Fact]
    public async Task Without_a_public_url_the_request_origin_counts()
    {
        using var local = app.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
        HttpRequestMessage Post(string origin)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/session") { Content = new StringContent("""{"username":"nobody","password":"x"}""", Encoding.UTF8, "application/json") };
            request.Headers.Add("Origin", origin);
            return request;
        }

        using var own = await local.SendAsync(Post($"{local.BaseAddress!.Scheme}://{local.BaseAddress.Authority}"), Ct);
        using var other = await local.SendAsync(Post(AppFactory.PublicUrl), Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, own.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, other.StatusCode);
    }

    [Fact]
    public async Task Unknown_api_path_is_json_404_after_sign_in()
    {
        var session = await SessionAsync();

        using var signedIn = await Api.SendAsync(HttpMethod.Get, "/api/no-such-thing", session: session);
        using var anonymous = await Api.SendAsync(HttpMethod.Get, "/api/no-such-thing");

        Assert.Equal(HttpStatusCode.NotFound, signedIn.StatusCode);
        Assert.Equal("application/json", signedIn.Content.Headers.ContentType?.MediaType);
        Assert.Equal("Not found.", await Dashboard.ErrorAsync(signedIn));
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }

    [Fact]
    public async Task Api_without_session_is_401()
    {
        foreach (var session in new string?[] { null, "not-a-session", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" })
        {
            using var response = await Api.SendAsync(HttpMethod.Get, "/api/session", session: session);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(SignIn, await Dashboard.ErrorAsync(response));
        }

        using var bearer = new HttpRequestMessage(HttpMethod.Get, "/api/session");
        bearer.Headers.Add("Authorization", "Bearer kgt_0123456789012345678901234567890123456789012");
        using var withBearer = await Api.CreateClient().SendAsync(bearer, Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, withBearer.StatusCode);

        using var signOut = await Api.SendAsync(HttpMethod.Delete, "/api/session");
        Assert.Equal(HttpStatusCode.Unauthorized, signOut.StatusCode);
    }

    [Fact]
    public async Task Mcp_without_a_credential_is_401_with_a_bearer_challenge()
    {
        // The session cookie opens nothing under /mcp.
        var session = await SessionAsync();
        foreach (var path in new[] { "/mcp", "/MCP", "/mcp/anything" })
        {
            using var response = await Api.SendAsync(HttpMethod.Post, path, new { jsonrpc = "2.0", id = 1, method = "tools/list" }, session: session);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("Bearer", response.Headers.WwwAuthenticate.ToString());
        }

        // A connection's URL that no connection has is not found, with a session as without (Task 8a).
        using var unknown = await Api.SendAsync(HttpMethod.Post, "/mcp/c/abcdefghijklmnop", new { jsonrpc = "2.0", id = 1, method = "tools/list" }, session: session);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
    }

    [Fact]
    public async Task Csp_and_nosniff_on_every_answer()
    {
        var session = await SessionAsync();
        var answers = new List<(string What, HttpResponseMessage Response)>
        {
            ("healthz", await Api.SendAsync(HttpMethod.Get, "/healthz")),
            ("signed-in api", await Api.SendAsync(HttpMethod.Get, "/api/session", session: session)),
            ("401 api", await Api.SendAsync(HttpMethod.Get, "/api/session")),
            ("404 api", await Api.SendAsync(HttpMethod.Get, "/api/nothing", session: session)),
            ("403 api", await Api.SendAsync(HttpMethod.Post, "/api/session", new { username = "x", password = "y" }, origin: null)),
            ("mcp", await Api.SendAsync(HttpMethod.Post, "/mcp")),
            ("web app", await Api.SendAsync(HttpMethod.Get, "/connections")),
            ("asset", await Api.SendAsync(HttpMethod.Get, "/assets/missing.js")),
            ("discovery", await Api.SendAsync(HttpMethod.Get, "/.well-known/oauth-authorization-server")),
        };

        foreach (var (what, response) in answers)
        {
            using (response)
            {
                var csp = response.Headers.TryGetValues("Content-Security-Policy", out var values) ? values.Single() : null;
                Assert.True(csp is not null && csp.Contains("default-src 'self'") && csp.Contains("frame-ancestors 'none'"), $"CSP on {what}");
                Assert.True(response.Headers.TryGetValues("X-Content-Type-Options", out var sniff) && sniff.Single() == "nosniff", $"nosniff on {what}");
                Assert.True(response.Headers.TryGetValues("Referrer-Policy", out var referrer) && referrer.Single() == "same-origin", $"Referrer-Policy on {what}");
                Assert.True(response.Headers.TryGetValues("Strict-Transport-Security", out var hsts) && hsts.Single().StartsWith("max-age="), $"HSTS on {what}");
                if (what.Contains("api"))
                    Assert.True(response.Headers.CacheControl?.NoStore, $"no-store on {what}");
            }
        }
    }

    [Fact]
    public async Task Missing_asset_is_a_plain_404()
    {
        using var response = await Api.SendAsync(HttpMethod.Get, "/assets/index-0000.js");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("", await response.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task Malformed_body_is_a_json_400()
    {
        using var request = Dashboard.Request(HttpMethod.Post, "/api/session");
        request.Content = new StringContent("{not json", Encoding.UTF8, "application/json");
        using var response = await Api.CreateClient().SendAsync(request, Ct);
        using var missing = await Api.SendAsync(HttpMethod.Post, "/api/session", new { username = "anna" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("The request body is missing, not JSON, or lacks a required field.", await Dashboard.ErrorAsync(response));
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        Assert.Equal("The request body is missing, not JSON, or lacks a required field.", await Dashboard.ErrorAsync(missing));
    }
}
