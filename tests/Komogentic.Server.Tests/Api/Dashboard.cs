// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Komogentic.Server.Tests.Api;

/// <summary>The dashboard's calls as the browser makes them: its own Origin, a client address of the test's, and the
/// session cookie sent by hand, so a test sees exactly what is set and sent.</summary>
internal static class Dashboard
{
    public const string Cookie = "kgt_session";

    private static int _addresses;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>An address no other test uses, so the in-memory limits of the shared hosts count apart.</summary>
    public static string NewAddress()
    {
        var n = Interlocked.Increment(ref _addresses);
        return $"198.51.{(n / 250) % 250}.{n % 250 + 1}";
    }

    public static HttpRequestMessage Request(
        HttpMethod method, string path, object? body = null, string? session = null, string? address = null, string? origin = AppFactory.PublicUrl)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("X-Forwarded-For", address ?? NewAddress());
        if (origin is not null) request.Headers.Add("Origin", origin);
        if (session is not null) request.Headers.Add("Cookie", $"{Cookie}={session}");
        if (body is not null) request.Content = JsonContent.Create(body);
        return request;
    }

    public static async Task<HttpResponseMessage> SendAsync(
        this WebApplicationFactory<Program> api, HttpMethod method, string path, object? body = null, string? session = null, string? address = null,
        string? origin = AppFactory.PublicUrl)
    {
        using var request = Request(method, path, body, session, address, origin);
        return await api.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, BaseAddress = new Uri(AppFactory.PublicUrl) })
            .SendAsync(request, Ct);
    }

    public static Task<HttpResponseMessage> PostSessionAsync(this WebApplicationFactory<Program> api, string username, string password, string? address = null) =>
        api.SendAsync(HttpMethod.Post, "/api/session", new { username, password }, address: address);

    /// <summary>Signs in and answers the session cookie's value.</summary>
    public static async Task<string> SignInAsync(this WebApplicationFactory<Program> api, string username, string password)
    {
        using var response = await api.PostSessionAsync(username, password);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return SessionCookie(response) ?? throw new InvalidOperationException("The sign-in set no session cookie.");
    }

    /// <summary>The <c>Set-Cookie</c> of the session, or null.</summary>
    public static string? SetCookie(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var values) ? values.FirstOrDefault(v => v.StartsWith(Cookie + "=", StringComparison.Ordinal)) : null;

    public static string? SessionCookie(HttpResponseMessage response) =>
        SetCookie(response) is { } header ? header.Split(';')[0][(Cookie.Length + 1)..] : null;

    public static async Task<JsonElement> JsonAsync(HttpResponseMessage response) =>
        (await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(Ct), cancellationToken: Ct)).RootElement.Clone();

    public static async Task<string?> ErrorAsync(HttpResponseMessage response) => (await JsonAsync(response)).GetProperty("error").GetString();
}
