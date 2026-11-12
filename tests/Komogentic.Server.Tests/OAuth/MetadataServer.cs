// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Collections.Concurrent;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Komogentic.Server.Tests.OAuth;

/// <summary>What <see cref="MetadataServer"/> answers on <c>/client.json</c>.</summary>
internal sealed record MetadataResponse(
    string Body = "{}",
    int Status = 200,
    IReadOnlyDictionary<string, string>? Headers = null,
    TimeSpan Delay = default,
    string? RedirectTo = null,
    bool Chunked = false);

/// <summary>A minimal server on a loopback port that plays a client's metadata document host, and counts what reaches it.</summary>
internal sealed class MetadataServer : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly ConcurrentQueue<string> _requests = new();

    private MetadataServer(WebApplication app, string origin, Func<MetadataResponse> response)
    {
        _app = app;
        Origin = origin;
        Response = response;
    }

    /// <summary>Replaced by a test to change what the next request gets.</summary>
    public Func<MetadataResponse> Response { get; set; }

    public string Origin { get; }

    public string ClientId => $"{Origin}/client.json";

    public int Requests => _requests.Count;

    public IReadOnlyCollection<string> Paths => _requests.ToArray();

    public static async Task<MetadataServer> StartAsync(MetadataResponse response)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        var app = builder.Build();
        MetadataServer? server = null;
        app.Run(async context =>
        {
            server!._requests.Enqueue(context.Request.Path);
            if (context.Request.Path != "/client.json")
            {
                await context.Response.WriteAsync("{}");
                return;
            }

            var r = server.Response();
            if (r.Delay > TimeSpan.Zero)
            {
                try
                {
                    await Task.Delay(r.Delay, context.RequestAborted);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }

            context.Response.StatusCode = r.RedirectTo is null ? r.Status : StatusCodes.Status302Found;
            if (r.RedirectTo is not null) context.Response.Headers.Location = r.RedirectTo;
            foreach (var (name, value) in r.Headers ?? new Dictionary<string, string>()) context.Response.Headers[name] = value;
            context.Response.ContentType = "application/json";
            var bytes = Encoding.UTF8.GetBytes(r.Body);
            if (!r.Chunked)
            {
                context.Response.ContentLength = bytes.Length;
                await context.Response.Body.WriteAsync(bytes);
                return;
            }

            // No Content-Length: the body arrives in chunks and its size is known only by counting.
            for (var offset = 0; offset < bytes.Length; offset += 1024)
            {
                await context.Response.Body.WriteAsync(bytes.AsMemory(offset, Math.Min(1024, bytes.Length - offset)));
                await context.Response.Body.FlushAsync();
            }
        });
        await app.StartAsync();
        var origin = app.Urls.Single().TrimEnd('/');
        server = new MetadataServer(app, origin, () => response);
        return server;
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}
