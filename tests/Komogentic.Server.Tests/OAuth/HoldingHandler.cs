// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Net;

namespace Komogentic.Server.Tests.OAuth;

/// <summary>Holds every request until <paramref name="release"/> completes, then answers 404; counts how many ran at once.</summary>
internal sealed class HoldingHandler(Task release) : HttpMessageHandler
{
    private int _running;
    private int _started;
    private int _mostAtOnce;

    public int Started => Volatile.Read(ref _started);

    public int MostAtOnce => Volatile.Read(ref _mostAtOnce);

    /// <summary>Returns once <paramref name="count"/> requests have arrived, or after 5 s whatever the count.</summary>
    public async Task StartedAsync(int count)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (Started < count && DateTime.UtcNow < deadline) await Task.Delay(20, TestContext.Current.CancellationToken);
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _started);
        var running = Interlocked.Increment(ref _running);
        int most;
        while (running > (most = Volatile.Read(ref _mostAtOnce)) && Interlocked.CompareExchange(ref _mostAtOnce, running, most) != most)
        {
        }

        try
        {
            await release.WaitAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }
        finally
        {
            Interlocked.Decrement(ref _running);
        }
    }
}
