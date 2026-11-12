// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Diagnostics;

namespace Komogentic.Server.Tests.Tools;

/// <summary>
/// A real clock that runs <paramref name="factor"/> times faster: timers, delays and timeouts made through it fire
/// sooner by that much. The tools' waits (2 s polls, a 5 s deadline) then take milliseconds, and still race against
/// the fake Core's real delays as they would in production.
/// </summary>
internal sealed class FastTime(double factor) : TimeProvider
{
    private readonly DateTimeOffset _start = DateTimeOffset.UtcNow;
    private readonly long _started = Stopwatch.GetTimestamp();

    public override DateTimeOffset GetUtcNow() => _start + Stopwatch.GetElapsedTime(_started) * factor;

    public override long GetTimestamp() => (long)(Stopwatch.GetTimestamp() * factor);

    public override long TimestampFrequency => Stopwatch.Frequency;

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
        new Scaled(System.CreateTimer(callback, state, Scale(dueTime), Scale(period)), factor);

    private TimeSpan Scale(TimeSpan t) => Scale(t, factor);

    private static TimeSpan Scale(TimeSpan t, double factor) => t == Timeout.InfiniteTimeSpan ? t : t / factor;

    private sealed class Scaled(ITimer inner, double factor) : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => inner.Change(Scale(dueTime, factor), Scale(period, factor));

        public void Dispose() => inner.Dispose();

        public ValueTask DisposeAsync() => inner.DisposeAsync();
    }
}
