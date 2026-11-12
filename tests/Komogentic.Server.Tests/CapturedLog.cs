// SPDX-License-Identifier: AGPL-3.0-or-later
using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Komogentic.Server.Tests;

/// <summary>Every log line of a host, formatted, for tests that check what reaches the log. With
/// <paramref name="scopes"/>, each line is followed by its scopes, as a provider with <c>IncludeScopes</c> prints them.</summary>
internal sealed class CapturedLog(bool scopes = false) : ILoggerProvider, ISupportExternalScope
{
    private IExternalScopeProvider? _scopeProvider;

    private IExternalScopeProvider? Scopes => scopes ? _scopeProvider : null;

    public ConcurrentQueue<string> Lines { get; } = new();

    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

    public void SetScopeProvider(IExternalScopeProvider scopeProvider) => _scopeProvider = scopeProvider;

    public void Dispose()
    {
    }

    private sealed class Logger(CapturedLog owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var line = new StringBuilder($"{logLevel} {category}: {formatter(state, exception)} {exception}");
            owner.Scopes?.ForEachScope((scope, text) => text.Append(" => ").Append(scope), line);
            owner.Lines.Enqueue(line.ToString());
        }
    }
}
