using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Halka.TestKit;

/// <summary>Keeps every formatted log line in memory so tests can assert that no secret or token was logged.</summary>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<string> _lines = new();

    public IReadOnlyCollection<string> Lines => _lines;

    public ILogger CreateLogger(string categoryName) => new Logger(categoryName, _lines);

    public void Dispose()
    {
    }

    private sealed class Logger(string category, ConcurrentQueue<string> lines) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            // The exception is included in full, exactly as a console logger would render it.
            lines.Enqueue($"{logLevel} {category}: {formatter(state, exception)} {exception}");
        }
    }
}
