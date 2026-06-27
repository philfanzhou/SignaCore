using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using QuantumZhou.Identity.Domain.Services.Sms;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain.Services;

public class SmsSenderTests
{
    [Fact]
    public async Task LoggingSmsSender_SendAsync_MasksCodeInLog()
    {
        var logger = new TestLogger<LoggingSmsSender>();
        var sender = new LoggingSmsSender(logger);

        await sender.SendAsync("13800138000", "123456");

        Assert.Single(logger.LogEntries);
        Assert.Contains("12****", logger.LogEntries[0]);
        Assert.DoesNotContain("123456", logger.LogEntries[0]);
        // Phone must also be masked per ErrorHandling.md sensitive data rules
        Assert.DoesNotContain("13800138000", logger.LogEntries[0]);
        Assert.Contains("138****8000", logger.LogEntries[0]);
    }

    [Fact]
    public async Task LoggingSmsSender_SendAsync_ShortCode_MasksCorrectly()
    {
        var logger = new TestLogger<LoggingSmsSender>();
        var sender = new LoggingSmsSender(logger);

        await sender.SendAsync("13800138000", "1");

        Assert.Single(logger.LogEntries);
        Assert.Contains("*", logger.LogEntries[0]);
    }

    [Fact]
    public async Task ThrowingSmsSender_SendAsync_ThrowsInvalidOperationException()
    {
        var logger = new TestLogger<ThrowingSmsSender>();
        var sender = new ThrowingSmsSender(logger);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => sender.SendAsync("13800138000", "123456"));

        Assert.Contains("No SMS provider", ex.Message);
    }

    [Fact]
    public async Task ThrowingSmsSender_SendAsync_LogsError()
    {
        var logger = new TestLogger<ThrowingSmsSender>();
        var sender = new ThrowingSmsSender(logger);

        try
        {
            await sender.SendAsync("13800138000", "123456");
        }
        catch (InvalidOperationException) { }

        Assert.Single(logger.LogEntries);
        // Per ErrorHandling.md sensitive data rules, phone must be masked in logs
        Assert.DoesNotContain("13800138000", logger.LogEntries[0]);
        Assert.Contains("138****8000", logger.LogEntries[0]);
    }

    private class TestLogger<T> : ILogger<T>
    {
        public List<string> LogEntries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            LogEntries.Add(formatter(state, exception));
        }
    }
}
