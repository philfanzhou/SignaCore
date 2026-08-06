using Microsoft.Extensions.Logging;
using SignaCore.Domain.Services.Sms;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

public class SmsSenderTests
{
    [Fact]
    public async Task LoggingSmsSender_MasksCodeAndPhone()
    {
        var logger = new TestLogger<LoggingSmsSender>();
        var sender = new LoggingSmsSender(logger);

        await sender.SendAsync(
            new SmsProviderProfile { Provider = SmsProviderNames.Logging },
            new SmsVerificationMessage("+8613800138000", "123456"),
            CancellationToken.None);

        var entry = Assert.Single(logger.LogEntries);
        Assert.Contains("******", entry);
        Assert.DoesNotContain("123456", entry);
        Assert.DoesNotContain("13800138000", entry);
    }

    private sealed class TestLogger<T> : ILogger<T>
    {
        public List<string> LogEntries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => LogEntries.Add(formatter(state, exception));
    }
}
