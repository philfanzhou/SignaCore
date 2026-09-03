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

    [Theory]
    [InlineData(SmsProviderNames.Logging)]
    [InlineData(SmsProviderNames.AlibabaCloud)]
    [InlineData(SmsProviderNames.TencentCloud)]
    public async Task SendAsync_AlreadyCancelled_DoesNotCreateClientReadMessageOrLog(string provider)
    {
        var logger = new TestLogger<LoggingSmsSender>();
        ISmsSender sender = provider switch
        {
            SmsProviderNames.Logging => new LoggingSmsSender(logger),
            SmsProviderNames.AlibabaCloud => new AlibabaCloudSmsSender(),
            SmsProviderNames.TencentCloud => new TencentCloudSmsSender(),
            _ => throw new ArgumentOutOfRangeException(nameof(provider))
        };
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var profile = new SmsProviderProfile { Provider = provider };

        // No message or credentials are supplied: cancellation must precede accessing either.
        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            sender.SendAsync(profile, null!, cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Empty(logger.LogEntries);
        if (provider != SmsProviderNames.Logging)
        {
            var field = sender.GetType().GetField("_clients",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            Assert.NotNull(field);
            var clients = Assert.IsAssignableFrom<System.Collections.IEnumerable>(field.GetValue(sender));
            Assert.Empty(clients.Cast<object>());
        }
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
