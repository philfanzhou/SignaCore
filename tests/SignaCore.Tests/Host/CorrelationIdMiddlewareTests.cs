using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host;

public class CorrelationIdMiddlewareTests
{
    private const string HeaderName = CorrelationIdMiddleware.CorrelationIdHeader;

    [Fact]
    public async Task InvokeAsync_GrpcContentType_NoLongerSkipped()
    {
        var logger = new TestLogger<CorrelationIdMiddleware>();
        var middleware = new CorrelationIdMiddleware(_ => Task.CompletedTask, logger);

        var context = new DefaultHttpContext();
        context.Request.ContentType = "application/grpc";
        context.Request.Headers[HeaderName] = "incoming-grpc-id";

        await middleware.InvokeAsync(context);

        // gRPC skip logic removed in Phase 2; all requests are now handled uniformly
        Assert.Equal("incoming-grpc-id", context.Response.Headers[HeaderName]);
        Assert.Equal("incoming-grpc-id", context.Items[CorrelationIdMiddleware.HttpContextItemsKey]);
    }

    [Fact]
    public async Task InvokeAsync_WithIncomingHeader_PropagatesToResponseAndItems()
    {
        var logger = new TestLogger<CorrelationIdMiddleware>();
        var middleware = new CorrelationIdMiddleware(_ => Task.CompletedTask, logger);
        var incomingId = "abc-123-correlation-id";

        var context = new DefaultHttpContext();
        context.Request.Headers[HeaderName] = incomingId;

        await middleware.InvokeAsync(context);

        Assert.Equal(incomingId, context.Response.Headers[HeaderName]);
        Assert.Equal(incomingId, context.Items[CorrelationIdMiddleware.HttpContextItemsKey]);
    }

    [Fact]
    public async Task InvokeAsync_WithoutIncomingHeader_GeneratesNewIdAndWritesResponseHeader()
    {
        var logger = new TestLogger<CorrelationIdMiddleware>();
        var middleware = new CorrelationIdMiddleware(_ => Task.CompletedTask, logger);

        var context = new DefaultHttpContext();

        await middleware.InvokeAsync(context);

        var generatedId = Assert.IsType<string>(context.Items[CorrelationIdMiddleware.HttpContextItemsKey]);
        Assert.False(string.IsNullOrEmpty(generatedId));
        Assert.NotEmpty(generatedId);
        Assert.Equal(generatedId, context.Response.Headers[HeaderName]);
        Assert.Empty(logger.LogEntries);
    }

    [Fact]
    public async Task InvokeAsync_NextThrows_LogsErrorAndRethrows()
    {
        var logger = new TestLogger<CorrelationIdMiddleware>();
        var expectedException = new InvalidOperationException("downstream failure");
        var middleware = new CorrelationIdMiddleware(_ => throw expectedException, logger);

        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/api/test";

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(() => middleware.InvokeAsync(context));

        Assert.Same(expectedException, thrown);
        Assert.Single(logger.LogEntries);
        Assert.Contains("HTTP request failed", logger.LogEntries[0]);
        Assert.Contains("/api/test", logger.LogEntries[0]);
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
