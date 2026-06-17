using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using QuantumZhou.Identity.Service;
using Xunit;

namespace QuantumZhou.Identity.Tests.Service;

public class CorrelationIdInterceptorTests
{
    private readonly ILogger<CorrelationIdInterceptor> _logger = NullLogger<CorrelationIdInterceptor>.Instance;

    [Fact]
    public async Task UnaryServerHandler_WithExistingCorrelationId_ReusesIt()
    {
        var interceptor = new CorrelationIdInterceptor(_logger);
        var expectedId = "existing-id-123";
        var headers = new Metadata { { "x-correlation-id", expectedId } };
        var responseTrailers = new Metadata();
        var context = new TestServerCallContextImpl(headers, responseTrailers);

        var continuationCalled = false;
        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            continuationCalled = true;
            await Task.Delay(1);
            return "response";
        }

        var result = await interceptor.UnaryServerHandler("request", context, Continuation);

        Assert.Equal("response", result);
        Assert.True(continuationCalled);
        var trailer = responseTrailers.FirstOrDefault(h => h.Key == "x-correlation-id");
        Assert.NotNull(trailer);
        Assert.Equal(expectedId, trailer!.Value);
    }

    [Fact]
    public async Task UnaryServerHandler_WithoutCorrelationId_GeneratesNewOne()
    {
        var interceptor = new CorrelationIdInterceptor(_logger);
        var responseTrailers = new Metadata();
        var context = new TestServerCallContextImpl(responseTrailers: responseTrailers);

        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            return "response";
        }

        var result = await interceptor.UnaryServerHandler("request", context, Continuation);

        Assert.Equal("response", result);
        var trailer = responseTrailers.FirstOrDefault(h => h.Key == "x-correlation-id");
        Assert.NotNull(trailer);
        Assert.False(string.IsNullOrEmpty(trailer!.Value));
        Assert.NotEqual("existing-id-123", trailer.Value);
    }

    [Fact]
    public async Task UnaryServerHandler_WhenContinuationThrows_RethrowsAndLogs()
    {
        var interceptor = new CorrelationIdInterceptor(_logger);
        var context = new TestServerCallContextImpl();

        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            throw new InvalidOperationException("Test failure");
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            interceptor.UnaryServerHandler("request", context, Continuation));
    }

    [Fact]
    public async Task UnaryServerHandler_WithCaseInsensitiveHeader_Matches()
    {
        var interceptor = new CorrelationIdInterceptor(_logger);
        var expectedId = "case-test-456";
        var headers = new Metadata { { "X-Correlation-Id", expectedId } };
        var responseTrailers = new Metadata();
        var context = new TestServerCallContextImpl(headers, responseTrailers);

        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            return "ok";
        }

        await interceptor.UnaryServerHandler("request", context, Continuation);

        var trailer = responseTrailers.FirstOrDefault(h => h.Key == "x-correlation-id");
        Assert.NotNull(trailer);
        Assert.Equal(expectedId, trailer!.Value);
    }
}
