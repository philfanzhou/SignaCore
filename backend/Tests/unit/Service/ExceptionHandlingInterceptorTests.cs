using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using QuantumZhou.Identity.Service;
using Xunit;

namespace QuantumZhou.Identity.Tests.Service;

public class ExceptionHandlingInterceptorTests
{
    private readonly ILogger<ExceptionHandlingInterceptor> _logger = NullLogger<ExceptionHandlingInterceptor>.Instance;

    [Fact]
    public async Task UnaryServerHandler_WhenContinuationSucceeds_ReturnsResponse()
    {
        var interceptor = new ExceptionHandlingInterceptor(_logger);
        var context = new TestServerCallContextImpl();

        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            return "success";
        }

        var result = await interceptor.UnaryServerHandler("request", context, Continuation);

        Assert.Equal("success", result);
    }

    [Fact]
    public async Task UnaryServerHandler_WhenRpcExceptionThrown_RethrowsAsIs()
    {
        var interceptor = new ExceptionHandlingInterceptor(_logger);
        var context = new TestServerCallContextImpl();
        var originalException = new RpcException(new Status(StatusCode.NotFound, "Not found"));

        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            throw originalException;
        }

        var ex = await Assert.ThrowsAsync<RpcException>(() =>
            interceptor.UnaryServerHandler("request", context, Continuation));
        Assert.Equal(StatusCode.NotFound, ex.StatusCode);
        Assert.Same(originalException, ex);
    }

    [Fact]
    public async Task UnaryServerHandler_WhenArgumentExceptionThrown_ConvertsToInvalidArgument()
    {
        var interceptor = new ExceptionHandlingInterceptor(_logger);
        var context = new TestServerCallContextImpl();

        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            throw new ArgumentException("Bad argument");
        }

        var ex = await Assert.ThrowsAsync<RpcException>(() =>
            interceptor.UnaryServerHandler("request", context, Continuation));
        Assert.Equal(StatusCode.InvalidArgument, ex.StatusCode);
        Assert.Contains("Bad argument", ex.Status.Detail);
    }

    [Fact]
    public async Task UnaryServerHandler_WhenInvalidOperationExceptionThrown_ConvertsToFailedPrecondition()
    {
        var interceptor = new ExceptionHandlingInterceptor(_logger);
        var context = new TestServerCallContextImpl();

        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            throw new InvalidOperationException("Invalid state");
        }

        var ex = await Assert.ThrowsAsync<RpcException>(() =>
            interceptor.UnaryServerHandler("request", context, Continuation));
        Assert.Equal(StatusCode.FailedPrecondition, ex.StatusCode);
        Assert.Contains("Invalid state", ex.Status.Detail);
    }

    [Fact]
    public async Task UnaryServerHandler_WhenGenericExceptionThrown_ConvertsToInternal()
    {
        var interceptor = new ExceptionHandlingInterceptor(_logger);
        var context = new TestServerCallContextImpl();

        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            throw new Exception("Unexpected error");
        }

        var ex = await Assert.ThrowsAsync<RpcException>(() =>
            interceptor.UnaryServerHandler("request", context, Continuation));
        Assert.Equal(StatusCode.Internal, ex.StatusCode);
        Assert.DoesNotContain("Unexpected error", ex.Status.Detail);
    }
}
