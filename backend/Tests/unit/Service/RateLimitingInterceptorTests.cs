using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using QuantumZhou.Identity.Service;
using Xunit;

namespace QuantumZhou.Identity.Tests.Service;

public class RateLimitingInterceptorTests
{
    private static ILogger<RateLimitingInterceptor> CreateLogger() => NullLogger<RateLimitingInterceptor>.Instance;

    [Fact]
    public async Task UnaryServerHandler_WithinLimit_AllowsRequest()
    {
        var options = new RateLimitingOptions { PermitLimitPerClient = 5, WindowSeconds = 60 };
        var interceptor = new RateLimitingInterceptor(options, CreateLogger());
        var context = new TestServerCallContextImpl();

        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            return "ok";
        }

        var result = await interceptor.UnaryServerHandler("request", context, Continuation);
        Assert.Equal("ok", result);
    }

    [Fact]
    public async Task UnaryServerHandler_ExceedsLimit_ThrowsResourceExhausted()
    {
        var options = new RateLimitingOptions { PermitLimitPerClient = 1, WindowSeconds = 60 };
        var interceptor = new RateLimitingInterceptor(options, CreateLogger());
        var context = new TestServerCallContextImpl();

        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            return "ok";
        }

        // First request succeeds
        await interceptor.UnaryServerHandler("request", context, Continuation);

        // Second request within window should be rejected
        var ex = await Assert.ThrowsAsync<RpcException>(() =>
            interceptor.UnaryServerHandler("request", context, Continuation));
        Assert.Equal(StatusCode.ResourceExhausted, ex.StatusCode);
    }

    [Fact]
    public async Task UnaryServerHandler_DifferentClientIps_CountedIndependently()
    {
        var options = new RateLimitingOptions { PermitLimitPerClient = 1, WindowSeconds = 60 };
        var interceptor = new RateLimitingInterceptor(options, CreateLogger());

        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            return "ok";
        }

        // Client 1 uses its quota
        await interceptor.UnaryServerHandler("request", new TestServerCallContextImpl(peer: "ipv4:1.1.1.1:5001"), Continuation);

        // Client 2 should still be allowed
        var result = await interceptor.UnaryServerHandler("request", new TestServerCallContextImpl(peer: "ipv4:2.2.2.2:5001"), Continuation);
        Assert.Equal("ok", result);
    }

    [Fact]
    public async Task UnaryServerHandler_WithIpv6Peer_ExtractsIpCorrectly()
    {
        var options = new RateLimitingOptions { PermitLimitPerClient = 1, WindowSeconds = 60 };
        var interceptor = new RateLimitingInterceptor(options, CreateLogger());

        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            return "ok";
        }

        // IPv6 peer should be handled without error
        var result = await interceptor.UnaryServerHandler("request", new TestServerCallContextImpl(peer: "ipv6:[::1]:5001"), Continuation);
        Assert.Equal("ok", result);
    }

    [Fact]
    public async Task UnaryServerHandler_WhenContinuationThrows_StillDisposesLease()
    {
        var options = new RateLimitingOptions { PermitLimitPerClient = 5, WindowSeconds = 60 };
        var interceptor = new RateLimitingInterceptor(options, CreateLogger());
        var context = new TestServerCallContextImpl();

        async Task<string> Continuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            throw new InvalidOperationException("fail");
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            interceptor.UnaryServerHandler("request", context, Continuation));

        // Should still be able to make requests (lease was disposed)
        async Task<string> SuccessContinuation(string req, ServerCallContext ctx)
        {
            await Task.Delay(1);
            return "recovered";
        }

        var result = await interceptor.UnaryServerHandler("request", context, SuccessContinuation);
        Assert.Equal("recovered", result);
    }
}
