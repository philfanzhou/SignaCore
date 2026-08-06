using Microsoft.AspNetCore.Http;
using SignaCore.Host.Http;
using SignaCore.Host.Controllers;
using SignaCore.Host.Middleware;
using Xunit;

namespace SignaCore.Tests.Host;

public class SensitiveHeaderRedactionMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_WithSecretHeader_MovesToItemsAndRemovesHeader()
    {
        var nextCalled = false;
        var middleware = new SensitiveHeaderRedactionMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });
        var context = new DefaultHttpContext();
        context.Request.Headers[IdentityHeaders.AppSecret] = "super-secret";

        await middleware.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.Equal("super-secret", context.Items[IdentityHeaders.AppSecret]);
        Assert.False(context.Request.Headers.ContainsKey(IdentityHeaders.AppSecret));
    }

    [Fact]
    public async Task InvokeAsync_WithoutSecretHeader_PassesThroughUntouched()
    {
        var nextCalled = false;
        var middleware = new SensitiveHeaderRedactionMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });
        var context = new DefaultHttpContext();

        await middleware.InvokeAsync(context);

        Assert.True(nextCalled);
        Assert.False(context.Items.ContainsKey(IdentityHeaders.AppSecret));
    }
}
