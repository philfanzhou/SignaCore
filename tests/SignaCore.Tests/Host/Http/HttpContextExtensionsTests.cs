using System.Net;
using Microsoft.AspNetCore.Http;
using SignaCore.Host.Http;
using Xunit;

namespace SignaCore.Tests.Host.Http;

/// <summary>
/// The Admin, Auth and Gateway controllers each used to carry their own copy of these accessors, and
/// they did not behave alike. Now that they have converged on HttpContextExtensions, this file pins
/// the single contract.
/// </summary>
public class HttpContextExtensionsTests
{
    private static DefaultHttpContext ContextWithRemoteIp(string ip = "10.0.0.9")
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(ip);
        return context;
    }

    [Fact]
    public void GetClientIp_WithoutForwardedHeader_UsesRemoteAddress()
    {
        Assert.Equal("10.0.0.9", ContextWithRemoteIp().GetClientIp());
    }

    [Fact]
    public void GetClientIp_WithForwardedChain_TakesFirstEntryTrimmed()
    {
        var context = ContextWithRemoteIp();
        context.Request.Headers[IdentityHeaders.ForwardedFor] = " 203.0.113.7 , 70.41.3.18 ";

        Assert.Equal("203.0.113.7", context.GetClientIp());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void GetClientIp_WithBlankForwardedHeader_FallsBackToRemoteAddress(string forwarded)
    {
        // The point where the behaviours converged: the old AuthController copy returned an empty
        // string in this case, which made the audit records of one and the same client differ
        // depending on which controller had served the request.
        var context = ContextWithRemoteIp();
        context.Request.Headers[IdentityHeaders.ForwardedFor] = forwarded;

        Assert.Equal("10.0.0.9", context.GetClientIp());
    }

    [Fact]
    public async Task GetCorrelationId_ReturnsTheValueTheMiddlewareEstablished()
    {
        var context = new DefaultHttpContext();
        await CorrelationTestPipeline.EstablishAsync(context, "from-middleware");
        context.Request.Headers["x-correlation-id"] = "from-caller";

        // Only the middleware's slot is read; the raw header never wins even after the fact.
        Assert.Equal("from-middleware", context.GetCorrelationId());
    }

    [Fact]
    public void GetCorrelationId_WithoutMiddleware_ThrowsAndNeverTrustsTheHeader()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["x-correlation-id"] = "from-caller";

        var thrown = Assert.Throws<InvalidOperationException>(() => context.GetCorrelationId());

        // A fixed, input-free message: neither the raw header value nor a fresh id is produced.
        Assert.Equal(
            "The correlation id is unavailable because the ServiceMantle correlation middleware has not run for this request.",
            thrown.Message);
    }

    [Fact]
    public void GetAppSecret_PrefersItemsBecauseRedactionMiddlewareMovesItThere()
    {
        var context = new DefaultHttpContext();
        context.Items[IdentityHeaders.AppSecret] = "moved-by-middleware";
        context.Request.Headers[IdentityHeaders.AppSecret] = "still-in-header";

        Assert.Equal("moved-by-middleware", context.GetAppSecret());
    }

    [Fact]
    public void GetAppIdAndSecret_FallBackToRequestHeaders()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers[IdentityHeaders.AppId] = "app-1";
        context.Request.Headers[IdentityHeaders.AppSecret] = "secret-1";

        Assert.Equal("app-1", context.GetAppId());
        Assert.Equal("secret-1", context.GetAppSecret());
    }

    [Fact]
    public void GetAppId_WhenAbsent_ReturnsNull()
    {
        Assert.Null(new DefaultHttpContext().GetAppId());
    }
}
