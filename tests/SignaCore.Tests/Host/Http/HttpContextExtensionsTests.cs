using System.Net;
using Microsoft.AspNetCore.Http;
using SignaCore.Host;
using SignaCore.Host.Http;
using Xunit;

namespace SignaCore.Tests.Host.Http;

/// <summary>
/// 这些取值方法此前在 Admin/Auth/Gateway 三个 controller 里各有一份且行为不一致，
/// 收敛到 HttpContextExtensions 后由本文件锁定唯一契约。
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
        // 行为统一点：AuthController 那份旧实现在这种情况下返回空字符串，
        // 导致同一个客户端的审计记录因为走哪个 controller 而不同。
        var context = ContextWithRemoteIp();
        context.Request.Headers[IdentityHeaders.ForwardedFor] = forwarded;

        Assert.Equal("10.0.0.9", context.GetClientIp());
    }

    [Fact]
    public void GetCorrelationId_PrefersValueProducedByMiddleware()
    {
        var context = new DefaultHttpContext();
        context.Items[CorrelationIdMiddleware.HttpContextItemsKey] = "from-middleware";
        context.Request.Headers[CorrelationIdMiddleware.CorrelationIdHeader] = "from-caller";

        Assert.Equal("from-middleware", context.GetCorrelationId());
    }

    [Fact]
    public void GetCorrelationId_WithoutMiddlewareValue_FallsBackToRequestHeader()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers[CorrelationIdMiddleware.CorrelationIdHeader] = "from-caller";

        Assert.Equal("from-caller", context.GetCorrelationId());
    }

    [Fact]
    public void GetCorrelationId_WithNothingSet_GeneratesNonEmptyValue()
    {
        Assert.False(string.IsNullOrWhiteSpace(new DefaultHttpContext().GetCorrelationId()));
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
