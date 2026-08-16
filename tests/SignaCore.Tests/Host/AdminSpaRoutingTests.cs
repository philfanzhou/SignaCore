using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host;

/// <summary>
/// SPA 分支是终止分支：被它接走的请求永远到不了 MapControllers()。
/// 这些用例守住"什么不能被 SPA 接走"——回归一次就是整条 API 静默 404。
/// </summary>
public class AdminSpaRoutingTests
{
    private const int HttpPort = 5002;

    [Theory]
    [InlineData("/")]
    [InlineData("/admin")]
    [InlineData("/admin/apps")]
    [InlineData("/assets/index.js")]
    public void ShouldServeSpa_ServesConsoleRoutes(string path)
    {
        Assert.True(AdminSpaRouting.ShouldServeSpa(Context(path), HttpPort));
    }

    /// <summary>
    /// 回归：/oauth2 曾经不在排除列表里，生产上整个 OAuth 端点被 SPA 分支吞掉，
    /// 而 TestServer 的 LocalPort 是 0 让测试完全看不到。
    /// </summary>
    [Theory]
    [InlineData("/api/auth/token")]
    [InlineData("/api/profile/wechat")]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/api/setup/status")]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    [InlineData("/.well-known/jwks.json")]
    [InlineData("/health")]
    [InlineData("/health/live")]
    [InlineData("/health/ready")]
    [InlineData("/metrics")]
    public void ShouldServeSpa_NeverSwallowsServiceRoutes(string path)
    {
        Assert.False(AdminSpaRouting.ShouldServeSpa(Context(path), HttpPort));
    }

    /// <summary>
    /// 主防线是"路由已经选中了 endpoint"，不是前缀名单：新加的路由自动被排除，
    /// 不需要有人记得回来改这个列表。
    /// </summary>
    [Fact]
    public void ShouldServeSpa_ExcludesAnyPathThatRoutingAlreadyMatched()
    {
        var context = Context("/some/future/endpoint");
        context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, null, "future"));

        Assert.False(AdminSpaRouting.ShouldServeSpa(context, HttpPort));
    }

    [Fact]
    public void ShouldServeSpa_IgnoresRequestsOnAnotherPort()
    {
        Assert.False(AdminSpaRouting.ShouldServeSpa(Context("/admin", port: 9443), HttpPort));
    }

    /// <summary>前缀比较按路径段：/apifoo 不是 /api 下的东西。</summary>
    [Fact]
    public void ShouldServeSpa_MatchesPrefixesOnSegmentBoundaries()
    {
        Assert.True(AdminSpaRouting.ShouldServeSpa(Context("/apifoo"), HttpPort));
    }

    private static DefaultHttpContext Context(string path, int? port = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Features.Set<IHttpConnectionFeature>(new HttpConnectionFeature { LocalPort = port ?? HttpPort });
        return context;
    }
}
