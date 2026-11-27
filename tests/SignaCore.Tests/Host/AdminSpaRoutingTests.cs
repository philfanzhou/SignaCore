using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host;

/// <summary>
/// The console fallback must never take a service route: one regression there silently answers an
/// API request with the console HTML.
/// </summary>
public class AdminSpaRoutingTests
{
    private const int HttpPort = 5002;

    [Theory]
    [InlineData("/")]
    [InlineData("/admin")]
    [InlineData("/admin/apps")]
    [InlineData("/assets/index.js")]
    public void ShouldServeSpaFallback_ServesConsoleRoutes(string path)
    {
        Assert.True(AdminSpaRouting.ShouldServeSpaFallback(Context(path), HttpPort));
    }

    /// <summary>
    /// Regression: /oauth2 was once missing from the exclusion list, so the SPA took the entire
    /// OAuth endpoint in production, while TestServer's LocalPort of 0 kept the tests from seeing
    /// any of it.
    /// </summary>
    [Theory]
    [InlineData("/api/auth/token")]
    [InlineData("/api/profile/wechat")]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/revoke")]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    [InlineData("/.well-known/jwks.json")]
    [InlineData("/health")]
    [InlineData("/health/live")]
    [InlineData("/health/ready")]
    [InlineData("/metrics")]
    public void ShouldServeSpaFallback_NeverTakesServiceRoutes(string path)
    {
        Assert.False(AdminSpaRouting.ShouldServeSpaFallback(Context(path), HttpPort));
    }

    [Fact]
    public void ShouldServeSpaFallback_IgnoresRequestsOnAnotherPort()
    {
        Assert.False(AdminSpaRouting.ShouldServeSpaFallback(Context("/admin", port: 9443), HttpPort));
    }

    /// <summary>
    /// Prefixes are compared on segment boundaries: /apifoo is not something under /api.
    /// </summary>
    [Fact]
    public void ShouldServeSpaFallback_MatchesPrefixesOnSegmentBoundaries()
    {
        Assert.True(AdminSpaRouting.ShouldServeSpaFallback(Context("/apifoo"), HttpPort));
    }

    private static DefaultHttpContext Context(string path, int? port = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Features.Set<IHttpConnectionFeature>(new HttpConnectionFeature { LocalPort = port ?? HttpPort });
        return context;
    }
}
