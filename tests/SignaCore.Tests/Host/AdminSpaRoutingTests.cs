using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host;

/// <summary>
/// The SPA branch is a terminal branch: a request it takes never reaches MapControllers().
/// These tests hold the line on what the SPA must not take — one regression there silently 404s a
/// whole API.
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
    /// Regression: /oauth2 was once missing from the exclusion list, so in production the SPA branch
    /// swallowed the entire OAuth endpoint, while TestServer's LocalPort of 0 kept the tests from
    /// seeing any of it.
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
    /// The main line of defence is that routing has already selected an endpoint, not the prefix
    /// list: a newly added route is excluded automatically, without anyone having to remember to
    /// come back and edit that list.
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

    /// <summary>
    /// Prefixes are compared on segment boundaries: /apifoo is not something under /api.
    /// </summary>
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
