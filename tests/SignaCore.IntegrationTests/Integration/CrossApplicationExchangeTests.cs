using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using SignaCore.Database;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// 跨应用换票的端到端契约：默认拒绝，管理员加上有向信任边后放行，来源应用的会话不受影响，
/// 换出来的 token 不能再换第二次。见 docs/adr/0003-cross-application-refresh-grant.md。
/// </summary>
public class CrossApplicationExchangeTests : IClassFixture<IdentityServerFixture>
{
    private readonly IdentityServerFixture _fixture;

    public CrossApplicationExchangeTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task RefreshTokenFromAnotherApplication_IsRejectedUntilAnExchangeTrustExists()
    {
        var source = await SeedAppAsync("source");
        var target = await SeedAppAsync("target");

        var sourceRefreshToken = await SignInAsync(source);

        // 没有信任边时，refresh token 就是应用绑定的凭据，别的应用拿着也换不到。
        var rejected = await RefreshAsync(target, sourceRefreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        Assert.Equal("invalid_grant", await ReadErrorAsync(rejected));

        await AddExchangeTrustAsync(target.AppId, source.AppId);

        var admitted = await RefreshAsync(target, sourceRefreshToken);
        Assert.Equal(HttpStatusCode.OK, admitted.StatusCode);
        var exchanged = await ReadRefreshTokenAsync(admitted);
        Assert.NotEqual(sourceRefreshToken, exchanged);
    }

    [Fact]
    public async Task AnExchangeDoesNotEndTheSourceApplicationSession()
    {
        // 换票如果走轮换，来源应用的 refresh token 会被顺手吊销——用户在来源站点会在下一次
        // 刷新时被登出，而且要等到那边 access token 过期才看得出来。
        var source = await SeedAppAsync("keepalive-source");
        var target = await SeedAppAsync("keepalive-target");
        await AddExchangeTrustAsync(target.AppId, source.AppId);

        var sourceRefreshToken = await SignInAsync(source);
        var exchange = await RefreshAsync(target, sourceRefreshToken);
        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);

        var sourceRefresh = await RefreshAsync(source, sourceRefreshToken);
        Assert.Equal(HttpStatusCode.OK, sourceRefresh.StatusCode);
    }

    [Fact]
    public async Task ExchangeTrustDoesNotComposeAcrossTwoHops()
    {
        // first → second 和 second → third 两条边不等于 first → third。
        var first = await SeedAppAsync("hop-first");
        var second = await SeedAppAsync("hop-second");
        var third = await SeedAppAsync("hop-third");
        await AddExchangeTrustAsync(second.AppId, first.AppId);
        await AddExchangeTrustAsync(third.AppId, second.AppId);

        var firstRefreshToken = await SignInAsync(first);
        var secondHop = await RefreshAsync(second, firstRefreshToken);
        Assert.Equal(HttpStatusCode.OK, secondHop.StatusCode);
        var secondRefreshToken = await ReadRefreshTokenAsync(secondHop);

        var thirdHop = await RefreshAsync(third, secondRefreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, thirdHop.StatusCode);
        Assert.Equal("invalid_grant", await ReadErrorAsync(thirdHop));

        // 同一个 token 在它自己的应用里刷新仍然正常——被拒的是"再换一次"，不是这张票本身。
        var ownApplication = await RefreshAsync(second, secondRefreshToken);
        Assert.Equal(HttpStatusCode.OK, ownApplication.StatusCode);
    }

    [Fact]
    public async Task ExchangeTrustIsDirected()
    {
        var source = await SeedAppAsync("directed-source");
        var target = await SeedAppAsync("directed-target");
        await AddExchangeTrustAsync(target.AppId, source.AppId);

        var targetOwnToken = await SignInAsync(target);

        // target 信任 source，不代表 source 信任 target。
        var reverse = await RefreshAsync(source, targetOwnToken);
        Assert.Equal(HttpStatusCode.BadRequest, reverse.StatusCode);
        Assert.Equal("invalid_grant", await ReadErrorAsync(reverse));
    }

    [Fact]
    public async Task RemovingAnExchangeTrustStopsFurtherExchanges()
    {
        var source = await SeedAppAsync("revoke-source");
        var target = await SeedAppAsync("revoke-target");
        await AddExchangeTrustAsync(target.AppId, source.AppId);

        var sourceRefreshToken = await SignInAsync(source);
        Assert.Equal(HttpStatusCode.OK, (await RefreshAsync(target, sourceRefreshToken)).StatusCode);

        using (var admin = await _fixture.CreateAdminHttpClientAsync())
        {
            var removed = await admin.DeleteAsync(
                $"/api/admin/apps/{target.AppId}/exchange-trusts/{source.AppId}");
            Assert.Equal(HttpStatusCode.OK, removed.StatusCode);
        }

        var afterRevocation = await RefreshAsync(target, sourceRefreshToken);
        Assert.Equal(HttpStatusCode.BadRequest, afterRevocation.StatusCode);
    }

    [Fact]
    public async Task AnApplicationCannotTrustItself()
    {
        var app = await SeedAppAsync("self-trust");

        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var response = await admin.PostAsJsonAsync(
            $"/api/admin/apps/{app.AppId}/exchange-trusts", new { sourceAppId = app.AppId });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private sealed record TestApp(string AppId, string AppSecret);

    private async Task<TestApp> SeedAppAsync(string prefix)
    {
        var app = new TestApp($"{prefix}_{Guid.NewGuid():N}", $"secret_{Guid.NewGuid():N}");
        await _fixture.SeedGatewayAppAsync(app.AppId, app.AppSecret);
        return app;
    }

    private async Task AddExchangeTrustAsync(string appId, string sourceAppId)
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var response = await admin.PostAsJsonAsync(
            $"/api/admin/apps/{appId}/exchange-trusts", new { sourceAppId });
        response.EnsureSuccessStatusCode();
    }

    /// <summary>Password grant at <paramref name="app"/>, returning the refresh token it issued.</summary>
    private async Task<string> SignInAsync(TestApp app)
    {
        using var http = CreateClientFor(app);
        var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = IdentityConstants.GrantTypePassword,
                ["username"] = IdentityServerFixture.AdminUsername,
                ["password"] = IdentityServerFixture.AdminPassword
            }));
        response.EnsureSuccessStatusCode();
        return await ReadRefreshTokenAsync(response);
    }

    private async Task<HttpResponseMessage> RefreshAsync(TestApp app, string refreshToken)
    {
        using var http = CreateClientFor(app);
        return await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = IdentityConstants.GrantTypeRefreshToken,
                ["refresh_token"] = refreshToken
            }));
    }

    private HttpClient CreateClientFor(TestApp app)
    {
        var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{app.AppId}:{app.AppSecret}")));
        return http;
    }

    private static async Task<string> ReadRefreshTokenAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        var token = body.GetProperty("refresh_token").GetString();
        Assert.False(string.IsNullOrWhiteSpace(token));
        return token!;
    }

    private static async Task<string?> ReadErrorAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return body.GetProperty("error").GetString();
    }
}
