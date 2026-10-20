using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using SignaCore.Database;
using SignaCore.Database.Entity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The end-to-end contract of cross-application exchange: rejected by default, admitted once an
/// administrator adds a directed trust edge, the source application's session is left untouched, and
/// a derived token can continue only along a fresh directed trust. See
/// docs/adr/0003-cross-application-refresh-grant.md.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
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

        // Without a trust edge, a refresh token is a credential bound to its application: holding
        // it gets another application nothing.
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
        // If an exchange rotated, the source application's refresh token would be revoked along the
        // way: the user would be signed out of the source site on its next refresh, and only
        // visibly so once that side's access token expired.
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
    public async Task DerivedTokensCompleteRepeatedCyclesWithFreshTrustChecks()
    {
        var first = await SeedAppAsync("hop-first");
        var second = await SeedAppAsync("hop-second");
        var third = await SeedAppAsync("hop-third");
        await AddExchangeTrustAsync(second.AppId, first.AppId);
        await AddExchangeTrustAsync(third.AppId, second.AppId);
        await AddExchangeTrustAsync(first.AppId, third.AppId);
        var original = await SignInAsync(first);
        var current = original;
        foreach (var target in new[] { second, third, first, second, third, first })
        {
            var exchanged = await RefreshAsync(target, current);
            Assert.Equal(HttpStatusCode.OK, exchanged.StatusCode);
            var next = await ReadRefreshTokenAsync(exchanged);
            Assert.NotEqual(current, next);
            current = next;
        }
        // A path through B does not grant a direct A-to-C exchange.
        Assert.Equal(HttpStatusCode.BadRequest, (await RefreshAsync(third, current)).StatusCode);
        using (var admin = await _fixture.CreateAdminHttpClientAsync())
        {
            var removed = await admin.DeleteAsync(
                $"/api/admin/apps/{second.AppId}/exchange-trusts/{first.AppId}",
                TestContext.Current.CancellationToken);
            removed.EnsureSuccessStatusCode();
        }
        Assert.Equal(HttpStatusCode.BadRequest, (await RefreshAsync(second, current)).StatusCode);
        // Cross-application minting has left the original source credential usable.
        Assert.Equal(HttpStatusCode.OK, (await RefreshAsync(first, original)).StatusCode);
    }

    [Fact]
    public async Task SmsDerivedTokensContinueAndRecheckTargetAdmission()
    {
        var sender = new FakeSmsSender();
        using var smsHost = _fixture.CreateSmsHost(sender);
        var first = await SeedAppAsync("sms-first");
        var second = await SeedAppAsync("sms-second");
        var third = await SeedAppAsync("sms-third");
        using (var scope = _fixture.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var names = new[] { first.AppId, second.AppId, third.AppId };
            foreach (var app in await db.AppRegistrations.Where(a => names.Contains(a.AppId)).ToListAsync(TestContext.Current.CancellationToken))
            {
                app.SmsLoginMode = SmsLoginMode.AutoProvision;
                app.SmsProfileKey = OAuthLoginSmsCodeTestSupport.ProfileKey;
            }
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }
        await AddExchangeTrustAsync(second.AppId, first.AppId);
        await AddExchangeTrustAsync(third.AppId, second.AppId);
        await AddExchangeTrustAsync(first.AppId, third.AppId);
        using var gateway = smsHost.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
        gateway.DefaultRequestHeaders.Add("X-Admin-AppId", first.AppId);
        gateway.DefaultRequestHeaders.Add("X-Admin-AppSecret", first.AppSecret);
        var phone = OAuthLoginSmsCodeTestSupport.NewPhone();
        using var sent = await gateway.PostAsJsonAsync("/api/auth/sms-code", new { phone }, TestContext.Current.CancellationToken);
        Assert.True((await sent.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("success").GetBoolean());
        using var signedIn = await gateway.PostAsJsonAsync("/api/auth/token", new { grantType = "sms", phone, code = sender.Calls.Last().Code }, TestContext.Current.CancellationToken);
        var initial = await signedIn.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        Assert.True(initial.GetProperty("success").GetBoolean());
        var current = initial.GetProperty("refreshToken").GetString()!;
        foreach (var target in new[] { second, third, first, second, third, first })
        {
            using var next = await RefreshAsync(target, current);
            Assert.Equal(HttpStatusCode.OK, next.StatusCode);
            current = await ReadRefreshTokenAsync(next);
        }
        using (var scope = _fixture.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            (await db.AppRegistrations.SingleAsync(a => a.AppId == second.AppId, TestContext.Current.CancellationToken)).SmsLoginMode = SmsLoginMode.Disabled;
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }
        using var denied = await RefreshAsync(second, current);
        Assert.Equal(HttpStatusCode.BadRequest, denied.StatusCode);
        Assert.Equal("unauthorized_client", await ReadErrorAsync(denied));
    }

    [Fact]
    public async Task ExchangeTrustIsDirected()
    {
        var source = await SeedAppAsync("directed-source");
        var target = await SeedAppAsync("directed-target");
        await AddExchangeTrustAsync(target.AppId, source.AppId);

        var targetOwnToken = await SignInAsync(target);

        // target trusting source does not mean source trusts target.
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
                $"/api/admin/apps/{target.AppId}/exchange-trusts/{source.AppId}",
                TestContext.Current.CancellationToken);
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
            $"/api/admin/apps/{app.AppId}/exchange-trusts",
            new { sourceAppId = app.AppId },
            cancellationToken: TestContext.Current.CancellationToken);

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
