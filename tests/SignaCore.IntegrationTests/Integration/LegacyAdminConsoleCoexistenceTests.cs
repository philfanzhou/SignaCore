using System.Net;
using System.Net.Http.Json;
using SignaCore.Database;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The legacy admin console keeps working between the #102 switch and the #133 removal: the
/// legacy cookie still signs in and authorizes <c>/api/admin/*</c>, and the two session surfaces
/// stay isolated — a management cookie never authorizes the legacy policy and vice versa.
/// </summary>
public sealed class LegacyAdminConsoleCoexistenceTests : IClassFixture<IdentityServerFixture>
{
    private readonly IdentityServerFixture _fixture;

    public LegacyAdminConsoleCoexistenceTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task LegacyLogin_StillSignsInAndAuthorizesTheAdminApi()
    {
        using var client = await _fixture.CreateAdminHttpClientAsync();

        using var response = await client.GetAsync(
            "/api/admin/session/me", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task LegacyCookie_DoesNotAuthorizeTheManagementSession()
    {
        // Sign in through the legacy console and take the cookie from the response Set-Cookie: the
        // factory client parks it in the handler's CookieContainer, not in DefaultRequestHeaders, so
        // it cannot be read back from there.
        using var legacy = _fixture.CreateHttpClient();
        using var loginResponse = await legacy.PostAsJsonAsync(
            "/api/admin/session/login",
            new
            {
                username = IdentityServerFixture.AdminUsername,
                password = IdentityServerFixture.AdminPassword,
                rememberMe = false
            },
            TestContext.Current.CancellationToken);
        loginResponse.EnsureSuccessStatusCode();
        Assert.True(loginResponse.Headers.NonValidated.TryGetValues("Set-Cookie", out var setCookies));
        var legacyCookie = setCookies
            .First(value => value.StartsWith("qz_admin_session=", StringComparison.Ordinal))
            .Split(';')[0];

        // Present only the legacy cookie to the management session entry.
        using var management = _fixture.CreateHttpClient();
        management.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", legacyCookie);
        using var response = await management.GetAsync(
            "/management/v1/session", TestContext.Current.CancellationToken);

        // The management session authenticates only its own fixed scheme and never sees the legacy
        // cookie name, so this is the no-management-cookie case: the closed unauthenticated 401. A
        // 403 is reserved for a valid identity that lacks the permission or an invalid claim.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("management.session.unauthenticated", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ManagementCookie_DoesNotAuthorizeTheLegacyAdminApi()
    {
        using var client = _fixture.CreateHttpClient();
        using var login = new HttpRequestMessage(
            HttpMethod.Post, "/management/v1/session/login")
        {
            Content = JsonContent.Create(new
            {
                username = IdentityServerFixture.AdminUsername,
                password = IdentityServerFixture.AdminPassword
            })
        };
        login.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        using var loginResponse = await client.SendAsync(login, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, loginResponse.StatusCode);
        Assert.True(loginResponse.Headers.NonValidated.TryGetValues("Set-Cookie", out var cookieValues));
        var managementCookie = cookieValues
            .Single(value => value.StartsWith("__Host-ServiceMantle.Management=", StringComparison.Ordinal))
            .Split(';')[0];

        using var legacy = _fixture.CreateHttpClient();
        legacy.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", managementCookie);
        using var response = await legacy.GetAsync(
            "/api/admin/session/me", TestContext.Current.CancellationToken);

        // AdminSession is pinned to the legacy cookie scheme: the management cookie does not
        // authenticate there, and the API path answers 401 rather than redirecting.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TheLegacyKeyStore_IsNoLongerWrittenByTheSharedRing()
    {
        using var client = await _fixture.CreateAdminHttpClientAsync();

        using var scope = _fixture.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        // The switch moved the active ring to the shared ServiceMantle table; the legacy table
        // keeps whatever was written before the switch and receives nothing new.
        var legacyKeys = await db.DataProtectionKeys.AsNoTracking()
            .CountAsync(TestContext.Current.CancellationToken);
        var sharedKeys = await db.Database.SqlQuery<int>(
                $"SELECT COUNT(*) AS Value FROM service_data_protection_keys")
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.True(sharedKeys.Single() > 0);
        Assert.Equal(0, legacyKeys);
    }
}
