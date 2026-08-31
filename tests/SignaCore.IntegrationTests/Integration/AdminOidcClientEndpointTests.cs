using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Database.Entity;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Wire contract of the interactive OIDC administration endpoints: who may call them, what a
/// successful call returns, and what a rejected one leaves behind.
/// </summary>
public class AdminOidcClientEndpointTests : IClassFixture<IdentityServerFixture>
{
    private const string AppId = "oidc-endpoint-test-app";

    /// <summary>
    /// The class shares one server fixture, so a test that mutates configuration uses its own
    /// application rather than the one a read-only assertion depends on.
    /// </summary>
    private const string ListAppId = "oidc-endpoint-list-app";

    private readonly IdentityServerFixture _fixture;

    public AdminOidcClientEndpointTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    /// <summary>
    /// Without a valid administration session none of the interactive endpoints answers, so no
    /// caller can read or change an application's OIDC configuration.
    /// </summary>
    [Fact]
    public async Task WithoutAnAdminSession_NoInteractiveEndpointAnswers()
    {
        await SeedAsync();
        using var http = _fixture.CreateHttpClient();

        var read = await http.GetAsync($"/api/admin/apps/{AppId}/oidc", TestContext.Current.CancellationToken);
        var list = await http.GetAsync("/api/admin/apps", TestContext.Current.CancellationToken);
        var policy = await http.PutAsJsonAsync(
            $"/api/admin/apps/{AppId}/oidc-policy",
            new { clientType = "Confidential", allowAuthorizationCode = false, allowedScopes = new[] { "openid" } },
            TestContext.Current.CancellationToken);
        var add = await http.PostAsJsonAsync(
            $"/api/admin/apps/{AppId}/oidc/redirect-uris",
            new { kind = "Redirect", uris = new[] { "https://bff.example.test/cb" } },
            TestContext.Current.CancellationToken);
        var remove = await http.DeleteAsync(
            $"/api/admin/apps/{AppId}/oidc/redirect-uris/{Guid.NewGuid()}",
            TestContext.Current.CancellationToken);

        foreach (var response in new[] { read, list, policy, add, remove })
        {
            Assert.Contains(
                response.StatusCode,
                new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
        }

        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var app = await dbContext.AppRegistrations
            .AsNoTracking()
            .Include(item => item.RedirectUris)
            .FirstAsync(item => item.AppId == AppId, TestContext.Current.CancellationToken);
        Assert.Empty(app.RedirectUris);
        Assert.False(app.AllowAuthorizationCode);
    }

    /// <summary>
    /// The full administrator round trip: register two kinds of URI, enable the code flow, read the
    /// result back, and remove a registration.
    /// </summary>
    [Fact]
    public async Task AnAdministrator_CanConfigureAndReadBackAnInteractiveClient()
    {
        await SeedAsync();
        using var http = await _fixture.CreateAdminHttpClientAsync();

        var added = await http.PostAsJsonAsync(
            $"/api/admin/apps/{AppId}/oidc/redirect-uris",
            new { kind = "Redirect", uris = new[] { "HTTPS://BFF.Endpoint.Test:443/callback" } },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, added.StatusCode);

        var addedPostLogout = await http.PostAsJsonAsync(
            $"/api/admin/apps/{AppId}/oidc/redirect-uris",
            new { kind = "PostLogout", uris = new[] { "https://bff.endpoint.test/signed-out" } },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, addedPostLogout.StatusCode);

        var policy = await http.PutAsJsonAsync(
            $"/api/admin/apps/{AppId}/oidc-policy",
            new
            {
                clientType = "Confidential",
                allowAuthorizationCode = true,
                allowedScopes = new[] { "openid", "profile" },
                allowRefreshToken = false,
                identitySessionMaxAgeSeconds = 1800
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, policy.StatusCode);

        var read = await http.GetFromJsonAsync<JsonElement>(
            $"/api/admin/apps/{AppId}/oidc",
            TestContext.Current.CancellationToken);
        Assert.True(read.GetProperty("allowAuthorizationCode").GetBoolean());
        Assert.Equal(
            ["openid", "profile"],
            read.GetProperty("allowedScopes").EnumerateArray().Select(value => value.GetString()));
        Assert.Equal(1800, read.GetProperty("identitySessionMaxAgeSeconds").GetInt32());

        var registration = read.GetProperty("redirectUris").EnumerateArray().Single();
        Assert.Equal("https://bff.endpoint.test/callback", registration.GetProperty("uri").GetString());
        Assert.Equal(
            "https://bff.endpoint.test/signed-out",
            read.GetProperty("postLogoutRedirectUris").EnumerateArray().Single().GetProperty("uri").GetString());

        // The last redirect URI cannot go while the code flow is on.
        var refused = await http.DeleteAsync(
            $"/api/admin/apps/{AppId}/oidc/redirect-uris/{registration.GetProperty("id").GetGuid()}",
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);

        // The post-logout registration is a different set and can go.
        var removed = await http.DeleteAsync(
            $"/api/admin/apps/{AppId}/oidc/redirect-uris/{read.GetProperty("postLogoutRedirectUris").EnumerateArray().Single().GetProperty("id").GetGuid()}",
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, removed.StatusCode);
    }

    /// <summary>
    /// The application list keeps the members it already had and reports the interactive ones
    /// alongside them.
    /// </summary>
    [Fact]
    public async Task TheApplicationList_KeepsItsExistingMembersAndAddsTheInteractiveOnes()
    {
        await SeedAsync(ListAppId);
        using var http = await _fixture.CreateAdminHttpClientAsync();

        var apps = await http.GetFromJsonAsync<JsonElement>(
            "/api/admin/apps",
            TestContext.Current.CancellationToken);

        var app = apps.EnumerateArray().Single(item => item.GetProperty("appId").GetString() == ListAppId);
        foreach (var name in new[]
                 {
                     "appId", "appName", "callbackUrl", "callbackExpiresAt", "isActive", "createdAt",
                     "ldapLoginMode", "smsLoginMode", "smsProfileKey", "wechatLoginMode",
                     "audienceMode", "audience"
                 })
        {
            Assert.True(app.TryGetProperty(name, out _), $"Missing existing member '{name}'.");
        }

        Assert.Equal("Confidential", app.GetProperty("clientType").GetString());
        Assert.False(app.GetProperty("allowAuthorizationCode").GetBoolean());
        Assert.Equal(
            ["openid"],
            app.GetProperty("allowedScopes").EnumerateArray().Select(value => value.GetString()));
        Assert.False(app.GetProperty("allowRefreshToken").GetBoolean());
        Assert.Empty(app.GetProperty("redirectUris").EnumerateArray());
        Assert.Empty(app.GetProperty("postLogoutRedirectUris").EnumerateArray());
    }

    /// <summary>
    /// No interactive endpoint activates anything: both discovery documents still describe the same
    /// capabilities.
    /// </summary>
    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    public async Task DiscoveryDocuments_AreUnchanged(string path)
    {
        using var http = _fixture.CreateHttpClient();

        var document = await http.GetFromJsonAsync<JsonElement>(
            path,
            TestContext.Current.CancellationToken);

        Assert.False(document.TryGetProperty("authorization_endpoint", out _));
        Assert.Empty(document.GetProperty("response_types_supported").EnumerateArray());
        Assert.DoesNotContain(
            "authorization_code",
            document.GetProperty("grant_types_supported").EnumerateArray().Select(value => value.GetString()));
    }

    private async Task SeedAsync(string appId = AppId)
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        if (await dbContext.AppRegistrations.AnyAsync(app => app.AppId == appId, TestContext.Current.CancellationToken))
        {
            return;
        }

        dbContext.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword("oidc-endpoint-test-secret"),
            AppName = "OIDC Endpoint Test App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication
        });
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
    }
}
