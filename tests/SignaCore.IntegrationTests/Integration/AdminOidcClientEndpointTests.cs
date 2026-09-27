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
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public class AdminOidcClientEndpointTests : IClassFixture<IdentityServerFixture>
{
    private const string AppId = "oidc-endpoint-test-app";

    /// <summary>
    /// The class shares one server fixture, so a test that mutates configuration uses its own
    /// application rather than the one a read-only assertion depends on.
    /// </summary>
    private const string ListAppId = "oidc-endpoint-list-app";

    /// <summary>
    /// The round trip enables the code flow and leaves a redirect registration behind — the last
    /// one cannot be removed while the flow is on — so it must not run against the application
    /// whose untouched state <see cref="WithoutAnAdminSession_NoInteractiveEndpointAnswers"/>
    /// asserts. Test order within the class is not fixed, so sharing that id makes both outcomes
    /// depend on which one runs first.
    /// </summary>
    private const string RoundTripAppId = "oidc-endpoint-round-trip-app";
    private const string OriginAppId = "oidc-endpoint-origin-app";
    private const string CorsAppId = "oidc-endpoint-cors-app";
    private const string OriginDeleteAppId = "oidc-endpoint-origin-delete-app";

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
        var origins = await http.PutAsJsonAsync(
            $"/api/admin/apps/{AppId}/oidc/allowed-origins",
            new { origins = new[] { "https://spa.example.test" } },
            TestContext.Current.CancellationToken);

        foreach (var response in new[] { read, list, policy, add, remove, origins })
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

    [Fact]
    public async Task PublicOrigins_ReplaceReadRejectInvalidAndClearAtomically()
    {
        await SeedAsync(OriginAppId, OidcClientType.Public);
        using var http = await _fixture.CreateAdminHttpClientAsync();
        var route = $"/api/admin/apps/{OriginAppId}/oidc/allowed-origins";
        var before = await http.GetFromJsonAsync<JsonElement>(
            $"/api/admin/apps/{OriginAppId}/oidc", TestContext.Current.CancellationToken);
        Assert.Empty(before.GetProperty("allowedOrigins").EnumerateArray());

        var first = await http.PutAsJsonAsync(route,
            new { origins = new[] { "HTTPS://SPA.EXAMPLE.TEST:443", "https://spa.example.test:8443" } },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var firstBody = await first.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        Assert.Equal(["https://spa.example.test", "https://spa.example.test:8443"],
            firstBody.GetProperty("allowedOrigins").EnumerateArray().Select(value => value.GetString()));

        var rejected = await http.PutAsJsonAsync(route,
            new { origins = new[] { "https://new.example.test", "https://spa.example.test/path" } },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        var duplicate = await http.PutAsJsonAsync(route,
            new { origins = new[] { "HTTPS://SPA.EXAMPLE.TEST:443", "https://spa.example.test" } },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, duplicate.StatusCode);

        var read = await http.GetFromJsonAsync<JsonElement>(
            $"/api/admin/apps/{OriginAppId}/oidc", TestContext.Current.CancellationToken);
        Assert.Equal(2, read.GetProperty("allowedOrigins").GetArrayLength());
        using (var scope = _fixture.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            Assert.Equal(2, await db.AppAllowedOrigins.CountAsync(
                row => row.AppRegistration.AppId == OriginAppId, TestContext.Current.CancellationToken));
            Assert.Single((await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                db, TestContext.Current.CancellationToken)).Where(row =>
                row.Action == "app_oidc_allowed_origins_replaced" && row.TargetId == OriginAppId));
        }

        var replaced = await http.PutAsJsonAsync(route,
            new { origins = new[] { "https://spa.example.test", "https://new.example.test" } },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, replaced.StatusCode);
        var replacedBody = await replaced.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        Assert.Equal(["https://new.example.test", "https://spa.example.test"],
            replacedBody.GetProperty("allowedOrigins").EnumerateArray().Select(value => value.GetString()));

        var cleared = await http.PutAsJsonAsync(route, new { origins = Array.Empty<string>() },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, cleared.StatusCode);
        var clearedBody = await cleared.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        Assert.Empty(clearedBody.GetProperty("allowedOrigins").EnumerateArray());
    }

    [Fact]
    public async Task ConfidentialApplication_CannotRegisterPublicOrigins()
    {
        await SeedAsync();
        using var http = await _fixture.CreateAdminHttpClientAsync();
        var response = await http.PutAsJsonAsync(
            $"/api/admin/apps/{AppId}/oidc/allowed-origins",
            new { origins = new[] { "https://spa.example.test" } },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RegisteredPublicOrigin_DoesNotEnableCorsResponses()
    {
        await SeedAsync(CorsAppId, OidcClientType.Public);
        using (var admin = await _fixture.CreateAdminHttpClientAsync())
        {
            var registered = await admin.PutAsJsonAsync(
                $"/api/admin/apps/{CorsAppId}/oidc/allowed-origins",
                new { origins = new[] { "https://spa-cors.example.test" } },
                TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, registered.StatusCode);
        }

        using var http = _fixture.CreateHttpClient();
        foreach (var (method, path) in new[]
                 {
                     (HttpMethod.Get, "/oauth2/authorize"),
                     (HttpMethod.Post, "/oauth2/token"),
                     (HttpMethod.Get, "/oauth2/userinfo"),
                     (HttpMethod.Options, "/oauth2/token"),
                     (HttpMethod.Options, "/oauth2/userinfo")
                 })
        {
            using var request = new HttpRequestMessage(method, path);
            request.Headers.Add("Origin", "https://spa-cors.example.test");
            if (method == HttpMethod.Options)
            {
                request.Headers.Add("Access-Control-Request-Method",
                    path == "/oauth2/token" ? "POST" : "GET");
            }
            if (method == HttpMethod.Post)
            {
                request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code",
                    ["client_id"] = CorsAppId
                });
            }

            using var response = await http.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
            Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
        }
    }

    [Fact]
    public async Task PublicOrigin_RemainsReadableWhenDisabledAndCascadesOnDelete()
    {
        await SeedAsync(OriginDeleteAppId, OidcClientType.Public);
        using var http = await _fixture.CreateAdminHttpClientAsync();
        var saved = await http.PutAsJsonAsync(
            $"/api/admin/apps/{OriginDeleteAppId}/oidc/allowed-origins",
            new { origins = new[] { "https://spa-delete.example.test" } },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);

        Guid rowId;
        using (var scope = _fixture.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var app = await db.AppRegistrations.SingleAsync(
                row => row.AppId == OriginDeleteAppId, TestContext.Current.CancellationToken);
            rowId = app.Id;
            app.IsActive = false;
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        var read = await http.GetFromJsonAsync<JsonElement>(
            $"/api/admin/apps/{OriginDeleteAppId}/oidc", TestContext.Current.CancellationToken);
        Assert.Equal("https://spa-delete.example.test",
            read.GetProperty("allowedOrigins").EnumerateArray().Single().GetString());

        var deleted = await http.DeleteAsync(
            $"/api/admin/apps/{OriginDeleteAppId}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, deleted.StatusCode);
        using (var scope = _fixture.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            Assert.False(await db.AppAllowedOrigins.AnyAsync(
                row => row.AppRegistrationId == rowId, TestContext.Current.CancellationToken));
        }
    }

    /// <summary>
    /// The full administrator round trip: register two kinds of URI, enable the code flow, read the
    /// result back, and remove a registration.
    /// </summary>
    [Fact]
    public async Task AnAdministrator_CanConfigureAndReadBackAnInteractiveClient()
    {
        await SeedAsync(RoundTripAppId);
        using var http = await _fixture.CreateAdminHttpClientAsync();

        var added = await http.PostAsJsonAsync(
            $"/api/admin/apps/{RoundTripAppId}/oidc/redirect-uris",
            new { kind = "Redirect", uris = new[] { "HTTPS://BFF.Endpoint.Test:443/callback" } },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, added.StatusCode);

        var addedPostLogout = await http.PostAsJsonAsync(
            $"/api/admin/apps/{RoundTripAppId}/oidc/redirect-uris",
            new { kind = "PostLogout", uris = new[] { "https://bff.endpoint.test/signed-out" } },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, addedPostLogout.StatusCode);

        var policy = await http.PutAsJsonAsync(
            $"/api/admin/apps/{RoundTripAppId}/oidc-policy",
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
            $"/api/admin/apps/{RoundTripAppId}/oidc",
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
            $"/api/admin/apps/{RoundTripAppId}/oidc/redirect-uris/{registration.GetProperty("id").GetGuid()}",
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);

        // The post-logout registration is a different set and can go.
        var removed = await http.DeleteAsync(
            $"/api/admin/apps/{RoundTripAppId}/oidc/redirect-uris/{read.GetProperty("postLogoutRedirectUris").EnumerateArray().Single().GetProperty("id").GetGuid()}",
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
    /// No interactive endpoint activates anything beyond the delivered core: both discovery
    /// documents describe the same capabilities regardless of registration state.
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

        Assert.True(document.TryGetProperty("authorization_endpoint", out _));
        Assert.Equal(
            ["code"],
            document.GetProperty("response_types_supported").EnumerateArray().Select(value => value.GetString()));
        Assert.Contains(
            "authorization_code",
            document.GetProperty("grant_types_supported").EnumerateArray().Select(value => value.GetString()));
    }

    /// <summary>
    /// <c>EV-34</c>: while a retained login continuation references the application, the hard
    /// delete answers 409 with the fixed message, keeps the application and its children, and
    /// writes no deletion audit; once the reference is gone the unchanged delete succeeds.
    /// </summary>
    [Fact]
    public async Task DeletingAReferencedApplication_IsAConflictAndWritesNothing()
    {
        using var http = await _fixture.CreateAdminHttpClientAsync();

        var created = await http.PostAsJsonAsync(
            "/api/admin/apps",
            new { appName = "Deletion Conflict App", callbackUrl = (string?)null, ttlSeconds = 3600 },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var creation = await created.Content.ReadFromJsonAsync<JsonElement>(
            TestContext.Current.CancellationToken);
        var appId = creation.GetProperty("appId").GetString()!;

        var addedRedirect = await http.PostAsJsonAsync(
            $"/api/admin/apps/{appId}/oidc/redirect-uris",
            new { kind = "Redirect", uris = new[] { "https://bff.deletion.test/callback" } },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, addedRedirect.StatusCode);

        Guid applicationRowId;
        using (var scope = _fixture.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            applicationRowId = await dbContext.AppRegistrations
                .Where(app => app.AppId == appId)
                .Select(app => app.Id)
                .SingleAsync(TestContext.Current.CancellationToken);
            dbContext.AuthorizationRequests.Add(new AuthorizationRequestEntity
            {
                Id = Guid.NewGuid(),
                HandleDigest = LoginHandleDigest.Compute(
                    "deletion-http-handle-0123456789abcdefghij"),
                AppRegistrationId = applicationRowId,
                RedirectUri = "https://bff.deletion.test/callback",
                Scope = "openid",
                State = "deletion-http-state",
                Nonce = "deletion-http-nonce",
                CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(
                    IdentityConstants.LoginHandleLifetimeMinutes)
            });
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        var refused = await http.DeleteAsync(
            $"/api/admin/apps/{appId}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
        var refusal = await refused.Content.ReadFromJsonAsync<JsonElement>(
            TestContext.Current.CancellationToken);
        Assert.Equal(
            "App is still referenced by retained interactive authorization records. " +
            "Deactivate it and retry after retention cleanup removes them.",
            refusal.GetProperty("message").GetString());

        // The application, its redirect registration, and its list membership survive, and no
        // deletion audit was written.
        var apps = await http.GetFromJsonAsync<JsonElement>(
            "/api/admin/apps", TestContext.Current.CancellationToken);
        Assert.Contains(
            apps.EnumerateArray(), item => item.GetProperty("appId").GetString() == appId);
        using (var scope = _fixture.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            Assert.True(await dbContext.AppRedirectUris.AsNoTracking()
                .AnyAsync(uri => uri.AppRegistrationId == applicationRowId, TestContext.Current.CancellationToken));
            Assert.False((await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                    dbContext, TestContext.Current.CancellationToken))
                .Any(log => log.Action == "app_deleted" && log.TargetId == appId));
        }

        // Retention cleanup removes the last reference; the unchanged delete succeeds and takes
        // the cascaded children with it.
        using (var scope = _fixture.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var continuation = await dbContext.AuthorizationRequests
                .SingleAsync(row => row.AppRegistrationId == applicationRowId,
                    TestContext.Current.CancellationToken);
            dbContext.AuthorizationRequests.Remove(continuation);
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        var deleted = await http.DeleteAsync(
            $"/api/admin/apps/{appId}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, deleted.StatusCode);

        using (var scope = _fixture.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            Assert.False(await dbContext.AppRegistrations.AsNoTracking()
                .AnyAsync(app => app.Id == applicationRowId, TestContext.Current.CancellationToken));
            Assert.False(await dbContext.AppRedirectUris.AsNoTracking()
                .AnyAsync(uri => uri.AppRegistrationId == applicationRowId, TestContext.Current.CancellationToken));
            Assert.True((await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                    dbContext, TestContext.Current.CancellationToken))
                .Any(log => log.Action == "app_deleted" && log.TargetId == appId));
        }
    }

    private async Task SeedAsync(
        string appId = AppId,
        OidcClientType clientType = OidcClientType.Confidential)
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
            AppSecretHash = clientType == OidcClientType.Public
                ? string.Empty : BCrypt.Net.BCrypt.HashPassword("oidc-endpoint-test-secret"),
            AppName = "OIDC Endpoint Test App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = clientType
        });
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
    }
}
