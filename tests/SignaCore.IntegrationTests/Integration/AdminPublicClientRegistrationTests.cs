using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Database.Entity;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The Public-client registration contract over the real administration endpoints: a Public
/// application never holds a secret or a hash at any point of its lifecycle, a Confidential
/// application can never be downgraded through an update, an omitted client type keeps the
/// current one, the explicit upgrade out of Public mints a secret inside the update transaction,
/// and both secret-verification surfaces fail closed on a Public or empty-hash row with the exact
/// shape of a wrong secret — never an unhandled exception.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class AdminPublicClientRegistrationTests : IClassFixture<IdentityServerFixture>
{
    private readonly IdentityServerFixture _fixture;

    public AdminPublicClientRegistrationTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- Acceptance 1, 2: creation ----

    [Fact]
    public async Task CreatingAPublicApp_StoresNoSecretAndReturnsNone()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var (created, appId) = await CreateAppAsync(admin, "Public");

        // The response carries no secret value.
        Assert.Null(created.GetProperty("appSecret").GetString());

        // The row carries the empty hash of the Public ⇔ empty-hash invariant.
        var app = await GetAppAsync(appId);
        Assert.Equal(OidcClientType.Public, app.ClientType);
        Assert.Equal(string.Empty, app.AppSecretHash);

        // The creation audit exists and carries no secret or hash material.
        var audit = await QueryAsync(context => context.AuditLogs.AsNoTracking()
            .SingleAsync(row => row.Action == "app_created" && row.TargetId == appId,
                TestContext.Current.CancellationToken));
        Assert.DoesNotContain("secret", audit.AfterSnapshot ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", audit.Description ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreatingAConfidentialApp_WithTheTypeOmitted_KeepsTheHistoricalBehavior()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        // Omitted clientType: the historical Confidential registration with a generated secret.
        var (created, appId) = await CreateAppAsync(admin, clientType: null);

        var secret = created.GetProperty("appSecret").GetString();
        Assert.False(string.IsNullOrEmpty(secret));

        var app = await GetAppAsync(appId);
        Assert.Equal(OidcClientType.Confidential, app.ClientType);
        Assert.False(string.IsNullOrEmpty(app.AppSecretHash));
        Assert.True(BCrypt.Net.BCrypt.Verify(secret, app.AppSecretHash));

        // The audit shape is unchanged: the same five fields, and still no secret or hash.
        var audit = await QueryAsync(context => context.AuditLogs.AsNoTracking()
            .SingleAsync(row => row.Action == "app_created" && row.TargetId == appId,
                TestContext.Current.CancellationToken));
        Assert.DoesNotContain("clientType", audit.AfterSnapshot ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(secret, audit.AfterSnapshot ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain(app.AppSecretHash, audit.AfterSnapshot ?? string.Empty, StringComparison.Ordinal);
    }

    // ---- Acceptance 3: reads expose no secret surface ----

    [Fact]
    public async Task ReadingAPublicApp_ExposesNoSecretMaterial()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var (_, appId) = await CreateAppAsync(admin, "Public");

        using var read = await admin.GetAsync(
            $"/api/admin/apps/{appId}/oidc", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        var raw = await read.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var oidc = JsonDocument.Parse(raw).RootElement;
        Assert.Equal("Public", oidc.GetProperty("clientType").GetString());
        // No secret field is rendered for a Public client (the one-time upgrade field is omitted).
        Assert.DoesNotContain("ecret", raw, StringComparison.Ordinal);
    }

    // ---- Acceptance 4, 5: the conversion policy ----

    [Fact]
    public async Task ConfidentialToPublic_IsRejectedAndLeavesTheRowUntouched()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var (_, appId) = await CreateAppAsync(admin, clientType: null);
        var before = await GetAppAsync(appId);

        using var response = await admin.PutAsJsonAsync(
            $"/api/admin/apps/{appId}/oidc-policy",
            new
            {
                clientType = "Public",
                allowAuthorizationCode = false,
                allowedScopes = new[] { "openid" },
                allowRefreshToken = false,
                identitySessionMaxAgeSeconds = (int?)null
            },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("conversion", body, StringComparison.OrdinalIgnoreCase);

        var after = await GetAppAsync(appId);
        Assert.Equal(OidcClientType.Confidential, after.ClientType);
        Assert.Equal(before.AppSecretHash, after.AppSecretHash);
    }

    [Fact]
    public async Task OmittingTheClientType_KeepsTheCurrentType_InBothDirections()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();

        // A Public app stays Public when the update omits the type.
        var (_, publicAppId) = await CreateAppAsync(admin, "Public");
        using var publicUpdate = await admin.PutAsJsonAsync(
            $"/api/admin/apps/{publicAppId}/oidc-policy",
            new
            {
                allowAuthorizationCode = false,
                allowedScopes = new[] { "openid" },
                allowRefreshToken = false,
                identitySessionMaxAgeSeconds = (int?)null
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, publicUpdate.StatusCode);
        var publicApp = await GetAppAsync(publicAppId);
        Assert.Equal(OidcClientType.Public, publicApp.ClientType);
        Assert.Equal(string.Empty, publicApp.AppSecretHash);

        // A Confidential app stays Confidential when the update omits the type.
        var (_, confidentialAppId) = await CreateAppAsync(admin, clientType: null);
        using var confidentialUpdate = await admin.PutAsJsonAsync(
            $"/api/admin/apps/{confidentialAppId}/oidc-policy",
            new
            {
                allowAuthorizationCode = false,
                allowedScopes = new[] { "openid" },
                allowRefreshToken = false,
                identitySessionMaxAgeSeconds = (int?)null
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, confidentialUpdate.StatusCode);
        var confidentialApp = await GetAppAsync(confidentialAppId);
        Assert.Equal(OidcClientType.Confidential, confidentialApp.ClientType);
        Assert.False(string.IsNullOrEmpty(confidentialApp.AppSecretHash));
    }

    // ---- Acceptance 6: the explicit upgrade mints a secret in the same transaction ----

    [Fact]
    public async Task PublicToConfidential_MintsASecretInsideTheUpdateTransaction()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var (_, appId) = await CreateAppAsync(admin, "Public");

        using var response = await admin.PutAsJsonAsync(
            $"/api/admin/apps/{appId}/oidc-policy",
            new
            {
                clientType = "Confidential",
                allowAuthorizationCode = false,
                allowedScopes = new[] { "openid" },
                allowRefreshToken = false,
                identitySessionMaxAgeSeconds = (int?)null
            },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var issued = JsonDocument.Parse(raw).RootElement.GetProperty("issuedAppSecret").GetString();
        Assert.False(string.IsNullOrEmpty(issued));

        // The hash is non-empty at the end and verifies against the one-time returned secret.
        var app = await GetAppAsync(appId);
        Assert.Equal(OidcClientType.Confidential, app.ClientType);
        Assert.False(string.IsNullOrEmpty(app.AppSecretHash));
        Assert.True(BCrypt.Net.BCrypt.Verify(issued, app.AppSecretHash));

        // The conversion is audited through the existing policy event, and neither the secret
        // nor the hash appears in the snapshots.
        var audit = await QueryAsync(context => context.AuditLogs.AsNoTracking()
            .SingleAsync(row => row.Action == "app_oidc_policy_updated" && row.TargetId == appId,
                TestContext.Current.CancellationToken));
        Assert.Contains("\"clientType\":\"Public\"", audit.BeforeSnapshot ?? string.Empty, StringComparison.Ordinal);
        Assert.Contains("\"clientType\":\"Confidential\"", audit.AfterSnapshot ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain(issued, audit.AfterSnapshot ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain(app.AppSecretHash, audit.AfterSnapshot ?? string.Empty, StringComparison.Ordinal);
    }

    // ---- Acceptance 7: reset-secret is refused for a Public app ----

    [Fact]
    public async Task ResetSecretOnAPublicApp_IsRejectedAndLeavesTheHashEmpty()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var (_, appId) = await CreateAppAsync(admin, "Public");

        using var response = await admin.PostAsync(
            $"/api/admin/apps/{appId}/reset-secret", content: null, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var app = await GetAppAsync(appId);
        Assert.Equal(string.Empty, app.AppSecretHash);
    }

    // ---- Acceptance 8, 9, 10: both verification surfaces fail closed, indistinguishably ----

    [Fact]
    public async Task OAuthClientAuthentication_AgainstAPublicApp_FailsClosedLikeAWrongSecret()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var (_, publicAppId) = await CreateAppAsync(admin, "Public");
        var (_, confidentialAppId) = await CreateAppAsync(admin, clientType: null);

        using var probe = _fixture.CreateHttpClient();

        // The Confidential control: a wrong secret produces the endpoint's invalid_client shape.
        using var wrongSecret = await PostTokenAsync(probe, confidentialAppId, "not-the-real-secret");
        // The Public app: any secret fails closed with the identical shape — no exception, no
        // 500, and nothing that distinguishes the type or the empty-hash state.
        using var publicAttempt = await PostTokenAsync(probe, publicAppId, "any-presented-secret");

        Assert.Equal(HttpStatusCode.Unauthorized, wrongSecret.StatusCode);
        Assert.Equal(wrongSecret.StatusCode, publicAttempt.StatusCode);
        var wrongBody = await wrongSecret.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var publicBody = await publicAttempt.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(wrongBody, publicBody);
        Assert.Contains("invalid_client", wrongBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CallbackRegistration_AgainstAPublicApp_FailsClosedLikeAWrongSecret()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var (_, publicAppId) = await CreateAppAsync(admin, "Public");
        var (_, confidentialAppId) = await CreateAppAsync(admin, clientType: null);

        using var probe = _fixture.CreateHttpClient();

        using var wrongSecret = await PostCallbackRegistrationAsync(
            probe, confidentialAppId, "not-the-real-secret");
        using var publicAttempt = await PostCallbackRegistrationAsync(
            probe, publicAppId, "any-presented-secret");

        // Identical status and body: the guard fails closed in the existing rejection shape and
        // reveals neither the client type nor the hash state.
        Assert.Equal(wrongSecret.StatusCode, publicAttempt.StatusCode);
        var wrongBody = await wrongSecret.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var publicBody = await publicAttempt.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(wrongBody, publicBody);
        Assert.NotEqual(HttpStatusCode.InternalServerError, publicAttempt.StatusCode);
    }

    // ---- Helpers ----

    private static async Task<(JsonElement Created, string AppId)> CreateAppAsync(
        HttpClient admin,
        string? clientType)
    {
        object payload = clientType is null
            ? new { appName = $"public-client-test-{Guid.NewGuid():N}", ttlSeconds = 0 }
            : new { appName = $"public-client-test-{Guid.NewGuid():N}", ttlSeconds = 0, clientType };
        using var response = await admin.PostAsJsonAsync(
            "/api/admin/apps", payload, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var created = JsonDocument.Parse(raw).RootElement.Clone();
        return (created, created.GetProperty("appId").GetString()!);
    }

    private static async Task<HttpResponseMessage> PostTokenAsync(
        HttpClient probe, string appId, string secret)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Headers =
            {
                Authorization = new AuthenticationHeaderValue(
                    "Basic",
                    Convert.ToBase64String(Encoding.UTF8.GetBytes($"{appId}:{secret}")))
            },
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = "a-token-that-never-existed"
            })
        };
        return await probe.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static async Task<HttpResponseMessage> PostCallbackRegistrationAsync(
        HttpClient probe, string appId, string secret)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/callback/register")
        {
            Headers =
            {
                { "X-Admin-AppId", appId },
                { "X-Admin-AppSecret", secret }
            },
            Content = JsonContent.Create(new { callbackUrl = "", ttlSeconds = 0 })
        };
        return await probe.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private Task<AppRegistrationEntity> GetAppAsync(string appId) =>
        QueryAsync(context => context.AppRegistrations.AsNoTracking()
            .SingleAsync(row => row.AppId == appId, TestContext.Current.CancellationToken));

    private async Task<TResult> QueryAsync<TResult>(Func<IdentityDbContext, Task<TResult>> query)
    {
        using var scope = _fixture.Services.CreateScope();
        return await query(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }
}
