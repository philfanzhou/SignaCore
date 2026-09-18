using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The admin-console contract of the identity-session view and revocation (<c>EV-15</c>): the
/// policy gate, the paged non-sensitive listing (unknown account → 404), the single-transaction
/// administrative revocation with its idempotent first fact, the family revocation in the same
/// unit, the bounded audit row, and the full-chain effect — a revoked session's bound code fails
/// redemption and its browser cookie falls back to the login page.
/// </summary>
public sealed class AdminIdentitySessionEndpointTests : IClassFixture<IdentityServerFixture>
{
    private const string Username = "admin_session_contract_user";
    private const string Password = "AdminSessionContract123";
    private const string AppId = "admin-session-contract-app";
    private const string AppSecret = "admin-session-contract-secret";
    private const string RegisteredRedirectUri = "https://bff.admin-session.test/callback";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly IdentityServerFixture _fixture;

    public AdminIdentitySessionEndpointTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task WithoutAnAdminSession_BothEndpointsAreRejected()
    {
        using var host = CreateHost();
        using var http = host.CreateClient();

        using var list = await http.GetAsync(
            $"/api/admin/users/{Guid.NewGuid()}/identity-sessions", TestContext.Current.CancellationToken);
        using var revoke = await http.PostAsync(
            $"/api/admin/users/{Guid.NewGuid()}/identity-sessions/{Guid.NewGuid()}/revoke",
            content: null,
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, list.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, revoke.StatusCode);
    }

    [Fact]
    public async Task Listing_AnswersTheNonSensitiveProjectionAnd404ForAnUnknownAccount()
    {
        using var host = CreateHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        using var http = await _fixture.CreateAdminHttpClientAsync();

        var page = await http.GetFromJsonAsync<JsonElement>(
            $"/api/admin/users/{accountId}/identity-sessions",
            TestContext.Current.CancellationToken);
        Assert.Equal(1, page.GetProperty("total").GetInt32());
        var item = page.GetProperty("items").EnumerateArray().Single();
        Assert.Equal(sessionId.ToString(), item.GetProperty("id").GetString());
        Assert.Equal("active", item.GetProperty("status").GetString());
        Assert.Equal("Password", item.GetProperty("authMethod").GetString());
        Assert.True(item.GetProperty("authTime").GetInt64() > 0);
        Assert.True(item.GetProperty("lastSeenAt").GetInt64() > 0);
        Assert.True(item.GetProperty("idleExpiresAt").GetInt64() > 0);
        Assert.True(item.GetProperty("absoluteExpiresAt").GetInt64() > 0);
        Assert.Equal(JsonValueKind.Null, item.GetProperty("revokedAt").ValueKind);
        Assert.Equal(JsonValueKind.Null, item.GetProperty("revocationReason").ValueKind);
        // The credential id is the one non-sensitive-facing field of the row and never appears.
        foreach (var property in item.EnumerateObject())
        {
            Assert.NotEqual("passwordCredentialId", property.Name);
        }

        using var unknown = await http.GetAsync(
            $"/api/admin/users/{Guid.NewGuid()}/identity-sessions", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
    }

    [Fact]
    public async Task Revoking_AnUnknownOrForeignSessionAnswers404()
    {
        using var host = CreateHost();
        var (accountId, _, _) = await LoginAndCaptureSessionAsync(host);
        var (_, otherSessionId, _) = await LoginAndCaptureSessionAsync(host);
        using var http = await _fixture.CreateAdminHttpClientAsync();

        using var unknown = await http.PostAsync(
            $"/api/admin/users/{accountId}/identity-sessions/{Guid.NewGuid()}/revoke",
            content: null,
            TestContext.Current.CancellationToken);
        // The named session exists but belongs to another account.
        using var foreign = await http.PostAsync(
            $"/api/admin/users/{accountId}/identity-sessions/{otherSessionId}/revoke",
            content: null,
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Null((await GetSessionAsync(otherSessionId)).RevokedAt);
    }

    [Fact]
    public async Task Revoking_RevokesTheSessionAndBoundFamiliesOnceAndIsIdempotent()
    {
        using var host = CreateHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        var familyRootId = await SeedInteractiveFamilyAsync(accountId, sessionId);
        using var http = await _fixture.CreateAdminHttpClientAsync();

        var first = await ReadRevokeResponseAsync(http, accountId, sessionId);
        Assert.True(first.GetProperty("success").GetBoolean());
        Assert.Equal("Identity session revoked.", first.GetProperty("message").GetString());

        var session = await GetSessionAsync(sessionId);
        Assert.NotNull(session.RevokedAt);
        Assert.Equal("administrative", session.RevocationReason);
        var family = await QueryAsync(async dbContext =>
            await dbContext.RefreshTokens.AsNoTracking()
                .SingleAsync(row => row.Id == familyRootId, TestContext.Current.CancellationToken));
        Assert.True(family.IsRevoked);

        // One bounded audit row names the session and the account.
        var audits = await QueryAsync(async dbContext =>
            await dbContext.AuditLogs.AsNoTracking()
                .Where(log => log.Action == "identity_session_revoked"
                    && log.TargetId == sessionId.ToString("D"))
                .ToListAsync(TestContext.Current.CancellationToken));
        var audit = Assert.Single(audits);
        Assert.Equal("IdentitySession", audit.TargetType);
        Assert.Contains($"account:{accountId}", audit.Description, StringComparison.Ordinal);

        // The idempotent retry succeeds, keeps the first revocation fact, and is itself audited
        // with the already_revoked result classification — one row per admin action.
        var second = await ReadRevokeResponseAsync(http, accountId, sessionId);
        Assert.True(second.GetProperty("success").GetBoolean());
        Assert.Contains("already revoked", second.GetProperty("message").GetString(), StringComparison.Ordinal);
        var revisted = await GetSessionAsync(sessionId);
        Assert.Equal(session.RevokedAt, revisted.RevokedAt);
        var auditRows = await QueryAsync(async dbContext =>
            await dbContext.AuditLogs.AsNoTracking()
                .Where(log => log.Action == "identity_session_revoked"
                    && log.TargetId == sessionId.ToString("D"))
                .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal(2, auditRows.Count);
        Assert.Single(auditRows, row => row.Description.Contains("already_revoked", StringComparison.Ordinal));
        Assert.Single(auditRows, row => !row.Description.Contains("already_revoked", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AfterAnAdministrativeRevocation_TheBoundCodeFailsAndTheBrowserFallsBackToLogin()
    {
        using var host = CreateHost();
        var (accountId, sessionId, cookieValue) = await LoginAndCaptureSessionAsync(host);
        var code = await SeedCodeAsync(accountId, sessionId);
        using var admin = await _fixture.CreateAdminHttpClientAsync();

        var revoked = await ReadRevokeResponseAsync(admin, accountId, sessionId);
        Assert.True(revoked.GetProperty("success").GetBoolean());

        // The bound code stays unconsumed and redemption fails the live-session check.
        using var redeem = host.CreateClient();
        redeem.DefaultRequestHeaders.Authorization = BasicHeader();
        var response = await redeem.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = RegisteredRedirectUri,
                ["code_verifier"] = Verifier
            }),
            TestContext.Current.CancellationToken);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
        var codeRow = await QueryAsync(async dbContext =>
            await dbContext.AuthorizationCodes.AsNoTracking()
                .SingleAsync(row => row.CodeDigest == AuthorizationCodeDigest.Compute(code), TestContext.Current.CancellationToken));
        Assert.Null(codeRow.ConsumedAt);

        // The revoked session's browser cookie no longer authorizes a code: the authorize
        // endpoint falls back to the login page.
        using var browser = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });
        using var authorize = await browser.GetAsync(
            "/oauth2/authorize?" + string.Join('&',
                $"client_id={AppId}",
                $"redirect_uri={Uri.EscapeDataString(RegisteredRedirectUri)}",
                "response_type=code",
                "scope=openid%20profile",
                "state=admin-session-state-0123456789",
                "nonce=admin-session-nonce-0123456789",
                $"code_challenge={Challenge}",
                "code_challenge_method=S256")
            , TestContext.Current.CancellationToken);
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            "/oauth2/authorize?" + string.Join('&',
                $"client_id={AppId}",
                $"redirect_uri={Uri.EscapeDataString(RegisteredRedirectUri)}",
                "response_type=code",
                "scope=openid%20profile",
                "state=admin-session-state-0123456789",
                "nonce=admin-session-nonce-0123456789",
                $"code_challenge={Challenge}",
                "code_challenge_method=S256"));
        request.Headers.TryAddWithoutValidation(
            "Cookie", $"{IdentitySessionDefaults.CookieName}={cookieValue}");
        using var withCookie = await browser.SendAsync(request, TestContext.Current.CancellationToken);

        foreach (var response2 in new[] { authorize, withCookie })
        {
            Assert.Equal(HttpStatusCode.Found, response2.StatusCode);
            Assert.StartsWith(
                "/oauth2/login?login_handle=",
                response2.Headers.Location?.ToString(),
                StringComparison.Ordinal);
        }
    }

    // ---- Helpers ----

    private static async Task<JsonElement> ReadRevokeResponseAsync(
        HttpClient http,
        Guid accountId,
        Guid sessionId)
    {
        using var response = await http.PostAsync(
            $"/api/admin/users/{accountId}/identity-sessions/{sessionId}/revoke",
            content: null,
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
    }

    private WebApplicationFactory<Program> CreateHost() =>
        _fixture.WithTestServices(_ => { });

    private static AuthenticationHeaderValue BasicHeader() =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{AppId}:{AppSecret}")));

    private async Task<Guid> SeedAppAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var application = await dbContext.AppRegistrations
            .FirstOrDefaultAsync(app => app.AppId == AppId, TestContext.Current.CancellationToken);
        if (application is null)
        {
            application = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = AppId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword(AppSecret),
                AppName = "Admin Session Contract App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = "openid profile",
                AllowRefreshToken = false
            };
            dbContext.AppRegistrations.Add(application);
            dbContext.AppRedirectUris.Add(new AppRedirectUriEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = application.Id,
                Kind = RedirectUriKind.Redirect,
                CanonicalUri = RegisteredRedirectUri
            });
        }

        application.IsActive = true;
        application.AllowAuthorizationCode = true;
        application.AllowedScopes = "openid profile";
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        dbContext.ChangeTracker.Clear();
        return application.Id;
    }

    private async Task<(Guid AccountId, Guid SessionId, string CookieValue)> LoginAndCaptureSessionAsync(
        WebApplicationFactory<Program> host)
    {
        var username = $"{Username}_{Guid.NewGuid():N}";
        var accountId = await OAuthLoginTestSupport.SeedUserAsync(_fixture.Services, username, Password);
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });
        var cookieValue = await OAuthLoginTestSupport.CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, client, username, Password);

        var sessionId = await QueryAsync(async dbContext =>
            await dbContext.IdentitySessions.AsNoTracking()
                .Where(session => session.AccountId == accountId)
                .OrderByDescending(session => session.AuthTime)
                .Select(session => session.Id)
                .FirstAsync(TestContext.Current.CancellationToken));
        return (accountId, sessionId, cookieValue);
    }

    private async Task<Guid> SeedInteractiveFamilyAsync(Guid accountId, Guid sessionId)
    {
        var now = DateTimeOffset.UtcNow;
        var rootId = Guid.NewGuid();
        await ExecuteAsync(async dbContext =>
        {
            dbContext.RefreshTokens.Add(new RefreshTokenEntity
            {
                Id = rootId,
                FamilyId = rootId,
                AccountId = accountId,
                TokenValue = RefreshTokenDigest.Compute("admin-session-family-" + sessionId.ToString("N")),
                CreatedAt = now,
                ExpiresAt = now.AddDays(7),
                AppId = AppId,
                IdentitySessionId = sessionId,
                Scope = "openid profile offline_access",
                AuthTime = now.AddMinutes(-10)
            });
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        });
        return rootId;
    }

    private async Task<string> SeedCodeAsync(Guid accountId, Guid sessionId)
    {
        var applicationRowId = await SeedAppAsync();
        using var scope = _fixture.Services.CreateScope();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var sessions = new IdentitySessionStore(
            scope.ServiceProvider.GetRequiredService<IIdentitySessionRepository>(), unitOfWork);
        var codes = new AuthorizationCodeStore(
            scope.ServiceProvider.GetRequiredService<IAuthorizationCodeRepository>(), unitOfWork);
        var lookup = await sessions.GetAsync(sessionId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
        var creation = await codes.CreateAsync(
            lookup.Session!,
            new AuthorizationCodeBinding(applicationRowId, RegisteredRedirectUri, "openid profile", "admin-session-nonce", Challenge),
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);
        return creation.Code;
    }

    private async Task<IdentitySessionEntity> GetSessionAsync(Guid sessionId) =>
        await QueryAsync(async dbContext =>
            await dbContext.IdentitySessions.AsNoTracking()
                .SingleAsync(row => row.Id == sessionId, TestContext.Current.CancellationToken));

    private async Task<TResult> QueryAsync<TResult>(Func<IdentityDbContext, Task<TResult>> query)
    {
        using var scope = _fixture.Services.CreateScope();
        return await query(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    private async Task ExecuteAsync(Func<IdentityDbContext, Task> action)
    {
        using var scope = _fixture.Services.CreateScope();
        await action(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }
}
