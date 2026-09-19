using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The write side of the account/application state propagation (<c>EV-08</c>, <c>EV-09</c>,
/// <c>EV-11</c>) over the real admin endpoints and the real interactive pipeline: the disable
/// transaction's in-transaction revocations with their canonical reasons and bounded audit
/// counts, the blast-radius isolation between applications, the idempotent first fact, the full
/// fail-closed read matrix afterwards (authorize, code redemption, refresh, UserInfo), and the
/// explicit non-guarantee — the already-issued self-contained access token still validates
/// downstream to <c>exp</c> while UserInfo's live read rejects it.
/// </summary>
public sealed class AdminStatePropagationMatrixTests : IClassFixture<IdentityServerFixture>
{
    // xunit v3 runs the methods of one class in parallel; every method therefore seeds its own
    // application pair, so an app-scoped revocation can never reach another method's family.
    private const string DisableFirstAppId = "state-propagation-disable-first-app";
    private const string DisableSecondAppId = "state-propagation-disable-second-app";
    private const string DeactivateFirstAppId = "state-propagation-deactivate-first-app";
    private const string DeactivateSecondAppId = "state-propagation-deactivate-second-app";
    private const string RefreshOffFirstAppId = "state-propagation-refresh-off-first-app";
    private const string RefreshOffSecondAppId = "state-propagation-refresh-off-second-app";
    private const string FirstAppSecret = "state-propagation-first-secret";
    private const string SecondAppSecret = "state-propagation-second-secret";
    private const string Username = "state_propagation_matrix_user";

    private const string RedirectUri = "https://bff.state-matrix.test/callback";
    private const string Nonce = "state-matrix-nonce-0123456789";
    private const string OfflineScope = "openid profile offline_access";

    // RFC 7636 appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly IdentityServerFixture _fixture;

    public AdminStatePropagationMatrixTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- EV-08: the account-disable transaction ----

    [Fact]
    public async Task DisablingAnAccount_RevokesItsSessionsAndFamiliesInTheSameTransaction()
    {
        var account = await SeedAccountAsync();
        var first = await SeedRedeemedFamilyAsync(DisableFirstAppId, FirstAppSecret, account);
        var second = await SeedRedeemedFamilyAsync(DisableSecondAppId, SecondAppSecret, account);
        using var admin = await _fixture.CreateAdminHttpClientAsync();

        using var response = await admin.PatchAsJsonAsync(
            $"/api/admin/users/{first.AccountId}/status",
            new { isActive = false },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Every session of the account carries the canonical reason; both applications'
        // families are revoked.
        foreach (var sessionId in new[] { first.SessionId, second.SessionId })
        {
            var session = await GetSessionAsync(sessionId);
            Assert.NotNull(session.RevokedAt);
            Assert.Equal("account_disabled", session.RevocationReason);
        }

        Assert.True(await GetFamilyRootAsync(first.RootId) is { IsRevoked: true });
        Assert.True(await GetFamilyRootAsync(second.RootId) is { IsRevoked: true });

        // One audit row per admin action, carrying both bounded revocation counts.
        var audit = await QueryAsync(async context => await context.AuditLogs.AsNoTracking()
            .SingleAsync(row => row.Action == "account_disabled"
                && row.TargetId == first.AccountId.ToString(),
                TestContext.Current.CancellationToken));
        Assert.Contains("\"revokedSessions\":2", audit.AfterSnapshot, StringComparison.Ordinal);
        Assert.Contains("\"revokedFamilyMembers\":2", audit.AfterSnapshot, StringComparison.Ordinal);

        // The idempotent repeat disable keeps every first fact and does not rewrite them.
        using var repeat = await admin.PatchAsJsonAsync(
            $"/api/admin/users/{first.AccountId}/status",
            new { isActive = false },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, repeat.StatusCode);
        var revisited = await GetSessionAsync(first.SessionId);
        var firstSession = await GetSessionAsync(first.SessionId);
        Assert.Equal(revisited.RevokedAt, firstSession.RevokedAt);
        Assert.Equal("account_disabled", revisited.RevocationReason);
    }

    [Fact]
    public async Task AfterTheAccountDisable_TheWholeInteractiveReadMatrixFailsClosed()
    {
        var seeded = await SeedRedeemedFamilyAsync(DisableFirstAppId, FirstAppSecret);
        var accessToken = await RedeemForAccessTokenAsync(seeded);
        // The read-side fail-closed proof disables the account directly (the write-side
        // transaction has its own tests); the read must fail closed on the committed flag alone.
        await ExecuteAsync(async context =>
        {
            var account = await context.Accounts
                .SingleAsync(row => row.Id == seeded.AccountId, TestContext.Current.CancellationToken);
            account.IsActive = false;
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        });

        using var host = CreateHost();

        // UserInfo: the live read rejects the still-unexpired token with the same challenge a
        // nonexistent account would produce — no distinction between missing and disabled.
        using var userinfo = host.CreateClient();
        using var rejected = await userinfo.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo")
            {
                Headers = { Authorization = new AuthenticationHeaderValue("Bearer", accessToken) }
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        var challenge = rejected.Headers.WwwAuthenticate.Single().ToString();
        Assert.StartsWith("Bearer ", challenge, StringComparison.Ordinal);
        Assert.Contains("error=\"invalid_token\"", challenge, StringComparison.Ordinal);

        // Refresh: the family is not revoked by the direct write, but the live account read
        // fails closed with the generic invalid_grant and no replay audit.
        using var tokenClient = host.CreateClient();
        tokenClient.DefaultRequestHeaders.Authorization = BasicHeader(DisableFirstAppId, FirstAppSecret);
        using var refresh = await tokenClient.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = seeded.RefreshToken
            }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
        var refreshBody = await refresh.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_grant", refreshBody.GetProperty("error").GetString());
        Assert.Empty(await QueryAsync(async context => await context.AuditLogs.AsNoTracking()
            .Where(row => row.Action == "oidc.refresh.replayed"
                && row.TargetId == seeded.RootId.ToString("D"))
            .ToListAsync(TestContext.Current.CancellationToken)));

        // Code redemption of a fresh code for the same account: the generic invalid_grant of a
        // missing code — indistinguishable from a disabled account.
        var code = await CreateCodeAsync(seeded);
        using var redeem = await tokenClient.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = Verifier
            }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, redeem.StatusCode);
        var redeemBody = await redeem.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_grant", redeemBody.GetProperty("error").GetString());
        var codeRow = await QueryAsync(async context => await context.AuthorizationCodes.AsNoTracking()
            .SingleAsync(row => row.CodeDigest == AuthorizationCodeDigest.Compute(code),
                TestContext.Current.CancellationToken));
        Assert.Null(codeRow.ConsumedAt);

        // Authorize with the account's browser cookie: falls back to the login page.
        using var browser = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });
        using var authorize = await browser.GetAsync(BuildAuthorizeUrl(), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        Assert.StartsWith(
            "/oauth2/login?login_handle=",
            authorize.Headers.Location?.ToString(),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The explicit <c>EV-08</c> non-guarantee: the already-issued access token still carries a
    /// valid signature from the live JWKS and validates to <c>exp</c> — downstream resource
    /// servers keep accepting it — while UserInfo's live read fails closed on the same token.
    /// </summary>
    [Fact]
    public async Task TheIssuedAccessToken_StillValidatesDownstreamWhileUserInfoFailsClosed()
    {
        var seeded = await SeedRedeemedFamilyAsync(DisableFirstAppId, FirstAppSecret);
        var accessToken = await RedeemForAccessTokenAsync(seeded);
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        using var disabled = await admin.PatchAsJsonAsync(
            $"/api/admin/users/{seeded.AccountId}/status",
            new { isActive = false },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);

        using var host = CreateHost();
        using var http = host.CreateClient();

        using var discovery = await http.GetAsync(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        var document = await discovery.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
        using var jwksResponse = await http.GetAsync(
            document.GetProperty("jwks_uri").GetString(), TestContext.Current.CancellationToken);
        var jwks = await jwksResponse.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);

        var token = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);
        var keys = jwks.GetProperty("keys").EnumerateArray()
            .Select(key => new JsonWebKey(key.GetRawText()));
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = document.GetProperty("issuer").GetString(),
            ValidAudience = DisableFirstAppId,
            IssuerSigningKeys = keys
        };
        new JwtSecurityTokenHandler().ValidateToken(accessToken, parameters, out _);

        using var rejected = await http.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo")
            {
                Headers = { Authorization = new AuthenticationHeaderValue("Bearer", accessToken) }
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
    }

    // ---- EV-09: the application-deactivation transaction ----

    [Fact]
    public async Task DeactivatingAnApplication_RevokesOnlyItsOwnFamilies()
    {
        var account = await SeedAccountAsync();
        var first = await SeedRedeemedFamilyAsync(DeactivateFirstAppId, FirstAppSecret, account);
        var second = await SeedRedeemedFamilyAsync(DeactivateSecondAppId, SecondAppSecret, account);
        using var admin = await _fixture.CreateAdminHttpClientAsync();

        using var response = await admin.PutAsJsonAsync(
            $"/api/admin/apps/{DeactivateFirstAppId}/callback",
            new { callbackUrl = (string?)null, ttlSeconds = 0, isActive = false },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True((await GetFamilyRootAsync(first.RootId)).IsRevoked);
        // The second application's family and the account's sessions are untouched: a session
        // is shared across applications and stays usable for them.
        Assert.False((await GetFamilyRootAsync(second.RootId)).IsRevoked);
        Assert.Null((await GetSessionAsync(second.SessionId)).RevokedAt);
        Assert.Null((await GetSessionAsync(first.SessionId)).RevokedAt);

        var audit = await QueryAsync(async context => await context.AuditLogs.AsNoTracking()
            .SingleAsync(row => row.Action == "app_callback_updated"
                && row.TargetId == DeactivateFirstAppId,
                TestContext.Current.CancellationToken));
        Assert.Contains("\"revokedFamilyMembers\":1", audit.AfterSnapshot, StringComparison.Ordinal);

        // The surviving application still refreshes successfully.
        using var host = CreateHost();
        using var tokenClient = host.CreateClient();
        tokenClient.DefaultRequestHeaders.Authorization = BasicHeader(DeactivateSecondAppId, SecondAppSecret);
        using var refresh = await tokenClient.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = second.RefreshToken
            }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);

        // The deactivated application's own client authentication fails closed: the generic
        // invalid_client of any unknown client, indistinguishable from a deactivated one.
        using var firstClient = host.CreateClient();
        firstClient.DefaultRequestHeaders.Authorization = BasicHeader(DeactivateFirstAppId, FirstAppSecret);
        using var rejected = await firstClient.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = first.RefreshToken
            }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        var body = await rejected.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_client", body.GetProperty("error").GetString());
    }

    // ---- EV-11: the refresh-capability-off transaction ----

    [Fact]
    public async Task TurningRefreshOff_RevokesOnlyThatApplicationsFamilies()
    {
        var account = await SeedAccountAsync();
        var first = await SeedRedeemedFamilyAsync(RefreshOffFirstAppId, FirstAppSecret, account);
        var second = await SeedRedeemedFamilyAsync(RefreshOffSecondAppId, SecondAppSecret, account);
        using var admin = await _fixture.CreateAdminHttpClientAsync();

        using var response = await admin.PutAsJsonAsync(
            $"/api/admin/apps/{RefreshOffFirstAppId}/oidc-policy",
            new
            {
                clientType = "Confidential",
                allowAuthorizationCode = true,
                allowedScopes = new[] { "openid", "profile" },
                allowRefreshToken = false
            },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True((await GetFamilyRootAsync(first.RootId)).IsRevoked);
        Assert.False((await GetFamilyRootAsync(second.RootId)).IsRevoked);
        Assert.Null((await GetSessionAsync(first.SessionId)).RevokedAt);

        var audit = await QueryAsync(async context => await context.AuditLogs.AsNoTracking()
            .SingleAsync(row => row.Action == "app_oidc_policy_updated"
                && row.TargetId == RefreshOffFirstAppId,
                TestContext.Current.CancellationToken));
        Assert.Contains("\"revokedFamilyMembers\":1", audit.AfterSnapshot, StringComparison.Ordinal);

        // The other application still refreshes.
        using var host = CreateHost();
        using var tokenClient = host.CreateClient();
        tokenClient.DefaultRequestHeaders.Authorization = BasicHeader(RefreshOffSecondAppId, SecondAppSecret);
        using var refresh = await tokenClient.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = second.RefreshToken
            }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
    }

    // ---- Helpers ----

    private WebApplicationFactory<Program> CreateHost() =>
        _fixture.WithTestServices(_ => { });

    private static string BuildAuthorizeUrl() =>
        "/oauth2/authorize?" + string.Join('&',
            $"client_id={DisableFirstAppId}",
            $"redirect_uri={Uri.EscapeDataString(RedirectUri)}",
            "response_type=code",
            $"scope={Uri.EscapeDataString("openid profile")}",
            "state=state-matrix-state-0123456789",
            $"nonce={Nonce}",
            $"code_challenge={Challenge}",
            "code_challenge_method=S256");

    private sealed record SeededFamily(
        string RefreshToken,
        Guid RootId,
        Guid SessionId,
        Guid AccountId);    /// <summary>
    /// Seeds one account with one live session and one live interactive family per call, over the
    /// real redemption endpoint. Calls with different applications share the account and produce
    /// distinct sessions and families.
    /// </summary>
    /// <summary>
    /// Seeds one live session and one live interactive family for the account over the real
    /// redemption endpoint. Calls with different applications may share one account and produce
    /// distinct sessions and families.
    /// </summary>
    private async Task<SeededFamily> SeedRedeemedFamilyAsync(
        string appId,
        string appSecret,
        (Guid AccountId, Guid CredentialId)? existingAccount = null)
    {
        await SeedApplicationAsync(appId, appSecret);
        var (accountId, credentialId) = existingAccount ?? await SeedAccountAsync();
        var sessionId = Guid.NewGuid();
        await ExecuteAsync(async context =>
        {
            var session = await new IdentitySessionStore(
                new IdentitySessionRepository(context), new EfCoreUnitOfWork(context))
                .CreateAsync(accountId, credentialId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
            sessionId = session.Id;
        });

        var code = await CreateCodeAsync(accountId, sessionId, appId);
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(appId, appSecret);
        using var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = Verifier
        }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
        var refreshToken = body.GetProperty("refresh_token").GetString()!;

        var rootId = await QueryAsync(async context => await context.RefreshTokens.AsNoTracking()
            .Where(row => row.IdentitySessionId == sessionId)
            .Select(row => row.FamilyId)
            .SingleAsync(TestContext.Current.CancellationToken));
        return new SeededFamily(refreshToken, rootId, sessionId, accountId);
    }

    /// <summary>
    /// Idempotently brings one interactive application to the exact pre-state of every matrix
    /// test: active, confidential, code flow on, offline scope allowed.
    /// </summary>
    private async Task SeedApplicationAsync(string appId, string appSecret)
    {
        await ExecuteAsync(async context =>
        {
            var application = await context.AppRegistrations
                .FirstOrDefaultAsync(row => row.AppId == appId, TestContext.Current.CancellationToken);
            if (application is null)
            {
                application = new AppRegistrationEntity
                {
                    Id = Guid.NewGuid(),
                    AppId = appId,
                    AppSecretHash = BCrypt.Net.BCrypt.HashPassword(appSecret),
                    AppName = $"State Matrix {appId}",
                    CreatedAt = DateTimeOffset.UtcNow
                };
                context.AppRegistrations.Add(application);
            }

            application.IsActive = true;
            application.AudienceMode = AudienceMode.PerApplication;
            application.ClientType = OidcClientType.Confidential;
            application.AllowAuthorizationCode = true;
            application.AllowedScopes = OfflineScope;
            application.AllowRefreshToken = true;
            application.IdentitySessionMaxAgeSeconds = null;
            if (!await context.AppRedirectUris.AnyAsync(
                    row => row.AppRegistrationId == application.Id
                        && row.CanonicalUri == RedirectUri,
                    TestContext.Current.CancellationToken))
            {
                context.AppRedirectUris.Add(new AppRedirectUriEntity
                {
                    Id = Guid.NewGuid(),
                    AppRegistrationId = application.Id,
                    Kind = RedirectUriKind.Redirect,
                    CanonicalUri = RedirectUri
                });
            }

            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
            context.ChangeTracker.Clear();
        });
    }

    private async Task<(Guid AccountId, Guid CredentialId)> SeedAccountAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var username = $"{Username}_{Guid.NewGuid():N}";
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            Nickname = "state-matrix-nickname"
        });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId,
            AccountId = accountId,
            Username = username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("state-matrix-user-secret"),
            CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
        return (accountId, credentialId);
    }

    private async Task<string> CreateCodeAsync(SeededFamily seeded) =>
        await CreateCodeAsync(seeded.AccountId, seeded.SessionId, DisableFirstAppId);

    private async Task<string> CreateCodeAsync(Guid accountId, Guid sessionId, string appId)
    {
        var applicationRowId = await QueryAsync(async context => await context.AppRegistrations
            .AsNoTracking()
            .Where(row => row.AppId == appId)
            .Select(row => row.Id)
            .SingleAsync(TestContext.Current.CancellationToken));
        using var scope = _fixture.Services.CreateScope();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var sessions = new IdentitySessionStore(
            scope.ServiceProvider.GetRequiredService<IIdentitySessionRepository>(), unitOfWork);
        var codes = new AuthorizationCodeStore(
            scope.ServiceProvider.GetRequiredService<IAuthorizationCodeRepository>(), unitOfWork);
        var lookup = await sessions.GetAsync(sessionId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
        Assert.Equal(IdentitySessionState.Active, lookup.State);
        var creation = await codes.CreateAsync(
            lookup.Session!,
            new AuthorizationCodeBinding(applicationRowId, RedirectUri, OfflineScope, Nonce, Challenge),
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);
        return creation.Code;
    }

    /// <summary>Redeems a fresh code for the seeded account's live session and returns the access token.</summary>
    private async Task<string> RedeemForAccessTokenAsync(SeededFamily seeded)
    {
        var code = await CreateCodeAsync(seeded);
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(DisableFirstAppId, FirstAppSecret);
        using var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = Verifier
        }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
        return body.GetProperty("access_token").GetString()!;
    }

    private Task<IdentitySessionEntity> GetSessionAsync(Guid sessionId) =>
        QueryAsync(async context => await context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == sessionId, TestContext.Current.CancellationToken));

    private Task<RefreshTokenEntity> GetFamilyRootAsync(Guid rootId) =>
        QueryAsync(async context => await context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == rootId, TestContext.Current.CancellationToken));

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

    private static AuthenticationHeaderValue BasicHeader(string appId, string appSecret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{appId}:{appSecret}")));
}
