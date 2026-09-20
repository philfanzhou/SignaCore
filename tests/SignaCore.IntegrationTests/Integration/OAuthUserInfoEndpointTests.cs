using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The SQLite HTTP contract of the scope-controlled OIDC UserInfo endpoint (#55): the closed
/// <c>PS-16</c> success set over the real code→token pipeline with its <c>sub</c> identical to
/// the ID-token subject, the exact <c>IN-28</c>/<c>IN-29</c> error rows (missing/malformed/
/// multiple header, alternate carriers, ID-token impersonation, tampered and legacy tokens),
/// the live-state rejections (<c>SC-10</c>–<c>SC-12</c>), the token-scope/current-allow-list
/// intersection, the no-CORS/no-store transport headers, and the <c>AC-08</c> Discovery
/// activation of <c>userinfo_endpoint</c>. Access tokens come from the real redemption endpoint,
/// never from hand-built strings.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class OAuthUserInfoEndpointTests : IClassFixture<IdentityServerFixture>
{
    private const string AppId = "userinfo-endpoint-app";
    private const string AppSecret = "userinfo-endpoint-secret-canary";
    private const string Username = "userinfo_endpoint_user";

    private const string RedirectUri = "https://bff.userinfo.test/callback?tenant=unit";
    private const string Nonce = "userinfo-nonce-0123456789abcdef";

    // RFC 7636 appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly IdentityServerFixture _fixture;

    public OAuthUserInfoEndpointTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- Acceptance 1: the PS-16 success set ----

    [Fact]
    public async Task UserInfo_WithALiveProfileToken_ReturnsTheClosedClaimSet()
    {
        var seeded = await SeedRedeemedTokenAsync("openid profile");

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization = BearerHeader(seeded.AccessToken),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Contains("no-cache", response.Headers.Pragma.ToString(), StringComparison.Ordinal);
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        // CORS: the endpoint never answers a browser — no Access-Control-* header at all.
        Assert.Empty(response.Headers.Where(header =>
            header.Key.StartsWith("Access-Control-", StringComparison.OrdinalIgnoreCase)));

        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(
            new HashSet<string>(StringComparer.Ordinal) { "sub", "name", "nickname" },
            body.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal));
        Assert.Equal(seeded.AccountId.ToString(), body.GetProperty("sub").GetString());
        Assert.Equal(Username, body.GetProperty("name").GetString());
        Assert.Equal("userinfo-nickname", body.GetProperty("nickname").GetString());

        // The sub is byte-for-byte the ID-token subject of the same flow.
        var idToken = new JwtSecurityTokenHandler().ReadJwtToken(seeded.IdToken);
        Assert.Equal(
            idToken.Claims.Single(claim => claim.Type == IdentityConstants.ClaimSubject).Value,
            body.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task UserInfo_WithoutProfileScope_ReturnsOnlySub()
    {
        var seeded = await SeedRedeemedTokenAsync("openid");

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization = BearerHeader(seeded.AccessToken),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(["sub"], body.EnumerateObject().Select(property => property.Name));
        Assert.Equal(seeded.AccountId.ToString(), body.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task UserInfo_WithAMixedCaseBearerScheme_IsAccepted()
    {
        var seeded = await SeedRedeemedTokenAsync("openid profile");

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization = new AuthenticationHeaderValue(
                "bEaReR", seeded.AccessToken),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ---- Acceptance 2: the IN-28 error rows ----

    [Fact]
    public async Task UserInfo_WithoutAnAuthorizationHeader_Answers401WithBareBearer()
    {
        await SeedRedeemedTokenAsync("openid");

        using var http = _fixture.CreateHttpClient();
        using var response = await http.GetAsync("/oauth2/userinfo", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Bearer", response.Headers.WwwAuthenticate.Single().ToString());
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    [Theory]
    [InlineData("Basic", "dXNlcjpwYXNz")]
    [InlineData("Bearer", "")]
    public async Task UserInfo_ForAMalformedHeader_Answers400InvalidRequest(
        string scheme, string parameter)
    {
        await SeedRedeemedTokenAsync("openid");

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization =
                parameter.Length == 0 ? new AuthenticationHeaderValue(scheme) : new AuthenticationHeaderValue(scheme, parameter),
            TestContext.Current.CancellationToken);

        await AssertErrorRowAsync(response, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task UserInfo_WithMultipleAuthorizationValues_Answers400InvalidRequest()
    {
        await SeedRedeemedTokenAsync("openid");

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.TryAddWithoutValidation(
                "Authorization",
                ["Bearer first-token", "Bearer second-token"]),
            TestContext.Current.CancellationToken);

        await AssertErrorRowAsync(response, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Theory]
    [InlineData("access_token")]
    [InlineData("id_token")]
    [InlineData("refresh_token")]
    [InlineData("client_secret")]
    public async Task UserInfo_ForAnAlternateCarrier_Answers400InvalidRequest(string carrier)
    {
        await SeedRedeemedTokenAsync("openid");

        using var http = _fixture.CreateHttpClient();
        using var response = await http.GetAsync(
            $"/oauth2/userinfo?{carrier}=whatever",
            TestContext.Current.CancellationToken);

        await AssertErrorRowAsync(response, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task UserInfo_WithAnOverlongToken_Answers400InvalidRequest()
    {
        await SeedRedeemedTokenAsync("openid");

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", new string('a', 8193)),
            TestContext.Current.CancellationToken);

        await AssertErrorRowAsync(response, HttpStatusCode.BadRequest, "invalid_request");
    }

    // ---- Acceptance 3: the IN-29 token rows ----

    [Fact]
    public async Task UserInfo_ForAnIdToken_Answers401InvalidToken()
    {
        var seeded = await SeedRedeemedTokenAsync("openid profile");

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization = BearerHeader(seeded.IdToken),
            TestContext.Current.CancellationToken);

        await AssertErrorRowAsync(response, HttpStatusCode.Unauthorized, "invalid_token");
    }

    [Fact]
    public async Task UserInfo_ForATamperedToken_Answers401InvalidToken()
    {
        var seeded = await SeedRedeemedTokenAsync("openid profile");
        var tampered = seeded.AccessToken[..^8] + (seeded.AccessToken[^8] == 'A' ? 'B' : 'A') + seeded.AccessToken[^7..];

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization = BearerHeader(tampered),
            TestContext.Current.CancellationToken);

        await AssertErrorRowAsync(response, HttpStatusCode.Unauthorized, "invalid_token");
    }

    [Fact]
    public async Task UserInfo_ForALegacySharedAudienceToken_Answers401InvalidToken()
    {
        await SeedRedeemedTokenAsync("openid profile");

        // A legacy password-grant access token: typ at+jwt and validly signed, but it carries
        // none of the interactive claims (sid, canonical scope) — insufficient_scope, never
        // a profile.
        using var gateway = _fixture.CreateHttpClient();
        gateway.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{IdentityServerFixture.GatewayAppId}:{IdentityServerFixture.GatewayAppSecret}")));
        var issued = await (await gateway.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = IdentityConstants.GrantTypePassword,
            ["username"] = IdentityServerFixture.AdminUsername,
            ["password"] = IdentityServerFixture.AdminPassword
        }), TestContext.Current.CancellationToken))
            .Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization = BearerHeader(issued.GetProperty("access_token").GetString()!),
            TestContext.Current.CancellationToken);

        await AssertErrorRowAsync(response, HttpStatusCode.Forbidden, "insufficient_scope");
    }

    // ---- Acceptance 4: the live-state rows (SC-10–SC-12) ----

    [Fact]
    public async Task UserInfo_AfterACommittedSessionRevocation_Answers401InvalidToken()
    {
        var seeded = await SeedRedeemedTokenAsync("openid profile");
        await ExecuteAsync(context => context.IdentitySessions
            .Where(row => row.Id == seeded.SessionId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.RevokedAt, DateTimeOffset.UtcNow)
                .SetProperty(row => row.RevocationReason, "administrative"),
                TestContext.Current.CancellationToken));

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization = BearerHeader(seeded.AccessToken),
            TestContext.Current.CancellationToken);

        await AssertErrorRowAsync(response, HttpStatusCode.Unauthorized, "invalid_token");
        // The read slides no idle deadline and writes nothing.
        var session = await QueryAsync(context => context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seeded.SessionId, TestContext.Current.CancellationToken));
        Assert.NotNull(session.RevokedAt);
    }

    [Fact]
    public async Task UserInfo_WhenTheSessionIdledOut_Answers401InvalidToken()
    {
        var seeded = await SeedRedeemedTokenAsync("openid profile");
        await ExecuteAsync(context => context.IdentitySessions
            .Where(row => row.Id == seeded.SessionId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.IdleExpiresAt, DateTimeOffset.UtcNow.AddMinutes(-1)),
                TestContext.Current.CancellationToken));

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization = BearerHeader(seeded.AccessToken),
            TestContext.Current.CancellationToken);

        await AssertErrorRowAsync(response, HttpStatusCode.Unauthorized, "invalid_token");
    }

    [Fact]
    public async Task UserInfo_WhenTheApplicationWasDeactivated_Answers401InvalidToken()
    {
        var seeded = await SeedRedeemedTokenAsync("openid profile");
        await ExecuteAsync(context => context.AppRegistrations
            .Where(row => row.Id == seeded.ApplicationId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false),
                TestContext.Current.CancellationToken));

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization = BearerHeader(seeded.AccessToken),
            TestContext.Current.CancellationToken);

        await AssertErrorRowAsync(response, HttpStatusCode.Unauthorized, "invalid_token");
    }

    [Fact]
    public async Task UserInfo_WhenTheAccountWasDisabled_Answers401InvalidToken()
    {
        var seeded = await SeedRedeemedTokenAsync("openid profile");
        await ExecuteAsync(context => context.Accounts
            .Where(row => row.Id == seeded.AccountId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false),
                TestContext.Current.CancellationToken));

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization = BearerHeader(seeded.AccessToken),
            TestContext.Current.CancellationToken);

        await AssertErrorRowAsync(response, HttpStatusCode.Unauthorized, "invalid_token");
    }

    [Fact]
    public async Task UserInfo_WhenTheApplicationMaxAgeWasExceeded_Answers401InvalidToken()
    {
        var seeded = await SeedRedeemedTokenAsync("openid profile", maxAgeSeconds: 5);
        await ExecuteAsync(context => context.IdentitySessions
            .Where(row => row.Id == seeded.SessionId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.AuthTime, DateTimeOffset.UtcNow.AddSeconds(-30)),
                TestContext.Current.CancellationToken));

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization = BearerHeader(seeded.AccessToken),
            TestContext.Current.CancellationToken);

        await AssertErrorRowAsync(response, HttpStatusCode.Unauthorized, "invalid_token");
    }

    // ---- Acceptance 5: the scope intersection (SC-11) ----

    [Fact]
    public async Task UserInfo_WhenProfileLeftTheCurrentAllowList_NarrowsTheResponse()
    {
        var seeded = await SeedRedeemedTokenAsync("openid profile");
        await ExecuteAsync(context => context.AppRegistrations
            .Where(row => row.Id == seeded.ApplicationId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.AllowedScopes, "openid"),
                TestContext.Current.CancellationToken));

        using var http = _fixture.CreateHttpClient();
        using var response = await SendAsync(
            http,
            "/oauth2/userinfo",
            request => request.Headers.Authorization = BearerHeader(seeded.AccessToken),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(["sub"], body.EnumerateObject().Select(property => property.Name));
    }

    // ---- Acceptance 6: the AC-08 Discovery activation ----

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    public async Task Discovery_AdvertisesTheDeliveredUserinfoEndpoint(string path)
    {
        using var http = _fixture.CreateHttpClient();
        var document = await http.GetFromJsonAsync<JsonElement>(path, TestContext.Current.CancellationToken);
        var origin = document.GetProperty("issuer").GetString()!.TrimEnd('/');

        Assert.Equal($"{origin}/oauth2/userinfo", document.GetProperty("userinfo_endpoint").GetString());
    }

    // ---- Seeding and helpers ----

    private sealed record SeededToken(
        string AccessToken,
        string IdToken,
        Guid SessionId,
        Guid AccountId,
        Guid ApplicationId);

    /// <summary>
    /// Seeds the full interactive pipeline through the real endpoints: one code, redeemed for
    /// the access and ID token the test then presents.
    /// </summary>
    private async Task<SeededToken> SeedRedeemedTokenAsync(string scope, int? maxAgeSeconds = null)
    {
        var applicationId = await SeedAppAsync(maxAgeSeconds);
        using var scope_ = _fixture.Services.CreateScope();
        var dbContext = scope_.ServiceProvider.GetRequiredService<IdentityDbContext>();

        var credential = await dbContext.PasswordCredentials
            .AsNoTracking()
            .FirstOrDefaultAsync(row => row.Username == Username, TestContext.Current.CancellationToken);
        Guid accountId;
        Guid credentialId;
        if (credential is not null)
        {
            var account = await dbContext.Accounts
                .SingleAsync(row => row.Id == credential.AccountId, TestContext.Current.CancellationToken);
            account.IsActive = true;
            account.Nickname = "userinfo-nickname";
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
            (accountId, credentialId) = (credential.AccountId, credential.Id);
        }
        else
        {
            accountId = Guid.NewGuid();
            credentialId = Guid.NewGuid();
            dbContext.Accounts.Add(new AccountEntity
            {
                Id = accountId,
                IsActive = true,
                Nickname = "userinfo-nickname",
                CreatedAt = DateTimeOffset.UtcNow
            });
            dbContext.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = credentialId,
                AccountId = accountId,
                Username = Username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("userinfo-user-secret"),
                CreatedAt = DateTimeOffset.UtcNow
            });
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        dbContext.ChangeTracker.Clear();
        var sessions = scope_.ServiceProvider.GetRequiredService<IIdentitySessionStore>();
        var codes = scope_.ServiceProvider.GetRequiredService<IAuthorizationCodeStore>();
        var now = DateTimeOffset.UtcNow;
        var session = await sessions.CreateAsync(accountId, credentialId, now, TestContext.Current.CancellationToken);
        var creation = await codes.CreateAsync(
            session,
            new AuthorizationCodeBinding(applicationId, RedirectUri, scope, Nonce, Challenge),
            now,
            TestContext.Current.CancellationToken);

        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{AppId}:{AppSecret}")));
        using var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = creation.Code,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = Verifier
        }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        return new SeededToken(
            body.GetProperty("access_token").GetString()!,
            body.GetProperty("id_token").GetString()!,
            session.Id,
            accountId,
            applicationId);
    }

    private async Task<Guid> SeedAppAsync(int? maxAgeSeconds = null)
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var application = await dbContext.AppRegistrations
            .FirstOrDefaultAsync(row => row.AppId == AppId, TestContext.Current.CancellationToken);
        if (application is null)
        {
            application = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = AppId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword(AppSecret),
                AppName = "UserInfo Endpoint Client",
                CreatedAt = DateTimeOffset.UtcNow
            };
            dbContext.AppRegistrations.Add(application);
        }

        application.IsActive = true;
        application.AudienceMode = AudienceMode.PerApplication;
        application.ClientType = OidcClientType.Confidential;
        application.AllowAuthorizationCode = true;
        application.AllowedScopes = "openid profile";
        application.AllowRefreshToken = false;
        application.IdentitySessionMaxAgeSeconds = maxAgeSeconds;
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        return application.Id;
    }

    private static AuthenticationHeaderValue BearerHeader(string token) => new("Bearer", token);

    private static async Task<HttpResponseMessage> SendAsync(
        HttpClient http,
        string path,
        Action<HttpRequestMessage> configure,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        configure(request);
        return await http.SendAsync(request, cancellationToken);
    }

    private static async Task AssertErrorRowAsync(
        HttpResponseMessage response,
        HttpStatusCode expectedStatus,
        string expectedError)
    {
        Assert.Equal(expectedStatus, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var challenge = response.Headers.WwwAuthenticate.Single().ToString();
        Assert.StartsWith("Bearer ", challenge, StringComparison.Ordinal);
        Assert.Contains($"error=\"{expectedError}\"", challenge, StringComparison.Ordinal);
        // The challenge names the class, never the failed predicate.
        Assert.DoesNotContain("signature", challenge, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("session", challenge, StringComparison.OrdinalIgnoreCase);
    }

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
