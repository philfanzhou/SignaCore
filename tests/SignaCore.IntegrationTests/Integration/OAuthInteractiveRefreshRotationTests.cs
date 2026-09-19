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
/// The SQLite HTTP contract of the interactive <c>refresh_token</c> branch (#98): the exact
/// <c>PS-15</c> success response of one committed rotation and of a chained rotation, the
/// <c>EV-31</c> reuse disposal with its one id-only audit, the single-instance <c>EV-30</c>
/// concurrency outcome, the <c>EV-32</c> family-revoking rejections, the legacy boundary
/// (<c>EV-33</c> — a legacy presentation keeps its own wire answers), the
/// <c>IN-20</c>/<c>IN-26</c>/<c>IN-27</c> input contract, the <c>AC-12</c> Discovery activation,
/// and the <c>DF-09</c> canary scan of the audit surface. Tokens, codes, and sessions are
/// obtained through the real endpoints and stores, never raw SQL.
/// </summary>
public sealed class OAuthInteractiveRefreshRotationTests : IClassFixture<IdentityServerFixture>
{
    private const string AppId = "refresh-rotation-app";
    private const string AppSecret = "refresh-rotation-secret-canary";
    private const string OtherAppId = "refresh-rotation-other-app";
    private const string OtherAppSecret = "refresh-rotation-other-secret";
    private const string Username = "refresh_rotation_user";

    private const string RedirectUri = "https://bff.rotation.test/callback?tenant=unit";
    private const string Nonce = "rotation-nonce-0123456789abcdef";

    // RFC 7636 appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private const string OfflineScope = "openid profile offline_access";
    private const string ReplayedAction = "oidc.refresh.replayed";
    private const string InvalidGrantDescription = "The refresh token is invalid.";

    private readonly IdentityServerFixture _fixture;

    public OAuthInteractiveRefreshRotationTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- Acceptance 1: PS-15 success and the chained rotation ----

    [Fact]
    public async Task Rotate_ReturnsThePs15ResponseAndGrowsTheFamily()
    {
        var seeded = await SeedRedeemedFamilyAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var response = await http.PostAsync(
            "/oauth2/token",
            RefreshForm(seeded.RefreshToken),
            TestContext.Current.CancellationToken);
        var body = await AssertPs15SuccessAsync(response, seeded);

        // The chain rotates again: the child is a fully usable member of the same family.
        var second = await http.PostAsync(
            "/oauth2/token",
            RefreshForm(body.RefreshToken),
            TestContext.Current.CancellationToken);
        var secondBody = await AssertPs15SuccessAsync(second, seeded);
        Assert.NotEqual(body.RefreshToken, secondBody.RefreshToken);

        var family = await GetFamilyAsync(seeded.RootId);
        Assert.Equal(3, family.Count);
        Assert.All(family, row => Assert.Equal(seeded.RootId, row.FamilyId));
        // The presented members are consumed; only the newest child stays live.
        Assert.Equal(2, family.Count(row => row.ConsumedAt is not null));
        Assert.Single(family, row => row.ConsumedAt is null && !row.IsRevoked);
        Assert.Empty(await GetReplayAuditsAsync(seeded.RootId));
    }

    [Fact]
    public async Task Rotate_WithPostAuthentication_ReturnsTheSameShape()
    {
        var seeded = await SeedRedeemedFamilyAsync();
        using var http = _fixture.CreateHttpClient();

        var response = await http.PostAsync(
            "/oauth2/token",
            RefreshForm(seeded.RefreshToken, withPostCredentials: true),
            TestContext.Current.CancellationToken);

        await AssertPs15SuccessAsync(response, seeded);
    }

    // ---- Acceptance 2: EV-31 reuse ----

    [Fact]
    public async Task Rotate_OnReplay_RejectsRevokesLiveDescendantsAndAuditsOnce()
    {
        var seeded = await SeedRedeemedFamilyAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        using var first = await http.PostAsync(
            "/oauth2/token", RefreshForm(seeded.RefreshToken), TestContext.Current.CancellationToken);
        var firstBody = await AssertPs15SuccessAsync(first, seeded);

        // Presenting the consumed root again: generic invalid_grant, the winner's live child
        // revoked, the session untouched, exactly one id-only audit.
        using var replay = await http.PostAsync(
            "/oauth2/token", RefreshForm(seeded.RefreshToken), TestContext.Current.CancellationToken);
        await AssertInvalidGrantAsync(replay, expectReplayAudit: true, rootId: seeded.RootId);

        var family = await GetFamilyAsync(seeded.RootId);
        Assert.Equal(2, family.Count);
        Assert.Single(family, row => row.ConsumedAt is not null && !row.IsRevoked);
        Assert.Single(family, row => row.ConsumedAt is null && row.IsRevoked);

        var session = await QueryAsync(context => context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seeded.SessionId, TestContext.Current.CancellationToken));
        Assert.Null(session.RevokedAt);

        var audit = Assert.Single(await GetReplayAuditsAsync(seeded.RootId));
        Assert.Equal("RefreshTokenFamily", audit.TargetType);
        Assert.Equal(seeded.RootId.ToString("D"), audit.TargetId);
        Assert.Equal(seeded.AccountId, audit.ActorId);
        Assert.Equal($"family:{seeded.RootId:D};member:{seeded.RootId:D};revoked:1;app:{AppId}", audit.Description);
        // DF-09 canary: neither the presented nor the issued plaintext ever reaches the audit.
        Assert.DoesNotContain(seeded.RefreshToken, audit.Description, StringComparison.Ordinal);
        Assert.DoesNotContain(firstBody.RefreshToken, audit.Description, StringComparison.Ordinal);

        // The revoked child is unusable too: an explicitly revoked member adds no write and no
        // second audit.
        using var childReplay = await http.PostAsync(
            "/oauth2/token", RefreshForm(firstBody.RefreshToken), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, childReplay.StatusCode);
        Assert.Single(await GetReplayAuditsAsync(seeded.RootId));
    }

    // ---- Acceptance 3: EV-30 concurrency, the single-instance form ----

    [Fact]
    public async Task Rotate_ConcurrentlyOnTheSingleInstance_ProducesExactlyOneWinner()
    {
        var seeded = await SeedRedeemedFamilyAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var responses = await Task.WhenAll(
            http.PostAsync("/oauth2/token", RefreshForm(seeded.RefreshToken), TestContext.Current.CancellationToken),
            http.PostAsync("/oauth2/token", RefreshForm(seeded.RefreshToken), TestContext.Current.CancellationToken));

        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.OK));
        var loser = Assert.Single(responses, response => response.StatusCode != HttpStatusCode.OK);
        var loserBody = await loser.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_grant", loserBody.GetProperty("error").GetString());

        // One root plus exactly one child; the winner's child was revoked by the loser's reuse
        // disposal, so nothing in the family remains usable.
        var family = await GetFamilyAsync(seeded.RootId);
        Assert.Equal(2, family.Count);
        Assert.Single(family, row => row.ConsumedAt is not null);
        Assert.All(family.Where(row => row.ConsumedAt is null), row => Assert.True(row.IsRevoked));
        Assert.Single(await GetReplayAuditsAsync(seeded.RootId));
    }

    // ---- Acceptance 4: EV-32 state propagation over HTTP ----

    [Fact]
    public async Task Rotate_AfterACommittedSessionRevocation_RevokesTheFamilyAndRejects()
    {
        var seeded = await SeedRedeemedFamilyAsync();
        await ExecuteAsync(context => context.IdentitySessions
            .Where(row => row.Id == seeded.SessionId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.RevokedAt, DateTimeOffset.UtcNow)
                .SetProperty(row => row.RevocationReason, "administrative"),
                TestContext.Current.CancellationToken));

        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);
        using var response = await http.PostAsync(
            "/oauth2/token", RefreshForm(seeded.RefreshToken), TestContext.Current.CancellationToken);

        await AssertInvalidGrantAsync(response, expectReplayAudit: false, rootId: seeded.RootId);
        Assert.True((await GetFamilyAsync(seeded.RootId)).All(row => row.IsRevoked));
    }

    [Fact]
    public async Task Rotate_WhenTheSessionIdledOut_RevokesTheFamilyAndRejects()
    {
        var seeded = await SeedRedeemedFamilyAsync();
        await ExecuteAsync(context => context.IdentitySessions
            .Where(row => row.Id == seeded.SessionId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.IdleExpiresAt, DateTimeOffset.UtcNow.AddMinutes(-1)),
                TestContext.Current.CancellationToken));

        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);
        using var response = await http.PostAsync(
            "/oauth2/token", RefreshForm(seeded.RefreshToken), TestContext.Current.CancellationToken);

        await AssertInvalidGrantAsync(response, expectReplayAudit: false, rootId: seeded.RootId);
        Assert.True((await GetFamilyAsync(seeded.RootId)).All(row => row.IsRevoked));
    }

    [Fact]
    public async Task Rotate_WhenScopeWasRemoved_RevokesTheFamilyAndRejects()
    {
        var seeded = await SeedRedeemedFamilyAsync();
        await ExecuteAsync(context => context.AppRegistrations
            .Where(row => row.Id == seeded.ApplicationId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(
                row => row.AllowedScopes, "openid profile"),
                TestContext.Current.CancellationToken));

        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);
        using var response = await http.PostAsync(
            "/oauth2/token", RefreshForm(seeded.RefreshToken), TestContext.Current.CancellationToken);

        await AssertInvalidGrantAsync(response, expectReplayAudit: false, rootId: seeded.RootId);
        Assert.True((await GetFamilyAsync(seeded.RootId)).All(row => row.IsRevoked));
    }

    [Fact]
    public async Task Rotate_WhenTheApplicationWasDeactivated_RejectsWithoutAFamilyWrite()
    {
        var seeded = await SeedRedeemedFamilyAsync();
        await ExecuteAsync(context => context.AppRegistrations
            .Where(row => row.Id == seeded.ApplicationId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false),
                TestContext.Current.CancellationToken));

        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);
        using var response = await http.PostAsync(
            "/oauth2/token", RefreshForm(seeded.RefreshToken), TestContext.Current.CancellationToken);

        // EV-09/IN-20: a deactivated application fails client authentication before any refresh
        // decision; the family keeps its facts and no audit appears.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain((await GetFamilyAsync(seeded.RootId)), row => row.IsRevoked);
        Assert.Empty(await GetReplayAuditsAsync(seeded.RootId));
    }

    [Fact]
    public async Task Rotate_WhenTheAccountWasDisabled_RejectsWithoutWrites()
    {
        var seeded = await SeedRedeemedFamilyAsync();
        await ExecuteAsync(context => context.Accounts
            .Where(row => row.Id == seeded.AccountId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false),
                TestContext.Current.CancellationToken));

        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);
        using var response = await http.PostAsync(
            "/oauth2/token", RefreshForm(seeded.RefreshToken), TestContext.Current.CancellationToken);

        await AssertInvalidGrantAsync(response, expectReplayAudit: false, rootId: seeded.RootId);
        Assert.DoesNotContain((await GetFamilyAsync(seeded.RootId)), row => row.IsRevoked);
    }

    // ---- Acceptance 5: the legacy boundary (EV-33) ----

    [Fact]
    public async Task Rotate_ForAnotherClientsFamily_RejectsWithoutSideEffects()
    {
        var seeded = await SeedRedeemedFamilyAsync();
        using var attacker = _fixture.CreateHttpClient();
        attacker.DefaultRequestHeaders.Authorization = BasicHeader(OtherAppId, OtherAppSecret);

        using var response = await attacker.PostAsync(
            "/oauth2/token", RefreshForm(seeded.RefreshToken), TestContext.Current.CancellationToken);

        await AssertInvalidGrantAsync(response, expectReplayAudit: false, rootId: seeded.RootId);
        var family = await GetFamilyAsync(seeded.RootId);
        Assert.Single(family);
        Assert.Null(family[0].ConsumedAt);
    }

    [Fact]
    public async Task Rotate_AMissingDigestKeepsTheLegacyGrantAnswers()
    {
        await SeedAppAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        // No scope field: the legacy grant answers its own invalid_grant.
        using var missing = await http.PostAsync(
            "/oauth2/token",
            RefreshForm("this-token-never-existed"),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        var missingBody = await missing.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_grant", missingBody.GetProperty("error").GetString());

        // With a scope field the legacy branch keeps its invalid_scope, not IN-27's
        // invalid_request.
        using var scoped = await http.PostAsync(
            "/oauth2/token",
            RefreshForm("this-token-never-existed", extra: [("scope", "openid")]),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, scoped.StatusCode);
        var scopedBody = await scoped.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_scope", scopedBody.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Rotate_ALegacyRefreshPresentation_StillRotatesOnTheLegacyPath()
    {
        // A real legacy token from the password grant, rotated through the shared endpoint
        // without any interactive involvement.
        using var gateway = _fixture.CreateHttpClient();
        gateway.DefaultRequestHeaders.Authorization = BasicHeader(
            IdentityServerFixture.GatewayAppId, IdentityServerFixture.GatewayAppSecret);
        var issued = await (await gateway.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = IdentityConstants.GrantTypePassword,
            ["username"] = IdentityServerFixture.AdminUsername,
            ["password"] = IdentityServerFixture.AdminPassword
        }), TestContext.Current.CancellationToken))
            .Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);

        var response = await gateway.PostAsync(
            "/oauth2/token",
            RefreshForm(issued.GetProperty("refresh_token").GetString()!),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.NotEqual(issued.GetProperty("refresh_token").GetString(), body.GetProperty("refresh_token").GetString());
        // The legacy response carries no ID token and no scope echo.
        Assert.False(body.TryGetProperty("id_token", out _));
        Assert.False(body.TryGetProperty("scope", out _));
    }

    // ---- Acceptance 6: the input contract (IN-20/IN-26/IN-27) ----

    [Fact]
    public async Task Rotate_WithAnInteractiveMemberAndAScopeField_RejectsWithInvalidRequest()
    {
        var seeded = await SeedRedeemedFamilyAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var response = await http.PostAsync(
            "/oauth2/token",
            RefreshForm(seeded.RefreshToken, extra: [("scope", "openid")]),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_request", body.GetProperty("error").GetString());
        // The interactive member was never consumed.
        Assert.Null((await GetFamilyAsync(seeded.RootId))[0].ConsumedAt);
    }

    [Fact]
    public async Task Rotate_WithMixedClientCredentials_Answers401InvalidClient()
    {
        var seeded = await SeedRedeemedFamilyAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var response = await http.PostAsync(
            "/oauth2/token",
            RefreshForm(seeded.RefreshToken, withPostCredentials: true),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, header => header.Scheme == "Basic");
        Assert.Null((await GetFamilyAsync(seeded.RootId))[0].ConsumedAt);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(257)]
    public async Task Rotate_WithAnOutOfBoundTokenLength_RejectsWithInvalidRequest(int length)
    {
        await SeedAppAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var response = await http.PostAsync(
            "/oauth2/token",
            RefreshForm(new string('a', length)),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_request", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Rotate_WithADuplicateRefreshTokenField_RejectsWithInvalidRequest()
    {
        await SeedAppAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new List<KeyValuePair<string, string>>
        {
            new("grant_type", "refresh_token"),
            new("refresh_token", "first-token"),
            new("refresh_token", "second-token")
        }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_request", body.GetProperty("error").GetString());
    }

    // ---- Acceptance 7: AC-12 Discovery activation ----

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    public async Task Discovery_AdvertisesOfflineAccessAndNothingElseNew(string path)
    {
        using var http = _fixture.CreateHttpClient();
        var document = await http.GetFromJsonAsync<JsonElement>(path, TestContext.Current.CancellationToken);

        Assert.Equal(
            ["openid", "profile", "offline_access"],
            document.GetProperty("scopes_supported").EnumerateArray().Select(item => item.GetString()));
        // userinfo_endpoint still waits for #55, and no other declaration changed with AC-12.
        Assert.False(document.TryGetProperty("userinfo_endpoint", out _));
        Assert.Equal(
            ["RS256"],
            document.GetProperty("id_token_signing_alg_values_supported").EnumerateArray()
                .Select(item => item.GetString()));
        var grants = document.GetProperty("grant_types_supported").EnumerateArray()
            .Select(item => item.GetString()).ToList();
        Assert.Contains("refresh_token", grants);
        Assert.Contains("authorization_code", grants);
    }

    // ---- Seeding and helpers ----

    private sealed record SeededFamily(
        string RefreshToken,
        Guid RootId,
        Guid SessionId,
        Guid AccountId,
        Guid ApplicationId);

    private sealed record Ps15Body(string AccessToken, string IdToken, string RefreshToken);

    /// <summary>
    /// Seeds the full interactive pipeline through the real endpoints: one code with
    /// <c>offline_access</c>, redeemed for the first token set, whose <c>refresh_token</c> names
    /// the committed family root.
    /// </summary>
    private async Task<SeededFamily> SeedRedeemedFamilyAsync()
    {
        var applicationId = await SeedAppAsync();
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

        var credential = await dbContext.PasswordCredentials
            .AsNoTracking()
            .FirstOrDefaultAsync(row => row.Username == Username, TestContext.Current.CancellationToken);
        Guid accountId;
        Guid credentialId;
        if (credential is not null)
        {
            // A test that deactivated the shared account must not poison the ones after it.
            var account = await dbContext.Accounts
                .SingleAsync(row => row.Id == credential.AccountId, TestContext.Current.CancellationToken);
            account.IsActive = true;
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
            (accountId, credentialId) = (credential.AccountId, credential.Id);
        }
        else
        {
            accountId = Guid.NewGuid();
            credentialId = Guid.NewGuid();
            dbContext.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
            dbContext.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = credentialId,
                AccountId = accountId,
                Username = Username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("rotation-user-secret"),
                CreatedAt = DateTimeOffset.UtcNow
            });
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        dbContext.ChangeTracker.Clear();

        var sessions = scope.ServiceProvider.GetRequiredService<IIdentitySessionStore>();
        var codes = scope.ServiceProvider.GetRequiredService<IAuthorizationCodeStore>();
        var now = DateTimeOffset.UtcNow;
        var session = await sessions.CreateAsync(accountId, credentialId, now, TestContext.Current.CancellationToken);
        var creation = await codes.CreateAsync(
            session,
            new AuthorizationCodeBinding(applicationId, RedirectUri, OfflineScope, Nonce, Challenge),
            now,
            TestContext.Current.CancellationToken);

        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);
        using var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = creation.Code,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = Verifier
        }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        var refreshToken = body.GetProperty("refresh_token").GetString()!;

        var rootId = await QueryAsync(context => context.AuthorizationCodes.AsNoTracking()
            .Where(row => row.Id == creation.Id)
            .Select(row => row.RefreshFamilyId!.Value)
            .SingleAsync(TestContext.Current.CancellationToken));
        return new SeededFamily(refreshToken, rootId, session.Id, accountId, applicationId);
    }

    private async Task<Guid> SeedAppAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        foreach (var (appId, appSecret) in new[] { (AppId, AppSecret), (OtherAppId, OtherAppSecret) })
        {
            var application = await dbContext.AppRegistrations
                .FirstOrDefaultAsync(row => row.AppId == appId, TestContext.Current.CancellationToken);
            if (application is null)
            {
                application = new AppRegistrationEntity
                {
                    Id = Guid.NewGuid(),
                    AppId = appId,
                    AppSecretHash = BCrypt.Net.BCrypt.HashPassword(appSecret),
                    AppName = $"Rotation {appId}",
                    CreatedAt = DateTimeOffset.UtcNow
                };
                dbContext.AppRegistrations.Add(application);
            }

            application.IsActive = true;
            application.AudienceMode = AudienceMode.PerApplication;
            application.ClientType = OidcClientType.Confidential;
            application.AllowAuthorizationCode = true;
            application.AllowedScopes = OfflineScope;
            application.AllowRefreshToken = true;
            application.IdentitySessionMaxAgeSeconds = null;
        }

        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        return await dbContext.AppRegistrations
            .AsNoTracking()
            .Where(row => row.AppId == AppId)
            .Select(row => row.Id)
            .SingleAsync(TestContext.Current.CancellationToken);
    }

    private static FormUrlEncodedContent RefreshForm(
        string refreshToken,
        bool withPostCredentials = false,
        params (string Name, string Value)[] extra)
    {
        var fields = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "refresh_token"),
            new("refresh_token", refreshToken)
        };
        if (withPostCredentials)
        {
            fields.Add(new KeyValuePair<string, string>("client_id", AppId));
            fields.Add(new KeyValuePair<string, string>("client_secret", AppSecret));
        }

        foreach (var (name, value) in extra)
        {
            fields.Add(new KeyValuePair<string, string>(name, value));
        }

        return new FormUrlEncodedContent(fields);
    }

    private async Task<Ps15Body> AssertPs15SuccessAsync(
        HttpResponseMessage response,
        SeededFamily seeded)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Contains("no-cache", response.Headers.Pragma.ToString(), StringComparison.Ordinal);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        // PS-15: exactly these six members.
        Assert.Equal(
            new HashSet<string>(StringComparer.Ordinal)
            {
                "access_token", "token_type", "expires_in", "scope", "id_token", "refresh_token"
            },
            body.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal));
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.Equal(900, body.GetProperty("expires_in").GetInt64());
        Assert.Equal(OfflineScope, body.GetProperty("scope").GetString());
        var refreshToken = body.GetProperty("refresh_token").GetString()!;
        Assert.Equal(43, refreshToken.Length);
        Assert.All(refreshToken, character =>
            Assert.True(char.IsAsciiLetterOrDigit(character) || character is '-' or '_'));
        Assert.NotEqual(seeded.RefreshToken, refreshToken);

        var accessToken = body.GetProperty("access_token").GetString()!;
        var token = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);
        Assert.Equal(JwtTokenService.AccessTokenType, token.Header.Typ);
        Assert.Equal(AppId, token.Audiences.Single());
        Assert.Equal(seeded.AccountId.ToString(), token.Claims.Single(claim => claim.Type == IdentityConstants.ClaimSubject).Value);
        Assert.Equal(seeded.SessionId.ToString(), token.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Sid).Value);
        Assert.Equal(OfflineScope, token.Claims.Single(claim => claim.Type == "scope").Value);

        var idToken = new JwtSecurityTokenHandler().ReadJwtToken(body.GetProperty("id_token").GetString()!);
        Assert.Equal("JWT", idToken.Header.Typ);
        Assert.Equal(AppId, idToken.Audiences.Single());
        Assert.Equal(seeded.AccountId.ToString(), idToken.Claims.Single(claim => claim.Type == IdentityConstants.ClaimSubject).Value);
        Assert.Equal(seeded.SessionId.ToString(), idToken.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Sid).Value);
        // The refresh variant omits the nonce and keeps the original authentication facts.
        Assert.DoesNotContain(idToken.Claims, claim => claim.Type == JwtRegisteredClaimNames.Nonce);
        Assert.Equal("pwd", idToken.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Amr).Value);
        Assert.Equal(
            IdentityConstants.InteractiveIdTokenLifetimeSeconds,
            (idToken.ValidTo - idToken.IssuedAt).TotalSeconds);
        return new Ps15Body(accessToken, body.GetProperty("id_token").GetString()!, refreshToken);
    }

    private async Task AssertInvalidGrantAsync(
        HttpResponseMessage response,
        bool expectReplayAudit,
        Guid rootId)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
        Assert.Equal(InvalidGrantDescription, body.GetProperty("error_description").GetString());
        Assert.Equal(expectReplayAudit ? 1 : 0, (await GetReplayAuditsAsync(rootId)).Count);
    }

    private Task<List<RefreshTokenEntity>> GetFamilyAsync(Guid rootId) =>
        QueryAsync(async context => await context.RefreshTokens.AsNoTracking()
            .Where(row => row.FamilyId == rootId)
            .OrderBy(row => row.CreatedAt)
            .ToListAsync(TestContext.Current.CancellationToken));

    private Task<List<AuditLogEntity>> GetReplayAuditsAsync(Guid rootId) =>
        QueryAsync(async context => await context.AuditLogs.AsNoTracking()
            .Where(row => row.TargetId == rootId.ToString("D") && row.Action == ReplayedAction)
            .ToListAsync(TestContext.Current.CancellationToken));

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
