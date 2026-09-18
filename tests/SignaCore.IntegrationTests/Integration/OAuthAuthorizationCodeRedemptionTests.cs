using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Security;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The SQLite HTTP contract of the internal <c>authorization_code</c> redemption
/// (<c>AC-06</c>): the exact four-field success response over Basic and post client
/// authentication, the <c>IN-20</c> credential mix, the capability gate, the
/// <c>IN-22</c>–<c>IN-25</c> field contract, the single generic <c>invalid_grant</c> of
/// <c>EV-22</c>/<c>EV-23</c> with zero writes, the <c>EV-24</c> replay disposal, the
/// single-instance form of the <c>EV-25</c> concurrency outcome, the <c>SC-05</c>/<c>SC-06</c>
/// serial shapes, the <c>EV-26</c> rollback with a later successful retry, the
/// <c>DF-03</c>/<c>DF-04</c>/<c>DF-06</c> canary scan, and the unchanged Discovery documents.
/// Codes and sessions are seeded through the real stores, never raw SQL.
/// </summary>
public sealed class OAuthAuthorizationCodeRedemptionTests : IClassFixture<IdentityServerFixture>
{
    private const string AppId = "code-redemption-app";
    private const string AppSecret = "code-redemption-secret-canary";
    private const string OtherAppId = "code-redemption-other-app";
    private const string OtherAppSecret = "code-redemption-other-secret";
    private const string Username = "code_redemption_user";

    private const string RedirectUri = "https://bff.redemption.test/callback?tenant=unit";
    private const string Nonce = "redemption-nonce-0123456789abcdef";

    // RFC 7636 appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private const string RedeemedAction = "oidc.code.redeemed";
    private const string ReplayedAction = "oidc.code.replayed";
    private const string InvalidGrantDescription = "The authorization code is invalid.";

    private readonly IdentityServerFixture _fixture;

    public OAuthAuthorizationCodeRedemptionTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- Acceptance 1: success over both authentication methods and both scopes ----

    [Fact]
    public async Task Redeem_WithBasicAuthenticationAndOpenIdScope_ReturnsTheInteractiveToken()
    {
        var seeded = await SeedCodeAsync(scope: "openid");
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var response = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        await AssertSuccessAsync(response, seeded, expectedScope: "openid");
    }

    [Fact]
    public async Task Redeem_WithPostAuthenticationAndProfileScope_ReturnsTheSameShape()
    {
        var seeded = await SeedCodeAsync(scope: "openid profile");
        using var http = _fixture.CreateHttpClient();

        var response = await http.PostAsync(
            "/oauth2/token",
            RedeemForm(seeded.Code, withPostCredentials: true),
            TestContext.Current.CancellationToken);
        await AssertSuccessAsync(response, seeded, expectedScope: "openid profile");
    }

    [Fact]
    public async Task Redeem_IgnoresUnknownFormFields()
    {
        var seeded = await SeedCodeAsync(scope: "openid");
        using var http = _fixture.CreateHttpClient();

        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);
        var response = await http.PostAsync(
            "/oauth2/token",
            RedeemForm(seeded.Code, extra: [("resource", "urn:example:ignored")]),
            TestContext.Current.CancellationToken);
        await AssertSuccessAsync(response, seeded, expectedScope: "openid");
    }

    /// <summary>
    /// The acceptance of <c>AC-07</c>: a standard JWT validator driven only by the published
    /// Discovery document and JWKS — issuer, audience, RS256 keys, type, lifetime — accepts the
    /// issued ID token, and the same validator rejects the access token as an ID token.
    /// </summary>
    [Fact]
    public async Task Redeem_TheIdTokenValidatesThroughDiscoveryAndJwks()
    {
        var seeded = await SeedCodeAsync(scope: "openid profile");
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var response = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        var idToken = body.GetProperty("id_token").GetString()!;

        var discovery = await http.GetFromJsonAsync<JsonElement>(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        var issuer = discovery.GetProperty("issuer").GetString()!;
        Assert.Equal(
            ["RS256"],
            discovery.GetProperty("id_token_signing_alg_values_supported").EnumerateArray()
                .Select(item => item.GetString()));

        var jwks = await http.GetFromJsonAsync<JsonElement>("/.well-known/jwks", TestContext.Current.CancellationToken);
        var keys = jwks.GetProperty("keys").EnumerateArray()
            .Select(key => new RsaSecurityKey(new RSAParameters
            {
                Modulus = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(key.GetProperty("n").GetString()!),
                Exponent = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(key.GetProperty("e").GetString()!)
            })
            { KeyId = key.GetProperty("kid").GetString() })
            .Cast<Microsoft.IdentityModel.Tokens.SecurityKey>()
            .ToArray();

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = issuer,
            ValidAudience = AppId,
            IssuerSigningKeys = keys,
            ValidTypes = ["JWT"],
            ValidateLifetime = true
        };

        var principal = handler.ValidateToken(idToken, parameters, out var validated);
        Assert.Equal(seeded.AccountId.ToString(), principal.FindFirst("sub")!.Value);
        Assert.Equal(Nonce, principal.FindFirst("nonce")!.Value);
        Assert.Equal(AppId, Assert.IsType<JwtSecurityToken>(validated).Audiences.Single());

        // The access token's typ is at+jwt and never validates as an ID token.
        var accessToken = body.GetProperty("access_token").GetString()!;
        Assert.ThrowsAny<SecurityTokenValidationException>(
            () => handler.ValidateToken(accessToken, parameters, out _));
    }

    // ---- Acceptance 2: client authentication ----

    [Fact]
    public async Task Redeem_WithoutClientCredentials_Returns401AndLeavesTheCodeUnconsumed()
    {
        var seeded = await SeedCodeAsync();
        using var http = _fixture.CreateHttpClient();

        var response = await http.PostAsync(
            "/oauth2/token",
            RedeemForm(seeded.Code),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, header => header.Scheme == "Basic");
        await AssertCodeUntouchedAsync(seeded);
    }

    [Fact]
    public async Task Redeem_WithAWrongSecret_Returns401AndLeavesTheCodeUnconsumed()
    {
        var seeded = await SeedCodeAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, "wrong-secret");

        var response = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        await AssertCodeUntouchedAsync(seeded);
    }

    [Fact]
    public async Task Redeem_MixingBasicAndFormCredentials_Returns401AndLeavesTheCodeUnconsumed()
    {
        var seeded = await SeedCodeAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        // IN-20: the mix is rejected even when both methods carry the same valid credentials.
        var response = await http.PostAsync(
            "/oauth2/token",
            RedeemForm(seeded.Code, withPostCredentials: true),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, header => header.Scheme == "Basic");
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_client", body.GetProperty("error").GetString());
        await AssertCodeUntouchedAsync(seeded);
        await AssertNoCodeAuditAsync(seeded.CodeId);
    }

    // ---- Acceptance 3: capability ----

    [Fact]
    public async Task Redeem_ForAnAppWithoutTheCodeCapability_ReturnsUnauthorizedClient()
    {
        var seeded = await SeedCodeAsync(allowAuthorizationCode: false);
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var response = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);

        await AssertErrorAsync(response, seeded, "unauthorized_client");
    }

    [Fact]
    public async Task Redeem_ForASharedAudienceApp_ReturnsUnauthorizedClient()
    {
        var seeded = await SeedCodeAsync(audienceMode: AudienceMode.Shared);
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var response = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);

        await AssertErrorAsync(response, seeded, "unauthorized_client");
    }

    // ---- Acceptance 4: the IN-22–IN-25 field contract ----

    public static TheoryData<string, string> MalformedBodies => new()
    {
        // Missing fields.
        { "missing code", $"grant_type=authorization_code&redirect_uri={Uri.EscapeDataString(RedirectUri)}&code_verifier={Verifier}" },
        { "missing redirect_uri", $"grant_type=authorization_code&code={new string('a', 43)}&code_verifier={Verifier}" },
        { "missing code_verifier", $"grant_type=authorization_code&code={new string('a', 43)}&redirect_uri={Uri.EscapeDataString(RedirectUri)}" },
        // Duplicate fields.
        { "duplicate code", $"grant_type=authorization_code&code={new string('a', 43)}&code={new string('b', 43)}&redirect_uri={Uri.EscapeDataString(RedirectUri)}&code_verifier={Verifier}" },
        { "duplicate redirect_uri", $"grant_type=authorization_code&code={new string('a', 43)}&redirect_uri={Uri.EscapeDataString(RedirectUri)}&redirect_uri={Uri.EscapeDataString(RedirectUri)}&code_verifier={Verifier}" },
        { "duplicate code_verifier", $"grant_type=authorization_code&code={new string('a', 43)}&redirect_uri={Uri.EscapeDataString(RedirectUri)}&code_verifier={Verifier}&code_verifier={Verifier}" },
        // Shapes.
        { "short code", $"grant_type=authorization_code&code={new string('a', 42)}&redirect_uri={Uri.EscapeDataString(RedirectUri)}&code_verifier={Verifier}" },
        { "long code", $"grant_type=authorization_code&code={new string('a', 44)}&redirect_uri={Uri.EscapeDataString(RedirectUri)}&code_verifier={Verifier}" },
        { "code with plus", $"grant_type=authorization_code&code={new string('a', 42)}%2B&redirect_uri={Uri.EscapeDataString(RedirectUri)}&code_verifier={Verifier}" },
        { "empty code", $"grant_type=authorization_code&code=&redirect_uri={Uri.EscapeDataString(RedirectUri)}&code_verifier={Verifier}" },
        { "empty redirect_uri", $"grant_type=authorization_code&code={new string('a', 43)}&redirect_uri=&code_verifier={Verifier}" },
        { "long redirect_uri", $"grant_type=authorization_code&code={new string('a', 43)}&redirect_uri={Uri.EscapeDataString("https://bff.test/" + new string('p', 500))}&code_verifier={Verifier}" },
        { "non-ascii redirect_uri", $"grant_type=authorization_code&code={new string('a', 43)}&redirect_uri=https%3A%2F%2Fbff.test%2Fcaf%C3%A9&code_verifier={Verifier}" },
        { "short verifier", $"grant_type=authorization_code&code={new string('a', 43)}&redirect_uri={Uri.EscapeDataString(RedirectUri)}&code_verifier={new string('v', 42)}" },
        { "long verifier", $"grant_type=authorization_code&code={new string('a', 43)}&redirect_uri={Uri.EscapeDataString(RedirectUri)}&code_verifier={new string('v', 129)}" },
        { "verifier with plus", $"grant_type=authorization_code&code={new string('a', 43)}&redirect_uri={Uri.EscapeDataString(RedirectUri)}&code_verifier={new string('v', 42)}%2B" },
        // IN-25: a scope field is never accepted, not even empty.
        { "scope present", $"grant_type=authorization_code&code={new string('a', 43)}&redirect_uri={Uri.EscapeDataString(RedirectUri)}&code_verifier={Verifier}&scope=openid" },
        { "scope present and empty", $"grant_type=authorization_code&code={new string('a', 43)}&redirect_uri={Uri.EscapeDataString(RedirectUri)}&code_verifier={Verifier}&scope=" },
    };

    [Theory]
    [MemberData(nameof(MalformedBodies))]
    public async Task Redeem_WithAMalformedFieldSet_ReturnsInvalidRequestWithoutEchoingValues(
        string label,
        string body)
    {
        var seeded = await SeedCodeAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        using var content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");
        var response = await http.PostAsync("/oauth2/token", content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_request", json.GetProperty("error").GetString());
        var description = json.GetProperty("error_description").GetString()!;
        Assert.Contains(description is "The authorization code grant does not accept a scope parameter."
            ? "scope"
            : "malformed", description, StringComparison.Ordinal);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(Verifier, raw, StringComparison.Ordinal);
        Assert.DoesNotContain(RedirectUri, raw, StringComparison.Ordinal);
        await AssertCodeUntouchedAsync(seeded);
        await AssertNoCodeAuditAsync(seeded.CodeId);
    }

    // ---- Acceptance 5: EV-22/EV-23 — one body, zero writes ----

    [Fact]
    public async Task Redeem_ForAnUnknownCode_ReturnsTheGenericInvalidGrant()
    {
        await AssertInvalidGrantNoWriteAsync(new string('z', 43));
    }

    [Fact]
    public async Task Redeem_AuthenticatedAsAnotherClient_ReturnsTheGenericInvalidGrant()
    {
        var seeded = await SeedCodeAsync();
        await AssertInvalidGrantNoWriteAsync(
            seeded.Code,
            seeded,
            basicAppId: OtherAppId,
            basicSecret: OtherAppSecret);
    }

    [Theory]
    [InlineData("trailing-slash", "https://bff.redemption.test/callback/?tenant=unit")]
    [InlineData("host-case", "https://BFF.redemption.test/callback?tenant=unit")]
    [InlineData("one-byte", "https://bff.redemption.test/callback?tenant=uniu")]
    public async Task Redeem_WithARedirectUriDifferingByOneByte_ReturnsTheGenericInvalidGrant(
        string label,
        string redirectUri)
    {
        var seeded = await SeedCodeAsync();
        await AssertInvalidGrantNoWriteAsync(seeded.Code, seeded, redirectUri: redirectUri);
    }

    [Fact]
    public async Task Redeem_WithAWrongVerifier_ReturnsTheGenericInvalidGrant()
    {
        var seeded = await SeedCodeAsync();
        await AssertInvalidGrantNoWriteAsync(
            seeded.Code,
            seeded,
            verifier: new string('w', 43));
    }

    [Fact]
    public async Task Redeem_WithThePlainFormVerifier_ReturnsTheGenericInvalidGrant()
    {
        // "plain" means sending the challenge itself as the verifier; S256 of it never matches.
        var seeded = await SeedCodeAsync();
        await AssertInvalidGrantNoWriteAsync(seeded.Code, seeded, verifier: Challenge);
    }

    [Fact]
    public async Task Redeem_AnExpiredUnconsumedCode_ReturnsTheGenericInvalidGrant()
    {
        var seeded = await SeedCodeAsync(createdAt: DateTimeOffset.UtcNow.AddSeconds(-61));
        await AssertInvalidGrantNoWriteAsync(seeded.Code, seeded);
    }

    [Fact]
    public async Task Redeem_ForARevokedSession_ReturnsTheGenericInvalidGrant()
    {
        var seeded = await SeedCodeAsync();
        await RevokeSessionAsync(seeded.SessionId, reason: "administrative");
        await AssertInvalidGrantNoWriteAsync(seeded.Code, seeded);
    }

    [Fact]
    public async Task Redeem_ForAnIdleExpiredSession_ReturnsTheGenericInvalidGrant()
    {
        var seeded = await SeedCodeAsync();
        await AdjustSessionAsync(seeded.SessionId, idleExpired: true);
        await AssertInvalidGrantNoWriteAsync(seeded.Code, seeded);
    }

    [Fact]
    public async Task Redeem_ForAnAbsolutelyExpiredSession_ReturnsTheGenericInvalidGrant()
    {
        var seeded = await SeedCodeAsync();
        await AdjustSessionAsync(seeded.SessionId, absoluteExpired: true);
        await AssertInvalidGrantNoWriteAsync(seeded.Code, seeded);
    }

    [Fact]
    public async Task Redeem_WhenTheApplicationMaxAgeIsReached_ReturnsTheGenericInvalidGrant()
    {
        var seeded = await SeedCodeAsync(maxAgeSeconds: 5);
        await AdjustSessionAsync(seeded.SessionId, authTimeInThePastSeconds: 10);
        await AssertInvalidGrantNoWriteAsync(seeded.Code, seeded);
    }

    [Fact]
    public async Task Redeem_ForADeactivatedAccount_ReturnsTheGenericInvalidGrant()
    {
        var seeded = await SeedCodeAsync();
        await DeactivateAccountAsync(seeded.AccountId);
        await AssertInvalidGrantNoWriteAsync(seeded.Code, seeded);
    }

    [Fact]
    public async Task Redeem_WhenAScopeMemberWasRemovedFromTheAllowList_ReturnsTheGenericInvalidGrant()
    {
        var seeded = await SeedCodeAsync(scope: "openid profile");
        await SetAllowedScopesAsync(seeded.ApplicationId, "openid");
        await AssertInvalidGrantNoWriteAsync(seeded.Code, seeded);
    }

    [Fact]
    public async Task Redeem_WithOfflineAccess_CommitsTheFamilyRootAndReturnsTheRefreshTokenOnce()
    {
        // EV-21: one transaction commits the consumption, the family root, the code-to-root link,
        // and the audit; the response carries the plaintext refresh token exactly once.
        var seeded = await SeedCodeAsync(
            scope: "openid offline_access",
            allowedScopes: "openid offline_access",
            allowRefreshToken: true);
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var response = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        var outcome = await AssertSuccessAsync(
            response, seeded, expectedScope: "openid offline_access", expectRefreshToken: true);

        // The committed root: complete interactive marker, the 7-day cap, and only the digest.
        var root = await QueryAsync(async dbContext =>
            await dbContext.RefreshTokens.AsNoTracking()
                .SingleAsync(row => row.IdentitySessionId == seeded.SessionId, TestContext.Current.CancellationToken));
        Assert.Equal(root.Id, root.FamilyId);
        Assert.Null(root.ParentId);
        Assert.Equal(seeded.AccountId, root.AccountId);
        Assert.Equal(AppId, root.AppId);
        Assert.Equal("openid offline_access", root.Scope);
        Assert.NotNull(root.AuthTime);
        Assert.False(root.IsRevoked);
        Assert.Equal(
            root.CreatedAt.AddDays(IdentityConstants.InteractiveRefreshFamilyLifetimeDays),
            root.ExpiresAt);
        Assert.Equal(RefreshTokenDigest.Compute(outcome.RefreshToken!), root.TokenValue);

        var codeRow = await GetCodeAsync(seeded.CodeId);
        Assert.Equal(root.Id, codeRow.RefreshFamilyId);
    }

    [Fact]
    public async Task Redeem_WithOfflineAccess_WhenRefreshWasDisabled_ReturnsTheGenericInvalidGrant()
    {
        // EV-11: the current AllowRefreshToken is an in-lock recheck; the allow list still
        // contains offline_access so only the toggle can produce this answer, and the code stays
        // unconsumed with no family written.
        var seeded = await SeedCodeAsync(
            scope: "openid offline_access",
            allowedScopes: "openid offline_access",
            allowRefreshToken: true);
        await ExecuteAsync(async dbContext =>
        {
            await dbContext.AppRegistrations
                .Where(row => row.Id == seeded.ApplicationId)
                .ExecuteUpdateAsync(
                    setters => setters.SetProperty(row => row.AllowRefreshToken, false),
                    TestContext.Current.CancellationToken);
        });

        await AssertInvalidGrantNoWriteAsync(seeded.Code, seeded);
        Assert.False(await QueryAsync(async dbContext =>
            await dbContext.RefreshTokens.AsNoTracking()
                .AnyAsync(row => row.IdentitySessionId == seeded.SessionId, TestContext.Current.CancellationToken)));
    }

    // ---- Acceptance 6: EV-24 replay ----

    [Fact]
    public async Task Replay_ACorrectlyBoundConsumedCode_RevokesTheSessionAndWritesOneAudit()
    {
        var seeded = await SeedCodeAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        using var first = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        await AssertSuccessAsync(first, seeded, expectedScope: "openid");

        using var replay = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        await AssertReplayAsync(replay, seeded);
    }

    [Fact]
    public async Task Replay_OfAConsumedCodePastItsExpiryButInsideRetention_IsStillAReplay()
    {
        var seeded = await SeedCodeAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        using var first = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        await AssertSuccessAsync(first, seeded, expectedScope: "openid");

        // EV-24 outranks expiry: move the code's deadline into the past inside the 24h retention.
        await ExpireCodeRowAsync(seeded.CodeId);

        using var replay = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        await AssertReplayAsync(replay, seeded);
    }

    [Fact]
    public async Task Replay_OfAnOfflineAccessCode_RevokesTheLinkedFamilyAndTheSession()
    {
        // EV-24 with a non-null family link: the exact named family is revoked, the session is
        // revoked, and the one id-only replay audit names the family id.
        var seeded = await SeedCodeAsync(
            scope: "openid offline_access",
            allowedScopes: "openid offline_access",
            allowRefreshToken: true);
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        using var first = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        await AssertSuccessAsync(
            first, seeded, expectedScope: "openid offline_access", expectRefreshToken: true);

        var rootId = (await GetCodeAsync(seeded.CodeId)).RefreshFamilyId;
        Assert.NotNull(rootId);

        using var replay = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        var body = await replay.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());

        var root = await QueryAsync(async dbContext =>
            await dbContext.RefreshTokens.AsNoTracking()
                .SingleAsync(row => row.Id == rootId, TestContext.Current.CancellationToken));
        Assert.True(root.IsRevoked);
        var session = await GetSessionAsync(seeded.SessionId);
        Assert.NotNull(session.RevokedAt);
        Assert.Equal("code_replay", session.RevocationReason);

        var audits = await GetCodeAuditsAsync(seeded.CodeId);
        var replayed = Assert.Single(audits, audit => audit.Action == ReplayedAction);
        Assert.Equal($"session:{seeded.SessionId};family:{rootId}", replayed.Description);
    }

    [Fact]
    public async Task Replay_WithAWrongVerifier_RejectsWithoutReplaySideEffects()
    {
        var seeded = await SeedCodeAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        using var first = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        await AssertSuccessAsync(first, seeded, expectedScope: "openid");

        var response = await http.PostAsync(
            "/oauth2/token",
            RedeemForm(seeded.Code, verifier: new string('w', 43)),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_grant", json.GetProperty("error").GetString());

        var session = await GetSessionAsync(seeded.SessionId);
        Assert.Null(session.RevokedAt);
        var audits = await GetCodeAuditsAsync(seeded.CodeId);
        Assert.Single(audits, audit => audit.Action == RedeemedAction);
        Assert.DoesNotContain(audits, audit => audit.Action == ReplayedAction);
    }

    [Fact]
    public async Task Replay_OnAnAlreadyRevokedSession_KeepsTheFirstRevocationFact()
    {
        var seeded = await SeedCodeAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        using var first = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        await AssertSuccessAsync(first, seeded, expectedScope: "openid");
        using var replay = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        await AssertReplayAsync(replay, seeded);
        var revokedAt = (await GetSessionAsync(seeded.SessionId)).RevokedAt;

        // The second replay is judged again — one audit per request — but the first revocation
        // stays authoritative.
        using var replayAgain = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, replayAgain.StatusCode);

        var session = await GetSessionAsync(seeded.SessionId);
        Assert.Equal(revokedAt, session.RevokedAt);
        Assert.Equal("code_replay", session.RevocationReason);
        var audits = await GetCodeAuditsAsync(seeded.CodeId);
        Assert.Equal(2, audits.Count(audit => audit.Action == ReplayedAction));
        Assert.Single(audits, audit => audit.Action == RedeemedAction);
    }

    // ---- Acceptance 7: the single-instance form of EV-25 ----

    [Fact]
    public async Task Redeem_ConcurrentlyOnTheSingleInstance_ProducesExactlyOneWinner()
    {
        var seeded = await SeedCodeAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var responses = await Task.WhenAll(
            http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken),
            http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken));

        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.OK));
        var loser = Assert.Single(responses, response => response.StatusCode != HttpStatusCode.OK);
        var json = await loser.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_grant", json.GetProperty("error").GetString());

        var audits = await GetCodeAuditsAsync(seeded.CodeId);
        Assert.Single(audits, audit => audit.Action == RedeemedAction);
        Assert.Single(audits, audit => audit.Action == ReplayedAction);
        var session = await GetSessionAsync(seeded.SessionId);
        Assert.Equal("code_replay", session.RevocationReason);
    }

    // ---- Acceptance 8: SC-05/SC-06 serial shapes on SQLite ----

    [Fact]
    public async Task Redeem_AfterACommittedSessionRevocation_RejectsWithoutConsumingOrAuditing()
    {
        var seeded = await SeedCodeAsync();
        await RevokeSessionAsync(seeded.SessionId, reason: "administrative");
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var response = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_grant", json.GetProperty("error").GetString());
        Assert.Null((await GetCodeAsync(seeded.CodeId)).ConsumedAt);
        await AssertNoCodeAuditAsync(seeded.CodeId);
    }

    [Fact]
    public async Task Revoke_AfterACommittedRedemption_SucceedsAndKeepsTheIssuedToken()
    {
        var seeded = await SeedCodeAsync();
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        using var first = await http.PostAsync("/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        await RevokeSessionAsync(seeded.SessionId, reason: "administrative");
        var session = await GetSessionAsync(seeded.SessionId);
        Assert.NotNull(session.RevokedAt);
        Assert.NotNull((await GetCodeAsync(seeded.CodeId)).ConsumedAt);
    }

    // ---- Acceptance 9: EV-26 rollback and the successful retry ----

    [Fact]
    public async Task Redeem_WhenSigningThrows_Returns500AndARollbackThenARetrySucceeds()
    {
        await AssertEv26Async(failByThrowing: true);
    }

    [Fact]
    public async Task Redeem_WhenTheTokenExceedsTheMaximumLength_Returns500AndARollbackThenARetrySucceeds()
    {
        await AssertEv26Async(failByThrowing: false);
    }

    // ---- Acceptance 11: the canary scan ----

    [Fact]
    public async Task SecretsNeverReachLogsAuditsOrErrorBodies()
    {
        var canaryRedirect = "https://bff.canary.test/callback?secret=canary-redirect-value";
        var canaryVerifier = "CanaryVerifier_0123456789abcdefghijklmnopqrstuvwxyz";
        var canaryChallenge = ComputeS256(canaryVerifier);
        var seeded = await SeedCodeAsync(
            scope: "openid offline_access",
            redirectUri: canaryRedirect,
            challenge: canaryChallenge,
            allowedScopes: "openid offline_access",
            allowRefreshToken: true);

        var capture = new CapturingLoggerProvider();
        using var factory = _fixture.WithTestServices(services =>
        {
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
            {
                logging.AddProvider(capture);
                logging.SetMinimumLevel(LogLevel.Information);
                logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
                logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
            }));
        });
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        var bodies = new List<string>();
        string? canaryRefreshToken = null;

        using (var success = await client.PostAsync(
            "/oauth2/token", RedeemForm(seeded.Code, verifier: canaryVerifier, redirectUri: canaryRedirect),
            TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.OK, success.StatusCode);
            var body = await success.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
            canaryRefreshToken = body.GetProperty("refresh_token").GetString();
        }

        foreach (var verifier in new[] { new string('w', 43), canaryChallenge })
        {
            using var failure = await client.PostAsync(
                "/oauth2/token", RedeemForm(seeded.Code, verifier: verifier, redirectUri: canaryRedirect),
                TestContext.Current.CancellationToken);
            bodies.Add(await failure.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }

        using (var unknown = await client.PostAsync(
            "/oauth2/token", RedeemForm(new string('z', 43), verifier: canaryVerifier, redirectUri: canaryRedirect),
            TestContext.Current.CancellationToken))
        {
            bodies.Add(await unknown.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }

        // The capture is proven non-empty through the redemption's own Information line.
        Assert.Contains(capture.Messages, message => message.Contains("Authorization code redeemed", StringComparison.Ordinal));

        var dump = new StringBuilder();
        foreach (var message in capture.Messages)
        {
            dump.AppendLine(message);
        }

        foreach (var audit in await GetCodeAuditsAsync(seeded.CodeId))
        {
            dump.Append("audit|").Append(audit.Action).Append('|').Append(audit.TargetType).Append('|')
                .Append(audit.TargetId).Append('|').Append(audit.ActorId).Append('|').Append(audit.Description)
                .AppendLine();
        }

        var dumpText = dump.ToString();
        Assert.DoesNotContain(seeded.Code, dumpText, StringComparison.Ordinal);
        Assert.DoesNotContain(canaryVerifier, dumpText, StringComparison.Ordinal);
        Assert.DoesNotContain(canaryChallenge, dumpText, StringComparison.Ordinal);
        Assert.DoesNotContain(canaryRedirect, dumpText, StringComparison.Ordinal);
        Assert.DoesNotContain(AppSecret, dumpText, StringComparison.Ordinal);
        Assert.DoesNotContain(canaryRefreshToken!, dumpText, StringComparison.Ordinal);
        foreach (var body in bodies)
        {
            Assert.DoesNotContain(seeded.Code, body, StringComparison.Ordinal);
            Assert.DoesNotContain(canaryVerifier, body, StringComparison.Ordinal);
            Assert.DoesNotContain(canaryRedirect, body, StringComparison.Ordinal);
            Assert.DoesNotContain(AppSecret, body, StringComparison.Ordinal);
            Assert.DoesNotContain(canaryRefreshToken!, body, StringComparison.Ordinal);
        }
    }

    // ---- Acceptance 12: Discovery advertises the delivered interactive core identically ----

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    public async Task Discovery_AdvertisesTheDeliveredInteractiveCore(string path)
    {
        using var http = _fixture.CreateHttpClient();
        var document = await http.GetStringAsync(path, TestContext.Current.CancellationToken);

        var parsed = JsonDocument.Parse(document);
        Assert.Equal(
            ["code"],
            parsed.RootElement.GetProperty("response_types_supported").EnumerateArray()
                .Select(item => item.GetString()));
        Assert.Contains("authorization_code", document, StringComparison.Ordinal);
        Assert.Contains("code_challenge_methods_supported", document, StringComparison.Ordinal);
        Assert.Equal(
            ["S256"],
            parsed.RootElement.GetProperty("code_challenge_methods_supported").EnumerateArray()
                .Select(item => item.GetString()));
    }

    [Fact]
    public async Task Discovery_ServesByteForByteIdenticalDocumentsOnBothPaths()
    {
        using var http = _fixture.CreateHttpClient();
        var oidc = await http.GetStringAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        var rfc8414 = await http.GetStringAsync("/.well-known/oauth-authorization-server", TestContext.Current.CancellationToken);

        Assert.Equal(oidc, rfc8414);
    }

    // ---- Seeding ----

    private sealed record SeededCode(string Code, Guid CodeId, Guid SessionId, Guid AccountId, Guid ApplicationId);

    private async Task<SeededCode> SeedCodeAsync(
        string scope = "openid",
        string redirectUri = RedirectUri,
        string challenge = Challenge,
        DateTimeOffset? createdAt = null,
        bool allowAuthorizationCode = true,
        AudienceMode audienceMode = AudienceMode.PerApplication,
        int? maxAgeSeconds = null,
        string allowedScopes = "openid profile",
        bool allowRefreshToken = false)
    {
        await SeedInteractiveAppAsync(
            _fixture.Services,
            AppId,
            AppSecret,
            allowAuthorizationCode: allowAuthorizationCode,
            audienceMode: audienceMode,
            maxAgeSeconds: maxAgeSeconds,
            allowedScopes: allowedScopes,
            allowRefreshToken: allowRefreshToken);
        await SeedInteractiveAppAsync(_fixture.Services, OtherAppId, OtherAppSecret);
        var (accountId, credentialId) = await SeedAccountAsync();

        using var scope_ = _fixture.Services.CreateScope();
        var sessions = scope_.ServiceProvider.GetRequiredService<IIdentitySessionStore>();
        var codes = scope_.ServiceProvider.GetRequiredService<IAuthorizationCodeStore>();
        var dbContext = scope_.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var applicationRowId = await dbContext.AppRegistrations
            .AsNoTracking()
            .Where(app => app.AppId == AppId)
            .Select(app => app.Id)
            .SingleAsync(TestContext.Current.CancellationToken);

        var now = createdAt ?? DateTimeOffset.UtcNow;
        var session = await sessions.CreateAsync(accountId, credentialId, now, TestContext.Current.CancellationToken);
        var creation = await codes.CreateAsync(
            session,
            new AuthorizationCodeBinding(applicationRowId, redirectUri, scope, Nonce, challenge),
            now,
            TestContext.Current.CancellationToken);
        return new SeededCode(creation.Code, creation.Id, session.Id, accountId, applicationRowId);
    }

    private static async Task<Guid> SeedInteractiveAppAsync(
        IServiceProvider services,
        string appId,
        string appSecret,
        bool allowAuthorizationCode = true,
        AudienceMode audienceMode = AudienceMode.PerApplication,
        int? maxAgeSeconds = null,
        string allowedScopes = "openid profile",
        bool allowRefreshToken = false)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        // The row is shared by the whole class while individual tests need different capability
        // shapes, so a reused row is always reset to this call's requested configuration.
        var application = await dbContext.AppRegistrations
            .FirstOrDefaultAsync(app => app.AppId == appId, TestContext.Current.CancellationToken);
        if (application is null)
        {
            application = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = appId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword(appSecret),
                AppName = $"Redemption {appId}",
                CreatedAt = DateTimeOffset.UtcNow
            };
            dbContext.AppRegistrations.Add(application);
        }

        application.IsActive = true;
        application.AudienceMode = audienceMode;
        application.ClientType = OidcClientType.Confidential;
        application.AllowAuthorizationCode = allowAuthorizationCode;
        application.AllowedScopes = allowedScopes;
        application.AllowRefreshToken = allowRefreshToken;
        application.IdentitySessionMaxAgeSeconds = maxAgeSeconds;
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        return application.Id;
    }

    private async Task<(Guid AccountId, Guid CredentialId)> SeedAccountAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var credential = await dbContext.PasswordCredentials
            .AsNoTracking()
            .FirstOrDefaultAsync(item => item.Username == Username, TestContext.Current.CancellationToken);
        if (credential is not null)
        {
            // A test that deactivated the shared account must not poison the ones after it.
            var account = await dbContext.Accounts
                .SingleAsync(row => row.Id == credential.AccountId, TestContext.Current.CancellationToken);
            account.IsActive = true;
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
            return (credential.AccountId, credential.Id);
        }

        var accountId = Guid.NewGuid();
        dbContext.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        var credentialId = Guid.NewGuid();
        dbContext.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId,
            AccountId = accountId,
            Username = Username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("redemption-user-secret"),
            CreatedAt = DateTimeOffset.UtcNow
        });
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        return (accountId, credentialId);
    }

    // ---- Requests ----

    private static FormUrlEncodedContent RedeemForm(
        string code,
        string? redirectUri = null,
        string? verifier = null,
        bool withPostCredentials = false,
        params (string Name, string Value)[] extra)
    {
        var fields = new List<KeyValuePair<string, string>>
        {
            new("grant_type", AuthorizationCodeRedemptionService.GrantType),
            new("code", code),
            new("redirect_uri", redirectUri ?? RedirectUri),
            new("code_verifier", verifier ?? Verifier)
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

    private static AuthenticationHeaderValue BasicHeader(string appId, string appSecret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{appId}:{appSecret}")));

    // ---- Assertions ----

    private sealed record SuccessOutcome(string AccessToken, string? RefreshToken);

    private async Task<SuccessOutcome> AssertSuccessAsync(
        HttpResponseMessage response,
        SeededCode seeded,
        string expectedScope,
        bool expectRefreshToken = false)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Contains("no-cache", response.Headers.Pragma.ToString(), StringComparison.Ordinal);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        var memberNames = body.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
        var expectedMembers = new HashSet<string>(StringComparer.Ordinal)
        {
            "access_token", "token_type", "expires_in", "scope", "id_token"
        };
        if (expectRefreshToken)
        {
            // PS-14: refresh_token appears only for a committed offline_access family.
            expectedMembers.Add("refresh_token");
        }

        Assert.Equal(expectedMembers, memberNames);
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.Equal(900, body.GetProperty("expires_in").GetInt64());
        Assert.Equal(expectedScope, body.GetProperty("scope").GetString());
        var refreshToken = expectRefreshToken ? body.GetProperty("refresh_token").GetString() : null;
        if (expectRefreshToken)
        {
            // DF-09 shape: 43 unpadded base64url characters, returned once.
            Assert.Equal(43, refreshToken!.Length);
            Assert.All(refreshToken, character =>
                Assert.True(char.IsAsciiLetterOrDigit(character) || character is '-' or '_'));
        }

        var accessToken = body.GetProperty("access_token").GetString()!;
        var token = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);
        Assert.Equal(JwtTokenService.AccessTokenType, token.Header.Typ);
        Assert.Equal(AppId, token.Audiences.Single());
        Assert.Equal(AppId, token.Claims.Single(claim => claim.Type == IdentityConstants.ClaimClientId).Value);
        Assert.Equal(seeded.AccountId.ToString(), token.Claims.Single(claim => claim.Type == IdentityConstants.ClaimSubject).Value);
        Assert.Equal(seeded.SessionId.ToString(), token.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Sid).Value);
        Assert.Equal(expectedScope, token.Claims.Single(claim => claim.Type == "scope").Value);
        Assert.Equal(
            IdentityConstants.InteractiveAccessTokenLifetimeSeconds,
            (token.ValidTo - token.ValidFrom).TotalSeconds);

        // The ID token is the PS-12 artifact of the same redemption: typ JWT (never at+jwt), the
        // exact authorization-request nonce, the session's auth facts, and the 5-minute lifetime.
        // It never appears in a legacy grant response.
        var idToken = new JwtSecurityTokenHandler().ReadJwtToken(body.GetProperty("id_token").GetString()!);
        Assert.Equal("JWT", idToken.Header.Typ);
        Assert.Equal(AppId, idToken.Audiences.Single());
        Assert.Equal(seeded.AccountId.ToString(), idToken.Claims.Single(claim => claim.Type == IdentityConstants.ClaimSubject).Value);
        Assert.Equal(seeded.SessionId.ToString(), idToken.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Sid).Value);
        Assert.Equal(Nonce, idToken.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Nonce).Value);
        Assert.Equal("pwd", idToken.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Amr).Value);
        Assert.Equal(
            IdentityConstants.InteractiveIdTokenLifetimeSeconds,
            (idToken.ValidTo - idToken.IssuedAt).TotalSeconds);
        Assert.DoesNotContain(idToken.Claims, claim => claim.Type is "scope" or IdentityConstants.ClaimClientId);
        // The profile scope decides whether the profile claims ride along.
        if (expectedScope.Contains("profile", StringComparison.Ordinal))
        {
            Assert.Contains(idToken.Claims, claim => claim.Type == IdentityConstants.ClaimName);
        }
        else
        {
            Assert.DoesNotContain(idToken.Claims, claim => claim.Type is IdentityConstants.ClaimName or IdentityConstants.ClaimNickname);
        }

        var codeRow = await GetCodeAsync(seeded.CodeId);
        Assert.NotNull(codeRow.ConsumedAt);
        if (!expectRefreshToken)
        {
            // EV-20: a no-refresh redemption commits a null family link.
            Assert.Null(codeRow.RefreshFamilyId);
            Assert.False(await QueryAsync(async dbContext =>
                await dbContext.RefreshTokens.AsNoTracking()
                    .AnyAsync(row => row.IdentitySessionId == seeded.SessionId, TestContext.Current.CancellationToken)));
        }

        var session = await GetSessionAsync(seeded.SessionId);
        Assert.Null(session.RevokedAt);
        Assert.Null(session.RevocationReason);

        var audits = await GetCodeAuditsAsync(seeded.CodeId);
        var redeemed = Assert.Single(audits, audit => audit.Action == RedeemedAction);
        Assert.Equal("AuthorizationCode", redeemed.TargetType);
        Assert.Equal(seeded.CodeId.ToString("D"), redeemed.TargetId);
        Assert.Equal(seeded.AccountId, redeemed.ActorId);
        Assert.Equal($"session:{seeded.SessionId}", redeemed.Description);
        return new SuccessOutcome(accessToken, refreshToken);
    }

    private async Task AssertReplayAsync(HttpResponseMessage response, SeededCode seeded)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
        Assert.Equal(InvalidGrantDescription, body.GetProperty("error_description").GetString());

        var session = await GetSessionAsync(seeded.SessionId);
        Assert.NotNull(session.RevokedAt);
        Assert.Equal("code_replay", session.RevocationReason);

        var audits = await GetCodeAuditsAsync(seeded.CodeId);
        var replayed = Assert.Single(audits, audit => audit.Action == ReplayedAction);
        Assert.Equal("AuthorizationCode", replayed.TargetType);
        Assert.Equal(seeded.CodeId.ToString("D"), replayed.TargetId);
        Assert.Equal(seeded.AccountId, replayed.ActorId);
        Assert.Equal($"session:{seeded.SessionId};family:none", replayed.Description);
        Assert.Single(audits, audit => audit.Action == RedeemedAction);
    }

    private async Task AssertInvalidGrantNoWriteAsync(
        string code,
        SeededCode? seeded = null,
        string? redirectUri = null,
        string? verifier = null,
        string? basicAppId = null,
        string? basicSecret = null)
    {
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(basicAppId ?? AppId, basicSecret ?? AppSecret);

        var response = await http.PostAsync(
            "/oauth2/token",
            RedeemForm(code, redirectUri: redirectUri, verifier: verifier),
            TestContext.Current.CancellationToken);

        await AssertErrorAsync(response, seeded ?? new SeededCode(code, Guid.Empty, Guid.Empty, Guid.Empty, Guid.Empty), "invalid_grant");
    }

    private async Task AssertErrorAsync(HttpResponseMessage response, SeededCode seeded, string errorCode)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(errorCode, body.GetProperty("error").GetString());
        if (errorCode == "invalid_grant")
        {
            Assert.Equal(InvalidGrantDescription, body.GetProperty("error_description").GetString());
        }

        if (seeded.CodeId != Guid.Empty)
        {
            await AssertCodeUntouchedAsync(seeded);
            await AssertNoCodeAuditAsync(seeded.CodeId);
        }
    }

    private async Task AssertCodeUntouchedAsync(SeededCode seeded)
    {
        var codeRow = await GetCodeAsync(seeded.CodeId);
        Assert.Null(codeRow.ConsumedAt);
        Assert.Null(codeRow.RefreshFamilyId);
    }

    private async Task AssertNoCodeAuditAsync(Guid codeId)
    {
        Assert.Empty(await GetCodeAuditsAsync(codeId));
    }

    // ---- Database access ----

    private Task<AuthorizationCodeEntity> GetCodeAsync(Guid codeId) =>
        QueryAsync(async dbContext => await dbContext.AuthorizationCodes.AsNoTracking()
            .SingleAsync(row => row.Id == codeId, TestContext.Current.CancellationToken));

    private Task<IdentitySessionEntity> GetSessionAsync(Guid sessionId) =>
        QueryAsync(async dbContext => await dbContext.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == sessionId, TestContext.Current.CancellationToken));

    private Task<List<AuditLogEntity>> GetCodeAuditsAsync(Guid codeId) =>
        QueryAsync(async dbContext => await dbContext.AuditLogs.AsNoTracking()
            .Where(row => row.TargetId == codeId.ToString("D")
                && (row.Action == RedeemedAction || row.Action == ReplayedAction))
            .OrderBy(row => row.Id)
            .ToListAsync(TestContext.Current.CancellationToken));

    private async Task RevokeSessionAsync(Guid sessionId, string reason) =>
        await ExecuteAsync(async dbContext =>
        {
            await dbContext.IdentitySessions
                .Where(row => row.Id == sessionId)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(row => row.RevokedAt, DateTimeOffset.UtcNow)
                    .SetProperty(row => row.RevocationReason, reason),
                    TestContext.Current.CancellationToken);
        });

    private async Task AdjustSessionAsync(
        Guid sessionId,
        bool idleExpired = false,
        bool absoluteExpired = false,
        int authTimeInThePastSeconds = 0) =>
        await ExecuteAsync(async dbContext =>
        {
            var now = DateTimeOffset.UtcNow;
            await dbContext.IdentitySessions
                .Where(row => row.Id == sessionId)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(
                        row => row.IdleExpiresAt,
                        row => idleExpired ? now.AddMinutes(-1) : row.IdleExpiresAt)
                    .SetProperty(
                        row => row.AbsoluteExpiresAt,
                        row => absoluteExpired ? now.AddMinutes(-1) : row.AbsoluteExpiresAt)
                    .SetProperty(
                        row => row.AuthTime,
                        row => authTimeInThePastSeconds > 0
                            ? now.AddSeconds(-authTimeInThePastSeconds)
                            : row.AuthTime),
                    TestContext.Current.CancellationToken);
        });

    private async Task DeactivateAccountAsync(Guid accountId) =>
        await ExecuteAsync(async dbContext =>
        {
            await dbContext.Accounts
                .Where(row => row.Id == accountId)
                .ExecuteUpdateAsync(
                    setters => setters.SetProperty(row => row.IsActive, false),
                    TestContext.Current.CancellationToken);
        });

    private async Task SetAllowedScopesAsync(Guid applicationId, string allowedScopes) =>
        await ExecuteAsync(async dbContext =>
        {
            await dbContext.AppRegistrations
                .Where(row => row.Id == applicationId)
                .ExecuteUpdateAsync(
                    setters => setters.SetProperty(row => row.AllowedScopes, allowedScopes),
                    TestContext.Current.CancellationToken);
        });

    private async Task ExpireCodeRowAsync(Guid codeId) =>
        await ExecuteAsync(async dbContext =>
        {
            await dbContext.AuthorizationCodes
                .Where(row => row.Id == codeId)
                .ExecuteUpdateAsync(
                    setters => setters.SetProperty(row => row.ExpiresAt, DateTimeOffset.UtcNow.AddHours(-1)),
                    TestContext.Current.CancellationToken);
        });

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

    // ---- EV-26 harness ----

    private async Task AssertEv26Async(bool failByThrowing)
    {
        var seeded = await SeedCodeAsync();
        var flaky = new FlakyInteractiveTokenFactory(failByThrowing);
        using var factory = _fixture.WithTestServices(services =>
        {
            services.RemoveAll<IInteractiveAccessTokenFactory>();
            services.AddSingleton<IInteractiveAccessTokenFactory>(_ => flaky);
        });
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader(AppId, AppSecret);

        using var failed = await client.PostAsync(
            "/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError, failed.StatusCode);
        Assert.Equal("no-store", failed.Headers.CacheControl?.ToString());
        var body = await failed.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("server_error", body.GetProperty("error").GetString());
        Assert.DoesNotContain("access_token", body.EnumerateObject().Select(property => property.Name));

        Assert.Equal(1, flaky.Calls);
        Assert.Null((await GetCodeAsync(seeded.CodeId)).ConsumedAt);
        await AssertNoCodeAuditAsync(seeded.CodeId);
        Assert.Null((await GetSessionAsync(seeded.SessionId)).RevokedAt);

        // SC-16: the rolled-back redemption was not a consumption — the retry succeeds and is
        // never treated as a replay.
        using var retried = await client.PostAsync(
            "/oauth2/token", RedeemForm(seeded.Code), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, retried.StatusCode);
        var audits = await GetCodeAuditsAsync(seeded.CodeId);
        Assert.Single(audits, audit => audit.Action == RedeemedAction);
        Assert.DoesNotContain(audits, audit => audit.Action == ReplayedAction);
    }

    private static string ComputeS256(string verifier)
    {
        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(digest).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>
    /// Fails the first <see cref="IInteractiveAccessTokenFactory.Create"/> call — by throwing or
    /// by the length refusal — and delegates every later call to the real factory built from the
    /// host's own <see cref="JwtOptions"/>.
    /// </summary>
    private sealed class FlakyInteractiveTokenFactory(bool failByThrowing) : IInteractiveAccessTokenFactory
    {
        private readonly InteractiveAccessTokenFactory _inner = new(
            new JwtOptions { Issuer = "https://redemption-flaky.test" },
            Microsoft.Extensions.Logging.Abstractions.NullLogger<InteractiveAccessTokenFactory>.Instance);

        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public InteractiveAccessTokenResult Create(
            InteractiveAccessTokenDescriptor descriptor,
            Microsoft.IdentityModel.Tokens.RsaSecurityKey signingKey,
            DateTimeOffset now)
        {
            if (Interlocked.Increment(ref _calls) == 1)
            {
                if (failByThrowing)
                {
                    throw new InvalidOperationException("The signing construction failed.");
                }

                return new InteractiveAccessTokenResult.ExceedsMaximumLength();
            }

            return _inner.Create(descriptor, signingKey, now);
        }
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _messages = new();

        public IReadOnlyCollection<string> Messages => _messages;

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(
            string categoryName,
            ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var message = formatter(state, exception);
                messages.Enqueue(exception is null
                    ? $"[{logLevel}] {categoryName}: {message}"
                    : $"[{logLevel}] {categoryName}: {message}{Environment.NewLine}{exception}");
            }
        }
    }
}
