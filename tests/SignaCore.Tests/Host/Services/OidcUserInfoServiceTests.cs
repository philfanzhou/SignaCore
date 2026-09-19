using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Host.Services;

/// <summary>
/// The UserInfo validation pipeline as a unit (<c>IN-28</c>/<c>IN-29</c>/<c>PS-16</c>): the
/// four-row error classification in predicate order, the exact per-application audience/client
/// binding, the interactive-claim presence split between <c>invalid_token</c> and
/// <c>insufficient_scope</c>, the live-state predicates under one captured instant, and the
/// closed response set with the token-scope/current-allow-list intersection. Access tokens are
/// signed with the same factory the endpoint trusts, so every cryptographic branch is real.
/// </summary>
public sealed class OidcUserInfoServiceTests
{
    private const string Issuer = "https://userinfo-unit.test";
    private const string ClientId = "userinfo-unit-app";
    private const string Username = "userinfo_unit_user";
    private const string CanonicalScope = "openid profile";

    [Fact]
    public async Task ReadAsync_ReturnsTheClosedPs16SetForALiveInteractiveToken()
    {
        await using var harness = await CreateHarnessAsync();
        var token = harness.IssueAccessToken();

        var outcome = await harness.Service.ReadAsync(
            Bearer(token), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.True(outcome.IsSuccess);
        Assert.Equal(harness.AccountId.ToString("D"), outcome.Subject);
        Assert.Equal(Username, outcome.Name);
        Assert.Equal("unit-nickname", outcome.Nickname);
    }

    [Fact]
    public async Task ReadAsync_SubjectMatchesTheIdTokenSubjectByteForByte()
    {
        await using var harness = await CreateHarnessAsync();
        var token = harness.IssueAccessToken();
        var idToken = harness.IssueIdToken();

        var outcome = await harness.Service.ReadAsync(
            Bearer(token), alternateCarrierPresent: false, TestContext.Current.CancellationToken);
        var subject = new JwtSecurityTokenHandler().ReadJwtToken(idToken)
            .Claims.Single(claim => claim.Type == IdentityConstants.ClaimSubject).Value;

        Assert.True(outcome.IsSuccess);
        Assert.Equal(subject, outcome.Subject);
    }

    [Fact]
    public async Task ReadAsync_WithoutProfileScope_ReturnsOnlySub()
    {
        await using var harness = await CreateHarnessAsync(scope: "openid");
        var token = harness.IssueAccessToken();

        var outcome = await harness.Service.ReadAsync(
            Bearer(token), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.True(outcome.IsSuccess);
        Assert.Equal(harness.AccountId.ToString("D"), outcome.Subject);
        Assert.Null(outcome.Name);
        Assert.Null(outcome.Nickname);
    }

    [Fact]
    public async Task ReadAsync_WhenProfileLeftTheCurrentAllowList_NarrowsToSub()
    {
        // SC-11: the token still carries profile, the application no longer allows it.
        await using var harness = await CreateHarnessAsync(allowedScopes: "openid");
        var token = harness.IssueAccessToken();

        var outcome = await harness.Service.ReadAsync(
            Bearer(token), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.True(outcome.IsSuccess);
        Assert.Null(outcome.Name);
        Assert.Null(outcome.Nickname);
    }

    [Fact]
    public async Task ReadAsync_WhenTheAccountHasNoNickname_OmitsOnlyTheNickname()
    {
        await using var harness = await CreateHarnessAsync(nickname: null);
        var token = harness.IssueAccessToken();

        var outcome = await harness.Service.ReadAsync(
            Bearer(token), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.True(outcome.IsSuccess);
        Assert.Equal(Username, outcome.Name);
        Assert.Null(outcome.Nickname);
    }

    // ---- IN-28: the structure rows ----

    [Fact]
    public async Task ReadAsync_WithoutAnAuthorizationHeader_AnswersMissingBearer()
    {
        await using var harness = await CreateHarnessAsync();

        var outcome = await harness.Service.ReadAsync(
            StringValues.Empty, alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.Equal(OidcUserInfoRejection.MissingBearer, outcome.Rejection);
    }

    [Theory]
    [InlineData("Basic dXNlcjpwYXNz")]
    [InlineData("Bearer")]
    [InlineData("Bearer ")]
    public async Task ReadAsync_ForAMalformedHeader_AnswersInvalidRequest(string header)
    {
        await using var harness = await CreateHarnessAsync();

        var outcome = await harness.Service.ReadAsync(
            new StringValues(header), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.Equal(OidcUserInfoRejection.InvalidRequest, outcome.Rejection);
    }

    [Fact]
    public async Task ReadAsync_WithMixedCaseBearerScheme_IsAccepted()
    {
        await using var harness = await CreateHarnessAsync();
        var token = harness.IssueAccessToken();

        var outcome = await harness.Service.ReadAsync(
            new StringValues($"bEaReR {token}"),
            alternateCarrierPresent: false,
            TestContext.Current.CancellationToken);

        Assert.True(outcome.IsSuccess);
    }

    [Fact]
    public async Task ReadAsync_WithMultipleAuthorizationValues_AnswersInvalidRequest()
    {
        await using var harness = await CreateHarnessAsync();
        var token = harness.IssueAccessToken();

        var outcome = await harness.Service.ReadAsync(
            new StringValues([$"Bearer {token}", $"Bearer {token}"]),
            alternateCarrierPresent: false,
            TestContext.Current.CancellationToken);

        Assert.Equal(OidcUserInfoRejection.InvalidRequest, outcome.Rejection);
    }

    [Fact]
    public async Task ReadAsync_WithAnAlternateCarrier_AnswersInvalidRequestBeforeReadingState()
    {
        await using var harness = await CreateHarnessAsync();
        var token = harness.IssueAccessToken();

        var outcome = await harness.Service.ReadAsync(
            Bearer(token), alternateCarrierPresent: true, TestContext.Current.CancellationToken);

        Assert.Equal(OidcUserInfoRejection.InvalidRequest, outcome.Rejection);
    }

    [Fact]
    public async Task ReadAsync_WithAnOverlongOrNonAsciiToken_AnswersInvalidRequest()
    {
        await using var harness = await CreateHarnessAsync();

        var overlong = await harness.Service.ReadAsync(
            new StringValues("Bearer " + new string('a', IdentityConstants.InteractiveTokenMaxSerializedLength + 1)),
            alternateCarrierPresent: false,
            TestContext.Current.CancellationToken);
        Assert.Equal(OidcUserInfoRejection.InvalidRequest, overlong.Rejection);

        var nonAscii = await harness.Service.ReadAsync(
            new StringValues("Bearer tökén-with-unicode"),
            alternateCarrierPresent: false,
            TestContext.Current.CancellationToken);
        Assert.Equal(OidcUserInfoRejection.InvalidRequest, nonAscii.Rejection);
    }

    // ---- IN-29: the cryptographic and binding rows ----

    [Fact]
    public async Task ReadAsync_ForAnIdToken_AnswersInvalidToken()
    {
        // An ID token carries typ JWT — the type confusion the endpoint must refuse (PS-12/PS-13).
        await using var harness = await CreateHarnessAsync();
        var idToken = harness.IssueIdToken();

        var outcome = await harness.Service.ReadAsync(
            Bearer(idToken), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.Equal(OidcUserInfoRejection.InvalidToken, outcome.Rejection);
    }

    [Fact]
    public async Task ReadAsync_ForATamperedToken_AnswersInvalidToken()
    {
        await using var harness = await CreateHarnessAsync();
        var token = harness.IssueAccessToken();
        var tampered = token[..^4] + (token[^4] == 'A' ? 'B' : 'A') + token[^3..];

        var outcome = await harness.Service.ReadAsync(
            Bearer(tampered), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.Equal(OidcUserInfoRejection.InvalidToken, outcome.Rejection);
    }

    [Fact]
    public async Task ReadAsync_ForAnExpiredToken_AnswersInvalidToken()
    {
        await using var harness = await CreateHarnessAsync();
        // Signed with the trusted key but issued long enough ago that exp has passed.
        var token = harness.IssueAccessToken(issuedAt: DateTimeOffset.UtcNow.AddHours(-1));

        var outcome = await harness.Service.ReadAsync(
            Bearer(token), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.Equal(OidcUserInfoRejection.InvalidToken, outcome.Rejection);
    }

    [Fact]
    public async Task ReadAsync_ForAnotherIssuer_AnswersInvalidToken()
    {
        await using var harness = await CreateHarnessAsync();
        var token = harness.IssueAccessToken(issuer: "https://attacker.example.test");

        var outcome = await harness.Service.ReadAsync(
            Bearer(token), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.Equal(OidcUserInfoRejection.InvalidToken, outcome.Rejection);
    }

    [Fact]
    public async Task ReadAsync_WhenTheAudienceIsNotTheClientBinding_AnswersInvalidToken()
    {
        await using var harness = await CreateHarnessAsync();
        var token = harness.IssueAccessToken(audience: "https://shared-audience.test");

        var outcome = await harness.Service.ReadAsync(
            Bearer(token), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.Equal(OidcUserInfoRejection.InvalidToken, outcome.Rejection);
    }

    [Fact]
    public async Task ReadAsync_WhenTheSessionRowIsMissing_AnswersInvalidToken()
    {
        await using var harness = await CreateHarnessAsync();
        var token = harness.IssueAccessToken(sessionId: Guid.NewGuid());

        var outcome = await harness.Service.ReadAsync(
            Bearer(token), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.Equal(OidcUserInfoRejection.InvalidToken, outcome.Rejection);
    }

    [Theory]
    [InlineData(true, false, false, false, false)]   // revoked session
    [InlineData(false, true, false, false, false)]   // idle expired (SC-10)
    [InlineData(false, false, true, false, false)]   // absolute expired (SC-10)
    [InlineData(false, false, false, true, false)]   // application max-age exceeded
    [InlineData(false, false, false, false, true)]   // deactivated application (SC-12)
    public async Task ReadAsync_ForRejectedCurrentState_AnswersInvalidToken(
        bool revokeSession,
        bool idleExpireSession,
        bool absoluteExpireSession,
        bool exceedMaxAge,
        bool deactivateApplication)
    {
        await using var harness = await CreateHarnessAsync(maxAgeSeconds: exceedMaxAge ? 5 : null);
        var token = harness.IssueAccessToken();
        var now = DateTimeOffset.UtcNow;
        await harness.Context.IdentitySessions
            .Where(row => row.Id == harness.SessionId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.RevokedAt, revokeSession ? now : (DateTimeOffset?)null)
                .SetProperty(row => row.RevocationReason, revokeSession ? "administrative" : null)
                .SetProperty(row => row.IdleExpiresAt, row => idleExpireSession ? now.AddMinutes(-1) : row.IdleExpiresAt)
                .SetProperty(row => row.AbsoluteExpiresAt, row => absoluteExpireSession ? now.AddMinutes(-1) : row.AbsoluteExpiresAt)
                .SetProperty(row => row.AuthTime, row => exceedMaxAge ? now.AddSeconds(-30) : row.AuthTime),
                TestContext.Current.CancellationToken);
        if (deactivateApplication)
        {
            await harness.Context.AppRegistrations
                .Where(row => row.Id == harness.ApplicationId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false),
                    TestContext.Current.CancellationToken);
        }

        var outcome = await harness.Service.ReadAsync(
            Bearer(token), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.Equal(OidcUserInfoRejection.InvalidToken, outcome.Rejection);
    }

    [Fact]
    public async Task ReadAsync_ForADeactivatedAccount_AnswersInvalidToken()
    {
        await using var harness = await CreateHarnessAsync();
        var token = harness.IssueAccessToken();
        await harness.Context.Accounts
            .Where(row => row.Id == harness.AccountId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false),
                TestContext.Current.CancellationToken);

        var outcome = await harness.Service.ReadAsync(
            Bearer(token), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.Equal(OidcUserInfoRejection.InvalidToken, outcome.Rejection);
    }

    // ---- IN-29: the interactive-claim presence row ----

    [Fact]
    public async Task ReadAsync_WithoutTheInteractiveClaims_AnswersInsufficientScope()
    {
        await using var harness = await CreateHarnessAsync();
        // A signature-valid RS256 at+jwt from this issuer, but with none of the interactive
        // binding claims and no openid scope — e.g. a service token minted by hand.
        var token = harness.IssueBareServiceToken();

        var outcome = await harness.Service.ReadAsync(
            Bearer(token), alternateCarrierPresent: false, TestContext.Current.CancellationToken);

        Assert.Equal(OidcUserInfoRejection.InsufficientScope, outcome.Rejection);
    }

    // ---- Harness ----

    private static StringValues Bearer(string token) => new($"Bearer {token}");

    private sealed class UserInfoHarness(
        SqliteConnection connection,
        IdentityDbContext context,
        OidcUserInfoService service,
        StaticKeyManager keys,
        Guid accountId,
        Guid sessionId,
        Guid applicationId,
        string scope) : IAsyncDisposable
    {
        public SqliteConnection Connection { get; } = connection;

        public IdentityDbContext Context { get; } = context;

        public OidcUserInfoService Service { get; } = service;

        public StaticKeyManager Keys { get; } = keys;

        public Guid AccountId { get; } = accountId;

        public Guid SessionId { get; } = sessionId;

        public Guid ApplicationId { get; } = applicationId;

        public string Scope { get; } = scope;

        public string IssueAccessToken(
            DateTimeOffset? issuedAt = null,
            string? issuer = null,
            string? audience = null,
            Guid? sessionId = null) => new InteractiveAccessTokenFactory(
                new JwtOptions { Issuer = issuer ?? Issuer },
                NullLogger<InteractiveAccessTokenFactory>.Instance)
            .Create(
                new InteractiveAccessTokenDescriptor(
                    AccountId,
                    ClientId,
                    sessionId ?? SessionId,
                    IdentityConstants.AuthMethodPassword,
                    Scope,
                    DisplayName: Username,
                    Nickname: "unit-nickname",
                    EnrichmentClaims: []),
                Keys.GetCurrentKey(),
                issuedAt ?? DateTimeOffset.UtcNow) switch
            {
                InteractiveAccessTokenResult.Issued issued when audience is null => issued.AccessToken,
                InteractiveAccessTokenResult.Issued issued => ReplaceAudience(issued.AccessToken, audience!),
                _ => throw new InvalidOperationException("The unit access token exceeded the length bound.")
            };

        public string IssueIdToken() => new InteractiveIdTokenFactory(new JwtOptions { Issuer = Issuer })
            .Create(
                new InteractiveIdTokenDescriptor(
                    AccountId,
                    ClientId,
                    SessionId,
                    IdentityConstants.AuthMethodPassword,
                    Scope,
                    Nonce: "userinfo-unit-nonce",
                    AuthTime: DateTimeOffset.UtcNow,
                    PasswordUsername: Username,
                    Nickname: "unit-nickname"),
                Keys.GetCurrentKey(),
                DateTimeOffset.UtcNow) switch
            {
                InteractiveIdTokenResult.Issued issued => issued.IdToken,
                _ => throw new InvalidOperationException("The unit ID token exceeded the length bound.")
            };

        /// <summary>
        /// A typ at+jwt token with a valid RS256 signature over the trusted key but without any
        /// interactive claim — no sub, client_id, sid, or scope.
        /// </summary>
        public string IssueBareServiceToken()
        {
            var credentials = new SigningCredentials(Keys.GetCurrentKey(), SecurityAlgorithms.RsaSha256);
            var header = new JwtHeader(credentials)
            {
                [JwtHeaderParameterNames.Typ] = JwtTokenService.AccessTokenType
            };
            var payload = new JwtPayload(
                issuer: Issuer,
                audience: ClientId,
                claims: [new Claim("unit", "service")],
                notBefore: DateTimeOffset.UtcNow.UtcDateTime,
                expires: DateTimeOffset.UtcNow.AddMinutes(5).UtcDateTime,
                issuedAt: DateTimeOffset.UtcNow.UtcDateTime);
            return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
        }

        private static string ReplaceAudience(string token, string audience)
        {
            // Rewrite only the aud member of the JSON payload and re-encode; the signature is
            // deliberately left invalid — the audience predicate must reject before it.
            var parts = token.Split('.');
            using var payload = System.Text.Json.JsonDocument.Parse(
                Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(parts[1]));
            var rewritten = new JsonObject
            {
                ["aud"] = audience
            };
            foreach (var member in payload.RootElement.EnumerateObject())
            {
                if (member.Name != JwtRegisteredClaimNames.Aud)
                {
                    rewritten[member.Name] = System.Text.Json.JsonSerializer.SerializeToNode(member.Value);
                }
            }

            return $"{parts[0]}.{Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(rewritten.ToJsonString()))}.{parts[2]}";
        }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }

    private static async Task<UserInfoHarness> CreateHarnessAsync(
        string scope = CanonicalScope,
        string allowedScopes = CanonicalScope,
        string? nickname = "unit-nickname",
        int? maxAgeSeconds = null)
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(connection).Options);
        await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);

        var applicationId = Guid.NewGuid();
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = applicationId,
            AppId = ClientId,
            AppSecretHash = "hash",
            AppName = "UserInfo Unit Client",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = allowedScopes,
            AllowRefreshToken = true,
            IdentitySessionMaxAgeSeconds = maxAgeSeconds
        });
        context.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            Nickname = nickname,
            CreatedAt = DateTimeOffset.UtcNow
        });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId,
            AccountId = accountId,
            Username = Username,
            PasswordHash = "hash",
            CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();

        var unitOfWork = new EfCoreUnitOfWork(context);
        var session = await new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork)
            .CreateAsync(accountId, credentialId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);

        var keys = new StaticKeyManager();
        var service = new OidcUserInfoService(
            keys,
            new AccountRepository(context),
            new PasswordCredentialRepository(context),
            context,
            new JwtOptions { Issuer = Issuer },
            NullLogger<OidcUserInfoService>.Instance);
        return new UserInfoHarness(
            connection, context, service, keys, accountId, session.Id, applicationId, scope);
    }

    /// <summary>A synchronous, in-memory key manager: one fixed RSA key, no refresh effect.</summary>
    private sealed class StaticKeyManager : IKeyManager
    {
        private readonly RsaSecurityKey _key;

        public StaticKeyManager()
        {
            var rsa = System.Security.Cryptography.RSA.Create(2048);
            _key = new RsaSecurityKey(rsa) { KeyId = Guid.NewGuid().ToString() };
        }

        public RsaSecurityKey GetCurrentKey() => _key;

        public IReadOnlyList<SecurityKey> GetValidationKeys() => [_key];

        public Task RefreshKeysAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<RsaSecurityKey>>([_key]);

        public Task<bool> NeedsKeyRotationAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task RotateKeyAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task InitializationCompleted => Task.CompletedTask;
    }
}
