using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Moq;
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
/// The redemption transaction as a unit: the committed success shape (consumption, id-only
/// audit, token claims including the bootstrap role), the <c>EV-21</c> offline_access family
/// (root, code link, one-shot plaintext refresh token), the <c>EV-11</c> refresh-toggle
/// rejection, the <c>EV-26</c> rollback for a failing or oversized token construction, the
/// unreachable-but-enforced conditional-consumption loss, the <c>EV-24</c> replay disposal with
/// and without a family link, the <c>EV-18</c> cancellation with zero writes, and the
/// <c>DF-03</c>/<c>DF-04</c>/<c>DF-09</c> canary scan of the log surface.
/// </summary>
public sealed class AuthorizationCodeRedemptionServiceTests
{
    private const string ClientId = "redemption-unit-app";
    private const string RedirectUri = "https://bff.redemption.unit.test/callback";
    private const string Nonce = "redemption-unit-nonce";
    private const string Username = "redemption_unit_user";
    private const string CorrelationId = "redemption-unit-correlation-0123";

    // RFC 7636 appendix B.
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    [Fact]
    public async Task RedeemAsync_CommitsTheConsumptionTheAuditAndBothTokens()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);

        var outcome = await database.Service.RedeemAsync(
            seed.Application,
            CreateForm(seed.Code),
            "203.0.113.9",
            CorrelationId,
            TestContext.Current.CancellationToken);

        Assert.True(outcome.IsSuccess);
        Assert.Equal(IdentityConstants.InteractiveAccessTokenLifetimeSeconds, outcome.ExpiresIn);
        Assert.Equal("openid profile", outcome.Scope);
        Assert.NotEqual(outcome.AccessToken, outcome.IdToken);

        var cancellationToken = TestContext.Current.CancellationToken;
        var codeRow = await database.Context.AuthorizationCodes.AsNoTracking()
            .SingleAsync(row => row.Id == seed.CodeId, cancellationToken);
        Assert.NotNull(codeRow.ConsumedAt);
        Assert.Null(codeRow.RefreshFamilyId);

        // The session row takes no write from a redemption.
        var sessionRow = await database.Context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, cancellationToken);
        Assert.Null(sessionRow.RevokedAt);

        var audit = Assert.Single(await database.Context.AuditLogs.AsNoTracking()
            .ToListAsync(cancellationToken));
        Assert.Equal("oidc.code.redeemed", audit.Action);
        Assert.Equal("AuthorizationCode", audit.TargetType);
        Assert.Equal(seed.CodeId.ToString("D"), audit.TargetId);
        Assert.Equal(seed.AccountId, audit.ActorId);
        Assert.Equal($"session:{seed.SessionId}", audit.Description);

        var token = new JwtSecurityTokenHandler().ReadJwtToken(outcome.AccessToken);
        Assert.Equal(JwtTokenService.AccessTokenType, token.Header.Typ);
        Assert.Equal(ClientId, token.Audiences.Single());
        Assert.Equal(seed.AccountId.ToString(), token.Claims.Single(c => c.Type == IdentityConstants.ClaimSubject).Value);
        Assert.Equal(seed.SessionId.ToString(), token.Claims.Single(c => c.Type == JwtRegisteredClaimNames.Sid).Value);
        Assert.Equal("openid profile", token.Claims.Single(c => c.Type == "scope").Value);
        // The display name falls back to the password credential username, and the bootstrap
        // admin rule injects role:admin for the configured account.
        Assert.Equal(Username, token.Claims.Single(c => c.Type == IdentityConstants.ClaimName).Value);
        Assert.Equal("admin", token.Claims.Single(c => c.Type == IdentityConstants.ClaimRole).Value);
        // The access token never carries a nonce.
        Assert.DoesNotContain(token.Claims, claim => claim.Type == JwtRegisteredClaimNames.Nonce);

        // The ID token is a separate PS-12 artifact: no at+jwt type, the exact code-row nonce
        // snapshot, the session's auth facts, and the profile sources — not the display-name
        // resolution the access token uses.
        var idToken = new JwtSecurityTokenHandler().ReadJwtToken(outcome.IdToken);
        Assert.Equal("JWT", idToken.Header.Typ);
        Assert.Equal(ClientId, idToken.Audiences.Single());
        Assert.Equal(seed.AccountId.ToString(), idToken.Claims.Single(c => c.Type == IdentityConstants.ClaimSubject).Value);
        Assert.Equal(seed.SessionId.ToString(), idToken.Claims.Single(c => c.Type == JwtRegisteredClaimNames.Sid).Value);
        Assert.Equal(Nonce, idToken.Claims.Single(c => c.Type == JwtRegisteredClaimNames.Nonce).Value);
        Assert.Equal("pwd", idToken.Claims.Single(c => c.Type == JwtRegisteredClaimNames.Amr).Value);
        Assert.Equal(Username, idToken.Claims.Single(c => c.Type == IdentityConstants.ClaimName).Value);
        Assert.Equal(
            seed.AuthTime.ToUnixTimeSeconds(),
            long.Parse(idToken.Claims.Single(c => c.Type == JwtRegisteredClaimNames.AuthTime).Value, CultureInfo.InvariantCulture));
        Assert.Equal(
            ((DateTimeOffset)idToken.IssuedAt).ToUnixTimeSeconds() + IdentityConstants.InteractiveIdTokenLifetimeSeconds,
            ((DateTimeOffset)idToken.ValidTo).ToUnixTimeSeconds());
        // The closed PS-12 set: no access-token binding claims and no enrichment of any kind.
        Assert.DoesNotContain(idToken.Claims, claim => claim.Type is "scope" or IdentityConstants.ClaimClientId
            or IdentityConstants.ClaimAuthMethod or IdentityConstants.ClaimRole or JwtRegisteredClaimNames.Jti);
        Assert.Null(idToken.Payload.Nbf);

        // A standard validator accepts the ID token through the same key material JWKS publishes.
        var key = database.Key;
        new JwtSecurityTokenHandler().ValidateToken(
            outcome.IdToken,
            new TokenValidationParameters
            {
                ValidIssuer = "https://redemption-unit.test",
                ValidAudience = ClientId,
                IssuerSigningKey = key,
                ValidTypes = ["JWT"],
                ValidateLifetime = true
            },
            out _);
    }

    [Fact]
    public async Task RedeemAsync_WithOfflineAccess_CommitsTheFamilyRootAndLinkAndReturnsTheRefreshToken()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context, scope: "openid profile offline_access", allowRefreshToken: true);

        var outcome = await database.Service.RedeemAsync(
            seed.Application,
            CreateForm(seed.Code),
            "203.0.113.9",
            CorrelationId,
            TestContext.Current.CancellationToken);

        Assert.True(outcome.IsSuccess);
        Assert.Equal("openid profile offline_access", outcome.Scope);
        Assert.NotNull(outcome.RefreshToken);
        // DF-09 shape: 256 bits of CSPRNG output, 43 unpadded base64url characters.
        Assert.Equal(43, outcome.RefreshToken.Length);
        Assert.All(outcome.RefreshToken, character =>
            Assert.True(char.IsAsciiLetterOrDigit(character) || character is '-' or '_'));

        var cancellationToken = TestContext.Current.CancellationToken;
        var codeRow = await database.Context.AuthorizationCodes.AsNoTracking()
            .SingleAsync(row => row.Id == seed.CodeId, cancellationToken);
        Assert.NotNull(codeRow.ConsumedAt);

        // The committed root: singleton root of its own family, complete interactive marker, the
        // 7-day cap on expires_at, and only the versioned digest — never the plaintext token.
        var root = Assert.Single(await database.Context.RefreshTokens.AsNoTracking()
            .ToListAsync(cancellationToken));
        Assert.Equal(codeRow.RefreshFamilyId, root.Id);
        Assert.Equal(root.Id, root.FamilyId);
        Assert.Null(root.ParentId);
        Assert.Equal(seed.AccountId, root.AccountId);
        Assert.Equal(ClientId, root.AppId);
        Assert.Equal(seed.SessionId, root.IdentitySessionId);
        Assert.Equal("openid profile offline_access", root.Scope);
        Assert.NotNull(root.AuthTime);
        Assert.False(root.IsRevoked);
        Assert.Equal(
            root.CreatedAt.AddDays(IdentityConstants.InteractiveRefreshFamilyLifetimeDays),
            root.ExpiresAt);
        Assert.Equal(RefreshTokenDigest.Compute(outcome.RefreshToken), root.TokenValue);
        Assert.DoesNotContain(outcome.RefreshToken, root.TokenValue, StringComparison.Ordinal);

        // The session row takes no write from a redemption, and the audit stays id-only.
        var sessionRow = await database.Context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, cancellationToken);
        Assert.Null(sessionRow.RevokedAt);
        var audit = Assert.Single(await database.Context.AuditLogs.AsNoTracking()
            .ToListAsync(cancellationToken));
        Assert.Equal("oidc.code.redeemed", audit.Action);
        Assert.Equal($"session:{seed.SessionId}", audit.Description);
    }

    [Fact]
    public async Task RedeemAsync_WithOfflineAccess_WhenRefreshIsDisabled_ReturnsTheGenericInvalidGrantAndWritesNothing()
    {
        // EV-11: the current AllowRefreshToken is an authoritative in-lock recheck. The code
        // stays unconsumed, no family is written, and no refresh token is released.
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context, scope: "openid offline_access", allowRefreshToken: false);

        var outcome = await database.Service.RedeemAsync(
            seed.Application,
            CreateForm(seed.Code),
            null,
            CorrelationId,
            TestContext.Current.CancellationToken);

        Assert.False(outcome.IsSuccess);
        Assert.Equal(400, outcome.Status);
        Assert.Equal("invalid_grant", outcome.ErrorCode);
        await AssertNothingWrittenAsync(database.Context, seed);
    }

    [Fact]
    public async Task RedeemAsync_WithOfflineAccess_AndACancelledToken_ThrowsAndWritesNothing()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context, scope: "openid offline_access", allowRefreshToken: true);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            database.Service.RedeemAsync(
                seed.Application,
                CreateForm(seed.Code),
                null,
                CorrelationId,
                cancellation.Token));

        await AssertNothingWrittenAsync(database.Context, seed);
    }

    [Fact]
    public async Task RedeemAsync_WithOfflineAccess_NeverLogsTheRefreshToken()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context, scope: "openid offline_access", allowRefreshToken: true);

        var capture = new List<string>();
        var service = database.CreateService(new RecordingLogger(capture));

        var outcome = await service.RedeemAsync(
            seed.Application, CreateForm(seed.Code), null, CorrelationId, TestContext.Current.CancellationToken);
        Assert.True(outcome.IsSuccess);

        var dump = string.Join(Environment.NewLine, capture);
        Assert.DoesNotContain(outcome.RefreshToken!, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(Nonce, dump, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RedeemAsync_WhenSigningThrows_ReturnsServerErrorAndWritesNothing()
    {
        await using var database = await CreateDatabaseAsync(tokenFactory: new ThrowingTokenFactory());
        var seed = await SeedAsync(database.Context);

        var outcome = await database.Service.RedeemAsync(
            seed.Application,
            CreateForm(seed.Code),
            null,
            CorrelationId,
            TestContext.Current.CancellationToken);

        Assert.False(outcome.IsSuccess);
        Assert.Equal(500, outcome.Status);
        Assert.Equal("server_error", outcome.ErrorCode);
        await AssertNothingWrittenAsync(database.Context, seed);
    }

    [Fact]
    public async Task RedeemAsync_WhenTheTokenExceedsTheMaximumLength_ReturnsServerErrorAndWritesNothing()
    {
        await using var database = await CreateDatabaseAsync(tokenFactory: new OversizedTokenFactory());
        var seed = await SeedAsync(database.Context);

        var outcome = await database.Service.RedeemAsync(
            seed.Application,
            CreateForm(seed.Code),
            null,
            CorrelationId,
            TestContext.Current.CancellationToken);

        Assert.False(outcome.IsSuccess);
        Assert.Equal(500, outcome.Status);
        Assert.Equal("server_error", outcome.ErrorCode);
        await AssertNothingWrittenAsync(database.Context, seed);
    }

    [Fact]
    public async Task RedeemAsync_WhenTheIdTokenExceedsTheMaximumLength_ReturnsServerErrorAndWritesNothing()
    {
        await using var database = await CreateDatabaseAsync(idTokenFactory: new OversizedIdTokenFactory());
        var seed = await SeedAsync(database.Context);

        var outcome = await database.Service.RedeemAsync(
            seed.Application,
            CreateForm(seed.Code),
            null,
            CorrelationId,
            TestContext.Current.CancellationToken);

        Assert.False(outcome.IsSuccess);
        Assert.Equal(500, outcome.Status);
        Assert.Equal("server_error", outcome.ErrorCode);
        await AssertNothingWrittenAsync(database.Context, seed);
    }

    [Fact]
    public async Task RedeemAsync_WhenTheIdTokenConstructionThrows_ReturnsServerErrorAndWritesNothing()
    {
        await using var database = await CreateDatabaseAsync(idTokenFactory: new ThrowingIdTokenFactory());
        var seed = await SeedAsync(database.Context);

        var outcome = await database.Service.RedeemAsync(
            seed.Application,
            CreateForm(seed.Code),
            null,
            CorrelationId,
            TestContext.Current.CancellationToken);

        Assert.False(outcome.IsSuccess);
        Assert.Equal(500, outcome.Status);
        Assert.Equal("server_error", outcome.ErrorCode);
        await AssertNothingWrittenAsync(database.Context, seed);
    }

    [Fact]
    public async Task RedeemAsync_WhenTheConditionalConsumptionLoses_ReturnsInvalidGrantAndWritesNothing()
    {
        // The loss is unreachable under the lock; the branch is still enforced against drift.
        await using var database = await CreateDatabaseAsync(
            codeStoreOverride: context => new LosingConsumptionCodeStore(new AuthorizationCodeStore(
                new AuthorizationCodeRepository(context), new EfCoreUnitOfWork(context))));
        var seed = await SeedAsync(database.Context);

        var outcome = await database.Service.RedeemAsync(
            seed.Application,
            CreateForm(seed.Code),
            null,
            CorrelationId,
            TestContext.Current.CancellationToken);

        Assert.False(outcome.IsSuccess);
        Assert.Equal(400, outcome.Status);
        Assert.Equal("invalid_grant", outcome.ErrorCode);
        await AssertNothingWrittenAsync(database.Context, seed);
    }

    [Fact]
    public async Task RedeemAsync_OnAReplayedCodeCarryingAFamilyLink_RevokesTheFamilyAndTheSession()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);

        // Commit a consumption and the family link of a first offline_access redemption, plus a
        // sibling family of the same session: EV-24 revokes exactly the named family directly,
        // and the sibling only through the session revocation.
        var rootId = Guid.NewGuid();
        var siblingId = Guid.NewGuid();
        var authTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        database.Context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = rootId,
            FamilyId = rootId,
            AccountId = seed.AccountId,
            TokenValue = RefreshTokenDigest.Compute("unit-family-root-token"),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AppId = ClientId,
            IdentitySessionId = seed.SessionId,
            Scope = "openid profile offline_access",
            AuthTime = authTime
        });
        database.Context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = siblingId,
            FamilyId = siblingId,
            AccountId = seed.AccountId,
            TokenValue = RefreshTokenDigest.Compute("unit-family-sibling-token"),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AppId = ClientId,
            IdentitySessionId = seed.SessionId,
            Scope = "openid profile offline_access",
            AuthTime = authTime
        });
        var codeRow = await database.Context.AuthorizationCodes
            .SingleAsync(row => row.Id == seed.CodeId, TestContext.Current.CancellationToken);
        codeRow.ConsumedAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        codeRow.RefreshFamilyId = rootId;
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        database.Context.ChangeTracker.Clear();

        var outcome = await database.Service.RedeemAsync(
            seed.Application,
            CreateForm(seed.Code),
            null,
            CorrelationId,
            TestContext.Current.CancellationToken);

        Assert.False(outcome.IsSuccess);
        Assert.Equal(400, outcome.Status);
        Assert.Equal("invalid_grant", outcome.ErrorCode);

        var cancellationToken = TestContext.Current.CancellationToken;
        var namedRoot = await database.Context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == rootId, cancellationToken);
        Assert.True(namedRoot.IsRevoked);
        var sessionRow = await database.Context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, cancellationToken);
        Assert.NotNull(sessionRow.RevokedAt);
        Assert.Equal("code_replay", sessionRow.RevocationReason);

        // The audit names the exact family id and nothing sensitive.
        var audit = Assert.Single(await database.Context.AuditLogs.AsNoTracking()
            .ToListAsync(cancellationToken));
        Assert.Equal("oidc.code.replayed", audit.Action);
        Assert.Equal($"session:{seed.SessionId};family:{rootId}", audit.Description);
    }

    [Fact]
    public async Task RedeemAsync_WithACancelledToken_ThrowsAndWritesNothing()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            database.Service.RedeemAsync(
                seed.Application,
                CreateForm(seed.Code),
                null,
                CorrelationId,
                cancellation.Token));

        await AssertNothingWrittenAsync(database.Context, seed);
    }

    [Fact]
    public async Task RedeemAsync_OnAConsumedCode_CommitsTheReplayDisposal()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);
        var codeRow = await database.Context.AuthorizationCodes
            .SingleAsync(row => row.Id == seed.CodeId, TestContext.Current.CancellationToken);
        codeRow.ConsumedAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        database.Context.ChangeTracker.Clear();

        var outcome = await database.Service.RedeemAsync(
            seed.Application,
            CreateForm(seed.Code),
            null,
            CorrelationId,
            TestContext.Current.CancellationToken);

        Assert.False(outcome.IsSuccess);
        Assert.Equal(400, outcome.Status);
        Assert.Equal("invalid_grant", outcome.ErrorCode);

        var sessionRow = await database.Context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, TestContext.Current.CancellationToken);
        Assert.NotNull(sessionRow.RevokedAt);
        Assert.Equal("code_replay", sessionRow.RevocationReason);

        var audit = Assert.Single(await database.Context.AuditLogs.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal("oidc.code.replayed", audit.Action);
        Assert.Equal(seed.AccountId, audit.ActorId);
        Assert.Equal($"session:{seed.SessionId};family:none", audit.Description);
    }

    [Fact]
    public async Task RedeemAsync_NeverLogsTheCodeTheVerifierOrTheRedirectUri()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);

        var capture = new List<string>();
        var service = database.CreateService(new RecordingLogger(capture));

        Assert.True((await service.RedeemAsync(
            seed.Application, CreateForm(seed.Code), null, CorrelationId, TestContext.Current.CancellationToken)).IsSuccess);
        Assert.False((await service.RedeemAsync(
            seed.Application, CreateForm(seed.Code), null, CorrelationId, TestContext.Current.CancellationToken)).IsSuccess);
        Assert.False((await service.RedeemAsync(
            seed.Application, CreateForm(seed.Code, verifier: new string('w', 43)), null, CorrelationId, TestContext.Current.CancellationToken)).IsSuccess);

        Assert.Contains(capture, message => message.Contains("Authorization code redeemed", StringComparison.Ordinal));

        var dump = string.Join(Environment.NewLine, capture);
        Assert.DoesNotContain(seed.Code, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(Verifier, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(RedirectUri, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(Nonce, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(seed.SessionId.ToString(), dump, StringComparison.Ordinal);
    }

    // ---- Harness ----

    private sealed record Seed(
        AppRegistrationEntity Application,
        Guid AccountId,
        Guid CredentialId,
        Guid SessionId,
        Guid CodeId,
        string Code,
        DateTimeOffset AuthTime);

    private static IFormCollection CreateForm(string code, string? verifier = null) =>
        new FormCollection(new Dictionary<string, StringValues>
        {
            ["grant_type"] = AuthorizationCodeRedemptionService.GrantType,
            ["code"] = code,
            ["redirect_uri"] = RedirectUri,
            ["code_verifier"] = verifier ?? Verifier
        });

    private sealed class RedemptionDatabase(
        SqliteConnection connection,
        IdentityDbContext context,
        AuthorizationCodeRedemptionService service,
        StaticKeyManager keys) : IAsyncDisposable
    {
        public SqliteConnection Connection { get; } = connection;
        public IdentityDbContext Context { get; } = context;
        public AuthorizationCodeRedemptionService Service { get; } = service;
        public StaticKeyManager Keys { get; } = keys;
        public RsaSecurityKey Key => Keys.GetCurrentKey();

        public AuthorizationCodeRedemptionService CreateService(
            ILogger<AuthorizationCodeRedemptionService> logger) =>
            BuildService(
                Context,
                NullTokenFactory(),
                NullIdTokenFactory(),
                codeStore: null,
                Keys,
                logger);

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }

    private static AuthorizationCodeRedemptionService BuildService(
        IdentityDbContext context,
        IInteractiveAccessTokenFactory tokenFactory,
        IInteractiveIdTokenFactory idTokenFactory,
        IAuthorizationCodeStore? codeStore,
        StaticKeyManager keys,
        ILogger<AuthorizationCodeRedemptionService> logger)
    {
        var unitOfWork = new EfCoreUnitOfWork(context);
        var accountRepository = new AccountRepository(context);
        return new AuthorizationCodeRedemptionService(
            codeStore ?? new AuthorizationCodeStore(
                new AuthorizationCodeRepository(context), unitOfWork),
            new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork),
            accountRepository,
            new PasswordCredentialRepository(context),
            tokenFactory,
            idTokenFactory,
            new RefreshTokenFamilyStore(
                new RefreshTokenRepository(context),
                unitOfWork,
                NullLogger<RefreshTokenFamilyStore>.Instance),
            callbackService: null,
            keys,
            new AuditService(new LoginHistoryRepository(context), new AuditLogRepository(context)),
            CreateMetrics(),
            unitOfWork,
            context,
            new AdminIdentityOptions { Username = Username },
            logger);
    }

    private static async Task<RedemptionDatabase> CreateDatabaseAsync(
        IInteractiveAccessTokenFactory? tokenFactory = null,
        IInteractiveIdTokenFactory? idTokenFactory = null,
        Func<IdentityDbContext, IAuthorizationCodeStore>? codeStoreOverride = null)
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(connection).Options);
        await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);

        var keys = new StaticKeyManager();
        var service = BuildService(
            context,
            tokenFactory ?? NullTokenFactory(),
            idTokenFactory ?? NullIdTokenFactory(),
            codeStoreOverride?.Invoke(context),
            keys,
            NullLogger<AuthorizationCodeRedemptionService>.Instance);
        return new RedemptionDatabase(connection, context, service, keys);
    }

    private static IInteractiveAccessTokenFactory NullTokenFactory() =>
        new InteractiveAccessTokenFactory(
            new JwtOptions { Issuer = "https://redemption-unit.test" },
            NullLogger<InteractiveAccessTokenFactory>.Instance);

    private static IInteractiveIdTokenFactory NullIdTokenFactory() =>
        new InteractiveIdTokenFactory(new JwtOptions { Issuer = "https://redemption-unit.test" });

    private static AuthMetrics CreateMetrics()
    {
        var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
        meterFactory
            .Setup(factory => factory.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>()))
            .Returns(new System.Diagnostics.Metrics.Meter("SignaCore"));
        return new AuthMetrics(meterFactory.Object);
    }

    private static async Task<Seed> SeedAsync(
        IdentityDbContext context,
        string scope = "openid profile",
        bool allowRefreshToken = false)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var application = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = ClientId,
            AppSecretHash = "hash",
            AppName = "Redemption Unit Client",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = scope,
            AllowRefreshToken = allowRefreshToken
        };
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        context.AppRegistrations.Add(application);
        context.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
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
        await context.SaveChangesAsync(cancellationToken);
        context.ChangeTracker.Clear();

        var unitOfWork = new EfCoreUnitOfWork(context);
        var sessions = new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork);
        var codes = new AuthorizationCodeStore(new AuthorizationCodeRepository(context), unitOfWork);
        var session = await sessions.CreateAsync(accountId, credentialId, DateTimeOffset.UtcNow, cancellationToken);
        var creation = await codes.CreateAsync(
            session,
            new AuthorizationCodeBinding(application.Id, RedirectUri, scope, Nonce, Challenge),
            DateTimeOffset.UtcNow,
            cancellationToken);
        return new Seed(application, accountId, credentialId, session.Id, creation.Id, creation.Code, session.AuthTime);
    }

    private static async Task AssertNothingWrittenAsync(IdentityDbContext context, Seed seed)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var codeRow = await context.AuthorizationCodes.AsNoTracking()
            .SingleAsync(row => row.Id == seed.CodeId, cancellationToken);
        Assert.Null(codeRow.ConsumedAt);
        Assert.Null(codeRow.RefreshFamilyId);
        var sessionRow = await context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, cancellationToken);
        Assert.Null(sessionRow.RevokedAt);
        Assert.Empty(await context.RefreshTokens.AsNoTracking().ToListAsync(cancellationToken));
        Assert.Empty(await context.AuditLogs.AsNoTracking().ToListAsync(cancellationToken));
    }

    private sealed class ThrowingTokenFactory : IInteractiveAccessTokenFactory
    {
        public InteractiveAccessTokenResult Create(
            InteractiveAccessTokenDescriptor descriptor,
            RsaSecurityKey signingKey,
            DateTimeOffset now) => throw new InvalidOperationException("The signing construction failed.");
    }

    private sealed class OversizedTokenFactory : IInteractiveAccessTokenFactory
    {
        public InteractiveAccessTokenResult Create(
            InteractiveAccessTokenDescriptor descriptor,
            RsaSecurityKey signingKey,
            DateTimeOffset now) => new InteractiveAccessTokenResult.ExceedsMaximumLength();
    }

    private sealed class ThrowingIdTokenFactory : IInteractiveIdTokenFactory
    {
        public InteractiveIdTokenResult Create(
            InteractiveIdTokenDescriptor descriptor,
            RsaSecurityKey signingKey,
            DateTimeOffset now) => throw new InvalidOperationException("The ID token construction failed.");
    }

    private sealed class OversizedIdTokenFactory : IInteractiveIdTokenFactory
    {
        public InteractiveIdTokenResult Create(
            InteractiveIdTokenDescriptor descriptor,
            RsaSecurityKey signingKey,
            DateTimeOffset now) => new InteractiveIdTokenResult.ExceedsMaximumLength();
    }

    /// <summary>
    /// Delegates everything to the real store except <see cref="TryConsumeAsync"/>, which always
    /// observes the loss.
    /// </summary>
    private sealed class LosingConsumptionCodeStore(IAuthorizationCodeStore inner) : IAuthorizationCodeStore
    {
        public Task<AuthorizationCodeCreation> CreateAsync(
            IdentitySessionEntity session,
            AuthorizationCodeBinding binding,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) =>
            inner.CreateAsync(session, binding, now, cancellationToken);

        public Task<AuthorizationCodeLookup> FindAsync(
            string code,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) =>
            inner.FindAsync(code, now, cancellationToken);

        public bool VerifyBinding(
            AuthorizationCodeEntity code,
            Guid applicationId,
            string redirectUri,
            string codeVerifier) => inner.VerifyBinding(code, applicationId, redirectUri, codeVerifier);

        public Task<AuthorizationCodeEntity?> LockAsync(
            Guid codeId,
            CancellationToken cancellationToken = default) =>
            inner.LockAsync(codeId, cancellationToken);

        public Task<bool> TryConsumeAsync(
            Guid codeId,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) => Task.FromResult(false);

        public Task<bool> LinkRefreshFamilyAsync(
            Guid codeId,
            Guid rootId,
            CancellationToken cancellationToken = default) =>
            inner.LinkRefreshFamilyAsync(codeId, rootId, cancellationToken);

        public Task<int> CleanupExpiredAsync(
            DateTimeOffset now,
            CancellationToken cancellationToken = default) =>
            inner.CleanupExpiredAsync(now, cancellationToken);
    }

    /// <summary>A synchronous, in-memory key manager: one fixed RSA key, no refresh effect.</summary>
    private sealed class StaticKeyManager : IKeyManager
    {
        private readonly RsaSecurityKey _key;

        public StaticKeyManager()
        {
            var rsa = RSA.Create(2048);
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

    private sealed class RecordingLogger(List<string> messages) : ILogger<AuthorizationCodeRedemptionService>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            messages.Add(formatter(state, exception));
    }
}
