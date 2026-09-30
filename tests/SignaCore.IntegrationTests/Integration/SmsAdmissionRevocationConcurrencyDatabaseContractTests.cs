using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using ServiceMantle.Persistence.Relational.Stores;
using ServiceMantle.Persistence.Relational;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Database;
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Services;
using SignaCore.Domain;
using SignaCore.Host.Controllers;
using SignaCore.Host.Management;
using SignaCore.Host.Services;
using SignaCore.Host;
using System.Net;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The <c>SC-24</c> concurrency cell (<c>PS-22</c>): the administrator's SMS-user revocation
/// (<c>DELETE /api/admin/apps/{appId}/sms-users/{loginId}</c>) against a refresh rotation of the
/// same application's interactive family on an <c>Sms</c> session. Exactly two serial outcomes are
/// admissible. Either the rotation commits first — then the next refresh finds the predicate false
/// and revokes the whole family, the committed child included — or the revocation is read first
/// and this refresh itself revokes the family without creating a child. A third outcome (a child
/// that survives the next refresh, or a rotation that commits after reading the revoked admission)
/// is a defect. The SQLite file form runs both serial orders everywhere; the shared-PostgreSQL
/// form races the two transactions and is gated on <c>RUN_SIGNACORE_DATABASE_CONTRACTS</c>.
/// </summary>
public sealed class SmsAdmissionRevocationConcurrencyDatabaseContractTests
{
    private const string ClientId = "sms-admission-concurrency-app";
    private const string CanonicalScope = "openid profile offline_access";
    private const string RedirectUri = "https://bff.sms-admission-concurrency.test/callback";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SerialOrders_OnSqlite_ProduceTheTwoCanonicalOutcomes(bool rotationFirst)
    {
        var path = Path.Combine(PhysicalTempPath.Root(), $"signacore-sms-admission-{Guid.NewGuid():N}.db");
        try
        {
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseSqlite(
                $"Data Source={path};Default Timeout=30;Pooling=False",
                provider => provider.MigrationsAssembly("SignaCore.Database.Migrations.Sqlite"));
            var options = optionsBuilder.Options;
            var seed = await SeedAsync(options);
            var family = await RedeemFamilyAsync(options, seed);

            object first;
            if (rotationFirst)
            {
                first = await RotateAsync(options, seed, family.RefreshToken);
                Assert.IsType<OkObjectResult>(await RevokeAsync(options, seed));
            }
            else
            {
                Assert.IsType<OkObjectResult>(await RevokeAsync(options, seed));
                first = await RotateAsync(options, seed, family.RefreshToken);
            }

            Assert.Equal(rotationFirst, first is RotationSuccess);
            await AssertCanonicalOutcomeAsync(options, seed, family, first);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public async Task RacingTransactions_OverOneSharedPostgreSql_AdmitExactlyTheTwoCanonicalOutcomes()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL SMS admission race.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();
        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(new DatabaseOptions
            {
                Provider = "PostgreSQL",
                ServerVersion = "15",
                ConnectionString = container.GetConnectionString()
            });
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            // Several rounds with shifting head starts, so both interleavings are exercised; every
            // round must satisfy the same two-outcome contract whichever order the race produced.
            var outcomes = new List<string>();
            foreach (var headStartMilliseconds in new[] { 0, 0, 5, 20, 60, 150 })
            {
                var seed = await SeedAsync(options);
                var family = await RedeemFamilyAsync(options, seed);

                var rotation = RotateAsync(options, seed, family.RefreshToken);
                if (headStartMilliseconds > 0)
                {
                    await Task.Delay(headStartMilliseconds, TestContext.Current.CancellationToken);
                }

                var revocation = RevokeAsync(options, seed);
                Assert.IsType<OkObjectResult>(await revocation);
                var first = await rotation;

                await AssertCanonicalOutcomeAsync(options, seed, family, first);
                outcomes.Add(first is RotationSuccess ? "rotation-first" : "revocation-first");
            }

            TestContext.Current.TestOutputHelper?.WriteLine("Observed orders: " + string.Join(", ", outcomes));
        }
    }

    /// <summary>
    /// The shared two-outcome judgement after both transactions committed: the admission is
    /// inactive, and after at most one more refresh the family — child included when the rotation
    /// won — is fully revoked, no refresh succeeds any more, and the session was never revoked.
    /// </summary>
    private static async Task AssertCanonicalOutcomeAsync(
        DbContextOptions<IdentityDbContext> options,
        Seed seed,
        RedeemedFamily family,
        object first)
    {
        var ct = TestContext.Current.CancellationToken;
        await using (var verification = new IdentityDbContext(options))
        {
            var access = await verification.AppSmsAccesses.AsNoTracking()
                .SingleAsync(row => row.AppRegistrationId == seed.Application.Id && row.UserLoginId == seed.SmsLoginId, ct);
            Assert.False(access.IsActive);
        }

        if (first is RotationSuccess success)
        {
            // The rotation committed first: one child exists and nothing is revoked yet; the next
            // refresh reads the revoked admission and revokes the whole family.
            await using (var verification = new IdentityDbContext(options))
            {
                var members = await verification.RefreshTokens.AsNoTracking()
                    .Where(row => row.FamilyId == family.RootId).ToListAsync(ct);
                Assert.Equal(2, members.Count);
                Assert.All(members, member => Assert.False(member.IsRevoked));
            }

            var next = Assert.IsType<RotationFailure>(await RotateAsync(options, seed, success.ChildToken));
            Assert.Equal("invalid_grant", next.Error);
        }
        else
        {
            // The revocation was read first: this refresh revoked the family and created no child.
            Assert.Equal("invalid_grant", Assert.IsType<RotationFailure>(first).Error);
        }

        await using (var verification = new IdentityDbContext(options))
        {
            var members = await verification.RefreshTokens.AsNoTracking()
                .Where(row => row.FamilyId == family.RootId).ToListAsync(ct);
            Assert.Equal(first is RotationSuccess ? 2 : 1, members.Count);
            Assert.All(members, member => Assert.True(member.IsRevoked));
            var session = await verification.IdentitySessions.AsNoTracking()
                .SingleAsync(row => row.Id == seed.SessionId, ct);
            Assert.Null(session.RevokedAt);
            var replayAudits = (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(verification, ct))
                .Where(row => row.Action == "oidc.refresh.replayed")
                .ToList();
            Assert.Empty(replayAudits);
        }
    }

    // ---- Drivers ----

    private sealed record RotationSuccess(string ChildToken);

    private sealed record RotationFailure(string Error);

    private static async Task<object> RotateAsync(
        DbContextOptions<IdentityDbContext> options, Seed seed, string refreshToken)
    {
        await using var context = new IdentityDbContext(options);
        var unitOfWork = new EfCoreUnitOfWork(context);
        var refreshTokens = new RefreshTokenRepository(context);
        var service = new InteractiveRefreshRotationService(
            refreshTokens,
            new RefreshTokenFamilyStore(refreshTokens, unitOfWork, NullLogger<RefreshTokenFamilyStore>.Instance),
            new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork),
            new AccountRepository(context),
            new PasswordCredentialRepository(context),
            new InteractiveAccessTokenFactory(
                new JwtOptions { Issuer = "https://sms-admission-concurrency.test" },
                NullLogger<InteractiveAccessTokenFactory>.Instance),
            new InteractiveIdTokenFactory(new JwtOptions { Issuer = "https://sms-admission-concurrency.test" }),
            Keys,
            new EfCoreManagementAuditWriter<IdentityDbContext>(context),
            new AuthMetrics(StubMeterFactory()),
            unitOfWork,
            new AppRegistrationRepository(context),
            context,
            new SmsAdmissionService(context),
            NullLogger<InteractiveRefreshRotationService>.Instance);
        var dispatch = await service.RotateAsync(
            seed.Application,
            Form(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken
            }),
            clientCredentialMixPresent: false,
            clientIp: null,
            correlationId: null,
            TestContext.Current.CancellationToken);
        Assert.True(dispatch.Handled);
        return dispatch.Outcome!.IsSuccess
            ? new RotationSuccess(dispatch.Outcome.RefreshToken)
            : new RotationFailure(dispatch.Outcome.ErrorCode!);
    }

    private static async Task<IActionResult> RevokeAsync(DbContextOptions<IdentityDbContext> options, Seed seed)
    {
        await using var context = new IdentityDbContext(options);
        return await new BareAdminController().RevokeSmsUser(
            ClientId,
            seed.SmsLoginId,
            context,
            new EfCoreManagementAuditWriter<IdentityDbContext>(context),
            TestContext.Current.CancellationToken);
    }

    private static IFormCollection Form(IReadOnlyDictionary<string, string> fields) =>
        new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>(
            fields.ToDictionary(
                pair => pair.Key,
                pair => new Microsoft.Extensions.Primitives.StringValues(pair.Value))));

    /// <summary>
    /// A minimal admin identity for the controller: the SMS-user revocation must not depend on the
    /// actor material.
    /// </summary>
    private sealed class BareAdminController : AdminController
    {
        public BareAdminController()
            : base(NullLogger<AdminController>.Instance, BuildServices())
        {
            var httpContext = new DefaultHttpContext();
            httpContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
            ControllerContext = new ControllerContext { HttpContext = httpContext };
        }

        private static IServiceProvider BuildServices()
        {
            var services = new ServiceCollection();
            services.AddSingleton<ManagementOperatorReader>();
            services.AddSingleton<ServiceMantle.Management.IManagementClaimsParser, ServiceMantle.Management.ManagementClaimsParser>();
            services.AddSingleton<ServiceMantle.Management.IManagementCurrentOperatorResolver, ServiceMantle.Management.ManagementCurrentOperatorResolver>();
            return services.BuildServiceProvider();
        }
    }

    // ---- Seeding ----

    private sealed record Seed(AppRegistrationEntity Application, Guid AccountId, Guid SmsLoginId, Guid SessionId);

    private sealed record RedeemedFamily(string RefreshToken, Guid RootId);

    /// <summary>
    /// One <c>ManualApproval</c> application whose Admin-approved admission covers one SMS login
    /// identity, and one live <c>Sms</c> session of that identity. The application id is fixed, so
    /// every round revokes a fresh identity's admission.
    /// </summary>
    private static async Task<Seed> SeedAsync(DbContextOptions<IdentityDbContext> options)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var context = new IdentityDbContext(options);
        await context.Database.MigrateAsync(ct);

        var application = await context.AppRegistrations.AsNoTracking()
            .SingleOrDefaultAsync(row => row.AppId == ClientId, ct);
        if (application is null)
        {
            application = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = ClientId,
                AppSecretHash = "hash",
                AppName = "SMS Admission Concurrency Client",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = CanonicalScope,
                AllowRefreshToken = true,
                SmsLoginMode = SmsLoginMode.ManualApproval
            };
            context.AppRegistrations.Add(application);
        }

        var accountId = Guid.NewGuid();
        var loginId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
        context.UserLogins.Add(new UserLoginEntity
        {
            Id = loginId,
            AccountId = accountId,
            ProviderName = IdentityConstants.AuthMethodSms,
            ProviderUserId = "+86139" + Random.Shared.NextInt64(0, 100_000_000)
                .ToString("D8", System.Globalization.CultureInfo.InvariantCulture)
        });
        context.AppSmsAccesses.Add(new AppSmsAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = application.Id,
            UserLoginId = loginId,
            ApprovalSource = SmsAccessApprovalSource.Admin,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(ct);
        context.ChangeTracker.Clear();

        var session = await new IdentitySessionStore(new IdentitySessionRepository(context), new EfCoreUnitOfWork(context))
            .CreateSmsAsync(accountId, loginId, DateTimeOffset.UtcNow, ct);
        return new Seed(application, accountId, loginId, session.Id);
    }

    /// <summary>Creates the family over the real redemption transaction while the admission holds.</summary>
    private static async Task<RedeemedFamily> RedeemFamilyAsync(DbContextOptions<IdentityDbContext> options, Seed seed)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var context = new IdentityDbContext(options);
        var unitOfWork = new EfCoreUnitOfWork(context);
        var sessions = new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork);
        var codes = new AuthorizationCodeStore(new AuthorizationCodeRepository(context), unitOfWork);
        var lookup = await sessions.GetAsync(seed.SessionId, DateTimeOffset.UtcNow, ct);
        var creation = await codes.CreateAsync(
            lookup.Session!,
            new AuthorizationCodeBinding(seed.Application.Id, RedirectUri, CanonicalScope, "sms-concurrency-nonce", Challenge),
            DateTimeOffset.UtcNow,
            ct);
        context.ChangeTracker.Clear();

        var redemption = new AuthorizationCodeRedemptionService(
            codes,
            sessions,
            new AccountRepository(context),
            new PasswordCredentialRepository(context),
            new InteractiveAccessTokenFactory(
                new JwtOptions { Issuer = "https://sms-admission-concurrency.test" },
                NullLogger<InteractiveAccessTokenFactory>.Instance),
            new InteractiveIdTokenFactory(new JwtOptions { Issuer = "https://sms-admission-concurrency.test" }),
            new RefreshTokenFamilyStore(new RefreshTokenRepository(context), unitOfWork, NullLogger<RefreshTokenFamilyStore>.Instance),
            callbackService: null,
            Keys,
            new EfCoreManagementAuditWriter<IdentityDbContext>(context),
            new AuthMetrics(StubMeterFactory()),
            unitOfWork,
            new AppRegistrationRepository(context),
            context,
            new AdminIdentityOptions(),
            new SmsAdmissionService(context),
            NullLogger<AuthorizationCodeRedemptionService>.Instance);
        var outcome = await redemption.RedeemAsync(
            seed.Application,
            Form(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = creation.Code,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = Verifier
            }),
            clientIp: null,
            correlationId: null,
            ct);
        Assert.True(outcome.IsSuccess);
        var rootId = await context.AuthorizationCodes.AsNoTracking()
            .Where(row => row.Id == creation.Id)
            .Select(row => row.RefreshFamilyId!.Value)
            .SingleAsync(ct);
        return new RedeemedFamily(outcome.RefreshToken!, rootId);
    }

    private static readonly StaticKeyManager Keys = new();

    private static System.Diagnostics.Metrics.IMeterFactory StubMeterFactory()
    {
        var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
        meterFactory
            .Setup(factory => factory.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>()))
            .Returns(new System.Diagnostics.Metrics.Meter("SignaCore"));
        return meterFactory.Object;
    }

    /// <summary>A synchronous, in-memory key manager: one fixed RSA key, no refresh effect.</summary>
    private sealed class StaticKeyManager : Domain.Keys.IKeyManager
    {
        private readonly Microsoft.IdentityModel.Tokens.RsaSecurityKey _key = new(
            System.Security.Cryptography.RSA.Create(2048)) { KeyId = Guid.NewGuid().ToString() };

        public Microsoft.IdentityModel.Tokens.RsaSecurityKey GetCurrentKey() => _key;

        public IReadOnlyList<Microsoft.IdentityModel.Tokens.SecurityKey> GetValidationKeys() => [_key];

        public Task RefreshKeysAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<IReadOnlyList<Microsoft.IdentityModel.Tokens.RsaSecurityKey>> GetValidKeysAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<Microsoft.IdentityModel.Tokens.RsaSecurityKey>>([_key]);

        public Task<bool> NeedsKeyRotationAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task RotateKeyAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task InitializationCompleted => Task.CompletedTask;
    }

    private static readonly string PostgreSqlImage =
        Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } image
            ? image
            : "postgres:15-alpine";

    private static bool ShouldRunContainerMatrix() =>
        bool.TryParse(
            Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS"),
            out var run) && run;

    private static async Task WaitUntilConnectableAsync(DbContextOptions<IdentityDbContext> options)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(120);
        Exception? lastError = null;
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                await using var context = new IdentityDbContext(options);
                if (await context.Database.CanConnectAsync(TestContext.Current.CancellationToken))
                {
                    return;
                }
            }
            catch (Exception exception)
            {
                lastError = exception;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(250), TestContext.Current.CancellationToken);
        }

        throw new InvalidOperationException("The container database never became connectable.", lastError);
    }
}
