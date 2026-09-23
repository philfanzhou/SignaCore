using System.Data.Common;
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using SignaCore.Host.Controllers;
using SignaCore.Host.Management;
using SignaCore.Host.Models;
using SignaCore.Host.Services;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The <c>EV-08</c> serialization contract of the account-disable transaction and the matching
/// contract of the self-service password-change transaction against the two live product
/// transactions of the same account — interactive refresh rotation (<c>EV-29</c>) and
/// authorization-code redemption (<c>EV-21</c>): run concurrently over one shared database, the
/// session-row lock order admits exactly two outcomes. Either the account-state transaction
/// commits first and the product transaction fails closed without consuming anything and without
/// manufacturing a replay audit, or the product transaction commits first and every artifact it
/// produced is revoked by the subsequently committing account-state transaction. A third outcome
/// — a consumed artifact, or a replay audit against it — is a defect.
/// <para>
/// The SQLite file form runs everywhere; the shared-PostgreSQL form is the production
/// multi-instance shape and is gated on <c>RUN_SIGNACORE_DATABASE_CONTRACTS</c> like the rest
/// of the container matrix.
/// </para>
/// </summary>
public sealed class AdminStatePropagationConcurrencyDatabaseContractTests
{
    private const string ClientId = "state-concurrency-app";
    private const string CanonicalScope = "openid profile offline_access";
    private const string Username = "state_concurrency_user";
    private const string CurrentPassword = "State-Concurrency-1";
    private const string ChangedPassword = "State-Concurrency-2";

    public static TheoryData<string, bool> Contenders()
    {
        var cases = new TheoryData<string, bool>();
        foreach (var contender in new[] { "rotation", "redemption" })
        {
            // The simultaneous start lets the disable transaction win its short path to the
            // session-row write; the head start lets the product transaction commit its
            // artifacts first. Both must satisfy the same two-outcome contract.
            cases.Add(contender, false);
            cases.Add(contender, true);
        }

        return cases;
    }

    [Theory]
    [MemberData(nameof(Contenders))]
    public async Task DisableAgainstAProductTransaction_AdmitsExactlyTheTwoCanonicalOutcomes(
        string contender,
        bool headStart)
    {
        await using var database = new ConcurrencyDatabase();
        var seed = await database.SeedAsync();
        var (_, plaintext) = await ConcurrencyDatabase.SeedRootMemberAsync(
            database.BuildOptions(), seed);
        var code = await ConcurrencyDatabase.SeedCodeAsync(database.BuildOptions(), seed);

        Task<object> contenderTask = contender == "rotation"
            ? RotateAsync(ConcurrencyDatabase.BuildRotationService(database.BuildOptions()), seed, plaintext)
            : RedeemAsync(ConcurrencyDatabase.BuildRedemptionService(database.BuildOptions()), seed, code);
        if (headStart)
        {
            // One beat for the contender's token construction (two RSA signatures) and its
            // commit; the assertions still admit either outcome, so a slow machine cannot fail.
            await Task.Delay(TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);
        }

        var disableTask = DisableAsync(database.BuildOptions(), seed);

        var disableResult = await disableTask;
        Assert.IsType<OkObjectResult>(disableResult);
        var outcome = await contenderTask;

        await using var verification = new IdentityDbContext(database.BuildOptions());
        var session = await verification.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, TestContext.Current.CancellationToken);
        var account = await verification.Accounts.AsNoTracking()
            .SingleAsync(row => row.Id == seed.AccountId, TestContext.Current.CancellationToken);
        var family = await verification.RefreshTokens.AsNoTracking()
            .Where(row => row.IdentitySessionId == seed.SessionId)
            .ToListAsync(TestContext.Current.CancellationToken);
        var replayAudits = (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                verification, TestContext.Current.CancellationToken))
            .Where(row => row.Action == "oidc.refresh.replayed" || row.Action == "oidc.code.replayed")
            .ToList();
        var codeRow = await verification.AuthorizationCodes.AsNoTracking()
            .SingleAsync(row => row.Id == code.Id, TestContext.Current.CancellationToken);

        // The disable transaction always committed its own two facts.
        Assert.False(account.IsActive);
        Assert.NotNull(session.RevokedAt);
        Assert.Equal("account_disabled", session.RevocationReason);

        if (outcome is ContenderSuccess)
        {
            // The product transaction committed first: its artifacts exist and every one of them
            // was revoked by the disable that committed after it.
            Assert.NotEmpty(family);
            Assert.All(family, member => Assert.True(member.IsRevoked));
            if (contender == "redemption")
            {
                // The seeded root plus the redemption's own family root.
                Assert.Equal(2, family.Count);
                Assert.NotNull(codeRow.ConsumedAt);
            }
            else
            {
                Assert.Equal(2, family.Count);
                Assert.Contains(family, member => member.ConsumedAt is not null);
            }
        }
        else
        {
            // The disable committed first: the product transaction failed closed, consumed
            // nothing, and manufactured no replay audit against the disable.
            var failure = Assert.IsType<ContenderFailure>(outcome);
            Assert.Equal("invalid_grant", failure.Error);
            if (contender == "redemption")
            {
                Assert.Null(codeRow.ConsumedAt);
            }
            else
            {
                Assert.Single(family);
                Assert.Null(family[0].ConsumedAt);
            }

            Assert.All(family, member => Assert.True(member.IsRevoked));
        }

        Assert.Empty(replayAudits);
    }

    /// <summary>
    /// The self-service password change against the same two product transactions: the session-row
    /// lock order admits the identical two canonical outcomes, with the sessions revoked under the
    /// <c>password_changed</c> reason and the account left active (a password change never disables).
    /// </summary>
    [Theory]
    [MemberData(nameof(Contenders))]
    public async Task PasswordChangeAgainstAProductTransaction_AdmitsExactlyTheTwoCanonicalOutcomes(
        string contender,
        bool headStart)
    {
        await using var database = new ConcurrencyDatabase();
        var seed = await database.SeedAsync();
        var (_, plaintext) = await ConcurrencyDatabase.SeedRootMemberAsync(
            database.BuildOptions(), seed);
        var code = await ConcurrencyDatabase.SeedCodeAsync(database.BuildOptions(), seed);

        Task<object> contenderTask = contender == "rotation"
            ? RotateAsync(ConcurrencyDatabase.BuildRotationService(database.BuildOptions()), seed, plaintext)
            : RedeemAsync(ConcurrencyDatabase.BuildRedemptionService(database.BuildOptions()), seed, code);
        if (headStart)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);
        }

        var changeTask = ChangePasswordAsync(database.BuildOptions(), seed);

        var changeResult = await changeTask;
        Assert.IsType<OkObjectResult>(changeResult);
        var outcome = await contenderTask;

        await using var verification = new IdentityDbContext(database.BuildOptions());
        var session = await verification.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, TestContext.Current.CancellationToken);
        var account = await verification.Accounts.AsNoTracking()
            .SingleAsync(row => row.Id == seed.AccountId, TestContext.Current.CancellationToken);
        var credential = await verification.PasswordCredentials.AsNoTracking()
            .SingleAsync(row => row.Id == seed.CredentialId, TestContext.Current.CancellationToken);
        var family = await verification.RefreshTokens.AsNoTracking()
            .Where(row => row.IdentitySessionId == seed.SessionId)
            .ToListAsync(TestContext.Current.CancellationToken);
        var replayAudits = (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                verification, TestContext.Current.CancellationToken))
            .Where(row => row.Action == "oidc.refresh.replayed" || row.Action == "oidc.code.replayed")
            .ToList();
        var codeRow = await verification.AuthorizationCodes.AsNoTracking()
            .SingleAsync(row => row.Id == code.Id, TestContext.Current.CancellationToken);

        // The password-change transaction always committed its own facts: the new hash and every
        // session revoked under the canonical reason, with the account left active.
        Assert.True(account.IsActive);
        Assert.True(BCrypt.Net.BCrypt.Verify(ChangedPassword, credential.PasswordHash));
        Assert.NotNull(session.RevokedAt);
        Assert.Equal("password_changed", session.RevocationReason);

        if (outcome is ContenderSuccess)
        {
            Assert.NotEmpty(family);
            Assert.All(family, member => Assert.True(member.IsRevoked));
            if (contender == "redemption")
            {
                Assert.Equal(2, family.Count);
                Assert.NotNull(codeRow.ConsumedAt);
            }
            else
            {
                Assert.Equal(2, family.Count);
            }
        }
        else
        {
            var failure = Assert.IsType<ContenderFailure>(outcome);
            Assert.Equal("invalid_grant", failure.Error);
            if (contender == "redemption")
            {
                Assert.Null(codeRow.ConsumedAt);
            }
            else
            {
                Assert.Single(family);
                Assert.Null(family[0].ConsumedAt);
            }

            Assert.All(family, member => Assert.True(member.IsRevoked));
        }

        Assert.Empty(replayAudits);
    }

    /// <summary>
    /// The <c>SC-14</c> cross-instance form: the disable controller and the product transaction
    /// over two independent contexts against one shared PostgreSQL database.
    /// </summary>
    [Theory]
    [InlineData("PostgreSQL", "rotation")]
    [InlineData("PostgreSQL", "redemption")]
    public async Task DisableAgainstAProductTransaction_OverOneSharedPostgreSql_AdmitsExactlyTheTwoCanonicalOutcomes(
        string provider,
        string contender)
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            $"Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the {provider} state-propagation matrix.");

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
                Provider = provider,
                ServerVersion = "15",
                ConnectionString = container.GetConnectionString()
            });
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            var seed = await ConcurrencyDatabase.SeedAsync(options);
            var (_, plaintext) = await ConcurrencyDatabase.SeedRootMemberAsync(options, seed);
            var code = await ConcurrencyDatabase.SeedCodeAsync(options, seed);

            var disableTask = DisableAsync(options, seed);
            Task<object> contenderTask = contender == "rotation"
                ? RotateAsync(ConcurrencyDatabase.BuildRotationService(options), seed, plaintext)
                : RedeemAsync(ConcurrencyDatabase.BuildRedemptionService(options), seed, code);

            var disableResult = await disableTask;
            Assert.IsType<OkObjectResult>(disableResult);
            var outcome = await contenderTask;

            await using var verification = new IdentityDbContext(options);
            var session = await verification.IdentitySessions.AsNoTracking()
                .SingleAsync(row => row.Id == seed.SessionId, TestContext.Current.CancellationToken);
            var account = await verification.Accounts.AsNoTracking()
                .SingleAsync(row => row.Id == seed.AccountId, TestContext.Current.CancellationToken);
            var family = await verification.RefreshTokens.AsNoTracking()
                .Where(row => row.IdentitySessionId == seed.SessionId)
                .ToListAsync(TestContext.Current.CancellationToken);
            var replayAudits = (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                    verification, TestContext.Current.CancellationToken))
                .Where(row => row.Action == "oidc.refresh.replayed" || row.Action == "oidc.code.replayed")
                .ToList();
            var codeRow = await verification.AuthorizationCodes.AsNoTracking()
                .SingleAsync(row => row.Id == code.Id, TestContext.Current.CancellationToken);

            Assert.False(account.IsActive);
            Assert.NotNull(session.RevokedAt);
            Assert.Equal("account_disabled", session.RevocationReason);

            if (outcome is ContenderSuccess)
            {
                Assert.NotEmpty(family);
                Assert.All(family, member => Assert.True(member.IsRevoked));
                if (contender == "redemption")
                {
                    Assert.Equal(2, family.Count);
                    Assert.NotNull(codeRow.ConsumedAt);
                }
                else
                {
                    Assert.Equal(2, family.Count);
                }
            }
            else
            {
            var failure = Assert.IsType<ContenderFailure>(outcome);
                Assert.Equal("invalid_grant", failure.Error);
                if (contender == "redemption")
                {
                    Assert.Null(codeRow.ConsumedAt);
                }
                else
                {
                    Assert.Single(family);
                    Assert.Null(family[0].ConsumedAt);
                }

                Assert.All(family, member => Assert.True(member.IsRevoked));
            }

            Assert.Empty(replayAudits);
        }
    }

    /// <summary>
    /// The <c>SC-14</c> cross-instance form of the password change: the profile controller and the
    /// product transaction over two independent contexts against one shared PostgreSQL database.
    /// </summary>
    [Theory]
    [InlineData("PostgreSQL", "rotation")]
    [InlineData("PostgreSQL", "redemption")]
    public async Task PasswordChangeAgainstAProductTransaction_OverOneSharedPostgreSql_AdmitsExactlyTheTwoCanonicalOutcomes(
        string provider,
        string contender)
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            $"Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the {provider} state-propagation matrix.");

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
                Provider = provider,
                ServerVersion = "15",
                ConnectionString = container.GetConnectionString()
            });
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            var seed = await ConcurrencyDatabase.SeedAsync(options);
            var (_, plaintext) = await ConcurrencyDatabase.SeedRootMemberAsync(options, seed);
            var code = await ConcurrencyDatabase.SeedCodeAsync(options, seed);

            var changeTask = ChangePasswordAsync(options, seed);
            Task<object> contenderTask = contender == "rotation"
                ? RotateAsync(ConcurrencyDatabase.BuildRotationService(options), seed, plaintext)
                : RedeemAsync(ConcurrencyDatabase.BuildRedemptionService(options), seed, code);

            var changeResult = await changeTask;
            Assert.IsType<OkObjectResult>(changeResult);
            var outcome = await contenderTask;

            await using var verification = new IdentityDbContext(options);
            var session = await verification.IdentitySessions.AsNoTracking()
                .SingleAsync(row => row.Id == seed.SessionId, TestContext.Current.CancellationToken);
            var account = await verification.Accounts.AsNoTracking()
                .SingleAsync(row => row.Id == seed.AccountId, TestContext.Current.CancellationToken);
            var credential = await verification.PasswordCredentials.AsNoTracking()
                .SingleAsync(row => row.Id == seed.CredentialId, TestContext.Current.CancellationToken);
            var family = await verification.RefreshTokens.AsNoTracking()
                .Where(row => row.IdentitySessionId == seed.SessionId)
                .ToListAsync(TestContext.Current.CancellationToken);
            var replayAudits = (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                    verification, TestContext.Current.CancellationToken))
                .Where(row => row.Action == "oidc.refresh.replayed" || row.Action == "oidc.code.replayed")
                .ToList();
            var codeRow = await verification.AuthorizationCodes.AsNoTracking()
                .SingleAsync(row => row.Id == code.Id, TestContext.Current.CancellationToken);

            Assert.True(account.IsActive);
            Assert.True(BCrypt.Net.BCrypt.Verify(ChangedPassword, credential.PasswordHash));
            Assert.NotNull(session.RevokedAt);
            Assert.Equal("password_changed", session.RevocationReason);

            if (outcome is ContenderSuccess)
            {
                Assert.NotEmpty(family);
                Assert.All(family, member => Assert.True(member.IsRevoked));
                if (contender == "redemption")
                {
                    Assert.Equal(2, family.Count);
                    Assert.NotNull(codeRow.ConsumedAt);
                }
                else
                {
                    Assert.Equal(2, family.Count);
                }
            }
            else
            {
                var failure = Assert.IsType<ContenderFailure>(outcome);
                Assert.Equal("invalid_grant", failure.Error);
                if (contender == "redemption")
                {
                    Assert.Null(codeRow.ConsumedAt);
                }
                else
                {
                    Assert.Single(family);
                    Assert.Null(family[0].ConsumedAt);
                }

                Assert.All(family, member => Assert.True(member.IsRevoked));
            }

            Assert.Empty(replayAudits);
        }
    }

    // ---- Contender drivers ----

    private static async Task<object> RotateAsync(
        InteractiveRefreshRotationService service,
        ConcurrencySeed seed,
        string plaintext)
    {
        var dispatch = await service.RotateAsync(
            seed.Application,
            Form(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = plaintext
            }),
            clientCredentialMixPresent: false,
            clientIp: null,
            correlationId: null,
            TestContext.Current.CancellationToken);
        Assert.True(dispatch.Handled);
        return dispatch.Outcome!.IsSuccess
            ? new ContenderSuccess()
            : new ContenderFailure(dispatch.Outcome.ErrorCode!);
    }

    private static async Task<object> RedeemAsync(
        AuthorizationCodeRedemptionService service,
        ConcurrencySeed seed,
        SeededCode code)
    {
        var outcome = await service.RedeemAsync(
            seed.Application,
            Form(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code.Code,
                ["redirect_uri"] = code.RedirectUri,
                ["code_verifier"] = code.Verifier
            }),
            clientIp: null,
            correlationId: null,
            TestContext.Current.CancellationToken);
        return outcome.IsSuccess
            ? new ContenderSuccess()
            : new ContenderFailure(outcome.ErrorCode!);
    }

    private sealed record ContenderSuccess;

    private sealed record ContenderFailure(string Error);

    private static IFormCollection Form(IReadOnlyDictionary<string, string> fields) =>
        new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>(
            fields.ToDictionary(
                pair => pair.Key,
                pair => new Microsoft.Extensions.Primitives.StringValues(pair.Value))));

    // ---- Disable driver ----

    /// <summary>
    /// A minimal admin identity for the controller: the operator reader resolves nothing without
    /// management claims, and the disable transaction must not depend on the actor material.
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
            var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
            services.AddSingleton<ManagementOperatorReader>();
            services.AddSingleton<ServiceMantle.Management.IManagementClaimsParser, ServiceMantle.Management.ManagementClaimsParser>();
            services.AddSingleton<ServiceMantle.Management.IManagementCurrentOperatorResolver, ServiceMantle.Management.ManagementCurrentOperatorResolver>();
            return services.BuildServiceProvider();
        }
    }

    private static Task<IActionResult> DisableAsync(
        DbContextOptions<IdentityDbContext> options,
        ConcurrencySeed seed)
    {
        var context = new IdentityDbContext(options);
        var unitOfWork = new EfCoreUnitOfWork(context);
        return new BareAdminController().UpdateUserStatus(
            seed.AccountId,
            new AdminUpdateStatusRequest(false),
            new AccountRepository(context),
            unitOfWork,
            new EfCoreManagementAuditWriter<IdentityDbContext>(context),
            context,
            new IdentitySessionRepository(context),
            new RefreshTokenFamilyStore(
                new RefreshTokenRepository(context),
                unitOfWork,
                NullLogger<RefreshTokenFamilyStore>.Instance),
            TestContext.Current.CancellationToken);
    }

    // ---- Password-change driver ----

    /// <summary>
    /// Invokes the self-service password change directly against a fresh context over the shared
    /// database. The controller reads the account id from the JWT name-identifier claim and the
    /// correlation id from the ServiceMantle slot, so both are established exactly as the composed
    /// host does — never by writing the library's private slot key.
    /// </summary>
    private static Task<IActionResult> ChangePasswordAsync(
        DbContextOptions<IdentityDbContext> options,
        ConcurrencySeed seed)
    {
        var context = new IdentityDbContext(options);
        var unitOfWork = new EfCoreUnitOfWork(context);
        var refreshTokens = new RefreshTokenRepository(context);
        var hasherOptions = new PasswordHasherOptions { WorkFactor = 4 };
        var controller = new ProfileController();
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        httpContext.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, seed.AccountId.ToString())],
            "Test"));
        CorrelationPipeline.Establish(httpContext);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        return controller.ChangePassword(
            new ChangePasswordRequest(CurrentPassword, ChangedPassword),
            new PasswordCredentialRepository(context),
            new BCryptPasswordHasher(hasherOptions),
            new DefaultPasswordPolicy(),
            new PasswordDecoyHash(hasherOptions),
            new LoginAttemptRepository(context),
            new IdentitySessionRepository(context),
            new RefreshTokenFamilyStore(
                refreshTokens, unitOfWork, NullLogger<RefreshTokenFamilyStore>.Instance),
            refreshTokens,
            context,
            unitOfWork,
            new EfCoreManagementAuditWriter<IdentityDbContext>(context),
            TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Runs the real ServiceMantle correlation middleware over an in-process context, through the
    /// same public registration the production hosts compose.
    /// </summary>
    private static class CorrelationPipeline
    {
        private static readonly RequestDelegate Pipeline = Build();

        public static void Establish(HttpContext context) =>
            Pipeline(context).GetAwaiter().GetResult();

        private static RequestDelegate Build()
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddSignaCoreServiceMantle();
            var provider = services.BuildServiceProvider();
            var app = new ApplicationBuilder(provider);
            app.UseServiceMantleCorrelationId();
            return app.Build();
        }
    }

    // ---- Shared database harness ----

    private sealed record ConcurrencySeed(
        AppRegistrationEntity Application,
        Guid AccountId,
        Guid CredentialId,
        Guid SessionId,
        DateTimeOffset AuthTime);

    private sealed record SeededCode(Guid Id, string Code, string RedirectUri, string Verifier);

    /// <summary>
    /// A file-backed SQLite test database on the production migration chain; contexts are created
    /// per collaborator so the two transactions run over independent connections, the
    /// single-instance two-connection shape.
    /// </summary>
    private sealed class ConcurrencyDatabase : IAsyncDisposable
    {
        private readonly string _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-state-concurrency-{Guid.NewGuid():N}.db");

        public DbContextOptions<IdentityDbContext> BuildOptions()
        {
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseSqlite(
                // Pooling=False keeps every handle inside this class's own contexts, so disposal
                // releases the file without a process-wide ClearAllPools().
                $"Data Source={_databasePath};Default Timeout=30;Pooling=False",
                providerOptions =>
                {
                    providerOptions.MigrationsAssembly("SignaCore.Database.Migrations.Sqlite");
                });
            return optionsBuilder.Options;
        }

        public static InteractiveRefreshRotationService BuildRotationService(
            DbContextOptions<IdentityDbContext> options)
        {
            var context = new IdentityDbContext(options);
            var unitOfWork = new EfCoreUnitOfWork(context);
            var refreshTokens = new RefreshTokenRepository(context);
            return new InteractiveRefreshRotationService(
                refreshTokens,
                new RefreshTokenFamilyStore(refreshTokens, unitOfWork, NullLogger<RefreshTokenFamilyStore>.Instance),
                new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork),
                new AccountRepository(context),
                new PasswordCredentialRepository(context),
                new InteractiveAccessTokenFactory(
                    new JwtOptions { Issuer = "https://state-concurrency.test" },
                    NullLogger<InteractiveAccessTokenFactory>.Instance),
                new InteractiveIdTokenFactory(new JwtOptions { Issuer = "https://state-concurrency.test" }),
                new StaticKeyManager(),
                new EfCoreManagementAuditWriter<IdentityDbContext>(context),
                new AuthMetrics(StubMeterFactory()),
                unitOfWork,
                context,
                NullLogger<InteractiveRefreshRotationService>.Instance);
        }

        public static AuthorizationCodeRedemptionService BuildRedemptionService(
            DbContextOptions<IdentityDbContext> options)
        {
            var context = new IdentityDbContext(options);
            var unitOfWork = new EfCoreUnitOfWork(context);
            var refreshTokens = new RefreshTokenRepository(context);
            return new AuthorizationCodeRedemptionService(
                new AuthorizationCodeStore(new AuthorizationCodeRepository(context), unitOfWork),
                new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork),
                new AccountRepository(context),
                new PasswordCredentialRepository(context),
                new InteractiveAccessTokenFactory(
                    new JwtOptions { Issuer = "https://state-concurrency.test" },
                    NullLogger<InteractiveAccessTokenFactory>.Instance),
                new InteractiveIdTokenFactory(new JwtOptions { Issuer = "https://state-concurrency.test" }),
                new RefreshTokenFamilyStore(refreshTokens, unitOfWork, NullLogger<RefreshTokenFamilyStore>.Instance),
                callbackService: null,
                new StaticKeyManager(),
                new EfCoreManagementAuditWriter<IdentityDbContext>(context),
                new AuthMetrics(StubMeterFactory()),
                unitOfWork,
                context,
                new AdminIdentityOptions(),
                NullLogger<AuthorizationCodeRedemptionService>.Instance);
        }

        private static System.Diagnostics.Metrics.IMeterFactory StubMeterFactory()
        {
            var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
            meterFactory
                .Setup(factory => factory.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>()))
                .Returns(new System.Diagnostics.Metrics.Meter("SignaCore"));
            return meterFactory.Object;
        }

        public async Task<ConcurrencySeed> SeedAsync() => await SeedAsync(BuildOptions());

        public static async Task<ConcurrencySeed> SeedAsync(DbContextOptions<IdentityDbContext> options)
        {
            await using var context = new IdentityDbContext(options);
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);

            var application = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = ClientId,
                AppSecretHash = "hash",
                AppName = "State Concurrency Client",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = CanonicalScope,
                AllowRefreshToken = true
            };
            var accountId = Guid.NewGuid();
            var credentialId = Guid.NewGuid();
            context.AppRegistrations.Add(application);
            context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
            context.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = credentialId,
                AccountId = accountId,
                Username = $"{Username}_{accountId:N}",
                // A real low-work-factor hash so the password-change driver can re-prove the
                // current password; the disable/rotation/redemption paths never verify it.
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(CurrentPassword, 4),
                CreatedAt = DateTimeOffset.UtcNow
            });
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
            context.ChangeTracker.Clear();

            var unitOfWork = new EfCoreUnitOfWork(context);
            var session = await new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork)
                .CreateAsync(accountId, credentialId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
            return new ConcurrencySeed(application, accountId, credentialId, session.Id, session.AuthTime);
        }

        public static async Task<(Guid RootId, string Plaintext)> SeedRootMemberAsync(
            DbContextOptions<IdentityDbContext> options,
            ConcurrencySeed seed)
        {
            await using var context = new IdentityDbContext(options);
            var unitOfWork = new EfCoreUnitOfWork(context);
            var creation = await new RefreshTokenFamilyStore(
                new RefreshTokenRepository(context), unitOfWork, NullLogger<RefreshTokenFamilyStore>.Instance)
                .CreateRootAsync(
                    new InteractiveRefreshFamilyRootDescriptor(
                        seed.AccountId, ClientId, seed.SessionId, CanonicalScope, seed.AuthTime),
                    DateTimeOffset.UtcNow,
                    TestContext.Current.CancellationToken);
            return (creation.RootId, creation.RefreshToken);
        }

        public static async Task<SeededCode> SeedCodeAsync(
            DbContextOptions<IdentityDbContext> options,
            ConcurrencySeed seed)
        {
            await using var context = new IdentityDbContext(options);
            var unitOfWork = new EfCoreUnitOfWork(context);
            var lookup = await new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork)
                .GetAsync(seed.SessionId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
            const string redirectUri = "https://bff.state-concurrency.test/callback";
            const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
            var creation = await new AuthorizationCodeStore(
                new AuthorizationCodeRepository(context), unitOfWork)
                .CreateAsync(
                    lookup.Session!,
                    new AuthorizationCodeBinding(
                        seed.Application.Id, redirectUri, CanonicalScope, "state-concurrency-nonce",
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
                    DateTimeOffset.UtcNow,
                    TestContext.Current.CancellationToken);
            return new SeededCode(creation.Id, creation.Code, redirectUri, verifier);
        }

        public async ValueTask DisposeAsync()
        {
            if (File.Exists(_databasePath))
            {
                File.Delete(_databasePath);
            }
        }
    }

    /// <summary>A synchronous, in-memory key manager: one fixed RSA key, no refresh effect.</summary>
    private sealed class StaticKeyManager : Domain.Keys.IKeyManager
    {
        private readonly Microsoft.IdentityModel.Tokens.RsaSecurityKey _key;

        public StaticKeyManager()
        {
            var rsa = System.Security.Cryptography.RSA.Create(2048);
            _key = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa) { KeyId = Guid.NewGuid().ToString() };
        }

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

        throw new InvalidOperationException(
            "The container database never became connectable.", lastError);
    }
}
