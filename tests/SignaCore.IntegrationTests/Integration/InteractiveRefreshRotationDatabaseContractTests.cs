using System.Data.Common;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Testcontainers.PostgreSql;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// Pins the atomicity and retry idempotency of the interactive refresh rotation
/// (<c>EV-29</c>/<c>EV-30</c>) against a file-backed SQLite database on the production migration
/// chain. Production PostgreSQL enables <c>EnableRetryOnFailure()</c>, so these tests install a
/// hand-made retrying strategy — the equivalent configuration — to prove that a transient commit
/// acknowledgement failure replays the whole transaction, that the request-local stable child
/// id/digest lets the replay resume its own committed rotation instead of minting a second child
/// or classifying itself as reuse (<c>PS-22</c>), that caller cancellation before commit rolls
/// everything back (<c>SC-20</c>), that two database instances over one shared file admit
/// exactly one winner (<c>SC-14</c>, the single-instance SQLite form; the PostgreSQL
/// cross-instance matrix runs in the container stage), and that the unique <c>parent_id</c>
/// index is the database backstop of the one-child invariant.
/// <para>
/// The <c>DatabaseContractTests</c> suffix is deliberate — CI's Database Contract Test stage
/// filters on <c>FullyQualifiedName~DatabaseContractTests</c>; this group needs no Docker and
/// runs in every environment.
/// </para>
/// </summary>
public sealed class InteractiveRefreshRotationDatabaseContractTests
{
    private const string ClientId = "rotation-contract-app";
    private const string CanonicalScope = "openid profile offline_access";
    private const string Username = "rotation_contract_user";

    [Fact]
    public async Task Rotation_WhenCommitAcknowledgementIsLostOnce_ResumesItsOwnCommittedChild()
    {
        var interceptor = new TransientCommitFailureInterceptor(failuresToInject: 1);
        await using var database = new RotationDatabase(interceptor);
        var seed = await database.SeedAsync();
        var (_, plaintext) = await database.SeedRootMemberAsync(seed);

        var service = RotationDatabase.BuildService(database.BuildOptions(withInterceptor: true));
        var dispatch = await service.RotateAsync(
            seed.Application,
            Form(plaintext),
            clientCredentialMixPresent: false,
            clientIp: null,
            correlationId: null,
            TestContext.Current.CancellationToken);

        Assert.Equal(1, interceptor.InjectedFailures);
        Assert.True(dispatch.Handled);
        Assert.True(dispatch.Outcome!.IsSuccess);

        // Exactly one committed child of the presented member; the parent is consumed once; no
        // reuse audit was manufactured against this attempt's own commit.
        await using var verification = new IdentityDbContext(database.BuildOptions());
        var family = await verification.RefreshTokens.AsNoTracking()
            .Where(row => row.IdentitySessionId != null)
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, family.Count);
        Assert.Single(family, row => row.ConsumedAt is not null);
        Assert.Single(family, row => row.ConsumedAt is null && !row.IsRevoked);
        Assert.Empty(await verification.AuditLogs.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));

        // The resumed plaintext is the one stable across the replay: it works once more and the
        // replayed presentation of the now-consumed parent is genuine reuse.
        var second = await service.RotateAsync(
            seed.Application,
            Form(plaintext),
            clientCredentialMixPresent: false,
            clientIp: null,
            correlationId: null,
            TestContext.Current.CancellationToken);
        Assert.True(second.Handled);
        Assert.False(second.Outcome!.IsSuccess);
        Assert.Equal("replay", second.Outcome.FailureReason);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Rotation_CancellationAroundCommit_RollsBackBeforeAndStaysAuthoritativeAfter(
        bool afterCommit)
    {
        using var cancellation = new CancellationTokenSource();
        var interceptor = new CommitCancellationInterceptor(cancellation, afterCommit);
        await using var database = new RotationDatabase(interceptor);
        var seed = await database.SeedAsync();
        var (_, plaintext) = await database.SeedRootMemberAsync(seed);

        var service = RotationDatabase.BuildService(database.BuildOptions(withInterceptor: true));
        Task<InteractiveRefreshDispatch> Operation() =>
            service.RotateAsync(
                seed.Application,
                Form(plaintext),
                clientCredentialMixPresent: false,
                clientIp: null,
                correlationId: null,
                cancellation.Token);

        if (afterCommit)
        {
            var committed = await Operation();
            Assert.True(committed.Handled && committed.Outcome!.IsSuccess);
        }
        else
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(Operation);
        }

        Assert.Equal(1, interceptor.CommitAttempts);
        await using var verification = new IdentityDbContext(database.BuildOptions());
        var family = await verification.RefreshTokens.AsNoTracking()
            .Where(row => row.IdentitySessionId != null)
            .ToListAsync(TestContext.Current.CancellationToken);
        if (afterCommit)
        {
            // SC-20 after commit: the committed consumption stays authoritative; a retry of the
            // same plaintext follows reuse behavior.
            Assert.Equal(2, family.Count);
            Assert.Single(family, row => row.ConsumedAt is not null);
        }
        else
        {
            // SC-20 before commit: everything rolled back — no consumption, no child, no audit.
            Assert.Single(family);
            Assert.Null(family[0].ConsumedAt);
            Assert.Empty(await verification.AuditLogs.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task Rotation_FromTwoInstancesOverOneDatabase_AdmitsExactlyOneWinner()
    {
        await using var database = new RotationDatabase();
        var seed = await database.SeedAsync();
        var (_, plaintext) = await database.SeedRootMemberAsync(seed);

        var winner = RotationDatabase.BuildService(database.BuildOptions());
        var loser = RotationDatabase.BuildService(database.BuildOptions());
        var results = await Task.WhenAll(
            winner.RotateAsync(seed.Application, Form(plaintext), false, null, null, TestContext.Current.CancellationToken),
            loser.RotateAsync(seed.Application, Form(plaintext), false, null, null, TestContext.Current.CancellationToken));

        Assert.Equal(1, results.Count(dispatch => dispatch.Outcome!.IsSuccess));
        var lost = Assert.Single(results, dispatch => !dispatch.Outcome!.IsSuccess);
        Assert.Equal("replay", lost.Outcome!.FailureReason);

        await using var verification = new IdentityDbContext(database.BuildOptions());
        var family = await verification.RefreshTokens.AsNoTracking()
            .Where(row => row.IdentitySessionId != null)
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, family.Count);
        Assert.Single(family, row => row.ConsumedAt is not null);
        // The winner's child was revoked by the loser's reuse disposal: nothing stays usable.
        var child = Assert.Single(family, row => row.ConsumedAt is null);
        Assert.True(child.IsRevoked);
        Assert.Single(await verification.AuditLogs.AsNoTracking()
            .Where(row => row.Action == "oidc.refresh.replayed")
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The <c>SC-14</c> cross-instance form: two rotation services over two independent contexts
    /// against one shared PostgreSQL database — the production multi-instance deployment shape.
    /// Gated like the rest of the container matrix; the SQLite file form above runs everywhere.
    /// </summary>
    [Theory]
    [InlineData("PostgreSQL")]
    public async Task Rotation_FromTwoInstancesOverOneSharedPostgreSql_AdmitsExactlyOneWinner(
        string provider)
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            $"Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the {provider} interactive rotation matrix.");

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

            var seed = await RotationDatabase.SeedAsync(options);
            var (_, plaintext) = await RotationDatabase.SeedRootMemberAsync(options, seed);
            var results = await Task.WhenAll(
                RotationDatabase.BuildService(options).RotateAsync(seed.Application, Form(plaintext), false, null, null, TestContext.Current.CancellationToken),
                RotationDatabase.BuildService(options).RotateAsync(seed.Application, Form(plaintext), false, null, null, TestContext.Current.CancellationToken));

            Assert.Equal(1, results.Count(dispatch => dispatch.Outcome!.IsSuccess));
            var lost = Assert.Single(results, dispatch => !dispatch.Outcome!.IsSuccess);
            Assert.Equal("replay", lost.Outcome!.FailureReason);

            await using var verification = new IdentityDbContext(options);
            var family = await verification.RefreshTokens.AsNoTracking()
                .Where(row => row.IdentitySessionId != null)
                .ToListAsync(TestContext.Current.CancellationToken);
            Assert.Equal(2, family.Count);
            Assert.Single(family, row => row.ConsumedAt is not null);
            var child = Assert.Single(family, row => row.ConsumedAt is null);
            Assert.True(child.IsRevoked);
            Assert.Single(await verification.AuditLogs.AsNoTracking()
                .Where(row => row.Action == "oidc.refresh.replayed")
                .ToListAsync(TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task FamilyWrites_SecondChildOfOneParentIsRejectedByTheUniqueIndex()
    {
        await using var database = new RotationDatabase();
        var seed = await database.SeedAsync();
        var (rootId, _) = await database.SeedRootMemberAsync(seed);

        await using var context = new IdentityDbContext(database.BuildOptions());
        var unitOfWork = new EfCoreUnitOfWork(context);
        var store = new RefreshTokenFamilyStore(
            new RefreshTokenRepository(context), unitOfWork, NullLogger<RefreshTokenFamilyStore>.Instance);
        var descriptor = new InteractiveRefreshChildDescriptor(
            Guid.NewGuid(), rootId, rootId, seed.AccountId, ClientId, seed.SessionId,
            CanonicalScope, seed.AuthTime, DateTimeOffset.UtcNow.AddDays(7),
            RefreshTokenDigest.Compute(RefreshTokenFamilyStore.GenerateRefreshToken()));
        await store.CreateChildAsync(descriptor, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);

        var second = descriptor with { ChildId = Guid.NewGuid() };
        await Assert.ThrowsAsync<DbUpdateException>(
            () => store.CreateChildAsync(second, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));
    }

    private static IFormCollection Form(string refreshToken) =>
        new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken
        });

    private sealed record Seed(
        AppRegistrationEntity Application,
        Guid AccountId,
        Guid CredentialId,
        Guid SessionId,
        DateTimeOffset AuthTime);

    /// <summary>
    /// A file-backed SQLite test database on the production migration chain, onto which a
    /// retrying execution strategy and interceptors attach as needed.
    /// </summary>
    private sealed class RotationDatabase(IInterceptor? interceptor = null) : IAsyncDisposable
    {
        private readonly string _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-rotation-family-{Guid.NewGuid():N}.db");

        /// <summary>
        /// Options without the interceptor: seeding must not consume the injected failures. The
        /// retrying strategy stays on both option sets — it is the production PostgreSQL shape.
        /// </summary>
        public DbContextOptions<IdentityDbContext> BuildOptions() => BuildOptions(withInterceptor: false);

        public DbContextOptions<IdentityDbContext> BuildOptions(bool withInterceptor)
        {
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseSqlite(
                // Pooling=False keeps every handle inside this class's own contexts, so disposal
                // releases the file without the process-wide ClearAllPools() that would also
                // close unrelated tests' pooled handles mid-flight.
                $"Data Source={_databasePath};Default Timeout=30;Pooling=False",
                providerOptions =>
                {
                    providerOptions.MigrationsAssembly("SignaCore.Database.Migrations.Sqlite");
                    // SQLite has no EnableRetryOnFailure; installing a retrying strategy by hand
                    // is the equivalent of the production PostgreSQL configuration (PS-22).
                    providerOptions.ExecutionStrategy(
                        dependencies => new TestRetryingExecutionStrategy(dependencies));
                });
            if (withInterceptor && interceptor is not null)
            {
                optionsBuilder.AddInterceptors(interceptor);
            }

            return optionsBuilder.Options;
        }

        public static InteractiveRefreshRotationService BuildService(DbContextOptions<IdentityDbContext> options)
        {
            var context = new IdentityDbContext(options);
            var unitOfWork = new EfCoreUnitOfWork(context);
            var refreshTokens = new RefreshTokenRepository(context);
            var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
            meterFactory
                .Setup(factory => factory.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>()))
                .Returns(new System.Diagnostics.Metrics.Meter("SignaCore"));
            return new InteractiveRefreshRotationService(
                refreshTokens,
                new RefreshTokenFamilyStore(refreshTokens, unitOfWork, NullLogger<RefreshTokenFamilyStore>.Instance),
                new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork),
                new AccountRepository(context),
                new PasswordCredentialRepository(context),
                new InteractiveAccessTokenFactory(
                    new JwtOptions { Issuer = "https://rotation-contract.test" },
                    NullLogger<InteractiveAccessTokenFactory>.Instance),
                new InteractiveIdTokenFactory(new JwtOptions { Issuer = "https://rotation-contract.test" }),
                new StaticKeyManager(),
                new AuditService(new LoginHistoryRepository(context), new AuditLogRepository(context)),
                new AuthMetrics(meterFactory.Object),
                unitOfWork,
                context,
                NullLogger<InteractiveRefreshRotationService>.Instance);
        }

        public Task<Seed> SeedAsync() => SeedAsync(BuildOptions());

        public static async Task<Seed> SeedAsync(DbContextOptions<IdentityDbContext> options)
        {
            await using var context = new IdentityDbContext(options);
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);

            var application = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = ClientId,
                AppSecretHash = "hash",
                AppName = "Rotation Contract Client",
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
                Username = Username,
                PasswordHash = "hash",
                CreatedAt = DateTimeOffset.UtcNow
            });
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
            context.ChangeTracker.Clear();

            var unitOfWork = new EfCoreUnitOfWork(context);
            var session = await new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork)
                .CreateAsync(accountId, credentialId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
            return new Seed(application, accountId, credentialId, session.Id, session.AuthTime);
        }

        /// <summary>
        /// Seeds one live interactive root through the family write API and returns its id with
        /// the one-shot plaintext, exactly the way a committed <c>EV-21</c> redemption would have
        /// left it.
        /// </summary>
        public Task<(Guid RootId, string Plaintext)> SeedRootMemberAsync(Seed seed) =>
            SeedRootMemberAsync(BuildOptions(), seed);

        public static async Task<(Guid RootId, string Plaintext)> SeedRootMemberAsync(
            DbContextOptions<IdentityDbContext> options,
            Seed seed)
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

        public async ValueTask DisposeAsync()
        {
            if (File.Exists(_databasePath))
            {
                File.Delete(_databasePath);
            }
        }
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

    /// <summary>
    /// Retries only the marker exception injected by the interceptors below; what matters is
    /// <c>MaxRetryCount &gt; 0</c>, which makes EF Core's <c>RetriesOnFailure</c> true and
    /// therefore triggers the same user-initiated transaction replay as
    /// NpgsqlRetryingExecutionStrategy.
    /// </summary>
    private sealed class TestRetryingExecutionStrategy : ExecutionStrategy
    {
        public TestRetryingExecutionStrategy(ExecutionStrategyDependencies dependencies)
            : base(dependencies, maxRetryCount: 3, maxRetryDelay: TimeSpan.FromMilliseconds(1))
        {
        }

        protected override bool ShouldRetryOn(Exception exception) =>
            exception is InjectedTransientException
            || exception.InnerException is InjectedTransientException;
    }

    private sealed class InjectedTransientException : Exception
    {
        public InjectedTransientException()
            : base("Injected transient database failure.")
        {
        }
    }

    /// <summary>
    /// Injects a transient failure into the first N commit attempts — the commit itself may have
    /// landed while the acknowledgement was lost, which is exactly the ambiguity the stable child
    /// id/digest must resolve.
    /// </summary>
    private sealed class TransientCommitFailureInterceptor(int failuresToInject) : DbTransactionInterceptor
    {
        public int InjectedFailures { get; private set; }

        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction,
            TransactionEventData eventData,
            InterceptionResult result,
            CancellationToken cancellationToken = default)
        {
            if (InjectedFailures < failuresToInject)
            {
                InjectedFailures++;
                throw new InjectedTransientException();
            }

            return ValueTask.FromResult(result);
        }
    }

    private sealed class CommitCancellationInterceptor(
        CancellationTokenSource cancellation,
        bool afterCommit) : DbTransactionInterceptor
    {
        public int CommitAttempts { get; private set; }

        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction,
            TransactionEventData eventData,
            InterceptionResult result,
            CancellationToken cancellationToken = default)
        {
            CommitAttempts++;
            if (!afterCommit)
            {
                cancellation.Cancel();
                cancellationToken.ThrowIfCancellationRequested();
            }

            return ValueTask.FromResult(result);
        }

        public override Task TransactionCommittedAsync(
            DbTransaction transaction,
            TransactionEndEventData eventData,
            CancellationToken cancellationToken = default)
        {
            cancellation.Cancel();
            return Task.CompletedTask;
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
}
