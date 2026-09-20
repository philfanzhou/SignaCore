using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SignaCore.ReferenceBff.Database;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.ReferenceBff.Tests;

/// <summary>
/// Migration and store contracts of the reference BFF's own administrator-binding storage. The
/// SQLite provider runs everywhere; the PostgreSQL cases join the container matrix gated by
/// <c>RUN_SIGNACORE_DATABASE_CONTRACTS=true</c>, which the CI database-contract job selects through
/// the <c>ReferenceBffDatabaseContractTests</c> name filter of its own BFF step.
/// <para>
/// Every SQLite file uses <c>Pooling=false</c> so each test owns its connections completely: this
/// project shares no process-wide SQLite pool state with any other assembly and never clears
/// pools. Every identity value is synthetic; issuer and subject stay opaque byte strings
/// throughout.
/// </para>
/// </summary>
public sealed class ReferenceBffDatabaseContractTests
{
    private const string Issuer = "https://identity.example.test/";
    private const string Subject = "unit-administrator-b7d1f0c2a4";

    private static readonly string PostgreSqlImage =
        Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } image
            ? image
            : "postgres:15-alpine";

    private static bool ShouldRunContainerMatrix() =>
        string.Equals(
            Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS"),
            "true",
            StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// From an empty database both providers migrate, a repeated migrate applies nothing further,
    /// and the model reports nothing pending. The migrated BFF database owns exactly its one
    /// binding table — no product or ServiceMantle object is reachable from this context.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Migrations_FromAnEmptyDatabase_AreIdempotentAndComplete(string provider)
    {
        await using var database = await BffDatabase.CreateAsync(provider);
        await using (var migration = database.CreateContext())
        {
            await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);
            await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);

            Assert.Empty(await migration.Database.GetPendingMigrationsAsync(TestContext.Current.CancellationToken));
            Assert.Equal(
                migration.Database.GetMigrations().Count(),
                (await migration.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken)).Count());
            var table = Assert.Single(migration.Model.GetEntityTypes());
            Assert.Equal("management_role_bindings", table.GetTableName());
        }
    }

    /// <summary>
    /// <c>Down</c> and <c>Up</c> round-trip on an isolated sample database for both providers, and
    /// <c>Down</c> deletes the binding data with the table. Only isolated empty sample databases
    /// are exercised here: an operator must never run <c>Down</c> against a live binding database
    /// without a backup.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Migrations_RoundTripThroughDownAndUpOnAnIsolatedDatabase(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);

        await using (var seeding = database.CreateContext())
        {
            Assert.Equal(
                ManagementRoleBindingStagingStatus.Staged,
                await new ManagementRoleBindingStore(seeding).StageInitialAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
            await seeding.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await using (var reader = database.CreateContext())
        {
            Assert.Equal(
                ManagementRoleBindingMatchStatus.MatchedActiveAdministrator,
                await new ManagementRoleBindingStore(reader).MatchAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
            var migrator = reader.Database.GetService<IMigrator>();
            await migrator.MigrateAsync("0", TestContext.Current.CancellationToken);

            await Assert.ThrowsAnyAsync<DbException>(() =>
                reader.Database.SqlQueryRaw<long>("SELECT COUNT(*) AS \"Value\" FROM management_role_bindings")
                    .SingleAsync(TestContext.Current.CancellationToken));

            await migrator.MigrateAsync(null, TestContext.Current.CancellationToken);
        }

        // The Down leg deleted the binding: the re-applied schema starts empty again.
        await using (var reader = database.CreateContext())
        {
            Assert.Equal(
                ManagementRoleBindingMatchStatus.NoBindingPresent,
                await new ManagementRoleBindingStore(reader).MatchAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
        }
    }

    /// <summary>
    /// A staged binding lives only in its own change tracker: another context cannot see it, the
    /// caller's save makes it visible, and a second staging attempt through the same context is
    /// refused before touching the database again.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task AStagedBinding_IsInvisibleToOtherContextsUntilTheCallerSaves(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        await using var stager = database.CreateContext();
        var store = new ManagementRoleBindingStore(stager);

        Assert.Equal(
            ManagementRoleBindingStagingStatus.Staged,
            await store.StageInitialAdministratorAsync(Issuer, Subject, TestContext.Current.CancellationToken));

        await using (var other = database.CreateContext())
        {
            Assert.Equal(
                ManagementRoleBindingMatchStatus.NoBindingPresent,
                await new ManagementRoleBindingStore(other).MatchAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
        }

        Assert.Equal(
            ManagementRoleBindingStagingStatus.SlotAlreadyBound,
            await store.StageInitialAdministratorAsync(Issuer, Subject, TestContext.Current.CancellationToken));

        await stager.SaveChangesAsync(TestContext.Current.CancellationToken);

        await using (var other = database.CreateContext())
        {
            Assert.Equal(
                ManagementRoleBindingMatchStatus.MatchedActiveAdministrator,
                await new ManagementRoleBindingStore(other).MatchAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
        }
    }

    /// <summary>
    /// A rolled-back caller transaction leaves no half row: the staged entity never reaches the
    /// database, so a fresh context still answers <c>NoBindingPresent</c>.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task ARolledBackCallerTransaction_LeavesNoHalfRow(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        await using var stager = database.CreateContext();

        await using var transaction = await stager.Database.BeginTransactionAsync(TestContext.Current.CancellationToken);
        var store = new ManagementRoleBindingStore(stager);
        Assert.Equal(
            ManagementRoleBindingStagingStatus.Staged,
            await store.StageInitialAdministratorAsync(Issuer, Subject, TestContext.Current.CancellationToken));
        await stager.SaveChangesAsync(TestContext.Current.CancellationToken);
        await transaction.RollbackAsync(TestContext.Current.CancellationToken);

        await using var other = database.CreateContext();
        Assert.Equal(
            ManagementRoleBindingMatchStatus.NoBindingPresent,
            await new ManagementRoleBindingStore(other).MatchAdministratorAsync(
                Issuer, Subject, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A save whose INSERT fails mid-flight leaves no half row either: the exception surfaces to
    /// the caller, the row stays absent for every other context, and the staged entity remains in
    /// the change tracker for the caller to resolve.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task AFailedSave_LeavesNoHalfRow(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        var interceptor = new InsertFailureInterceptor();
        await using var stager = database.CreateContext(interceptor);

        var store = new ManagementRoleBindingStore(stager);
        Assert.Equal(
            ManagementRoleBindingStagingStatus.Staged,
            await store.StageInitialAdministratorAsync(Issuer, Subject, TestContext.Current.CancellationToken));

            var failure = await Assert.ThrowsAsync<DbUpdateException>(() =>
                stager.SaveChangesAsync(TestContext.Current.CancellationToken));
            Assert.IsType<InvalidOperationException>(failure.InnerException);
            Assert.Equal(1, interceptor.InjectedFailures);
        Assert.Contains(stager.ChangeTracker.Entries<ManagementRoleBindingEntity>(),
            entry => entry.State == EntityState.Added);

        await using var other = database.CreateContext();
        Assert.Equal(
            ManagementRoleBindingMatchStatus.NoBindingPresent,
            await new ManagementRoleBindingStore(other).MatchAdministratorAsync(
                Issuer, Subject, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A deactivated row still occupies the slot: it grants nothing, and the initial administrator
    /// can never be re-claimed through the missing active row.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task ADeactivatedBinding_GrantsNothingAndKeepsTheSlot(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);

        await using (var stager = database.CreateContext())
        {
            var store = new ManagementRoleBindingStore(stager);
            Assert.Equal(
                ManagementRoleBindingStagingStatus.Staged,
                await store.StageInitialAdministratorAsync(Issuer, Subject, TestContext.Current.CancellationToken));
            await stager.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await using (var admin = database.CreateContext())
        {
            var row = await admin.ManagementRoleBindings.SingleAsync(TestContext.Current.CancellationToken);
            row.IsActive = false;
            await admin.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await using (var reader = database.CreateContext())
        {
            var store = new ManagementRoleBindingStore(reader);
            Assert.Equal(
                ManagementRoleBindingMatchStatus.BindingInactive,
                await store.MatchAdministratorAsync(Issuer, Subject, TestContext.Current.CancellationToken));
            Assert.Equal(
                ManagementRoleBindingStagingStatus.SlotAlreadyBound,
                await store.StageInitialAdministratorAsync(Issuer, Subject, TestContext.Current.CancellationToken));
        }
    }

    /// <summary>
    /// Only the exact active pair matches: an issuer that differs by case or by a trailing slash,
    /// a different subject, and empty identity values all answer no-permission. Nothing is
    /// normalized away — the meaningful bytes decide.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Matching_RequiresTheExactActiveIdentityPair(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);

        await using (var stager = database.CreateContext())
        {
            Assert.Equal(
                ManagementRoleBindingStagingStatus.Staged,
                await new ManagementRoleBindingStore(stager).StageInitialAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
            await stager.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await using var reader = database.CreateContext();
        var store = new ManagementRoleBindingStore(reader);
        Assert.Equal(
            ManagementRoleBindingMatchStatus.MatchedActiveAdministrator,
            await store.MatchAdministratorAsync(Issuer, Subject, TestContext.Current.CancellationToken));
        Assert.Equal(
            ManagementRoleBindingMatchStatus.IdentityMismatch,
            await store.MatchAdministratorAsync(
                "HTTPS://IDENTITY.EXAMPLE.TEST/", Subject, TestContext.Current.CancellationToken));
        Assert.Equal(
            ManagementRoleBindingMatchStatus.IdentityMismatch,
            await store.MatchAdministratorAsync(
                "https://identity.example.test", Subject, TestContext.Current.CancellationToken));
        Assert.Equal(
            ManagementRoleBindingMatchStatus.IdentityMismatch,
            await store.MatchAdministratorAsync(
                Issuer, "unit-administrator-ffffffffffff", TestContext.Current.CancellationToken));
        Assert.Equal(
            ManagementRoleBindingMatchStatus.IdentityMismatch,
            await store.MatchAdministratorAsync("", Subject, TestContext.Current.CancellationToken));
        Assert.Equal(
            ManagementRoleBindingMatchStatus.IdentityMismatch,
            await store.MatchAdministratorAsync(Issuer, "", TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Identity columns are unbounded and un-indexed: very long issuer and subject values stage,
    /// save, and match without any index-size failure, and the stored bytes read back exactly as
    /// they were asserted.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task UnboundedIdentities_RoundTripByteExact(string provider)
    {
        var longIssuer = "https://identity.example.test/tenants/" + new string('i', 5_000);
        var longSubject = "unit-administrator-" + new string('s', 5_000) + "-é名";

        await using var database = await BffDatabase.CreateMigratedAsync(provider);

        await using (var stager = database.CreateContext())
        {
            Assert.Equal(
                ManagementRoleBindingStagingStatus.Staged,
                await new ManagementRoleBindingStore(stager).StageInitialAdministratorAsync(
                    longIssuer, longSubject, TestContext.Current.CancellationToken));
            await stager.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await using var reader = database.CreateContext();
        Assert.Equal(
            ManagementRoleBindingMatchStatus.MatchedActiveAdministrator,
            await new ManagementRoleBindingStore(reader).MatchAdministratorAsync(
                longIssuer, longSubject, TestContext.Current.CancellationToken));
        var row = await reader.ManagementRoleBindings.AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(longIssuer, row.Issuer);
        Assert.Equal(longSubject, row.Subject);
    }

    /// <summary>
    /// Two contexts that both staged before either saved race on the single slot: the database
    /// admits at most one commit, the loser's save fails, and the loser never overwrites the
    /// winner's row. This exercises the slot's uniqueness only — it is not the setup-flow
    /// single-winner contract.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task RacingWriters_CommitAtMostOneBindingAndNeverOverwrite(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);

        const string winnerIssuer = "https://identity.example.test/";
        const string winnerSubject = "unit-administrator-111111111111";
        const string loserSubject = "unit-administrator-222222222222";

        await using var winner = database.CreateContext();
        await using var loser = database.CreateContext();
        Assert.Equal(
            ManagementRoleBindingStagingStatus.Staged,
            await new ManagementRoleBindingStore(winner).StageInitialAdministratorAsync(
                winnerIssuer, winnerSubject, TestContext.Current.CancellationToken));
        Assert.Equal(
            ManagementRoleBindingStagingStatus.Staged,
            await new ManagementRoleBindingStore(loser).StageInitialAdministratorAsync(
                winnerIssuer, loserSubject, TestContext.Current.CancellationToken));

        await winner.SaveChangesAsync(TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<DbUpdateException>(() =>
            loser.SaveChangesAsync(TestContext.Current.CancellationToken));

        await using var reader = database.CreateContext();
        var store = new ManagementRoleBindingStore(reader);
        Assert.Equal(
            ManagementRoleBindingMatchStatus.MatchedActiveAdministrator,
            await store.MatchAdministratorAsync(
                winnerIssuer, winnerSubject, TestContext.Current.CancellationToken));
        Assert.Equal(
            ManagementRoleBindingMatchStatus.IdentityMismatch,
            await store.MatchAdministratorAsync(
                winnerIssuer, loserSubject, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Cancellation propagates through both entries: a pre-canceled token stages nothing, a
    /// pre-canceled save inside a caller transaction can be rolled back, and a cancellation after
    /// the commit does not undo the committed binding.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Cancellation_PropagatesWithoutStagingSavingOrUndoingCommits(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        var canceled = new CancellationToken(canceled: true);

        await using (var stager = database.CreateContext())
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                new ManagementRoleBindingStore(stager).StageInitialAdministratorAsync(
                    Issuer, Subject, canceled).AsTask());
            Assert.Empty(stager.ChangeTracker.Entries<ManagementRoleBindingEntity>());
        }

        await using (var stager = database.CreateContext())
        {
            await using var transaction =
                await stager.Database.BeginTransactionAsync(TestContext.Current.CancellationToken);
            var store = new ManagementRoleBindingStore(stager);
            Assert.Equal(
                ManagementRoleBindingStagingStatus.Staged,
                await store.StageInitialAdministratorAsync(Issuer, Subject, TestContext.Current.CancellationToken));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                stager.SaveChangesAsync(canceled));
            await transaction.RollbackAsync(TestContext.Current.CancellationToken);
        }

        await using (var stager = database.CreateContext())
        {
            Assert.Equal(
                ManagementRoleBindingStagingStatus.Staged,
                await new ManagementRoleBindingStore(stager).StageInitialAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
            await stager.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await using var reader = database.CreateContext();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new ManagementRoleBindingStore(reader).MatchAdministratorAsync(Issuer, Subject, canceled).AsTask());
        Assert.Equal(
            ManagementRoleBindingMatchStatus.MatchedActiveAdministrator,
            await new ManagementRoleBindingStore(reader).MatchAdministratorAsync(
                Issuer, Subject, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Fails the one statement that persists the binding so the caller's save fails mid-flight.
    /// </summary>
    private sealed class InsertFailureInterceptor : DbCommandInterceptor
    {
        public int InjectedFailures { get; private set; }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfShouldFail(command);
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }

        public override ValueTask<InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<System.Data.Common.DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfShouldFail(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }

        private void ThrowIfShouldFail(DbCommand command)
        {
            // Only the binding INSERT matches; the store's read-only pre-checks must not consume
            // the injected failure. Identifier quoting differs between providers, so the match is
            // quote-agnostic.
            if (InjectedFailures >= 1
                || !command.CommandText.Contains("INSERT INTO", StringComparison.Ordinal)
                || !command.CommandText.Contains("management_role_bindings", StringComparison.Ordinal))
            {
                return;
            }

            InjectedFailures++;
            throw new InvalidOperationException("Injected binding INSERT failure for the contract test.");
        }
    }

    private sealed class BffDatabase : IAsyncDisposable
    {
        private BffDatabase(
            IAsyncDisposable owner,
            Func<DbContextOptionsBuilder<ReferenceBffDbContext>> optionsBuilderFactory)
        {
            Owner = owner;
            OptionsBuilderFactory = optionsBuilderFactory;
        }

        private IAsyncDisposable Owner { get; }

        private Func<DbContextOptionsBuilder<ReferenceBffDbContext>> OptionsBuilderFactory { get; }

        public static async Task<BffDatabase> CreateAsync(string provider)
        {
            if (provider == "SQLite")
            {
                var path = Path.Combine(
                    Path.GetTempPath(), $"signacore-reference-bff-{Guid.NewGuid():N}.db");
                // Pooling=false keeps every connection inside this test: no process-wide pool
                // state is shared and nothing here ever clears pools.
                var connectionString = $"Data Source={path};Pooling=false";
                return new BffDatabase(
                    new TempSqliteFileOwner(path),
                    () => new DbContextOptionsBuilder<ReferenceBffDbContext>()
                        .UseReferenceBffSqlite(connectionString));
            }

            if (provider != "PostgreSQL")
            {
                throw new InvalidOperationException($"Unsupported provider '{provider}'.");
            }

            if (!ShouldRunContainerMatrix())
            {
                Assert.Skip(
                    "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL reference BFF storage matrix.");
            }

            var container = CreatePostgreSqlContainer();
            await container.StartAsync(TestContext.Current.CancellationToken);
            try
            {
                var optionsFactory = TokenizePostgreSqlOptions(container.GetConnectionString());
                var database = new BffDatabase(container, optionsFactory);
                await WaitUntilConnectableAsync(database);
                return database;
            }
            catch
            {
                await container.DisposeAsync();
                throw;
            }
        }

        public static async Task<BffDatabase> CreateMigratedAsync(string provider)
        {
            var database = await CreateAsync(provider);
            await using var migration = database.CreateContext();
            await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);
            return database;
        }

        public ReferenceBffDbContext CreateContext() => new(OptionsBuilderFactory().Options);

        public ReferenceBffDbContext CreateContext(IInterceptor interceptor) =>
            new(OptionsBuilderFactory().AddInterceptors(interceptor).Options);

        private static Func<DbContextOptionsBuilder<ReferenceBffDbContext>> TokenizePostgreSqlOptions(
            string connectionString) =>
            () => new DbContextOptionsBuilder<ReferenceBffDbContext>()
                .UseReferenceBffPostgreSql(connectionString);

        private static PostgreSqlContainer CreatePostgreSqlContainer() =>
            new PostgreSqlBuilder(PostgreSqlImage)
                .WithDatabase("reference_bff")
                .WithUsername("postgres")
                .WithPassword("postgres")
                .Build();

        /// <summary>
        /// Rapid container churn on a shared Docker daemon can briefly refuse the mapped port even
        /// after the container reports started; connect attempts are retried until the database
        /// actually answers.
        /// </summary>
        private static async Task WaitUntilConnectableAsync(BffDatabase database)
        {
            var deadline = DateTimeOffset.UtcNow.AddSeconds(60);
            while (DateTimeOffset.UtcNow < deadline)
            {
                try
                {
                    await using var probe = database.CreateContext();
                    if (await probe.Database.CanConnectAsync(TestContext.Current.CancellationToken))
                    {
                        return;
                    }
                }
                catch (Exception)
                {
                    // Retry until the deadline: the container may still be forwarding ports.
                }

                await Task.Delay(200, TestContext.Current.CancellationToken);
            }

            throw new InvalidOperationException(
                "The reference BFF contract database did not become connectable within 60s.");
        }

        public async ValueTask DisposeAsync() => await Owner.DisposeAsync();

        private sealed class TempSqliteFileOwner(string path) : IAsyncDisposable
        {
            public ValueTask DisposeAsync()
            {
                TryDelete(path);
                TryDelete(path + "-journal");
                TryDelete(path + "-wal");
                TryDelete(path + "-shm");
                return ValueTask.CompletedTask;
            }

            private static void TryDelete(string file)
            {
                try
                {
                    if (File.Exists(file))
                    {
                        File.Delete(file);
                    }
                }
                catch (IOException)
                {
                    // Best effort cleanup of the isolated sample file only.
                }
            }
        }
    }
}
