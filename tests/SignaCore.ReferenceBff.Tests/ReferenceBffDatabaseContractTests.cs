using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.Audit;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.ReferenceBff.Database;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.ReferenceBff.Tests;

/// <summary>
/// Migration and store contracts of the reference BFF's own storage: the administrator-binding
/// slot from the first slice plus the shared ServiceMantle installation and audit tables. The
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
    private const string CanarySecret = "synthetic-canary-4f6a2d9b7e1c";

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
    /// and the model reports nothing pending. The migrated BFF database owns exactly its three
    /// tables — the binding slot plus the two shared ServiceMantle tables — and no product or
    /// other ServiceMantle object is reachable from this context.
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
            var tableNames = migration.Model.GetEntityTypes()
                .Select(entityType => entityType.GetTableName())
                .OrderBy(name => name, StringComparer.Ordinal)
                .ToArray();
            Assert.Equal(
                ["management_role_bindings", "service_audit_logs", "service_installations"],
                tableNames);
            Assert.False(migration.Database.HasPendingModelChanges());
        }
    }

    /// <summary>
    /// A database held at the initial binding-only snapshot upgrades to latest without touching
    /// the stored binding: every persisted binding column reads back exactly as it was, and the
    /// upgrade itself seeds no installation or audit row.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Migrations_FromTheInitialSnapshot_UpgradeKeepsStoredBindingsExact(string provider)
    {
        await using var database = await BffDatabase.CreateAsync(provider);

        await using (var initial = database.CreateContext())
        {
            await initial.Database.MigrateAsync(InitialMigrationId(provider), TestContext.Current.CancellationToken);
        }

        (Guid Id, string Issuer, string Subject, bool IsActive, DateTimeOffset CreatedAt) stored;
        await using (var seeding = database.CreateContext())
        {
            Assert.Equal(
                ManagementRoleBindingStagingStatus.Staged,
                await new ManagementRoleBindingStore(seeding).StageInitialAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
            await seeding.SaveChangesAsync(TestContext.Current.CancellationToken);
            var row = await seeding.ManagementRoleBindings.AsNoTracking()
                .SingleAsync(TestContext.Current.CancellationToken);
            stored = (row.Id, row.Issuer, row.Subject, row.IsActive, row.CreatedAtUtc);
        }

        await using (var upgrade = database.CreateContext())
        {
            await upgrade.Database.MigrateAsync(TestContext.Current.CancellationToken);
            Assert.Empty(await upgrade.Database.GetPendingMigrationsAsync(TestContext.Current.CancellationToken));
            Assert.False(upgrade.Database.HasPendingModelChanges());

            var binding = await upgrade.ManagementRoleBindings.AsNoTracking()
                .SingleAsync(TestContext.Current.CancellationToken);
            Assert.Equal(stored.Id, binding.Id);
            Assert.Equal(stored.Issuer, binding.Issuer);
            Assert.Equal(stored.Subject, binding.Subject);
            Assert.Equal(stored.IsActive, binding.IsActive);
            Assert.Equal(stored.CreatedAt, binding.CreatedAtUtc);

            Assert.Equal(0, await upgrade.ServiceInstallations
                .AsNoTracking().CountAsync(TestContext.Current.CancellationToken));
        }
    }

    /// <summary>
    /// <c>Down</c> to the initial binding-only migration removes exactly the two shared tables —
    /// the stored binding survives untouched — and re-applying latest rebuilds the shared tables
    /// empty. Only isolated sample databases are exercised here: an operator must never downgrade
    /// a live database without a backup, because the shared installation and audit data is deleted
    /// with the tables.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Migrations_DownToTheInitialSnapshot_DropsOnlyTheSharedTables(string provider)
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

        await using (var downgrade = database.CreateContext())
        {
            var migrator = downgrade.Database.GetService<IMigrator>();
            await migrator.MigrateAsync(InitialMigrationId(provider), TestContext.Current.CancellationToken);

            Assert.Equal(
                ManagementRoleBindingMatchStatus.MatchedActiveAdministrator,
                await new ManagementRoleBindingStore(downgrade).MatchAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
            await Assert.ThrowsAnyAsync<DbException>(() =>
                downgrade.Database.SqlQueryRaw<long>("SELECT COUNT(*) AS \"Value\" FROM service_installations")
                    .SingleAsync(TestContext.Current.CancellationToken));
            await Assert.ThrowsAnyAsync<DbException>(() =>
                downgrade.Database.SqlQueryRaw<long>("SELECT COUNT(*) AS \"Value\" FROM service_audit_logs")
                    .SingleAsync(TestContext.Current.CancellationToken));

            await migrator.MigrateAsync(null, TestContext.Current.CancellationToken);
        }

        await using (var reader = database.CreateContext())
        {
            Assert.Equal(
                ManagementRoleBindingMatchStatus.MatchedActiveAdministrator,
                await new ManagementRoleBindingStore(reader).MatchAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
            Assert.Equal(0, await reader.ServiceInstallations
                .AsNoTracking().CountAsync(TestContext.Current.CancellationToken));
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
    /// The store registration resolves both shared stores over one scoped caller-owned context: an
    /// audit record staged through the registered writer lands in that same context's change
    /// tracker, and resolving the registration performs no database writes — no installation row
    /// and no administrator binding appears.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task RegisteredStores_ShareOneScopedContextAndWriteNothingByThemselves(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);

        var services = new ServiceCollection();
        services.AddScoped(_ => database.CreateContext());
        services.AddReferenceBffServiceMantleStores();
        await using var serviceProvider = services.BuildServiceProvider();

        using (var scope = serviceProvider.CreateScope())
        {
            var scopedContext = scope.ServiceProvider.GetRequiredService<ReferenceBffDbContext>();
            var installationStore = scope.ServiceProvider.GetRequiredService<IServiceInstallationStore>();
            var auditWriter = scope.ServiceProvider.GetRequiredService<IManagementAuditWriter>();

            await auditWriter.RecordAsync(
                BuildAdministratorAuditEvent(Guid.NewGuid()), TestContext.Current.CancellationToken);
            Assert.Equal("service_audit_logs",
                Assert.Single(scopedContext.ChangeTracker.Entries(),
                    entry => entry.State != EntityState.Unchanged).Metadata.GetTableName());

            Assert.Null(await installationStore.FindAsync(
                ReferenceBffServiceMantle.ServiceId, TestContext.Current.CancellationToken));
            Assert.Equal(0, await scopedContext.ServiceInstallations
                .CountAsync(TestContext.Current.CancellationToken));
            Assert.Equal(0, await scopedContext.ManagementRoleBindings
                .CountAsync(TestContext.Current.CancellationToken));
            Assert.Equal(0, await CountSharedAuditRowsAsync(scopedContext));
        }
    }

    /// <summary>
    /// The shared initialization contract over the sample's fixed service id: a clean context
    /// creates exactly one pending row and every later read or create is idempotent; a dirty
    /// context is refused before any save, leaving the caller's staged business row unsaved;
    /// cancellation propagates out of reads; and <c>MarkCompletedAsync</c> cannot bypass the Setup
    /// Code flow that a later slice owns.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task InstallationInitialization_FollowsTheSharedSaveContract(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        var serviceId = ReferenceBffServiceMantle.ServiceId;

        await using (var initializer = database.CreateContext())
        {
            var store = new EfCoreServiceInstallationStore<ReferenceBffDbContext>(initializer);
            var created = await store.CreatePendingAsync(serviceId, TestContext.Current.CancellationToken);
            Assert.Equal(InstallationStatus.PendingSetup, created.Status);
            Assert.Equal(ReferenceBffServiceMantle.ServiceIdValue, created.ServiceId.Value);

            var reread = await store.FindAsync(serviceId, TestContext.Current.CancellationToken);
            Assert.NotNull(reread);
            Assert.Equal(InstallationStatus.PendingSetup, reread.Status);
        }

        await using (var second = database.CreateContext())
        {
            var again = await new EfCoreServiceInstallationStore<ReferenceBffDbContext>(second)
                .CreatePendingAsync(serviceId, TestContext.Current.CancellationToken);
            Assert.Equal(InstallationStatus.PendingSetup, again.Status);
            Assert.Equal(1, await second.ServiceInstallations
                .AsNoTracking().CountAsync(TestContext.Current.CancellationToken));
        }

        await using (var dirty = database.CreateContext())
        {
            Assert.Equal(
                ManagementRoleBindingStagingStatus.Staged,
                await new ManagementRoleBindingStore(dirty).StageInitialAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
            var refused = await Assert.ThrowsAsync<ServiceInstallationStoreException>(() =>
                new EfCoreServiceInstallationStore<ReferenceBffDbContext>(dirty)
                    .CreatePendingAsync(serviceId, TestContext.Current.CancellationToken).AsTask());
            Assert.Equal(WellKnownSetupCodeErrorCodes.DirtyContext, refused.ErrorCode);
        }

        await using (var untouched = database.CreateContext())
        {
            Assert.Equal(
                ManagementRoleBindingMatchStatus.NoBindingPresent,
                await new ManagementRoleBindingStore(untouched).MatchAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
        }

        await using (var reader = database.CreateContext())
        {
            var store = new EfCoreServiceInstallationStore<ReferenceBffDbContext>(reader);
            var canceled = new CancellationToken(canceled: true);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                store.FindAsync(serviceId, canceled).AsTask());
            var bypass = await Assert.ThrowsAsync<ServiceInstallationStoreException>(() =>
                store.MarkCompletedAsync(serviceId, TestContext.Current.CancellationToken).AsTask());
            Assert.Equal(WellKnownSetupCodeErrorCodes.SetupCodeRequired, bypass.ErrorCode);
        }
    }

    /// <summary>
    /// The caller-owned unit of work spans all three BFF tables: the shared initialization save,
    /// a staged binding, and a staged audit record commit together in one explicit transaction.
    /// A cancellation observed after the commit cannot undo the durable facts.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SharedUnitOfWork_CommitsRoleInstallationAndAuditTogether(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);

        await using (var worker = database.CreateContext())
        {
            await using var transaction =
                await worker.Database.BeginTransactionAsync(TestContext.Current.CancellationToken);
            await new EfCoreServiceInstallationStore<ReferenceBffDbContext>(worker)
                .CreatePendingAsync(ReferenceBffServiceMantle.ServiceId, TestContext.Current.CancellationToken);
            Assert.Equal(
                ManagementRoleBindingStagingStatus.Staged,
                await new ManagementRoleBindingStore(worker).StageInitialAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
            var bindingRow = worker.ManagementRoleBindings.Local.Single();
            await new EfCoreManagementAuditWriter<ReferenceBffDbContext>(worker).RecordAsync(
                BuildAdministratorAuditEvent(bindingRow.Id), TestContext.Current.CancellationToken);
            await worker.SaveChangesAsync(TestContext.Current.CancellationToken);
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        }

        // Cancellation observed after the commit changes nothing: a canceled read still refuses
        // to run while the committed facts stay readable for every other context.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new ManagementRoleBindingStore(database.CreateContext()).MatchAdministratorAsync(
                Issuer, Subject, new CancellationToken(canceled: true)).AsTask());

        await using (var reader = database.CreateContext())
        {
            Assert.Equal(
                ManagementRoleBindingMatchStatus.MatchedActiveAdministrator,
                await new ManagementRoleBindingStore(reader).MatchAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
            Assert.Equal(InstallationStatus.PendingSetup, (await reader.ServiceInstallations
                .AsNoTracking().SingleAsync(TestContext.Current.CancellationToken)).Status);
            Assert.Equal(1, await CountSharedAuditRowsAsync(reader));
        }
    }

    /// <summary>
    /// The same unit of work fails closed: a caller rollback, an injected save failure, or a
    /// pre-commit cancellation leaves no half data — no binding, no installation row, and no audit
    /// record survives for any other context. Each leg runs against its own isolated database.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SharedUnitOfWork_LeavesNoHalfRowOnRollbackFailureOrPreCommitCancel(string provider)
    {
        await RunUnitOfWorkLegAsync(provider, commit: false);
        await RunUnitOfWorkLegAsync(provider, commit: false, failBindingInsert: true);
        await RunUnitOfWorkLegAsync(provider, commit: false, cancelBeforeCommit: true);
    }

    /// <summary>
    /// Drives one caller-owned unit of work that stages all three BFF writes, then fails or
    /// commits it, and finally asserts that exactly the committed outcome is readable.
    /// </summary>
    private static async Task RunUnitOfWorkLegAsync(
        string provider,
        bool commit,
        bool failBindingInsert = false,
        bool cancelBeforeCommit = false)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        var worker = failBindingInsert
            ? database.CreateContext(new InsertFailureInterceptor())
            : database.CreateContext();
        await using (worker)
        {
            await using var transaction =
                await worker.Database.BeginTransactionAsync(TestContext.Current.CancellationToken);
            await new EfCoreServiceInstallationStore<ReferenceBffDbContext>(worker)
                .CreatePendingAsync(ReferenceBffServiceMantle.ServiceId, TestContext.Current.CancellationToken);
            Assert.Equal(
                ManagementRoleBindingStagingStatus.Staged,
                await new ManagementRoleBindingStore(worker).StageInitialAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
            await new EfCoreManagementAuditWriter<ReferenceBffDbContext>(worker).RecordAsync(
                BuildAdministratorAuditEvent(worker.ManagementRoleBindings.Local.Single().Id),
                TestContext.Current.CancellationToken);

            if (failBindingInsert)
            {
                await Assert.ThrowsAsync<DbUpdateException>(() =>
                    worker.SaveChangesAsync(TestContext.Current.CancellationToken));
            }
            else if (cancelBeforeCommit)
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                    worker.SaveChangesAsync(new CancellationToken(canceled: true)));
            }
            else
            {
                await worker.SaveChangesAsync(TestContext.Current.CancellationToken);
            }

            if (commit)
            {
                await transaction.CommitAsync(TestContext.Current.CancellationToken);
            }
            else
            {
                await transaction.RollbackAsync(TestContext.Current.CancellationToken);
            }
        }

        await using (var reader = database.CreateContext())
        {
            Assert.Equal(
                commit
                    ? ManagementRoleBindingMatchStatus.MatchedActiveAdministrator
                    : ManagementRoleBindingMatchStatus.NoBindingPresent,
                await new ManagementRoleBindingStore(reader).MatchAdministratorAsync(
                    Issuer, Subject, TestContext.Current.CancellationToken));
            Assert.Equal(commit ? 1 : 0, await reader.ServiceInstallations
                .AsNoTracking().CountAsync(TestContext.Current.CancellationToken));
            Assert.Equal(commit ? 1 : 0, await CountSharedAuditRowsAsync(reader));
        }
    }

    /// <summary>
    /// A staged audit record is invisible to other contexts, and a save alone is not a commit
    /// inside an explicit transaction: until the caller commits, no other context can read the
    /// row, and a rollback discards it.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task AStagedAuditRecord_IsInvisibleUntilTheCallerCommits(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        await using var worker = database.CreateContext();

        await new EfCoreManagementAuditWriter<ReferenceBffDbContext>(worker).RecordAsync(
            BuildAdministratorAuditEvent(Guid.NewGuid()), TestContext.Current.CancellationToken);

        await using (var other = database.CreateContext())
        {
            Assert.Equal(0, await CountSharedAuditRowsAsync(other));
        }

        await using (var transaction =
            await worker.Database.BeginTransactionAsync(TestContext.Current.CancellationToken))
        {
            await worker.SaveChangesAsync(TestContext.Current.CancellationToken);
            await using (var other = database.CreateContext())
            {
                Assert.Equal(0, await CountSharedAuditRowsAsync(other));
            }

            await transaction.RollbackAsync(TestContext.Current.CancellationToken);
        }

        await using (var final = database.CreateContext())
        {
            Assert.Equal(0, await CountSharedAuditRowsAsync(final));
        }
    }

    /// <summary>
    /// Two contexts competing on the same installation row resolve through the shared version
    /// concurrency token: at most one commit wins, the loser fails without an automatic retry, and
    /// the durable row reflects exactly one version bump.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task CompetingInstallationWriters_CommitAtMostOneVersionBump(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);

        await using (var initializer = database.CreateContext())
        {
            await new EfCoreServiceInstallationStore<ReferenceBffDbContext>(initializer)
                .CreatePendingAsync(ReferenceBffServiceMantle.ServiceId, TestContext.Current.CancellationToken);
        }

        await using var winner = database.CreateContext();
        await using var loser = database.CreateContext();
        var winnerRow = await winner.ServiceInstallations.SingleAsync(TestContext.Current.CancellationToken);
        var loserRow = await loser.ServiceInstallations.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, winnerRow.Version);
        Assert.Equal(1, loserRow.Version);

        // Test-only direct state edit mirroring the shared store's explicit version bump: the
        // schema's concurrency contract is under test, not the completion flow a later slice
        // owns through the shared Setup Code store.
        foreach (var row in new[] { winnerRow, loserRow })
        {
            row.Status = InstallationStatus.Completed;
            row.CompletedAtUtc = DateTime.UtcNow;
            row.Version += 1;
        }

        await winner.SaveChangesAsync(TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() =>
            loser.SaveChangesAsync(TestContext.Current.CancellationToken));

        await using (var reader = database.CreateContext())
        {
            var durable = await reader.ServiceInstallations.AsNoTracking()
                .SingleAsync(TestContext.Current.CancellationToken);
            Assert.Equal(InstallationStatus.Completed, durable.Status);
            Assert.Equal(2, durable.Version);
        }

        Assert.Contains(loser.ChangeTracker.Entries<ServiceInstallationEntity>(),
            entry => entry.State == EntityState.Modified);
    }

    /// <summary>
    /// The audit surface stays opaque: a synthetic sensitive canary is rejected with a bounded
    /// exception that never echoes it, and a legitimately staged record — opaque target only —
    /// persists no canary and no issuer/subject identity in any readable column or projection.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task AuditContent_StaysOpaqueAndRejectsSensitiveValues(string provider)
    {
        var rejected = Assert.Throws<ManagementAuditException>(() =>
            ManagementAuditOperator.Create(
                WellKnownManagementAuditOperatorSources.InteractiveAdmin,
                operatorId: $"Bearer {CanarySecret}"));
        Assert.DoesNotContain(CanarySecret, rejected.Message);
        Assert.DoesNotContain(CanarySecret, rejected.ToString());

        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        await using (var worker = database.CreateContext())
        {
            var record = await new EfCoreManagementAuditWriter<ReferenceBffDbContext>(worker).RecordAsync(
                BuildAdministratorAuditEvent(Guid.NewGuid()), TestContext.Current.CancellationToken);
            Assert.DoesNotContain(CanarySecret, record.ToString());
            Assert.DoesNotContain(Issuer, record.ToString());
            Assert.DoesNotContain(Subject, record.ToString());
            await worker.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await using (var reader = database.CreateContext())
        {
            var row = await reader.Database.SqlQueryRaw<SharedAuditRow>(
                """
                SELECT security_description AS "Description",
                       target_id AS "TargetId",
                       action AS "Action",
                       COALESCE(metadata_json, '') AS "MetadataJson"
                FROM service_audit_logs
                """)
                .SingleAsync(TestContext.Current.CancellationToken);
            foreach (var text in new[] { row.Description, row.TargetId, row.Action, row.MetadataJson })
            {
                Assert.DoesNotContain(CanarySecret, text);
                Assert.DoesNotContain(Issuer, text);
                Assert.DoesNotContain(Subject, text);
            }
        }
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

    /// <summary>The provider-specific migration id of the binding-only initial snapshot.</summary>
    private static string InitialMigrationId(string provider) => provider == "SQLite"
        ? "20260920023218_AddManagementRoleBindings"
        : "20260920023212_AddManagementRoleBindings";

    /// <summary>Counts committed shared audit rows through raw SQL: the audit entity is internal.</summary>
    private static async Task<long> CountSharedAuditRowsAsync(ReferenceBffDbContext context) =>
        await context.Database.SqlQueryRaw<long>(
            "SELECT COUNT(*) AS \"Value\" FROM service_audit_logs")
            .SingleAsync(TestContext.Current.CancellationToken);

    /// <summary>
    /// Builds the audit event the BFF's data phase records for a staged binding: a system
    /// operator, an opaque row-id target, and a description that names no identity value.
    /// </summary>
    private static ManagementAuditEvent BuildAdministratorAuditEvent(Guid bindingRowId) =>
        ManagementAuditEvent.Create(
            ManagementAuditOperator.System(displayName: "Reference BFF data phase"),
            ManagementAuditAction.Parse("reference_bff.administrator_binding.staged"),
            ManagementAuditTarget.Create(
                ManagementAuditTargetType.Parse("reference_bff.administrator_binding"),
                bindingRowId.ToString("D")),
            ManagementAuditOutcome.Success,
            securityDescription: "Initial administrator binding staged for the reference BFF.");

    /// <summary>The readable projection of one shared audit row used by the opacity assertions.</summary>
    private sealed record SharedAuditRow(string Description, string TargetId, string Action, string MetadataJson);

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
