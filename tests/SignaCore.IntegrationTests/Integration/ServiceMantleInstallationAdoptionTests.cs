using DotNet.Testcontainers.Containers;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using Testcontainers.PostgreSql;
using Xunit;
using SignaCore.Tests.Integration;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// Verifies the <c>AddServiceInstallations</c> migration (ServiceMantle issue #70): the shared
/// <c>service_installations</c> mapping is composed into <see cref="IdentityDbContext"/>, both
/// provider models match their snapshots, and the fail-closed adoption backfill never leaves an
/// upgraded database looking like a fresh, setup-open install.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class ServiceMantleInstallationAdoptionTests
{
    private const string ServiceIdValue = "signacore";

    // The migration immediately preceding AddServiceInstallations in each lineage. Seeding happens at
    // this point, where accounts/installation_state already have their full schema and only
    // service_installations is still absent.
    private const string SqlitePreMigration = "20260831103622_PersistInteractiveOidcClientConfiguration";
    private const string PostgreSqlPreMigration = "20260831103620_PersistInteractiveOidcClientConfiguration";

    private static readonly string PostgreSqlImage =
        Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } image
            ? image
            : "postgres:15-alpine";

    public enum AdoptionScenario
    {
        CompletedInstallationState,
        BusinessDataWithoutInstallationState,
        PendingWithBusinessData,
        PendingWithoutBusinessData,
        FreshEmptyDatabase
    }

    // ----- SQLite (runs locally; no container required) -----

    [Theory]
    [InlineData(AdoptionScenario.CompletedInstallationState)]
    [InlineData(AdoptionScenario.BusinessDataWithoutInstallationState)]
    [InlineData(AdoptionScenario.PendingWithBusinessData)]
    [InlineData(AdoptionScenario.PendingWithoutBusinessData)]
    [InlineData(AdoptionScenario.FreshEmptyDatabase)]
    public async Task SqliteAddServiceInstallations_AdoptsFailClosed(AdoptionScenario scenario)
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-sm-install-{scenario}-{Guid.NewGuid():N}.db");
        var options = CreateSqliteOptions(databasePath);

        try
        {
            var row = await RunAdoptionAsync(options, SqlitePreMigration, scenario);
            AssertAdoptionResult(row, scenario);
        }
        finally
        {
            TestSqlitePools.ClearAll();
            if (File.Exists(databasePath))
            {
                File.Delete(databasePath);
            }
        }
    }

    [Fact]
    public async Task SqliteModelMatchesSnapshot_NoPendingChanges()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-sm-symmetry-{Guid.NewGuid():N}.db");
        var options = CreateSqliteOptions(databasePath);

        try
        {
            await using var context = new IdentityDbContext(options);
            Assert.False(context.Database.HasPendingModelChanges());
        }
        finally
        {
            TestSqlitePools.ClearAll();
            if (File.Exists(databasePath))
            {
                File.Delete(databasePath);
            }
        }
    }

    // ----- PostgreSQL (gated behind the container matrix; runs in CI and locally with the env var) -----

    [Theory]
    [InlineData(AdoptionScenario.CompletedInstallationState)]
    [InlineData(AdoptionScenario.BusinessDataWithoutInstallationState)]
    [InlineData(AdoptionScenario.PendingWithBusinessData)]
    [InlineData(AdoptionScenario.PendingWithoutBusinessData)]
    [InlineData(AdoptionScenario.FreshEmptyDatabase)]
    public async Task PostgreSqlAddServiceInstallations_AdoptsFailClosed(AdoptionScenario scenario)
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL adoption matrix.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var options = CreatePostgreSqlOptions(container.GetConnectionString());
            await WaitUntilConnectableAsync(options);

            var row = await RunAdoptionAsync(options, PostgreSqlPreMigration, scenario);
            AssertAdoptionResult(row, scenario);
        }
    }

    [Fact]
    public async Task PostgreSqlModelMatchesSnapshot_NoPendingChanges()
    {
        // HasPendingModelChanges compares the model against the snapshot; it never opens a
        // connection, so a well-formed but unreachable connection string is sufficient.
        var options = CreatePostgreSqlOptions(
            "Host=localhost;Port=5432;Database=signacore_symmetry;Username=postgres;Password=postgres");
        await using var context = new IdentityDbContext(options);
        Assert.False(context.Database.HasPendingModelChanges());
    }

    // ----- Shared adoption runner and assertions -----

    private static async Task<ServiceInstallationEntity?> RunAdoptionAsync(
        DbContextOptions<IdentityDbContext> options,
        string preMigration,
        AdoptionScenario scenario)
    {
        await using var context = new IdentityDbContext(options);
        var migrator = context.Database.GetService<IMigrator>();

        // Bring the schema up to the migration just before AddServiceInstallations, seed the legacy
        // pre-upgrade state, then apply the remaining migrations so the backfill runs against it.
        await migrator.MigrateAsync(preMigration, TestContext.Current.CancellationToken);
        await SeedAsync(context, scenario);
        context.ChangeTracker.Clear();

        await migrator.MigrateAsync(cancellationToken: TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();

        return await context.ServiceInstallations
            .AsNoTracking()
            .SingleOrDefaultAsync(TestContext.Current.CancellationToken);
    }

    private static async Task SeedAsync(IdentityDbContext context, AdoptionScenario scenario)
    {
        // The legacy installation_state entity and mapping are gone from the runtime model (the
        // forward drop migration retires the table), so the pre-upgrade singleton row is seeded the
        // way the historical schema actually received it: raw SQL against the still-present table.
        switch (scenario)
        {
            case AdoptionScenario.CompletedInstallationState:
                await SeedLegacyInstallationStateAsync(context, completed: true);
                break;
            case AdoptionScenario.BusinessDataWithoutInstallationState:
                context.Accounts.Add(NewAccount());
                break;
            case AdoptionScenario.PendingWithBusinessData:
                await SeedLegacyInstallationStateAsync(context, completed: false);
                context.Accounts.Add(NewAccount());
                break;
            case AdoptionScenario.PendingWithoutBusinessData:
                await SeedLegacyInstallationStateAsync(context, completed: false);
                break;
            case AdoptionScenario.FreshEmptyDatabase:
                return;
            default:
                throw new ArgumentOutOfRangeException(nameof(scenario), scenario, null);
        }

        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    private static async Task SeedLegacyInstallationStateAsync(
        IdentityDbContext context,
        bool completed)
    {
        var installationId = Guid.NewGuid();
        var completedAt = DateTimeOffset.UtcNow;
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1);

        if (context.Database.IsSqlite())
        {
            // The historical SQLite mapping stored instants as Unix microseconds; raw SQL bypasses
            // the (now removed) EF value converter, so convert explicitly.
            static long ToUnixMicroseconds(DateTimeOffset value) =>
                (value.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;

            await context.Database.ExecuteSqlAsync($"""
                INSERT INTO installation_state (id, status, installation_id, setup_code_hash, setup_code_expires_at, completed_at, configuration_version)
                VALUES (1, {(completed ? 1 : 0)}, {installationId}, {(completed ? (string?)null : "legacy-setup-code-hash")}, {(completed ? (long?)null : ToUnixMicroseconds(expiresAt))}, {(completed ? ToUnixMicroseconds(completedAt) : (long?)null)}, {(completed ? 1 : 0)});
                """, TestContext.Current.CancellationToken);
            return;
        }

        await context.Database.ExecuteSqlAsync($"""
            INSERT INTO installation_state (id, status, installation_id, setup_code_hash, setup_code_expires_at, completed_at, configuration_version)
            VALUES (1, {(completed ? 1 : 0)}, {installationId}, {(completed ? (string?)null : "legacy-setup-code-hash")}, {(completed ? (DateTimeOffset?)null : expiresAt)}, {(completed ? completedAt : (DateTimeOffset?)null)}, {(completed ? 1 : 0)});
            """, TestContext.Current.CancellationToken);
    }

    private static AccountEntity NewAccount() => new()
    {
        Id = Guid.NewGuid(),
        IsActive = true,
        CreatedAt = DateTimeOffset.UtcNow
    };

    private static void AssertAdoptionResult(
        ServiceInstallationEntity? row,
        AdoptionScenario scenario)
    {
        if (!ExpectAdopted(scenario))
        {
            // A Pending singleton with no business data, and a brand-new empty database, must stay
            // empty so anonymous setup remains open for a not-yet-completed install.
            Assert.Null(row);
            return;
        }

        // Anything that is not a brand-new empty install adopts a single Completed row, so a later
        // switch to reading service_installations never classifies an upgraded database as
        // PendingSetup and never re-exposes anonymous setup.
        Assert.NotNull(row);
        Assert.Equal(ServiceIdValue, row!.ServiceId);
        Assert.Equal(ServiceMantle.Installation.InstallationStatus.Completed, row.Status);
        Assert.Equal(1, row.Version);
        Assert.Equal(0, row.SetupCodeGeneration);
        Assert.Null(row.SetupCodeDigest);

        // The store mapper invariants the adopted row must satisfy to be readable as Completed:
        // CreatedAtUtc != default, and Completed implies CompletedAtUtc >= CreatedAtUtc. This also
        // proves the migration-written timestamp round-trips through EF on both providers.
        Assert.NotEqual(default, row.CreatedAtUtc);
        Assert.NotNull(row.CompletedAtUtc);
        Assert.True(row.CompletedAtUtc!.Value >= row.CreatedAtUtc);
    }

    private static bool ExpectAdopted(AdoptionScenario scenario) => scenario switch
    {
        AdoptionScenario.CompletedInstallationState => true,
        AdoptionScenario.BusinessDataWithoutInstallationState => true,
        AdoptionScenario.PendingWithBusinessData => true,
        AdoptionScenario.PendingWithoutBusinessData => false,
        AdoptionScenario.FreshEmptyDatabase => false,
        _ => throw new ArgumentOutOfRangeException(nameof(scenario), scenario, null)
    };

    // ----- Provider options and container helpers -----

    private static DbContextOptions<IdentityDbContext> CreateSqliteOptions(string databasePath)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = $"Data Source={databasePath}"
        });
        return optionsBuilder.Options;
    }

    private static DbContextOptions<IdentityDbContext> CreatePostgreSqlOptions(string connectionString)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(new DatabaseOptions
        {
            Provider = "PostgreSQL",
            ServerVersion = "15",
            ConnectionString = connectionString
        });
        return optionsBuilder.Options;
    }

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
                if (await context.Database.CanConnectAsync())
                {
                    return;
                }
            }
            catch (Exception exception)
            {
                lastError = exception;
            }

            await Task.Delay(TimeSpan.FromSeconds(1));
        }

        throw new InvalidOperationException(
            $"Database did not become connectable within 120s. Last error: {lastError?.Message ?? "CanConnectAsync kept returning false"}",
            lastError);
    }
}
