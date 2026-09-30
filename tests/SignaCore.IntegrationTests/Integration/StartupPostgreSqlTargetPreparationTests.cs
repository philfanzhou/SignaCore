using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using ServiceMantle;
using ServiceMantle.Bootstrap;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Startup;
using SignaCore.Host.Installation;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// Real-PostgreSQL startup target-preparation contracts, gated behind
/// <c>RUN_SIGNACORE_DATABASE_CONTRACTS=true</c>: a missing database is created through the shared
/// preparation provider and confirmed before migrations run, two concurrent instances converge on
/// one created target, an already-connectable target needs no maintenance access or creation
/// privileges, and unreachable, unauthorized, or cancelled starts fail closed without leaking
/// credentials or deleting a created target.
/// </summary>
public sealed class StartupPostgreSqlTargetPreparationTests
{
    private const string ServiceIdValue = "signacore";
    private const string PasswordSentinel = "correct-horse-battery-staple-SENTINEL";

    private static readonly string PostgreSqlImage =
        Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } image
            ? image
            : "postgres:15-alpine";

    [Fact]
    public async Task MissingDatabase_IsCreatedThroughSharedPreparationAndStartupReachesSetup()
    {
        await using var container = await StartContainerAsync();
        var database = MissingDatabaseOptions(container, "signacore_startup_missing_fresh");

        var result = await InstallationStartup.RunAsync(
            NewBootstrap(database),
            new ConfigurationBuilder().Build(),
            StubEnvironment(),
            NullLoggerFactory.Instance);

        Assert.Equal(InstallationPhase.PendingSetup, result.Phase);

        // The target exists as an ordinary PostgreSQL database, the confirming observation let the
        // initialization lock and migrations run, and the pending installation was created.
        Assert.True(await DatabaseExistsAsync(container, "signacore_startup_missing_fresh"));
        await using var context = CreateContext(database);
        var applied = await context.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken);
        Assert.Equal(context.Database.GetMigrations().Count(), applied.Count());
        Assert.Equal(
            1,
            await context.ServiceInstallations.AsNoTracking().CountAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TwoConcurrentInstancesOnMissingDatabase_BothReachSetupWithOneInstallationRow()
    {
        await using var container = await StartContainerAsync();
        var database = MissingDatabaseOptions(container, "signacore_startup_missing_race");

        var results = await Task.WhenAll(
            InstallationStartup.RunAsync(
                NewBootstrap(database),
                new ConfigurationBuilder().Build(),
                StubEnvironment(),
                NullLoggerFactory.Instance),
            InstallationStartup.RunAsync(
                NewBootstrap(database),
                new ConfigurationBuilder().Build(),
                StubEnvironment(),
                NullLoggerFactory.Instance));

        // One instance created the target, the other converged on it through the shared provider's
        // race handling; both then ran the unchanged outer-lock-and-migration sequence.
        Assert.All(results, result => Assert.Equal(InstallationPhase.PendingSetup, result.Phase));
        Assert.True(await DatabaseExistsAsync(container, "signacore_startup_missing_race"));
        await using var context = CreateContext(database);
        Assert.Equal(
            1,
            await context.ServiceInstallations.AsNoTracking().CountAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ExistingConnectableTargetWithoutMaintenanceAccess_StartsUpUnchanged()
    {
        await using var container = await StartContainerAsync();

        // A role that owns an existing database but can neither connect to the maintenance
        // database nor create databases: startup on this target must not need either privilege.
        await ExecuteControlSqlAsync(
            container,
            "REVOKE CONNECT ON DATABASE postgres FROM PUBLIC",
            useMaintenanceDatabase: true);
        await ExecuteControlSqlAsync(
            container,
            "CREATE ROLE signacore_limited LOGIN PASSWORD 'limited-password'",
            useMaintenanceDatabase: true);
        await ExecuteControlSqlAsync(
            container,
            "CREATE DATABASE signacore_startup_existing OWNER signacore_limited",
            useMaintenanceDatabase: true);

        var database = new DatabaseOptions
        {
            Provider = "PostgreSQL",
            ServerVersion = "15",
            ConnectionString =
                $"Host={container.Hostname};Port={container.GetMappedPublicPort(5432)};" +
                "Database=signacore_startup_existing;Username=signacore_limited;Password=limited-password"
        };

        var result = await InstallationStartup.RunAsync(
            NewBootstrap(database),
            new ConfigurationBuilder().Build(),
            StubEnvironment(),
            NullLoggerFactory.Instance);

        Assert.Equal(InstallationPhase.PendingSetup, result.Phase);
        await using var context = CreateContext(database);
        var applied = await context.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken);
        Assert.Equal(context.Database.GetMigrations().Count(), applied.Count());
    }

    [Fact]
    public async Task AuthenticationFailure_FailsClosedClassifiedAndCreatesNothing()
    {
        await using var container = await StartContainerAsync();
        var database = MissingDatabaseOptions(container, "signacore_startup_missing_auth");
        database.ConnectionString = new NpgsqlConnectionStringBuilder(database.ConnectionString)
        {
            Password = PasswordSentinel
        }.ConnectionString;

        var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
            InstallationStartup.RunAsync(
                NewBootstrap(database),
                new ConfigurationBuilder().Build(),
                StubEnvironment(),
                NullLoggerFactory.Instance));

        Assert.Equal("database_target_preparation.authentication_failed", exception.ErrorCode);
        Assert.DoesNotContain(PasswordSentinel, exception.Message, StringComparison.Ordinal);
        Assert.Null(exception.InnerException);

        // Nothing was created and migrations never ran: a refused credential is never mistaken
        // for a missing target.
        Assert.False(await DatabaseExistsAsync(container, "signacore_startup_missing_auth"));
    }

    [Fact]
    public async Task UnreachableServer_FailsClosedClassifiedWithoutSecrets()
    {
        var database = new DatabaseOptions
        {
            Provider = "PostgreSQL",
            ServerVersion = "15",
            ConnectionString =
                $"Host=127.0.0.1;Port=1;Database=signacore_startup_unreachable;Username=postgres;Password={PasswordSentinel};Timeout=3"
        };

        var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
            InstallationStartup.RunAsync(
                NewBootstrap(database),
                new ConfigurationBuilder().Build(),
                StubEnvironment(),
                NullLoggerFactory.Instance));

        Assert.Equal("database_target_preparation.connection_failed", exception.ErrorCode);
        Assert.DoesNotContain(PasswordSentinel, exception.Message, StringComparison.Ordinal);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public async Task CreatedTargetSurvivesCancelledRestartAndNextStartReobservesIt()
    {
        await using var container = await StartContainerAsync();
        var database = MissingDatabaseOptions(container, "signacore_startup_missing_cancel");

        // The first start creates the target and confirms it.
        await StartupDatabase.EnsureDatabaseExistsAsync(database, TestContext.Current.CancellationToken);
        Assert.True(await DatabaseExistsAsync(container, "signacore_startup_missing_cancel"));

        // A cancelled start stops before observing and never deletes the created target.
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            StartupDatabase.EnsureDatabaseExistsAsync(database, cancellation.Token));
        Assert.True(await DatabaseExistsAsync(container, "signacore_startup_missing_cancel"));

        // The next start re-observes the existing target and proceeds into lock and migrations.
        var result = await InstallationStartup.RunAsync(
            NewBootstrap(database),
            new ConfigurationBuilder().Build(),
            StubEnvironment(),
            NullLoggerFactory.Instance);
        Assert.Equal(InstallationPhase.PendingSetup, result.Phase);
    }

    private static async Task<PostgreSqlContainer> StartContainerAsync()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL startup preparation tests.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();
        await container.StartAsync(TestContext.Current.CancellationToken);

        await WaitUntilConnectableAsync(container.GetConnectionString());
        return container;
    }

    private static DatabaseOptions MissingDatabaseOptions(PostgreSqlContainer container, string databaseName)
    {
        var builder = new NpgsqlConnectionStringBuilder(container.GetConnectionString())
        {
            Database = databaseName
        };
        return new DatabaseOptions
        {
            Provider = "PostgreSQL",
            ServerVersion = "15",
            ConnectionString = builder.ConnectionString
        };
    }

    private static async Task<bool> DatabaseExistsAsync(PostgreSqlContainer container, string databaseName)
    {
        await using var connection = new NpgsqlConnection(MaintenanceConnectionString(container));
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1 FROM pg_database WHERE datname = @name";
        command.Parameters.AddWithValue("@name", databaseName);
        return await command.ExecuteScalarAsync(TestContext.Current.CancellationToken) is not null;
    }

    private static async Task ExecuteControlSqlAsync(
        PostgreSqlContainer container,
        string sql,
        bool useMaintenanceDatabase)
    {
        var builder = new NpgsqlConnectionStringBuilder(container.GetConnectionString());
        if (useMaintenanceDatabase)
        {
            builder.Database = "postgres";
        }

        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private static string MaintenanceConnectionString(PostgreSqlContainer container)
    {
        var builder = new NpgsqlConnectionStringBuilder(container.GetConnectionString())
        {
            Database = "postgres"
        };
        return builder.ConnectionString;
    }

    private static IdentityDbContext CreateContext(DatabaseOptions database)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(database);
        return new IdentityDbContext(optionsBuilder.Options);
    }

    private static BootstrapConfiguration NewBootstrap(DatabaseOptions database) => new(
        ServiceId.Parse(ServiceIdValue),
        new BootstrapDatabaseConfiguration(database.Provider, database.ServerVersion, database.ConnectionString),
        "root-secret-for-tests-only");

    private static async Task WaitUntilConnectableAsync(string connectionString)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(120);
        Exception? lastError = null;
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                await using var connection = new NpgsqlConnection(connectionString);
                await connection.OpenAsync();
                return;
            }
            catch (Exception exception)
            {
                lastError = exception;
            }

            await Task.Delay(TimeSpan.FromSeconds(1));
        }

        throw new InvalidOperationException(
            $"PostgreSQL did not become connectable within 120s. Last error: {lastError?.Message}");
    }

    private static bool ShouldRunContainerMatrix() =>
        bool.TryParse(
            Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS"),
            out var run) && run;

    private static IHostEnvironment StubEnvironment() => new TestHostEnvironment();

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "SignaCore.IntegrationTests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } =
            new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}
