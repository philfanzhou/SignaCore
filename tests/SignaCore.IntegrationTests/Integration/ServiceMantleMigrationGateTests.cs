using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Migration;
using SignaCore.Host.Startup;
using ServiceMantle.Migration;
using Testcontainers.PostgreSql;
using SignaCore.Host.Installation;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// Real-PostgreSQL startup migration gate contracts (ServiceMantle issue #71), gated behind
/// <c>RUN_SIGNACORE_DATABASE_CONTRACTS=true</c>: the shared lock actually serializes two instances
/// on the same database and service id, the new entry waits behind SignaCore's retained outer lock,
/// lease loss fails closed before any later stage, and the fixed failure projection never carries
/// connection secrets or original exceptions.
/// </summary>
public sealed class ServiceMantleMigrationGateTests
{
    private const string ServiceIdValue = "signacore";
    private const string PostgreSqlPreServiceInstallations =
        "20260831103620_PersistInteractiveOidcClientConfiguration";

    private const string PasswordSentinel = "correct-horse-battery-staple-SENTINEL";

    private static readonly string PostgreSqlImage =
        Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } image
            ? image
            : "postgres:15-alpine";

    [Fact]
    public async Task PostgreSqlGate_FreshDatabase_RunsMigrationAndCreatesPendingInstallation()
    {
        await using var container = await StartContainerAsync();
        var database = ContainerDatabaseOptions(container);

        var result = await BootstrapPhase.RunAsync(
            NewBootstrap(database),
            new ConfigurationBuilder().Build(),
            StubEnvironment(),
            NullLoggerFactory.Instance);

        Assert.Equal(InstallationPhase.PendingSetup, result.Phase);
        Assert.NotNull(result.PlaintextSetupCode);

        await using var context = CreateContext(database);
        var applied = await context.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken);
        Assert.Equal(context.Database.GetMigrations().Count(), applied.Count());
        Assert.Equal(
            1,
            await context.ServiceInstallations.AsNoTracking().CountAsync(TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(ObservationScenario.KnownPrefixHistory)]
    [InlineData(ObservationScenario.CurrentHistory)]
    [InlineData(ObservationScenario.UnknownHistoryId)]
    [InlineData(ObservationScenario.KnownHistoryGap)]
    [InlineData(ObservationScenario.EmptyHistoryWithApplicationObjects)]
    [InlineData(ObservationScenario.ObservationFailure)]
    public async Task PostgreSqlGate_ObservationMatrix_FailsOrSkipsExactlyAsSpecified(ObservationScenario scenario)
    {
        await using var container = await StartContainerAsync();
        var database = ContainerDatabaseOptions(container);
        await PrepareScenarioAsync(container, database, scenario);

        await using var context = CreateContext(database);
        var executor = new SignaCoreMigrationExecutor(context, database);
        var observed = await executor.InspectAsync(TestContext.Current.CancellationToken);

        Assert.Equal(scenario switch
        {
            ObservationScenario.KnownPrefixHistory => MigrationObservationState.PendingMigration,
            ObservationScenario.CurrentHistory => MigrationObservationState.CurrentVersionCompatible,
            ObservationScenario.UnknownHistoryId => MigrationObservationState.VersionTooNew,
            ObservationScenario.KnownHistoryGap => MigrationObservationState.InspectionFailed,
            ObservationScenario.EmptyHistoryWithApplicationObjects => MigrationObservationState.InspectionFailed,
            ObservationScenario.ObservationFailure => MigrationObservationState.InspectionFailed,
            _ => throw new ArgumentOutOfRangeException(nameof(scenario), scenario, null)
        }, observed);

        if (scenario == ObservationScenario.KnownPrefixHistory)
        {
            await executor.ExecuteAsync(TestContext.Current.CancellationToken);
            Assert.Equal(
                MigrationObservationState.CurrentVersionCompatible,
                await executor.InspectAsync(TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task PostgreSqlGate_TwoInstancesSameDatabase_SharedLockSerializesAndOnlyOneExecutes()
    {
        await using var container = await StartContainerAsync();
        var database = ContainerDatabaseOptions(container);

        var order = new List<string>();
        var sync = new object();
        void Record(string @event)
        {
            lock (sync)
            {
                order.Add(@event);
            }
        }

        var executeStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var allowExecuteCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executed = false;

        var first = new DelegateMigrationExecutor
        {
            InspectImpl = _ => ValueTask.FromResult(executed
                ? MigrationObservationState.CurrentVersionCompatible
                : MigrationObservationState.Empty),
            ExecuteImpl = async _ =>
            {
                Record("first-execute");
                executed = true;
                executeStarted.TrySetResult();
                await allowExecuteCompletion.Task;
            }
        };

        var second = new DelegateMigrationExecutor
        {
            InspectImpl = _ =>
            {
                Record("second-inspect");
                return ValueTask.FromResult(executed
                    ? MigrationObservationState.CurrentVersionCompatible
                    : MigrationObservationState.Empty);
            },
            ExecuteImpl = _ =>
            {
                Record("second-execute");
                return ValueTask.CompletedTask;
            }
        };

        var firstGate = RunGate(database, first);
        await executeStarted.Task.WaitAsync(TimeSpan.FromSeconds(30));

        var secondGate = RunGate(database, second);
        await Assert.ThrowsAsync<TimeoutException>(() =>
            secondGate.WaitAsync(TimeSpan.FromMilliseconds(500)));

        allowExecuteCompletion.TrySetResult();
        await firstGate;
        await secondGate;

        Assert.Equal(1, first.ExecuteCount);
        Assert.Equal(0, second.ExecuteCount);
        Assert.Equal(1, second.InspectCount);
        Assert.True(order.IndexOf("second-inspect") > order.IndexOf("first-execute"));
    }

    [Fact]
    public async Task PostgreSqlGate_TwoRealBootstrapInstances_BothSucceedWithOneInstallRowAndCurrentHistory()
    {
        await using var container = await StartContainerAsync();
        var database = ContainerDatabaseOptions(container);

        // Bring the schema up first: the fresh-migration single-execute proof lives in the seam
        // test above; here both real instances contend for an already-current schema, which keeps
        // the retained outer lock's command timeout out of the assertion under test.
        await MigrateToAsync(database, null);

        var firstPhase = BootstrapPhase.RunAsync(
            NewBootstrap(database),
            new ConfigurationBuilder().Build(),
            StubEnvironment(),
            NullLoggerFactory.Instance);
        var secondPhase = BootstrapPhase.RunAsync(
            NewBootstrap(database),
            new ConfigurationBuilder().Build(),
            StubEnvironment(),
            NullLoggerFactory.Instance);

        var results = await Task.WhenAll(firstPhase, secondPhase);

        foreach (var result in results)
        {
            Assert.Equal(InstallationPhase.PendingSetup, result.Phase);
        }

        // Exactly one instance created the pending installation and its one-time setup code; the
        // other observed the existing pending row and issued nothing.
        Assert.Single(results, result => result.PlaintextSetupCode is not null);

        await using var context = CreateContext(database);
        var applied = await context.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken);
        Assert.Equal(context.Database.GetMigrations().Count(), applied.Count());
        Assert.Equal(
            1,
            await context.ServiceInstallations.AsNoTracking().CountAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task PostgreSqlGate_WaitsWhileAnotherInstanceHoldsOnlyTheOldOuterLock()
    {
        await using var container = await StartContainerAsync();
        var database = ContainerDatabaseOptions(container);

        // The schema is already current so the injected executor can honestly skip execution;
        // what is under test is the wait behind the retained outer lock, not migration itself.
        await MigrateToAsync(database, null);

        // Retain SignaCore's original outer initialization lock alone (the shape every pre-gate
        // binary and the setup-code rotation command still produce).
        var outerLock =
            await SignaCore.Host.Startup.StartupDatabase.AcquireInitializationLockAsync(
                database,
                TestContext.Current.CancellationToken);

        var executor = new DelegateMigrationExecutor
        {
            InspectImpl = _ => ValueTask.FromResult(MigrationObservationState.CurrentVersionCompatible)
        };

        // The full bootstrap phase is what acquires the outer lock before the gate, so a process
        // holding only the old outer lock makes the new entry wait exactly as before.
        var phase = BootstrapPhase.RunAsync(
            NewBootstrap(database),
            new ConfigurationBuilder().Build(),
            StubEnvironment(),
            NullLoggerFactory.Instance,
            executor,
            CancellationToken.None);
        await Assert.ThrowsAsync<TimeoutException>(() => phase.WaitAsync(TimeSpan.FromSeconds(2)));

        await outerLock.DisposeAsync();
        var result = await phase.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(0, executor.ExecuteCount);
        Assert.Equal(InstallationPhase.PendingSetup, result.Phase);
    }

    [Fact]
    public async Task PostgreSqlGate_LeaseLostDuringInspection_FailsClosedBeforeAnyExecution()
    {
        await using var container = await StartContainerAsync();
        var database = ContainerDatabaseOptions(container);

        var inspectionEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executor = new DelegateMigrationExecutor
        {
            InspectImpl = async token =>
            {
                inspectionEntered.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return MigrationObservationState.Empty;
            }
        };

        var gate = RunGate(database, executor);
        await inspectionEntered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        var leasePid = await FindAdvisoryLockHolderAsync(database);
        Assert.NotNull(leasePid);
        await ExecuteControlSqlAsync(
            database,
            $"SELECT pg_terminate_backend({leasePid})");

        // The executor observes its cancellation token (the orchestrator's authority token links
        // the caller token with the lease's loss signal); the lease probes its dedicated session
        // and signals within its bounded detection window, which is what breaks the inspection.
        var exception = await Assert.ThrowsAsync<StartupMigrationException>(() => gate);
        Assert.Equal(WellKnownMigrationErrorCodes.LockFailed, exception.ErrorCode);
        Assert.Equal(0, executor.ExecuteCount);

        // Nothing was executed and no application object was taken over.
        var objectCount = await ExecuteControlScalarAsync(
            database,
            """
            SELECT COUNT(*) FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relname NOT IN ('__EFMigrationsHistory')
              AND c.relkind IN ('r', 'v', 'm', 'f', 'p')
            """);
        Assert.Equal(0, Convert.ToInt64(objectCount));
    }

    [Fact]
    public async Task PostgreSqlGate_LockFailure_DeliversFixedMessageWithoutConnectionSecrets()
    {
        await using var container = await StartContainerAsync();
        var builder = new NpgsqlConnectionStringBuilder(container.GetConnectionString())
        {
            Password = PasswordSentinel
        };

        var database = new DatabaseOptions
        {
            Provider = "PostgreSQL",
            ServerVersion = "15",
            ConnectionString = builder.ConnectionString
        };

        var executor = new DelegateMigrationExecutor();

        // The credentials are real, but the database does not exist yet, so EF cannot connect and
        // the bootstrap file has not been written to create it: lock acquisition fails.
        builder.Database = "signacore_gate_missing_database";
        database.ConnectionString = builder.ConnectionString;

        var exception = await Assert.ThrowsAsync<StartupMigrationException>(() => RunGate(database, executor));
        Assert.Equal(WellKnownMigrationErrorCodes.LockFailed, exception.ErrorCode);
        Assert.DoesNotContain(PasswordSentinel, exception.Message, StringComparison.Ordinal);
        Assert.Null(exception.InnerException);
    }

    public enum ObservationScenario
    {
        KnownPrefixHistory,
        CurrentHistory,
        UnknownHistoryId,
        KnownHistoryGap,
        EmptyHistoryWithApplicationObjects,
        ObservationFailure
    }

    private static async Task<PostgreSqlContainer> StartContainerAsync()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL migration gate tests.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();
        await container.StartAsync(TestContext.Current.CancellationToken);

        await WaitUntilConnectableAsync(container.GetConnectionString());
        return container;
    }

    private static async Task PrepareScenarioAsync(
        PostgreSqlContainer container,
        DatabaseOptions database,
        ObservationScenario scenario)
    {
        switch (scenario)
        {
            case ObservationScenario.KnownPrefixHistory:
                await MigrateToAsync(database, PostgreSqlPreServiceInstallations);
                break;
            case ObservationScenario.CurrentHistory:
                await MigrateToAsync(database, null);
                break;
            case ObservationScenario.UnknownHistoryId:
                await MigrateToAsync(database, null);
                await ExecuteControlSqlAsync(
                    database,
                    "INSERT INTO \"__EFMigrationsHistory\" (\"MigrationId\", \"ProductVersion\") VALUES ('99990101000000_NotInThisBuild', '10.0.12')");
                break;
            case ObservationScenario.KnownHistoryGap:
            {
                await MigrateToAsync(database, null);
                await using var context = CreateContext(database);
                var applied = await context.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken);
                var middle = applied.OrderBy(id => id, StringComparer.Ordinal).Skip(1).First();
                await ExecuteControlSqlAsync(
                    database,
                    $"DELETE FROM \"__EFMigrationsHistory\" WHERE \"MigrationId\" = '{middle}'");
                break;
            }
            case ObservationScenario.EmptyHistoryWithApplicationObjects:
                await ExecuteControlSqlAsync(
                    database,
                    "CREATE TABLE legacy_business_data (id uuid PRIMARY KEY, value text)");
                break;
            case ObservationScenario.ObservationFailure:
                // The history catalog cannot be read as a migration history: fixed safe failure.
                await ExecuteControlSqlAsync(
                    database,
                    "CREATE TABLE \"__EFMigrationsHistory\" (wrong_column text)");
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(scenario), scenario, null);
        }
    }

    private static async Task MigrateToAsync(DatabaseOptions database, string? migrationId)
    {
        await using var context = CreateContext(database);
        var migrator = context.Database.GetService<IMigrator>();
        await migrator.MigrateAsync(migrationId, TestContext.Current.CancellationToken);
    }

    private static Task RunGate(DatabaseOptions database, IDatabaseMigrationExecutor executor) =>
        RunGate(database, executor, CancellationToken.None);

    private static async Task RunGate(
        DatabaseOptions database,
        IDatabaseMigrationExecutor executor,
        CancellationToken cancellationToken)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(database);
        await using var context = new IdentityDbContext(optionsBuilder.Options);
        await StartupMigrationGate.RunAsync(
            context,
            database,
            NullLogger.Instance,
            executor,
            cancellationToken);
    }

    private static IdentityDbContext CreateContext(DatabaseOptions database)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(database);
        return new IdentityDbContext(optionsBuilder.Options);
    }

    private static BootstrapConfiguration NewBootstrap(DatabaseOptions database) =>
        new(database, "root-secret-for-tests-only", "tests");

    private static DatabaseOptions ContainerDatabaseOptions(PostgreSqlContainer container) => new()
    {
        Provider = "PostgreSQL",
        ServerVersion = "15",
        ConnectionString = container.GetConnectionString()
    };

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

    private static async Task ExecuteControlSqlAsync(DatabaseOptions database, string sql)
    {
        await using var connection = new NpgsqlConnection(database.ConnectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
    }

    private static async Task<object?> ExecuteControlScalarAsync(DatabaseOptions database, string sql)
    {
        await using var connection = new NpgsqlConnection(database.ConnectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteScalarAsync(TestContext.Current.CancellationToken);
    }

    private static async Task<long?> FindAdvisoryLockHolderAsync(DatabaseOptions database)
    {
        var result = await ExecuteControlScalarAsync(
            database,
            """
            SELECT a.pid FROM pg_stat_activity a
            WHERE a.datname = current_database()
              AND a.pid <> pg_backend_pid()
              AND EXISTS (
                  SELECT 1 FROM pg_locks l
                  WHERE l.pid = a.pid AND l.locktype = 'advisory' AND l.granted)
            LIMIT 1
            """);
        return result is null ? null : Convert.ToInt64(result);
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

/// <summary>A recording executor whose stage behavior is supplied by the test.</summary>
internal sealed class DelegateMigrationExecutor : IDatabaseMigrationExecutor
{
    public Func<CancellationToken, ValueTask<MigrationObservationState>>? InspectImpl { get; set; }

    public Func<CancellationToken, ValueTask>? ExecuteImpl { get; set; }

    public int InspectCount { get; private set; }

    public int ExecuteCount { get; private set; }

    public async ValueTask<MigrationObservationState> InspectAsync(CancellationToken cancellationToken = default)
    {
        InspectCount++;
        if (InspectImpl is null)
        {
            return MigrationObservationState.CurrentVersionCompatible;
        }

        return await InspectImpl(cancellationToken);
    }

    public async ValueTask ExecuteAsync(CancellationToken cancellationToken = default)
    {
        ExecuteCount++;
        if (ExecuteImpl is not null)
        {
            await ExecuteImpl(cancellationToken);
        }
    }
}
