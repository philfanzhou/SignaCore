using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using ServiceMantle;
using ServiceMantle.Bootstrap;
using ServiceMantle.Migration;
using SignaCore.Database;
using SignaCore.Host.Migration;
using SignaCore.Host.Startup;
using SignaCore.Host.Installation;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration.Integration;

/// <summary>
/// Acceptance of the migration-failure recovery contract on real PostgreSQL, gated behind
/// <c>RUN_SIGNACORE_DATABASE_CONTRACTS=true</c> exactly like the migration gate tests: an
/// execution failure injected mid-migration fails the host startup with the fixed
/// <c>migration.execution_failed</c> code and zero state advance, and the root cause being fixed
/// makes the next start retry deterministically and complete. Caller cancellation propagates as
/// <see cref="OperationCanceledException"/> on the original token while an internal cancellation
/// is classified as a closed failure. A database with a too-new migration id fails every start
/// with <c>migration.version_too_new</c> and never loops.
/// <para>
/// Per the tracked acceptance scope, only PostgreSQL is verified here; SQLite failure semantics
/// are explicitly not guaranteed by the underlying task.
/// </para>
/// </summary>
public sealed class MigrationRecoveryAcceptanceTests
{
    /// <summary>A real mid-lineage point: the injected failure leaves a valid applied prefix.</summary>
    private const string PostgreSqlMidLineage = "20260831103620_PersistInteractiveOidcClientConfiguration";

    private static readonly string PostgreSqlImage =
        Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } image
            ? image
            : "postgres:15-alpine";

    [Fact]
    public async Task ExecutionFailure_MidMigration_FailsClosedWithTheFixedCode_AndARetryAfterTheFixCompletes()
    {
        await using var container = await StartContainerAsync();
        var database = ContainerDatabaseOptions(container);

        // The injected fault: real migration work up to a mid-lineage point, then a deterministic
        // failure — the shape of a deployment whose migration run died half-way through.
        var failing = new InjectedFaultExecutor(
            database,
            executeImpl: async cancellationToken =>
            {
                await MigrateToAsync(database, PostgreSqlMidLineage, cancellationToken);
                throw new InvalidOperationException("injected: the migration run died mid-way");
            });

        var exception = await Assert.ThrowsAsync<StartupMigrationException>(
            () => InstallationStartup.RunAsync(
                NewBootstrap(database),
                new ConfigurationBuilder().Build(),
                StubEnvironment(),
                NullLoggerFactory.Instance,
                failing,
                TestContext.Current.CancellationToken));

        // The fixed projection carries the stable code only: no original exception text, no
        // connection details, no inner exception.
        Assert.Equal(WellKnownMigrationErrorCodes.ExecutionFailed, exception.ErrorCode);
        Assert.Equal(
            "SignaCore startup database migration failed (migration.execution_failed).",
            exception.Message);
        Assert.Null(exception.InnerException);

        await using (var context = CreateContext(database))
        {
            // Zero state advance: the mid-lineage prefix never even reached the
            // service_installations migration, so the table itself must not exist — no partial
            // installation state of any shape was created. The applied history holds exactly the
            // prefix the fault left behind.
            var installationTable = await ExecuteControlScalarAsync(
                database, "SELECT to_regclass('public.service_installations')::text");
            Assert.True(installationTable is null or DBNull);
            var applied = await context.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken);
            Assert.Contains(PostgreSqlMidLineage, applied);
            Assert.True(applied.Count() < context.Database.GetMigrations().Count());
        }

        // The root cause fixed (the real executor again): the next start retries deterministically
        // from the partial history and completes — full history, one pending installation, a
        // one-time setup code, and no Ready phase anywhere in between.
        var recovered = await InstallationStartup.RunAsync(
            NewBootstrap(database),
            new ConfigurationBuilder().Build(),
            StubEnvironment(),
            NullLoggerFactory.Instance,
            migrationExecutor: null,
            TestContext.Current.CancellationToken);
        Assert.Equal(InstallationPhase.PendingSetup, recovered.Phase);
        Assert.NotNull(recovered.PlaintextSetupCode);

        await using (var context = CreateContext(database))
        {
            var applied = await context.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken);
            Assert.Equal(context.Database.GetMigrations().Count(), applied.Count());
            Assert.Equal(
                1,
                await context.ServiceInstallations.AsNoTracking()
                    .CountAsync(TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task CallerCancellation_PropagatesOnTheOriginalToken_WhileInternalCancellationFailsClosed()
    {
        await using var container = await StartContainerAsync();
        var database = ContainerDatabaseOptions(container);

        // A cancellation on the caller's own token propagates as OperationCanceledException —
        // never as a migration failure code. The handshake makes it deterministic: the executor
        // runs, the caller's token is then canceled, and the in-flight execution unwinds.
        using var callerSource = new CancellationTokenSource();
        var executionStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelledByCaller = new DelegateMigrationExecutor(
            executeImpl: async cancellationToken =>
            {
                executionStarted.SetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, callerSource.Token);
            });
        var gateTask = RunGateAsync(database, cancelledByCaller, callerSource.Token);
        await executionStarted.Task.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        await callerSource.CancelAsync();
        var propagated = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => gateTask);
        Assert.Equal(callerSource.Token, propagated.CancellationToken);
        Assert.Equal(1, cancelledByCaller.ExecuteCount);

        // A cancellation on a foreign (internal) token is not caller cancellation: the gate
        // classifies it as a closed execution failure with the fixed code.
        var cancelledInternally = new DelegateMigrationExecutor(
            executeImpl: _ => throw new OperationCanceledException(new CancellationToken(canceled: true)));
        var classified = await Assert.ThrowsAsync<StartupMigrationException>(
            () => RunGateAsync(database, cancelledInternally, CancellationToken.None));
        Assert.Equal(WellKnownMigrationErrorCodes.ExecutionFailed, classified.ErrorCode);

        // A pre-cancelled caller token never reaches the executor at all.
        var neverRuns = new DelegateMigrationExecutor();
        using var preCancelled = new CancellationTokenSource();
        await preCancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => RunGateAsync(database, neverRuns, preCancelled.Token));
        Assert.Equal(0, neverRuns.ExecuteCount);
        Assert.Equal(0, neverRuns.InspectCount);
    }

    [Fact]
    public async Task VersionTooNew_FailsEveryStartWithTheFixedCode_AndNeverLoops()
    {
        await using var container = await StartContainerAsync();
        var database = ContainerDatabaseOptions(container);

        await MigrateToAsync(database, migrationId: null, TestContext.Current.CancellationToken);
        await ExecuteControlSqlAsync(
            database,
            """
            INSERT INTO "__EFMigrationsHistory" ("MigrationId", "ProductVersion")
            VALUES ('20990101000000_FromTheFuture', '10.0.0')
            """);

        // A degraded start (an older build against a newer database) fails closed with the fixed
        // too-new code and leaves the installation state untouched.
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var exception = await Assert.ThrowsAsync<StartupMigrationException>(
                () => InstallationStartup.RunAsync(
                    NewBootstrap(database),
                    new ConfigurationBuilder().Build(),
                    StubEnvironment(),
                    NullLoggerFactory.Instance,
                    migrationExecutor: null,
                    TestContext.Current.CancellationToken));
            Assert.Equal(WellKnownMigrationErrorCodes.VersionTooNew, exception.ErrorCode);

            await using var context = CreateContext(database);
            Assert.Equal(
                0,
                await context.ServiceInstallations.AsNoTracking()
                    .CountAsync(TestContext.Current.CancellationToken));
        }
    }

    /// <summary>
    /// A test executor whose observation defaults to <c>PendingMigration</c> (so the injected
    /// execution stage actually runs) and whose stages are otherwise supplied by the test.
    /// </summary>
    private sealed class DelegateMigrationExecutor(
        Func<CancellationToken, ValueTask>? executeImpl = null,
        Func<CancellationToken, ValueTask<MigrationObservationState>>? inspectImpl = null)
        : IDatabaseMigrationExecutor
    {
        public int ExecuteCount { get; private set; }

        public int InspectCount { get; private set; }

        public async ValueTask<MigrationObservationState> InspectAsync(
            CancellationToken cancellationToken = default)
        {
            InspectCount++;
            return inspectImpl is null
                ? MigrationObservationState.PendingMigration
                : await inspectImpl(cancellationToken);
        }

        public async ValueTask ExecuteAsync(CancellationToken cancellationToken = default)
        {
            ExecuteCount++;
            if (executeImpl is not null)
            {
                await executeImpl(cancellationToken);
            }
        }
    }

    private sealed class InjectedFaultExecutor(
        DatabaseOptions database,
        Func<CancellationToken, ValueTask> executeImpl) : IDatabaseMigrationExecutor
    {
        public ValueTask<MigrationObservationState> InspectAsync(
            CancellationToken cancellationToken = default)
        {
            var context = CreateContext(database);
            return new SignaCoreMigrationExecutor(context, database).InspectAsync(cancellationToken);
        }

        public async ValueTask ExecuteAsync(CancellationToken cancellationToken = default) =>
            await executeImpl(cancellationToken);
    }

    private static async Task RunGateAsync(
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

    private static async Task MigrateToAsync(
        DatabaseOptions database,
        string? migrationId,
        CancellationToken cancellationToken)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(database);
        await using var context = new IdentityDbContext(optionsBuilder.Options);
        var migrator = context.Database.GetService<IMigrator>();
        await migrator.MigrateAsync(migrationId, cancellationToken);
    }

    private static IdentityDbContext CreateContext(DatabaseOptions database)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(database);
        return new IdentityDbContext(optionsBuilder.Options);
    }

    private static BootstrapConfiguration NewBootstrap(DatabaseOptions database) => new(
        ServiceMantle.ServiceId.Parse("signacore"),
        new BootstrapDatabaseConfiguration(database.Provider, database.ServerVersion, database.ConnectionString),
        "root-secret-for-tests-only");

    private static DatabaseOptions ContainerDatabaseOptions(PostgreSqlContainer container) => new()
    {
        Provider = "PostgreSQL",
        ServerVersion = "15",
        ConnectionString = container.GetConnectionString()
    };

    private static async Task<PostgreSqlContainer> StartContainerAsync()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL migration recovery acceptance tests.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();
        await container.StartAsync(TestContext.Current.CancellationToken);

        await WaitUntilConnectableAsync(container.GetConnectionString());
        return container;
    }

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
