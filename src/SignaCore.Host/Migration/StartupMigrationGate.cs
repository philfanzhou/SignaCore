using Microsoft.Extensions.DependencyInjection;
using ServiceMantle;
using ServiceMantle.Bootstrap;
using ServiceMantle.Database.PostgreSql.Migration;
using ServiceMantle.Database.Sqlite;
using ServiceMantle.Migration;
using SignaCore.Database;

namespace SignaCore.Host.Migration;

/// <summary>
/// The fixed safe failure surfaced by the SignaCore startup migration gate. Only the fixed error
/// code from the shared well-known set is carried; original exceptions, inner exceptions, and any
/// dependency text stay out of <see cref="Exception.Message"/>.
/// </summary>
internal sealed class StartupMigrationException : Exception
{
    public StartupMigrationException(string errorCode)
        : base($"SignaCore startup database migration failed ({errorCode}).")
    {
        ErrorCode = errorCode;
    }

    public string ErrorCode { get; }
}

/// <summary>
/// Calls the shared startup database gate inside SignaCore's outer initialization lock. Target
/// preparation remains before that lock so the legacy pre-check still precedes migration. A fresh
/// receipt and isolated provider belong to each call; the executor and context belong to the caller.
/// The shared migration lock wait budget is 30 seconds, independent of the surrounding startup.
/// </summary>
internal static class StartupMigrationGate
{
    internal static readonly TimeSpan SharedLockWaitBudget = TimeSpan.FromSeconds(30);

    internal static InstanceId CreateStartupInstanceId()
        => InstanceId.CreateRandom(ServiceId.Parse("signacore-startup"));

    /// <summary>
    /// Runs the shared migration orchestration with SignaCore's real executor. Caller cancellation
    /// propagates as <see cref="OperationCanceledException"/> on the original token; every other
    /// failure is delivered as a <see cref="StartupMigrationException"/> with a fixed code and
    /// message.
    /// </summary>
    public static async Task RunAsync(
        IdentityDbContext database,
        DatabaseOptions databaseOptions,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        var executor = new SignaCoreMigrationExecutor(database, databaseOptions);
        await RunAsync(database, databaseOptions, logger, executor, cancellationToken);
    }

    /// <summary>
    /// Composition seam with an injectable executor; production always goes through
    /// <see cref="RunAsync(IdentityDbContext, DatabaseOptions, ILogger, CancellationToken)"/>.
    /// </summary>
    internal static async Task RunAsync(
        IdentityDbContext database,
        DatabaseOptions databaseOptions,
        ILogger logger,
        IDatabaseMigrationExecutor executor,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(databaseOptions);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(executor);

        var serviceId = ServiceId.Parse(ServiceMantleComposition.ServiceIdentifier);
        var bootstrap = new BootstrapDatabaseConfiguration(
            databaseOptions.Provider,
            databaseOptions.ServerVersion,
            databaseOptions.ConnectionString);

        var mode = databaseOptions.ProviderKind switch
        {
            DatabaseProvider.PostgreSql => DatabaseDeploymentMode.MultiInstance,
            DatabaseProvider.Sqlite => DatabaseDeploymentMode.SingleInstance,
            _ => throw new InvalidOperationException("Unsupported database provider.")
        };
        var options = new StartupDatabaseGateOptions(
            bootstrap, mode, SharedLockWaitBudget, enableTargetPreparation: false);
        var services = new ServiceCollection();
        var builder = services.AddServiceMantle(
            serviceId, CreateStartupInstanceId());
        if (databaseOptions.ProviderKind == DatabaseProvider.PostgreSql)
        {
            services.AddSingleton<IDatabaseMigrationLockProvider, PostgreSqlMigrationLockProvider>();
            services.AddSingleton<IDatabaseDeploymentCapabilityProvider, PostgreSqlDeploymentCapability>();
        }
        else
        {
            services.AddSingleton<IDatabaseDeploymentCapabilityProvider, SqliteDatabaseTargetPreparationProvider>();
        }

        // The shared gate owns its scope, but never the caller's executor or DbContext. Register a
        // non-disposable delegate so disposable test executors also remain caller-owned.
        services.AddScoped<IDatabaseMigrationExecutor>(_ => new BorrowedExecutor(executor));
        builder.AddStartupDatabaseGate(options);
        StartupDatabaseGateResult result;
        await using (var provider = services.BuildServiceProvider())
        {
            // Direct invocation only: none of this isolated provider's hosted services are started.
            result = await provider.GetRequiredService<StartupDatabaseGate>().RunAsync(
                options, new StartupDatabaseReceipt(), serviceId, cancellationToken);
        }

        // Completion checkpoint after the orchestration and its owned cleanup (shared lease or
        // single-instance turn release) have settled: original-token cancellation takes precedence
        // over delivering success to the caller.
        cancellationToken.ThrowIfCancellationRequested();

        if (!result.Succeeded)
        {
            throw new StartupMigrationException(result.ErrorCode!);
        }

        if (result.ExecutorWasCalled)
        {
            logger.LogInformation(
                "Database schema is current after the shared migration orchestration.");
        }
        else
        {
            logger.LogInformation(
                "Database schema was already current; the migration executor was skipped.");
        }
    }

    // The shared PostgreSQL lock supplies coordination; the product explicitly authorizes its
    // existing multi-instance deployment. Canonical target identity is only used by SingleInstance.
    private sealed class PostgreSqlDeploymentCapability : IDatabaseDeploymentCapabilityProvider
    {
        public DatabaseDeploymentCapability Capability { get; } = new(
            WellKnownDatabaseProviderIds.PostgreSql, DatabaseDeploymentSupport.SingleAndMultiInstance);

        public ValueTask<string> GetCanonicalTargetIdentityAsync(
            BootstrapDatabaseConfiguration target, CancellationToken cancellationToken)
            => throw new InvalidOperationException("PostgreSQL startup requires multi-instance coordination.");
    }

    private sealed class BorrowedExecutor(IDatabaseMigrationExecutor executor) : IDatabaseMigrationExecutor
    {
        public ValueTask<MigrationObservationState> InspectAsync(CancellationToken cancellationToken = default)
            => executor.InspectAsync(cancellationToken);

        public ValueTask ExecuteAsync(CancellationToken cancellationToken = default)
            => executor.ExecuteAsync(cancellationToken);
    }
}
