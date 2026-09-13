using ServiceMantle;
using ServiceMantle.Bootstrap;
using ServiceMantle.Database.PostgreSql.Migration;
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
/// Composes SignaCore's migration executor into the shared
/// <see cref="DatabaseMigrationOrchestrator"/> during startup. PostgreSQL uses the real
/// <see cref="PostgreSqlMigrationLockProvider"/> under the fixed service id <c>signacore</c>;
/// SQLite uses the shared single-instance overload with the local-file deployment capability. The
/// lock wait budget is fixed at 30 seconds for the shared migration lock only; it is not a wall
/// clock bound for the surrounding startup phase, which stays serialized by SignaCore's own outer
/// lock.
/// </summary>
internal static class StartupMigrationGate
{
    internal static readonly TimeSpan SharedLockWaitBudget = TimeSpan.FromSeconds(30);

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

        MigrationExecutionResult result;
        if (databaseOptions.ProviderKind == DatabaseProvider.PostgreSql)
        {
            var orchestrator = new DatabaseMigrationOrchestrator(
                executor,
                new DatabaseMigrationLockProviderRegistry(
                    [new PostgreSqlMigrationLockProvider()],
                    DatabaseProviderIdResolver.Empty));

            result = await orchestrator.OrchestrateMigrationAsync(
                serviceId,
                bootstrap,
                SharedLockWaitBudget,
                cancellationToken);
        }
        else if (databaseOptions.ProviderKind == DatabaseProvider.Sqlite)
        {
            var orchestrator = new DatabaseMigrationOrchestrator(
                executor,
                new DatabaseMigrationLockProviderRegistry(
                    providers: null,
                    DatabaseProviderIdResolver.Empty),
                new DatabaseDeploymentCapabilityRegistry(
                    [new SqliteDeploymentCapabilityProvider()],
                    DatabaseProviderIdResolver.Empty));

            result = await orchestrator.OrchestrateMigrationAsync(
                serviceId,
                bootstrap,
                DatabaseDeploymentMode.SingleInstance,
                SharedLockWaitBudget,
                cancellationToken);
        }
        else
        {
            throw new InvalidOperationException("Unsupported database provider.");
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
}
