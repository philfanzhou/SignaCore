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
/// receipt belongs to each run; the startup core container owns its services while the executor and
/// context belong to the caller.
/// The shared migration lock wait budget is 30 seconds, independent of the surrounding startup.
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
    /// Direct-call seam with an injectable executor. The installation startup reuses one core
    /// composition across target preparation and migration.
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

        await using (var composition = Startup.StartupDatabaseComposition.Create(databaseOptions, executor))
        {
            await composition.RunMigrationAsync(logger, cancellationToken);
        }

        cancellationToken.ThrowIfCancellationRequested();
    }
}
