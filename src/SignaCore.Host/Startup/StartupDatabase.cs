using System.Data.Common;
using Microsoft.Data.Sqlite;
using Npgsql;
using ServiceMantle.Bootstrap;
using ServiceMantle.Database.PostgreSql;
using SignaCore.Database;

namespace SignaCore.Host.Startup;

/// <summary>
/// Startup-owned database preparation that stays outside the shared ServiceMantle migration
/// orchestration: preparing the named database before anything connects to it, and the outer
/// initialization advisory lock that serializes whole-bootstrap-phase work across instances.
/// </summary>
/// <remarks>
/// <para>
/// The lock keeps its historical key so a fleet that still runs pre-gate binaries (and the setup
/// code rotation command) serializes against this process exactly as before. It covers the shared
/// migration gate, installation resolution, the legacy configuration import, and the settings
/// snapshot load; the shared migration lock inside the gate only covers migration itself.
/// </para>
/// <para>
/// PostgreSQL target preparation delegates to the shared
/// <see cref="PostgreSqlDatabaseTargetPreparationProvider"/> — the same provider the bootstrap
/// candidate path uses — so both paths share one creation semantics: observe the target first, and
/// only a proven-missing target is created through the maintenance database, then re-observed
/// before the initialization lock is taken. An already-connectable target needs no maintenance
/// access and no creation privileges.
/// </para>
/// <para>
/// SQLite has no server-side advisory lock: startup relies on the process-local single-instance
/// turn of the shared migration orchestration plus SQLite's own file-level writer serialization.
/// </para>
/// </remarks>
internal static class StartupDatabase
{
    private const long PostgreSqlInitializationLockId = 5860957687944148308;

    /// <summary>
    /// The fixed preparation budget, matching the bootstrap candidate path so both creation paths
    /// share one deployment rule.
    /// </summary>
    private static readonly TimeSpan TargetPreparationTimeout = TimeSpan.FromSeconds(30);

    public static async Task EnsureDatabaseExistsAsync(
        DatabaseOptions options,
        CancellationToken cancellationToken = default)
    {
        switch (options.ProviderKind)
        {
            case DatabaseProvider.PostgreSql:
                await EnsurePostgreSqlDatabaseExistsAsync(
                    options,
                    targetPreparationProvider: null,
                    cancellationToken);
                break;
            case DatabaseProvider.Sqlite:
                EnsureSqliteDirectoryExists(options.ConnectionString);
                break;
            default:
                throw new InvalidOperationException("Unsupported database provider.");
        }
    }

    public static async Task<IAsyncDisposable> AcquireInitializationLockAsync(
        DatabaseOptions options,
        CancellationToken cancellationToken = default)
    {
        switch (options.ProviderKind)
        {
            case DatabaseProvider.PostgreSql:
            {
                var connection = new NpgsqlConnection(options.ConnectionString);
                await connection.OpenAsync(cancellationToken);
                await using var command = connection.CreateCommand();
                command.CommandText = "SELECT pg_advisory_lock(@lock_id)";
                command.Parameters.AddWithValue("@lock_id", PostgreSqlInitializationLockId);
                await command.ExecuteScalarAsync(cancellationToken);
                return new DatabaseInitializationLock(
                    connection,
                    "SELECT pg_advisory_unlock(@lock_id)",
                    command =>
                    {
                        var parameter = command.CreateParameter();
                        parameter.ParameterName = "@lock_id";
                        parameter.Value = PostgreSqlInitializationLockId;
                        command.Parameters.Add(parameter);
                    });
            }
            case DatabaseProvider.Sqlite:
                return NoOpAsyncDisposable.Instance;
            default:
                throw new InvalidOperationException("Unsupported database provider.");
        }
    }

    /// <summary>
    /// Observes the PostgreSQL target through the shared preparation provider and creates it only
    /// when it is proven missing, mirroring the bootstrap candidate path's deployment rules.
    /// </summary>
    /// <param name="options">
    /// The loaded database options. Only the provider, server version, and connection string are
    /// read; nothing is logged here.
    /// </param>
    /// <param name="targetPreparationProvider">
    /// Composition seam with an injectable preparation provider for startup-level tests; the
    /// production entry always uses the shared PostgreSQL provider.
    /// </param>
    internal static async Task EnsurePostgreSqlDatabaseExistsAsync(
        DatabaseOptions options,
        IDatabaseTargetPreparationProvider? targetPreparationProvider,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var provider = targetPreparationProvider ?? new PostgreSqlDatabaseTargetPreparationProvider();
        var target = new BootstrapDatabaseConfiguration(
            options.Provider,
            options.ServerVersion,
            options.ConnectionString);

        // Observation runs against the target itself: an existing connectable database never
        // touches the maintenance database and needs no creation or ownership privileges.
        var observation = await provider.ObserveAsync(target, cancellationToken);
        if (observation.Status == DatabaseTargetObservationStatus.TargetConnectable)
        {
            return;
        }

        // Only a proven-missing target is prepared. Unreachable servers, failed authentication,
        // and refused access fail closed here, so they are never mistaken for a missing target.
        if (observation.Status != DatabaseTargetObservationStatus.TargetMissing)
        {
            throw PostgreSqlPreparationFailure(observation.ErrorCode);
        }

        // The maintenance connection reuses the target's own credentials against the provider's
        // maintenance database, the same convention the bootstrap candidate path applies.
        var maintenance = new NpgsqlConnectionStringBuilder(options.ConnectionString)
        {
            Database = "postgres",
            Pooling = false
        };
        var prepared = await provider.PrepareAsync(
            new DatabaseTargetPreparationRequest(target, maintenance.ConnectionString),
            TargetPreparationTimeout,
            cancellationToken);
        if (!prepared.Succeeded)
        {
            throw PostgreSqlPreparationFailure(prepared.ErrorCode);
        }

        // The final observation is never skipped: a created (or concurrently already created)
        // target counts only once it is connectable itself. A failure here fails closed before the
        // initialization lock and migrations, leaves any created database in place for the next
        // start, and never rewrites the bootstrap file or the installation authority.
        var confirmation = await provider.ObserveAsync(target, cancellationToken);
        if (confirmation.Status != DatabaseTargetObservationStatus.TargetConnectable)
        {
            throw PostgreSqlPreparationFailure(confirmation.ErrorCode);
        }
    }

    private static StartupDatabaseException PostgreSqlPreparationFailure(string? errorCode)
    {
        var code = errorCode ?? WellKnownDatabaseTargetPreparationErrorCodes.PreparationFailed;
        return new StartupDatabaseException(code, DescribePostgreSqlPreparationFailure(code));
    }

    /// <summary>
    /// The fixed, sanitized operator message per closed classification. Messages never contain the
    /// connection string, credentials, or an original exception value.
    /// </summary>
    private static string DescribePostgreSqlPreparationFailure(string errorCode) => errorCode switch
    {
        WellKnownDatabaseTargetPreparationErrorCodes.AuthenticationFailed =>
            "SignaCore could not authenticate against the configured PostgreSQL server. Verify the " +
            "credentials in the bootstrap database configuration; startup fails closed and no " +
            "database was created.",
        WellKnownDatabaseTargetPreparationErrorCodes.PermissionDenied =>
            "Access to the PostgreSQL database target or its creation was denied. Verify the " +
            "account's privileges, or create the target database manually and restart; startup " +
            "fails closed and the existing target was not modified.",
        WellKnownDatabaseTargetPreparationErrorCodes.ConnectionFailed =>
            "The PostgreSQL server could not be reached. Verify network reachability and the " +
            "configured host; startup fails closed and no database was created.",
        WellKnownDatabaseTargetPreparationErrorCodes.InvalidTarget =>
            "The PostgreSQL database target configuration is invalid.",
        WellKnownDatabaseTargetPreparationErrorCodes.TargetConflict =>
            "The PostgreSQL database target already exists under a different owner and was not " +
            "modified.",
        WellKnownDatabaseTargetPreparationErrorCodes.Timeout =>
            "Preparing the PostgreSQL database target timed out. Startup fails closed; a database " +
            "created before the timeout is kept and re-observed on the next start.",
        _ =>
            "The PostgreSQL database target could not be prepared. Startup fails closed; the " +
            "existing target, if any, was not modified."
    };

    private static void EnsureSqliteDirectoryExists(string connectionString)
    {
        var builder = new SqliteConnectionStringBuilder(connectionString);
        var databasePath = builder.DataSource;
        if (!Path.IsPathFullyQualified(databasePath))
        {
            databasePath = Path.GetFullPath(databasePath);
        }

        var directory = Path.GetDirectoryName(databasePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    private sealed class DatabaseInitializationLock : IAsyncDisposable
    {
        private readonly DbConnection _connection;
        private readonly string _releaseSql;
        private readonly Action<DbCommand> _configureReleaseCommand;

        public DatabaseInitializationLock(
            DbConnection connection,
            string releaseSql,
            Action<DbCommand> configureReleaseCommand)
        {
            _connection = connection;
            _releaseSql = releaseSql;
            _configureReleaseCommand = configureReleaseCommand;
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                await using var command = _connection.CreateCommand();
                command.CommandText = _releaseSql;
                _configureReleaseCommand(command);
                await command.ExecuteScalarAsync();
            }
            finally
            {
                await _connection.DisposeAsync();
            }
        }
    }

    private sealed class NoOpAsyncDisposable : IAsyncDisposable
    {
        public static readonly NoOpAsyncDisposable Instance = new();

        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>
/// Fatal startup database-target preparation failure, delivered with the closed shared
/// classification code and a fixed operator message. The message is safe to print: it identifies
/// the classification only, never the connection string, credentials, or an original exception.
/// </summary>
internal sealed class StartupDatabaseException : Exception
{
    public StartupDatabaseException(string errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    public string ErrorCode { get; }
}
