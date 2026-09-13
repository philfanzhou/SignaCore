using System.Data.Common;
using Microsoft.Data.Sqlite;
using Npgsql;
using SignaCore.Database;

namespace SignaCore.Host.Startup;

/// <summary>
/// Startup-owned database preparation that stays outside the shared ServiceMantle migration
/// orchestration: creating the named database before anything connects to it, and the outer
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
/// SQLite has no server-side advisory lock: startup relies on the process-local single-instance
/// turn of the shared migration orchestration plus SQLite's own file-level writer serialization.
/// </para>
/// </remarks>
internal static class StartupDatabase
{
    private const long PostgreSqlInitializationLockId = 5860957687944148308;

    public static async Task EnsureDatabaseExistsAsync(
        DatabaseOptions options,
        CancellationToken cancellationToken = default)
    {
        switch (options.ProviderKind)
        {
            case DatabaseProvider.PostgreSql:
                await EnsurePostgreSqlDatabaseExistsAsync(
                    options.ConnectionString,
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

    private static async Task EnsurePostgreSqlDatabaseExistsAsync(
        string connectionString,
        CancellationToken cancellationToken)
    {
        var target = new NpgsqlConnectionStringBuilder(connectionString);
        var databaseName = target.Database
            ?? throw new InvalidOperationException(
                "PostgreSQL connection string must specify Database.");
        var maintenance = new NpgsqlConnectionStringBuilder(connectionString)
        {
            Database = "postgres",
            Pooling = false
        };

        await using var connection = new NpgsqlConnection(maintenance.ConnectionString);
        await connection.OpenAsync(cancellationToken);

        await using var checkCommand = connection.CreateCommand();
        checkCommand.CommandText = "SELECT 1 FROM pg_database WHERE datname = @name";
        checkCommand.Parameters.AddWithValue("@name", databaseName);
        if (await checkCommand.ExecuteScalarAsync(cancellationToken) is not null)
        {
            return;
        }

        await using var createCommand = connection.CreateCommand();
        createCommand.CommandText =
            $"CREATE DATABASE \"{databaseName.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
        try
        {
            await createCommand.ExecuteNonQueryAsync(cancellationToken);
        }
        catch (PostgresException exception)
            when (exception.SqlState == PostgresErrorCodes.DuplicateDatabase)
        {
            // Another instance completed database creation after the existence check.
        }
    }

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
