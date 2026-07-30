using System.Data.Common;
using Microsoft.Data.Sqlite;
using MySqlConnector;
using Npgsql;
using QuantumZhou.Identity.Database;

namespace QuantumZhou.Identity.Host;

internal static class DatabaseProvisioner
{
    private const long PostgreSqlMigrationLockId = 5860957687944148308;
    private const string MySqlMigrationLockName = "QuantumZhou.Identity.Migrations";

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
            case DatabaseProvider.MySql:
            case DatabaseProvider.MariaDb:
                await EnsureMySqlDatabaseExistsAsync(
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

    public static async Task<IAsyncDisposable> AcquireMigrationLockAsync(
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
                command.Parameters.AddWithValue("@lock_id", PostgreSqlMigrationLockId);
                await command.ExecuteScalarAsync(cancellationToken);
                return new DatabaseMigrationLock(
                    connection,
                    "SELECT pg_advisory_unlock(@lock_id)",
                    command =>
                    {
                        var parameter = command.CreateParameter();
                        parameter.ParameterName = "@lock_id";
                        parameter.Value = PostgreSqlMigrationLockId;
                        command.Parameters.Add(parameter);
                    });
            }
            case DatabaseProvider.MySql:
            case DatabaseProvider.MariaDb:
            {
                var connection = new MySqlConnection(options.ConnectionString);
                await connection.OpenAsync(cancellationToken);
                await using var command = connection.CreateCommand();
                command.CommandText = "SELECT GET_LOCK(@lock_name, 60)";
                command.Parameters.AddWithValue("@lock_name", MySqlMigrationLockName);
                var acquired = Convert.ToInt32(
                    await command.ExecuteScalarAsync(cancellationToken)) == 1;
                if (!acquired)
                {
                    await connection.DisposeAsync();
                    throw new InvalidOperationException(
                        "Timed out while acquiring the database migration lock.");
                }

                return new DatabaseMigrationLock(
                    connection,
                    "SELECT RELEASE_LOCK(@lock_name)",
                    releaseCommand =>
                    {
                        var parameter = releaseCommand.CreateParameter();
                        parameter.ParameterName = "@lock_name";
                        parameter.Value = MySqlMigrationLockName;
                        releaseCommand.Parameters.Add(parameter);
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

    private static async Task EnsureMySqlDatabaseExistsAsync(
        string connectionString,
        CancellationToken cancellationToken)
    {
        var target = new MySqlConnectionStringBuilder(connectionString);
        var databaseName = target.Database;
        var maintenance = new MySqlConnectionStringBuilder(connectionString)
        {
            Database = string.Empty,
            Pooling = false
        };

        await using var connection = new MySqlConnection(maintenance.ConnectionString);
        await connection.OpenAsync(cancellationToken);

        var escapedDatabaseName = databaseName.Replace("`", "``", StringComparison.Ordinal);
        await using var command = connection.CreateCommand();
        command.CommandText =
            $"CREATE DATABASE IF NOT EXISTS `{escapedDatabaseName}` " +
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_bin";
        await command.ExecuteNonQueryAsync(cancellationToken);
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

    private sealed class DatabaseMigrationLock : IAsyncDisposable
    {
        private readonly DbConnection _connection;
        private readonly string _releaseSql;
        private readonly Action<DbCommand> _configureReleaseCommand;

        public DatabaseMigrationLock(
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
