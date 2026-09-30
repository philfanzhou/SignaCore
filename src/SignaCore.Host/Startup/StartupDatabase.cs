using System.Data.Common;
using Microsoft.Data.Sqlite;
using Npgsql;
using ServiceMantle.Bootstrap;
using ServiceMantle.Database.Sqlite;
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
/// SQLite target preparation delegates to the shared
/// <see cref="SqliteDatabaseTargetPreparationProvider"/> — the same provider the bootstrap
/// candidate path uses — behind SignaCore's own idempotent parent-directory pre-step. The path
/// contract is narrowed to platform-absolute canonical file paths: relative paths,
/// <c>|DataDirectory|</c>, <c>file:</c> URIs, and symlinked or aliased targets are rejected by
/// the provider and fail startup closed. An existing dirty target (WAL/journal sidecars, or a
/// failed read-only probe) is deliberately passed through to EF's native open, which stays the
/// final judge exactly as before.
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
                    options.ConnectionString,
                    cancellationToken);
                break;
            case DatabaseProvider.Sqlite:
                await EnsureSqliteDatabaseExistsAsync(
                    options,
                    targetPreparationProvider: null,
                    createParentDirectory: null,
                    cancellationToken);
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

    /// <summary>
    /// Prepares the SQLite file target through the shared preparation provider, behind SignaCore's
    /// own idempotent parent-directory pre-step, per the product's narrowed compatibility contract.
    /// </summary>
    /// <param name="options">
    /// The loaded database options. Only the provider and connection string are read; nothing is
    /// logged here.
    /// </param>
    /// <param name="targetPreparationProvider">
    /// Composition seam with an injectable preparation provider for startup-level tests; the
    /// production entry always uses the shared SQLite provider.
    /// </param>
    /// <param name="createParentDirectory">
    /// Composition seam for the directory pre-step, so its failure classification can be exercised
    /// deterministically; the production entry always uses <see cref="Directory.CreateDirectory"/>.
    /// </param>
    internal static async Task EnsureSqliteDatabaseExistsAsync(
        DatabaseOptions options,
        IDatabaseTargetPreparationProvider? targetPreparationProvider,
        Func<string, DirectoryInfo>? createParentDirectory,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureSqliteParentDirectoryExists(options.ConnectionString, createParentDirectory);

        var provider = targetPreparationProvider ?? new SqliteDatabaseTargetPreparationProvider();
        var target = new BootstrapDatabaseConfiguration(
            options.Provider,
            options.ServerVersion,
            options.ConnectionString);

        var observation = await provider.ObserveAsync(target, cancellationToken);
        if (observation.Status == DatabaseTargetObservationStatus.TargetConnectable)
        {
            return;
        }

        // An existing dirty target — WAL/journal sidecars present, or a read-only probe failure —
        // is not a startup precondition failure: EF's native open stays the final judge, completing
        // WAL recovery or failing exactly as it did before this contract existed. Only the shared
        // target-conflict classification is passed through; every other unreachable observation
        // (permission denied, connection failed, invalid target) fails closed.
        if (observation.Status == DatabaseTargetObservationStatus.TargetUnreachable &&
            string.Equals(
                observation.ErrorCode,
                WellKnownDatabaseTargetPreparationErrorCodes.TargetConflict,
                StringComparison.Ordinal))
        {
            return;
        }

        // Only a proven-missing target is created, and never over anything that already exists.
        if (observation.Status != DatabaseTargetObservationStatus.TargetMissing)
        {
            throw SqlitePreparationFailure(observation.ErrorCode);
        }

        var prepared = await provider.PrepareAsync(
            DatabaseTargetPreparationRequest.ForFile(target),
            TargetPreparationTimeout,
            cancellationToken);
        if (!prepared.Succeeded)
        {
            throw SqlitePreparationFailure(prepared.ErrorCode);
        }

        // The final observation is never skipped: a created (or concurrently already created) file
        // counts only once it is connectable itself. A failure here fails closed before the
        // initialization lock and migrations, leaves any created file in place for the next start,
        // and never rewrites the bootstrap file or the installation authority.
        var confirmation = await provider.ObserveAsync(target, cancellationToken);
        if (confirmation.Status != DatabaseTargetObservationStatus.TargetConnectable)
        {
            throw SqlitePreparationFailure(confirmation.ErrorCode);
        }
    }

    /// <summary>
    /// SignaCore's idempotent pre-step: create the target's parent directory (never the database
    /// file) when it is missing, so the first-install experience of pointing SignaCore at a fresh
    /// directory keeps working. Paths that are not platform-absolute are left untouched — the
    /// shared provider refuses them with its invalid-target classification instead of resolving
    /// them against the working directory.
    /// </summary>
    private static void EnsureSqliteParentDirectoryExists(
        string connectionString,
        Func<string, DirectoryInfo>? createParentDirectory)
    {
        string dataSource;
        try
        {
            dataSource = new SqliteConnectionStringBuilder(connectionString).DataSource;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            // The shared provider refuses an unparseable connection string with the same
            // classification this startup reports for every other invalid input.
            throw SqlitePreparationFailure(WellKnownDatabaseTargetPreparationErrorCodes.InvalidTarget);
        }

        if (!Path.IsPathFullyQualified(dataSource))
        {
            return;
        }

        // The parent chain is computed from the canonical form so a path the provider will refuse
        // for its shape (for example a `..` segment) does not materialize directories first; the
        // input is already absolute, so this never consults the working directory.
        var canonicalPath = Path.GetFullPath(dataSource);
        var directory = Path.GetDirectoryName(canonicalPath);
        if (string.IsNullOrEmpty(directory) || Directory.Exists(directory))
        {
            return;
        }

        try
        {
            (createParentDirectory ?? Directory.CreateDirectory)(directory);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException
            or IOException
            or NotSupportedException)
        {
            throw new StartupDatabaseException(
                WellKnownDatabaseTargetPreparationErrorCodes.PermissionDenied,
                "The parent directory of the SQLite database target could not be created. Verify " +
                "the configured path and the account's write permissions; startup fails closed " +
                "and no database file was created.");
        }
    }

    private static StartupDatabaseException SqlitePreparationFailure(string? errorCode)
    {
        var code = errorCode ?? WellKnownDatabaseTargetPreparationErrorCodes.PreparationFailed;
        return new StartupDatabaseException(code, DescribeSqlitePreparationFailure(code));
    }

    /// <summary>
    /// The fixed, sanitized operator message per closed classification. Messages never contain the
    /// connection string or an original exception value.
    /// </summary>
    private static string DescribeSqlitePreparationFailure(string errorCode) => errorCode switch
    {
        WellKnownDatabaseTargetPreparationErrorCodes.InvalidTarget =>
            "The SQLite database target must be a platform-absolute canonical file path. Relative " +
            "paths, |DataDirectory| substitution, file: URIs, symbolic links, and other aliases " +
            "are rejected; update the bootstrap database configuration to use an absolute path.",
        WellKnownDatabaseTargetPreparationErrorCodes.PermissionDenied =>
            "Access to the SQLite database target or its creation was denied. Verify the file and " +
            "directory permissions of the configured path; startup fails closed and the existing " +
            "target was not modified.",
        WellKnownDatabaseTargetPreparationErrorCodes.ConnectionFailed =>
            "The SQLite database file could not be opened or read. Verify that the configured " +
            "target is a readable SQLite database file; startup fails closed.",
        WellKnownDatabaseTargetPreparationErrorCodes.TargetConflict =>
            "The SQLite database target could not be created because conflicting files (for " +
            "example WAL or journal sidecars) are present next to it. Resolve the conflict and " +
            "restart; startup fails closed and the existing files were not modified.",
        WellKnownDatabaseTargetPreparationErrorCodes.Timeout =>
            "Preparing the SQLite database target timed out. Startup fails closed; a file created " +
            "before the timeout is kept and re-observed on the next start.",
        _ =>
            "The SQLite database target could not be prepared. Startup fails closed; the existing " +
            "target, if any, was not modified."
    };

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
