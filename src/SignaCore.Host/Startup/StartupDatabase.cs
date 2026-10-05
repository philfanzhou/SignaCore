using System.Data.Common;
using Microsoft.Data.Sqlite;
using Npgsql;
using ServiceMantle.Bootstrap;
using ServiceMantle.Database.PostgreSql;
using ServiceMantle.Database.Sqlite;
using SignaCore.Database;

namespace SignaCore.Host.Startup;

/// <summary>
/// Startup-owned database preparation through the shared ServiceMantle gate before anything
/// connects to the named target, and the outer
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

    public static async Task EnsureDatabaseExistsAsync(
        DatabaseOptions options,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await using var composition = StartupDatabaseComposition.Create(options);
        await composition.PrepareAsync(cancellationToken);
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
        await using var composition = StartupDatabaseComposition.Create(
            options, targetPreparationProvider: targetPreparationProvider);
        await composition.PrepareAsync(cancellationToken);
    }

    internal static StartupDatabaseException PreparationFailure(DatabaseProvider provider, string? code)
        => provider == DatabaseProvider.PostgreSql
            ? PostgreSqlPreparationFailure(code)
            : SqlitePreparationFailure(code);

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
    /// <param name="canonicalizePath">
    /// Composition seam for the path canonicalization inside the pre-step, so its failure
    /// classification can be exercised deterministically on every platform; the production entry
    /// always uses <see cref="Path.GetFullPath(string)"/>.
    /// </param>
    internal static async Task EnsureSqliteDatabaseExistsAsync(
        DatabaseOptions options,
        IDatabaseTargetPreparationProvider? targetPreparationProvider,
        Func<string, DirectoryInfo>? createParentDirectory,
        CancellationToken cancellationToken,
        Func<string, string>? canonicalizePath = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await using var composition = StartupDatabaseComposition.Create(
            options, targetPreparationProvider: targetPreparationProvider);
        await composition.PrepareAsync(cancellationToken, createParentDirectory, canonicalizePath);
    }

    /// <summary>
    /// SignaCore's idempotent pre-step: create the target's parent directory (never the database
    /// file) when it is missing, so the first-install experience of pointing SignaCore at a fresh
    /// directory keeps working. Paths that are not platform-absolute are left untouched — the
    /// shared provider refuses them with its invalid-target classification instead of resolving
    /// them against the working directory.
    /// </summary>
    internal static void EnsureSqliteParentDirectoryExists(
        string connectionString,
        Func<string, DirectoryInfo>? createParentDirectory,
        Func<string, string>? canonicalizePath)
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
        // input is already absolute, so this never consults the working directory. Canonicalization
        // runs through the same closed classification as the connection-string parse above: a value
        // the OS full-path expansion refuses (for example a drive-absolute path with an extra
        // colon on Windows) fails startup closed with the fixed sanitized invalid-target message
        // instead of letting the BCL exception — whose text embeds the configured path — escape.
        string? directory;
        try
        {
            var canonicalPath = (canonicalizePath ?? Path.GetFullPath)(dataSource);
            directory = Path.GetDirectoryName(canonicalPath);
        }
        catch (Exception exception) when (exception is ArgumentException
            or NotSupportedException
            or PathTooLongException
            or IOException)
        {
            throw SqlitePreparationFailure(WellKnownDatabaseTargetPreparationErrorCodes.InvalidTarget);
        }

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
