using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using SignaCore.Database;
using ServiceMantle.Migration;

namespace SignaCore.Host.Migration;

/// <summary>
/// SignaCore's adapter from the shared migration orchestration boundary to its own schema workflow.
/// <see cref="InspectAsync"/> performs the limited read-only observation defined by the startup
/// migration gate; <see cref="ExecuteAsync"/> runs the existing <see cref="SchemaMigrator"/> so the
/// PostgreSQL expand/backfill/contract phases, the normalized-collision checks, and the OTP
/// uniqueness check are preserved. The borrowed <see cref="IdentityDbContext"/> is never disposed
/// and no consumer entity is saved by this adapter.
/// </summary>
internal sealed class SignaCoreMigrationExecutor : IDatabaseMigrationExecutor
{
    private const string DefaultHistoryTableName = "__EFMigrationsHistory";
    private const string HistoryLockTableName = "__EFMigrationsHistoryLock";

    private readonly IdentityDbContext _database;
    private readonly DatabaseOptions _databaseOptions;

    public SignaCoreMigrationExecutor(IdentityDbContext database, DatabaseOptions databaseOptions)
    {
        _database = database ?? throw new ArgumentNullException(nameof(database));
        _databaseOptions = databaseOptions ?? throw new ArgumentNullException(nameof(databaseOptions));
    }

    /// <inheritdoc />
    public async ValueTask<MigrationObservationState> InspectAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (_databaseOptions.ProviderKind == DatabaseProvider.Sqlite &&
                !SqliteTargetFileExists())
            {
                // No connection is opened for a missing file: the read-only observation must not
                // create it. DatabaseOptions validation already rejects in-memory targets.
                return MigrationObservationState.Empty;
            }

            var applied = (await _database.Database.GetAppliedMigrationsAsync(cancellationToken))
                .OrderBy(id => id, StringComparer.Ordinal)
                .ToList();
            var lineage = _database.Database.GetMigrations()
                .OrderBy(id => id, StringComparer.Ordinal)
                .ToList();

            if (applied.Count == 0)
            {
                var hasApplicationObjects = await HasApplicationObjectsAsync(cancellationToken);
                return hasApplicationObjects
                    ? MigrationObservationState.InspectionFailed
                    : MigrationObservationState.Empty;
            }

            var known = lineage.ToHashSet(StringComparer.Ordinal);
            if (applied.Any(id => !known.Contains(id)))
            {
                return MigrationObservationState.VersionTooNew;
            }

            if (applied.Count > lineage.Count ||
                !lineage.Take(applied.Count).SequenceEqual(applied, StringComparer.Ordinal))
            {
                return MigrationObservationState.InspectionFailed;
            }

            return applied.Count == lineage.Count
                ? MigrationObservationState.CurrentVersionCompatible
                : MigrationObservationState.PendingMigration;
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            // Observation could not reliably read or identify the history/object catalogs on the
            // target. Fail closed without executing or taking over the database.
            return MigrationObservationState.InspectionFailed;
        }
    }

    /// <inheritdoc />
    public async ValueTask ExecuteAsync(CancellationToken cancellationToken = default)
    {
        await SchemaMigrator.MigrateAsync(_database, _databaseOptions, cancellationToken);
    }

    private bool SqliteTargetFileExists()
    {
        var builder = new SqliteConnectionStringBuilder(_databaseOptions.ConnectionString);
        var path = builder.DataSource;

        if (path.StartsWith("file:", StringComparison.Ordinal))
        {
            // Best-effort URI path extraction so an existing file: target is not misclassified as
            // Empty; ordinary local paths remain the supported spelling.
            var cut = path.IndexOfAny(['?', '#']);
            path = cut >= 0 ? path["file:".Length..cut] : path["file:".Length..];
        }

        // File.Exists is false both for missing files and for directories; a directory (or any
        // other non-file entry) is not a normal local path the existing flow could create, so it
        // fails closed instead of counting as an empty creatable target.
        if (Directory.Exists(path))
        {
            throw new InvalidOperationException(
                "The SQLite data source is not a local database file path.");
        }

        return File.Exists(path);
    }

    /// <summary>
    /// Counts application tables/views in the same schema the connection's migration history uses.
    /// The EF history table and EF's own lock table are not application objects; any other object
    /// counts even when it holds no data.
    /// </summary>
    private async Task<bool> HasApplicationObjectsAsync(CancellationToken cancellationToken)
    {
        var relationalOptions = _database.GetService<IDbContextOptions>()
            .FindExtension<RelationalOptionsExtension>();
        var historyTableName = relationalOptions?.MigrationsHistoryTableName ?? DefaultHistoryTableName;

        return _databaseOptions.ProviderKind switch
        {
            DatabaseProvider.PostgreSql => await HasPostgreSqlApplicationObjectsAsync(
                relationalOptions?.MigrationsHistoryTableSchema,
                historyTableName,
                cancellationToken),
            DatabaseProvider.Sqlite => await HasSqliteApplicationObjectsAsync(
                historyTableName,
                cancellationToken),
            _ => throw new InvalidOperationException("Unsupported database provider.")
        };
    }

    private async Task<bool> HasPostgreSqlApplicationObjectsAsync(
        string? configuredHistorySchema,
        string historyTableName,
        CancellationToken cancellationToken)
    {
        // When a history-table schema is configured, the history table lives there and the object
        // catalog is observed in that schema. Otherwise the effective schema is resolved on the
        // same connection the history query uses, so both observations share one target; failing
        // to locate it fails closed.
        var sql = configuredHistorySchema is null
            ? """
              SELECT COUNT(*) AS "Value" FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = current_schema()
                AND c.relname NOT IN ({0}, {1})
                AND c.relkind IN ('r', 'v', 'm', 'f', 'p')
              """
            : """
              SELECT COUNT(*) AS "Value" FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = {2}
                AND c.relname NOT IN ({0}, {1})
                AND c.relkind IN ('r', 'v', 'm', 'f', 'p')
              """;

        var count = await _database.Database
            .SqlQueryRaw<long>(sql, historyTableName, HistoryLockTableName, configuredHistorySchema!)
            .FirstAsync(cancellationToken);
        return count > 0;
    }

    private async Task<bool> HasSqliteApplicationObjectsAsync(
        string historyTableName,
        CancellationToken cancellationToken)
    {
        var count = await _database.Database
            .SqlQueryRaw<long>(
                """
                SELECT COUNT(*) AS "Value" FROM sqlite_master
                WHERE type IN ('table', 'view')
                  AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'
                  AND name NOT IN ({0}, {1})
                """,
                historyTableName,
                HistoryLockTableName)
            .FirstAsync(cancellationToken);
        return count > 0;
    }
}
