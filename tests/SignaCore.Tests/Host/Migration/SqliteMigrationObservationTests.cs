using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SignaCore.Database;
using SignaCore.Host.Migration;
using ServiceMantle.Bootstrap;
using ServiceMantle.Migration;
using Xunit;
using static SignaCore.Tests.Host.Migration.SqliteMigrationGateTestSupport;

namespace SignaCore.Tests.Host.Migration;

/// <summary>
/// Verifies the limited read-only observation of SignaCore's migration executor on SQLite targets:
/// the full observation matrix, that observation never creates the file, the history table, or any
/// data, and that the borrowed context stays owned by the caller.
/// </summary>
public sealed class SqliteMigrationObservationTests
{
    // A known strict prefix of the SQLite lineage (everything except AddServiceInstallations).
    private const string PreServiceInstallations = "20260831103622_PersistInteractiveOidcClientConfiguration";

    [Fact]
    public async Task Inspect_MissingFile_ReturnsEmpty_AndNeverCreatesTheFile()
    {
        var databasePath = NewDatabasePath();
        var (executor, db) = CreateExecutor(databasePath);

        try
        {
            Assert.Equal(MigrationObservationState.Empty, await executor.InspectAsync());
            Assert.Equal(MigrationObservationState.Empty, await executor.InspectAsync());
            Assert.False(File.Exists(databasePath));
        }
        finally
        {
            await db.DisposeAsync();
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Inspect_ExistingEmptyDatabase_ReturnsEmpty_AndWritesNothing()
    {
        var databasePath = NewDatabasePath();
        File.WriteAllBytes(databasePath, []);
        var (executor, db) = CreateExecutor(databasePath);

        try
        {
            var lengthBefore = new FileInfo(databasePath).Length;
            Assert.Equal(MigrationObservationState.Empty, await executor.InspectAsync());
            Assert.Equal(MigrationObservationState.Empty, await executor.InspectAsync());

            // File snapshot plus an independent connection prove the observation created neither
            // the history table nor any other object or data.
            Assert.Equal(lengthBefore, new FileInfo(databasePath).Length);
            Assert.Empty(ListDatabaseObjects(databasePath));
        }
        finally
        {
            await db.DisposeAsync();
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Inspect_KnownPrefixHistory_ReturnsPendingMigration()
    {
        var databasePath = NewDatabasePath();
        var (executor, db) = CreateExecutor(databasePath);

        try
        {
            await MigrateToAsync(db, PreServiceInstallations);
            Assert.Equal(MigrationObservationState.PendingMigration, await executor.InspectAsync());
        }
        finally
        {
            await db.DisposeAsync();
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Inspect_CurrentHistory_ReturnsCurrentVersionCompatible()
    {
        var databasePath = NewDatabasePath();
        var (executor, db) = CreateExecutor(databasePath);

        try
        {
            await db.Database.MigrateAsync(TestContext.Current.CancellationToken);
            Assert.Equal(MigrationObservationState.CurrentVersionCompatible, await executor.InspectAsync());
        }
        finally
        {
            await db.DisposeAsync();
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Inspect_UnknownHistoryId_ReturnsVersionTooNew()
    {
        var databasePath = NewDatabasePath();
        var (executor, db) = CreateExecutor(databasePath);

        try
        {
            await db.Database.MigrateAsync(TestContext.Current.CancellationToken);
            ExecuteSql(
                databasePath,
                "INSERT INTO __EFMigrationsHistory (MigrationId, ProductVersion) VALUES ('99990101000000_NotInThisBuild', '10.0.12')");
            Assert.Equal(MigrationObservationState.VersionTooNew, await executor.InspectAsync());
        }
        finally
        {
            await db.DisposeAsync();
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Inspect_KnownHistoryWithGap_ReturnsInspectionFailed()
    {
        var databasePath = NewDatabasePath();
        var (executor, db) = CreateExecutor(databasePath);

        try
        {
            await db.Database.MigrateAsync(TestContext.Current.CancellationToken);
            var applied = await db.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken);
            var middle = applied.OrderBy(id => id, StringComparer.Ordinal).Skip(1).First();
            ExecuteSql(databasePath, $"DELETE FROM __EFMigrationsHistory WHERE MigrationId = '{middle}'");
            Assert.Equal(MigrationObservationState.InspectionFailed, await executor.InspectAsync());
        }
        finally
        {
            await db.DisposeAsync();
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Inspect_EmptyHistoryWithApplicationObjects_ReturnsInspectionFailed_AndAdoptsNothing()
    {
        var databasePath = NewDatabasePath();
        ExecuteSql(databasePath, "CREATE TABLE legacy_business_data (id INTEGER PRIMARY KEY, value TEXT)");
        var (executor, db) = CreateExecutor(databasePath);

        try
        {
            var objectsBefore = ListDatabaseObjects(databasePath);
            var lengthBefore = new FileInfo(databasePath).Length;

            Assert.Equal(MigrationObservationState.InspectionFailed, await executor.InspectAsync());

            // No history was created or backfilled for the unknown database, and the object
            // catalog is unchanged: the executor does not take over the target.
            Assert.Equal(objectsBefore, ListDatabaseObjects(databasePath));
            Assert.Equal(lengthBefore, new FileInfo(databasePath).Length);
        }
        finally
        {
            await db.DisposeAsync();
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Inspect_UnreadableTarget_ReturnsInspectionFailed()
    {
        // A directory as the data source exists as a file entry but cannot be opened as a SQLite
        // database, so the history catalog cannot be reliably read: fixed safe failure.
        var directoryPath = Path.Combine(Path.GetTempPath(), $"signacore-gate-dir-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directoryPath);
        var (executor, db) = CreateExecutor(directoryPath);

        try
        {
            Assert.Equal(MigrationObservationState.InspectionFailed, await executor.InspectAsync());
        }
        finally
        {
            await db.DisposeAsync();
            Directory.Delete(directoryPath);
        }
    }

    [Fact]
    public async Task Execute_RunsFullSchemaMigrator_AndLeavesBorrowedContextUsable()
    {
        var databasePath = NewDatabasePath();
        var (executor, db) = CreateExecutor(databasePath);

        try
        {
            await executor.ExecuteAsync(TestContext.Current.CancellationToken);

            // The executor does not dispose or break the caller-owned context.
            var applied = await db.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken);
            Assert.Equal(db.Database.GetMigrations().Count(), applied.Count());
            Assert.Equal(MigrationObservationState.CurrentVersionCompatible, await executor.InspectAsync());
        }
        finally
        {
            await db.DisposeAsync();
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task CapabilityProvider_NormalizesOrdinaryPathsAndEquivalentConnectionStrings()
    {
        var provider = new SqliteDeploymentCapabilityProvider();
        Assert.Equal(
            DatabaseDeploymentSupport.SingleInstanceOnly,
            provider.Capability.Support);

        var file = Path.Combine(Path.GetTempPath(), $"signacore-identity-{Guid.NewGuid():N}.db");
        var absolute = $"Data Source={file}";
        var relative = $"Data Source={Path.GetRelativePath(Environment.CurrentDirectory, file)}";
        var equivalents = new[]
        {
            absolute,
            relative,
            $"DataSource={file};Default Timeout=30",
            $"Data Source={file};Cache=Shared",
            $"data source={file};Pooling=False"
        };

        var identity = await provider.GetCanonicalTargetIdentityAsync(
            new BootstrapDatabaseConfiguration(WellKnownDatabaseProviderIds.Sqlite, null, absolute),
            TestContext.Current.CancellationToken);

        foreach (var equivalent in equivalents)
        {
            Assert.Equal(
                identity,
                await provider.GetCanonicalTargetIdentityAsync(
                    new BootstrapDatabaseConfiguration(WellKnownDatabaseProviderIds.Sqlite, null, equivalent),
                    TestContext.Current.CancellationToken));
        }

        Assert.Equal(Path.GetFullPath(file), identity);

        var otherFile = Path.Combine(Path.GetTempPath(), $"signacore-other-{Guid.NewGuid():N}.db");
        Assert.NotEqual(
            identity,
            await provider.GetCanonicalTargetIdentityAsync(
                new BootstrapDatabaseConfiguration(WellKnownDatabaseProviderIds.Sqlite, null, $"Data Source={otherFile}"),
                TestContext.Current.CancellationToken));

        // A file: URI target is used verbatim and stays distinct from the plain path identity.
        Assert.Equal(
            "file:identity.db?mode=ro",
            await provider.GetCanonicalTargetIdentityAsync(
                new BootstrapDatabaseConfiguration(WellKnownDatabaseProviderIds.Sqlite, null, "Data Source=file:identity.db?mode=ro"),
                TestContext.Current.CancellationToken));

        // Identity resolution does not rewrite the caller's connection string or options.
        var target = new BootstrapDatabaseConfiguration(WellKnownDatabaseProviderIds.Sqlite, null, absolute);
        await provider.GetCanonicalTargetIdentityAsync(target, TestContext.Current.CancellationToken);
        Assert.Equal(absolute, target.ConnectionString);
    }

    private static (SignaCoreMigrationExecutor Executor, IdentityDbContext Database) CreateExecutor(
        string databasePath)
    {
        var options = TestDatabaseOptions(databasePath);
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(options);
        var db = new IdentityDbContext(optionsBuilder.Options);
        return (new SignaCoreMigrationExecutor(db, options), db);
    }

    private static async Task MigrateToAsync(IdentityDbContext db, string migrationId)
    {
        var migrator = db.Database.GetService<IMigrator>();
        await migrator.MigrateAsync(migrationId, TestContext.Current.CancellationToken);
    }
}

internal static class SqliteMigrationGateTestSupport
{
    public static string NewDatabasePath() =>
        Path.Combine(Path.GetTempPath(), $"signacore-gate-{Guid.NewGuid():N}.db");

    public static DatabaseOptions TestDatabaseOptions(string databasePath, string? extra = null) => new()
    {
        Provider = "SQLite",
        ConnectionString = extra is null
            ? $"Data Source={databasePath}"
            : $"Data Source={databasePath};{extra}"
    };

    public static void ExecuteSql(string databasePath, string sql)
    {
        using var connection = new SqliteConnection($"Data Source={databasePath}");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    public static IReadOnlyList<string> ListDatabaseObjects(string databasePath)
    {
        using var connection = new SqliteConnection($"Data Source={databasePath}");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT type || ':' || name FROM sqlite_master ORDER BY type, name";
        var objects = new List<string>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            objects.Add(reader.GetString(0));
        }

        return objects;
    }

    public static IReadOnlyList<string> ListHistoryRows(string databasePath)
    {
        using var connection = new SqliteConnection($"Data Source={databasePath}");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT MigrationId FROM __EFMigrationsHistory ORDER BY MigrationId";
        var rows = new List<string>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            rows.Add(reader.GetString(0));
        }

        return rows;
    }

    public static bool TableExists(string databasePath, string tableName)
    {
        using var connection = new SqliteConnection($"Data Source={databasePath}");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $name";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "$name";
        parameter.Value = tableName;
        command.Parameters.Add(parameter);
        return Convert.ToInt64(command.ExecuteScalar()) > 0;
    }

    public static long Scalar(string databasePath, string sql)
    {
        using var connection = new SqliteConnection($"Data Source={databasePath}");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar());
    }

    public static void Cleanup(string databasePath)
    {
        SqliteConnection.ClearAllPools();
        if (File.Exists(databasePath))
        {
            File.Delete(databasePath);
        }
    }
}
