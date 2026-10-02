using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SignaCore.Database;
using SignaCore.Host.Migration;
using ServiceMantle;
using ServiceMantle.Bootstrap;
using ServiceMantle.Database.Sqlite;
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
    public async Task Execute_RunsTheFullSignaCoreMigrationWorkflow_AndLeavesBorrowedContextUsable()
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
    public async Task SharedCapability_EquivalentAbsoluteTargetsHavePrivateStableIdentityWithoutCreatingFiles()
    {
        var provider = new SqliteDatabaseTargetPreparationProvider();
        Assert.Equal(DatabaseDeploymentSupport.SingleInstanceOnly, provider.Capability.Support);

        var file = NewDatabasePath();
        var absolute = $"Data Source={file}";
        var target = new BootstrapDatabaseConfiguration(WellKnownDatabaseProviderIds.Sqlite, null, absolute);
        var identity = await provider.GetCanonicalTargetIdentityAsync(target, TestContext.Current.CancellationToken);

        foreach (var equivalent in new[]
        {
            absolute,
            $"DataSource={file};Default Timeout=30",
            $"data source={file};Pooling=False"
        })
        {
            Assert.Equal(identity, await provider.GetCanonicalTargetIdentityAsync(
                new BootstrapDatabaseConfiguration(WellKnownDatabaseProviderIds.Sqlite, null, equivalent),
                TestContext.Current.CancellationToken));
        }

        Assert.Matches("^sqlite-file-sha256:[0-9A-F]{64}$", identity);
        Assert.DoesNotContain(file, identity);
        Assert.DoesNotContain(Path.GetFileName(file), identity);
        Assert.Equal(absolute, target.ConnectionString);
        Assert.False(File.Exists(file));

        var otherFile = NewDatabasePath();
        Assert.NotEqual(identity, await provider.GetCanonicalTargetIdentityAsync(
            new BootstrapDatabaseConfiguration(WellKnownDatabaseProviderIds.Sqlite, null, $"Data Source={otherFile}"),
            TestContext.Current.CancellationToken));
        Assert.False(File.Exists(otherFile));
    }

    [Fact]
    public async Task SharedCapability_PreCancelledIdentityResolutionPreservesOriginalTokenWithoutCreatingFile()
    {
        var file = NewDatabasePath();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var provider = new SqliteDatabaseTargetPreparationProvider();
        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await provider.GetCanonicalTargetIdentityAsync(
                new BootstrapDatabaseConfiguration(WellKnownDatabaseProviderIds.Sqlite, null, $"Data Source={file}"),
                cts.Token));
        Assert.Equal(cts.Token, exception.CancellationToken);
        Assert.False(File.Exists(file));
    }

    [Theory]
    [InlineData("relative")]
    [InlineData("uri")]
    [InlineData("shared-cache")]
    [InlineData("read-only")]
    [InlineData("memory")]
    public async Task SharedCapability_UnsupportedInputIsRejectedWithoutCreatingFile(string kind)
    {
        var file = NewDatabasePath();
        var connectionString = kind switch
        {
            "relative" => $"Data Source={Path.GetRelativePath(Environment.CurrentDirectory, file)}",
            "uri" => $"Data Source=file:{file}",
            "shared-cache" => $"Data Source={file};Cache=Shared",
            "read-only" => $"Data Source={file};Mode=ReadOnly",
            _ => $"Data Source={file};Mode=Memory"
        };
        var provider = new SqliteDatabaseTargetPreparationProvider();
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await provider.GetCanonicalTargetIdentityAsync(
                new BootstrapDatabaseConfiguration(WellKnownDatabaseProviderIds.Sqlite, null, connectionString),
                TestContext.Current.CancellationToken));
        Assert.DoesNotContain(file, exception.Message);
        Assert.DoesNotContain(connectionString, exception.Message);
        Assert.False(File.Exists(file));
    }

    [Fact]
    public async Task SharedCapability_MultiInstanceFailsClosedWithoutCallingExecutorOrCreatingFile()
    {
        var file = NewDatabasePath();
        var executor = new DelegateMigrationExecutor();
        var orchestrator = new DatabaseMigrationOrchestrator(
            executor,
            new DatabaseMigrationLockProviderRegistry(providers: null, DatabaseProviderIdResolver.Empty),
            new DatabaseDeploymentCapabilityRegistry(
                [new SqliteDatabaseTargetPreparationProvider()], DatabaseProviderIdResolver.Empty));
        var result = await orchestrator.OrchestrateMigrationAsync(
            ServiceId.Parse("signacore"),
            new BootstrapDatabaseConfiguration(WellKnownDatabaseProviderIds.Sqlite, null, $"Data Source={file}"),
            DatabaseDeploymentMode.MultiInstance,
            StartupMigrationGate.SharedLockWaitBudget,
            TestContext.Current.CancellationToken);

        Assert.False(result.Succeeded);
        Assert.Equal(WellKnownMigrationErrorCodes.LockNotSupported, result.ErrorCode);
        Assert.Equal(0, executor.InspectCount);
        Assert.Equal(0, executor.ExecuteCount);
        Assert.False(File.Exists(file));
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
    /// <summary>
    /// The shared SQLite target preparation contract rejects symlinked path components, and macOS
    /// exposes the per-user temp directory under <c>/var</c>, a symlink to <c>/private/var</c>:
    /// tests that run the real startup preparation need the physical location so they exercise the
    /// contract instead of the platform's symlink.
    /// </summary>
    public static string PhysicalTempPath()
    {
        var temp = Path.GetTempPath();
        if (temp.StartsWith("/var/", StringComparison.Ordinal) && Directory.Exists("/private" + temp))
        {
            return "/private" + temp;
        }

        return temp;
    }

    public static string NewDatabasePath() =>
        Path.Combine(PhysicalTempPath(), $"signacore-gate-{Guid.NewGuid():N}.db");

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
