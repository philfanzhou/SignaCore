using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using ServiceMantle;
using ServiceMantle.Bootstrap;
using SignaCore.Database;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;
using SignaCore.Host.Startup;
using Xunit;
using static SignaCore.Tests.Host.Migration.SqliteMigrationGateTestSupport;

namespace SignaCore.Tests.Host.Migration;

/// <summary>
/// The retirement boundary of the legacy <c>system_settings</c> table on SQLite: a database that
/// still holds unmigrated legacy rows is refused by both the startup pre-check and the
/// in-migration guard (and every legacy row survives each refusal), while a fresh database drops
/// the empty table as part of the initial chain and stays on the pending-setup path.
/// </summary>
public sealed class SqliteSystemSettingsRetirementTests
{
    private const string LastPreRetirementMigration = "20260918054621_AddLogoutRequests";
    private const string RetirementMigration = "20260921130547_RetireSystemSettings";

    private const string LegacySentinelSecret = "legacy-envelope-sentinel-not-an-envelope";

    /// <summary>
    /// Stages a pre-retirement database holding the fixed historical schema with raw legacy rows —
    /// one public and one secret — exactly like a deployment that never ran a bridge build.
    /// </summary>
    private static async Task<string> StageUnmigratedLegacyDatabaseAsync()
    {
        var databasePath = NewDatabasePath();
        var options = TestDatabaseOptions(databasePath);
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(options);
        await using (var db = new IdentityDbContext(optionsBuilder.Options))
        {
            var migrator = db.Database.GetService<IMigrator>();
            await migrator.MigrateAsync(LastPreRetirementMigration, TestContext.Current.CancellationToken);
        }

        ExecuteSql(
            databasePath,
            $"""
            INSERT INTO system_settings (key, value, value_type, is_secret, version, updated_at, updated_by)
            VALUES
                ('Jwt:Issuer', 'https://legacy.example.test', 'String', 0, 1, 0, 'legacy-admin'),
                ('Sms:OtpHmacKey', '{LegacySentinelSecret}', 'String', 1, 1, 0, 'legacy-admin')
            """);
        return databasePath;
    }

    private static void AssertLegacyRowsSurvive(string databasePath)
    {
        // The refusal path must preserve the unmigrated source byte-for-byte: dropping first and
        // checking afterwards would leave zero rows here and fail this assertion.
        Assert.True(TableExists(databasePath, "system_settings"));
        Assert.Equal(
            2,
            Scalar(databasePath, "SELECT COUNT(*) FROM system_settings"));
        Assert.Equal(
            1,
            Scalar(
                databasePath,
                $"SELECT COUNT(*) FROM system_settings WHERE key = 'Sms:OtpHmacKey' AND value = '{LegacySentinelSecret}'"));
        // No aggregate was created by the refusal.
        Assert.Equal(0, Scalar(databasePath, "SELECT COUNT(*) FROM service_settings"));
    }

    [Fact]
    public async Task UnmigratedLegacyRows_AreRefusedByTheStartupPreCheckAndSurvive()
    {
        var databasePath = await StageUnmigratedLegacyDatabaseAsync();
        try
        {
            var exception = await Assert.ThrowsAsync<SettingsSnapshotException>(
                () => InstallationStartup.RunAsync(
                    NewBootstrap(TestDatabaseOptions(databasePath)),
                    EmptyConfiguration(),
                    StubEnvironment(),
                    NullLoggerFactory.Instance));

            Assert.Contains("bridge build", exception.Message, StringComparison.Ordinal);
            Assert.Contains(
                "docs/database/system-settings-retirement.md",
                exception.Message,
                StringComparison.Ordinal);
            Assert.Empty(exception.Keys);

            // The refusal is deterministic: a retry refuses again without touching the source.
            await Assert.ThrowsAsync<SettingsSnapshotException>(
                () => InstallationStartup.RunAsync(
                    NewBootstrap(TestDatabaseOptions(databasePath)),
                    EmptyConfiguration(),
                    StubEnvironment(),
                    NullLoggerFactory.Instance));

            AssertLegacyRowsSurvive(databasePath);
            Assert.DoesNotContain(
                RetirementMigration,
                string.Join('|', ListHistoryRows(databasePath)),
                StringComparison.Ordinal);
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    /// <summary>
    /// The authoritative guard lives inside the migration: even when the startup pre-check is
    /// bypassed (an operator running the migrations directly), the in-transaction guard refuses
    /// before the drop, the refusal carries the fixed constraint name, and the whole migration
    /// rolls back leaving no half-completed drop.
    /// </summary>
    [Fact]
    public async Task UnmigratedLegacyRows_AreRefusedByTheInMigrationGuardAndSurvive()
    {
        var databasePath = await StageUnmigratedLegacyDatabaseAsync();
        try
        {
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(TestDatabaseOptions(databasePath));
            await using var db = new IdentityDbContext(optionsBuilder.Options);

            var exception = await Assert.ThrowsAsync<SqliteException>(
                () => db.Database.MigrateAsync(TestContext.Current.CancellationToken));

            Assert.Contains(
                "system_settings_retirement_guard",
                exception.Message,
                StringComparison.Ordinal);
            AssertLegacyRowsSurvive(databasePath);
            Assert.DoesNotContain(
                RetirementMigration,
                string.Join('|', ListHistoryRows(databasePath)),
                StringComparison.Ordinal);
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    /// <summary>
    /// A bridge-completed database (shared aggregate present, legacy rows still on disk) upgrades
    /// through the drop: the guard observes the aggregate and lets the drop proceed, the aggregate
    /// stays byte-identical, and the retired table is gone.
    /// </summary>
    [Fact]
    public async Task BridgedDatabase_DropsTheLegacyTableAndKeepsTheAggregate()
    {
        var databasePath = await StageUnmigratedLegacyDatabaseAsync();
        try
        {
            // The bridge build's outcome: the shared aggregate exists with the migrated values. A
            // real sensitive envelope (not a sentinel) proves the drop decision reads the
            // aggregate's existence only and the legacy rows are irrelevant to it.
            var rootSecret = "root-secret-for-tests-only";
            var envelope = new ServiceMantle.Configuration.SensitiveValueProtector(
                    SignaCore.Host.Installation.InstallationStores.ServiceId,
                    "sms.otp_hmac_key")
                .Protect(
                    "legacy-plaintext-hmac-key",
                    Convert.ToBase64String(
                        new SignaCore.Domain.Keys.BootstrapMasterKeyProvider(rootSecret).GetMasterKey()));
            var valuesJson = "{\"sms.otp_hmac_key\":\"" + envelope.Replace("'", "''") + "\"}";
            ExecuteSql(
                databasePath,
                $"""
                INSERT INTO service_settings (service_id, values_json, version, updated_at_utc, updated_by, restart_required)
                VALUES ('signacore', '{valuesJson}', 1, '2026-09-21 00:00:00', 'settings-migration', 0)
                """);

            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(TestDatabaseOptions(databasePath));
            await using (var db = new IdentityDbContext(optionsBuilder.Options))
            {
                await db.Database.MigrateAsync(TestContext.Current.CancellationToken);
            }

            Assert.False(TableExists(databasePath, "system_settings"));
            var persistedJson = ScalarText(
                databasePath,
                "SELECT values_json FROM service_settings WHERE service_id = 'signacore'");
            Assert.NotNull(persistedJson);
            Assert.Contains(envelope, persistedJson, StringComparison.Ordinal);
            Assert.Equal(
                1,
                Scalar(databasePath, "SELECT version FROM service_settings WHERE service_id = 'signacore'"));
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    /// <summary>
    /// Caller cancellation keeps its original token and leaves the guarded drop entirely
    /// unattempted: the unmigrated source is a restart-safe retry, never a half-completed drop.
    /// </summary>
    [Fact]
    public async Task CancelledBeforeMigration_PropagatesTheOriginalTokenAndWritesNothing()
    {
        var databasePath = await StageUnmigratedLegacyDatabaseAsync();
        try
        {
            using var cancellation = new CancellationTokenSource();
            await cancellation.CancelAsync();

            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(TestDatabaseOptions(databasePath));
            await using var db = new IdentityDbContext(optionsBuilder.Options);

            var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => db.Database.MigrateAsync(cancellation.Token));
            Assert.Equal(cancellation.Token, exception.CancellationToken);

            AssertLegacyRowsSurvive(databasePath);
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task FreshDatabase_DropsTheEmptyLegacyTableDuringTheInitialChain()
    {
        var databasePath = NewDatabasePath();
        try
        {
            var result = await InstallationStartup.RunAsync(
                NewBootstrap(TestDatabaseOptions(databasePath)),
                EmptyConfiguration(),
                StubEnvironment(),
                NullLoggerFactory.Instance);

            // The pending/code path is unchanged: the empty legacy table is dropped inside the
            // initial chain without creating any administrator.
            Assert.Equal(InstallationPhase.PendingSetup, result.Phase);
            Assert.False(TableExists(databasePath, "system_settings"));
            Assert.Equal(1, Scalar(databasePath, "SELECT COUNT(*) FROM service_installations"));
            Assert.Equal(0, Scalar(databasePath, "SELECT COUNT(*) FROM accounts"));
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    private static BootstrapConfiguration NewBootstrap(DatabaseOptions options) => new(
        ServiceId.Parse("signacore"),
        new BootstrapDatabaseConfiguration(options.Provider, options.ServerVersion, options.ConnectionString),
        "root-secret-for-tests-only");

    private static IConfiguration EmptyConfiguration() =>
        new ConfigurationBuilder().AddInMemoryCollection().Build();

    private static IHostEnvironment StubEnvironment() => new TestHostEnvironment();

    private static string? ScalarText(string databasePath, string sql)
    {
        using var connection = new SqliteConnection($"Data Source={databasePath}");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar() as string;
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string ApplicationName { get; set; } = "SignaCore.Tests";
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ContentRootPath { get; set; } = Directory.GetCurrentDirectory();
        public IFileProvider ContentRootFileProvider { get; set; } =
            new NullFileProvider();
    }
}
