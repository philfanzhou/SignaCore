using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using ServiceMantle;
using ServiceMantle.Bootstrap;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;
using SignaCore.Host.Startup;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The system_settings retirement matrix on real provider databases: a database holding unmigrated
/// legacy rows is refused by the in-migration guard (and every row survives), a bridge-completed
/// database drops through with the aggregate intact and activates, a fresh database applies the
/// guarded drop inside the initial chain, a wrong root key fails startup closed, and an empty
/// legacy table with business data takes the protected import. The PostgreSQL variants run only
/// under <c>RUN_SIGNACORE_DATABASE_CONTRACTS=true</c>, matching the CI matrix.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class SystemSettingsRetirementTests
{
    private const string SqliteLastPreRetirement = "20260918054621_AddLogoutRequests";
    private const string PostgreSqlLastPreRetirement = "20260918054611_AddLogoutRequests";
    private const string LegacySentinelSecret = "retirement-matrix-legacy-envelope-sentinel";
    private const string RootSecret = "retirement-matrix-root-secret";

    /// <summary>Valid base64 of 32 zero bytes: the SMS binder rejects anything else.</summary>
    private const string BridgePlaintextHmacKey = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=";

    private static DbContextOptions<IdentityDbContext> CreateSqliteOptions(string path)
    {
        var builder = new DbContextOptionsBuilder<IdentityDbContext>();
        builder.UseIdentityDatabase(new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = new SqliteConnectionStringBuilder { DataSource = path }.ConnectionString
        });
        return builder.Options;
    }

    private static string NewSqlitePath() =>
        Path.Combine(Path.GetTempPath(), $"signacore-retirement-{Guid.NewGuid():N}.db");

    /// <summary>
    /// Two raw legacy rows — one public, one secret sentinel — staged on the fixed historical
    /// schema, exactly like a deployment that never ran a bridge build. No legacy value is a real
    /// secret: the guard must decide on existence only.
    /// </summary>
    private static async Task StageLegacyRowsAsync(
        IdentityDbContext context,
        string lastPreRetirementMigration)
    {
        var migrator = context.Database.GetService<IMigrator>();
        await migrator.MigrateAsync(lastPreRetirementMigration, TestContext.Current.CancellationToken);
        await context.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO system_settings (key, value, value_type, is_secret, version, updated_at, updated_by)
            VALUES
                ('Jwt:Issuer', 'https://legacy.example.test', 'String', false, 1, {DateTime.UtcNow}, 'legacy-admin'),
                ('Sms:OtpHmacKey', {LegacySentinelSecret}, 'String', true, 1, {DateTime.UtcNow}, 'legacy-admin')
            """,
            TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
    }

    /// <summary>
    /// Stages the bridge build's outcome: a completed installation, the shared aggregate with one
    /// real sensitive envelope, and the legacy rows still on disk.
    /// </summary>
    private static async Task StageBridgedStateAsync(
        IdentityDbContext context,
        string rootSecret)
    {
        context.ServiceInstallations.Add(new ServiceInstallationEntity
        {
            ServiceId = InstallationStores.ServiceIdValue,
            Status = ServiceMantle.Installation.InstallationStatus.Completed,
            CreatedAtUtc = DateTime.UtcNow,
            CompletedAtUtc = DateTime.UtcNow,
            Version = 1
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);

        var rootKey = Convert.ToBase64String(new BootstrapMasterKeyProvider(rootSecret).GetMasterKey());
        var envelope = new ServiceMantle.Configuration.SensitiveValueProtector(
                InstallationStores.ServiceId,
                "sms.otp_hmac_key")
            .Protect(BridgePlaintextHmacKey, rootKey);
        // The complete loadable corpus the fixture-equivalent aggregate needs: the two
        // setup-collected keys, the required non-blank administrator, the explicit plain-HTTP
        // opt-in, and the sensitive envelope.
        var valuesJson =
            "{\"endpoints.public_base_url\":\"http://localhost\"," +
            "\"jwt.issuer\":\"http://localhost\"," +
            "\"security.allow_non_https_issuer\":\"true\"," +
            "\"admin.username\":\"retirement-admin\"," +
            "\"sms.otp_hmac_key\":\"" + envelope + "\"}";
        await context.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO service_settings (service_id, values_json, version, updated_at_utc, updated_by, restart_required)
            VALUES ({InstallationStores.ServiceIdValue}, {valuesJson}, 1, {DateTime.UtcNow}, 'settings-migration', false)
            """,
            TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
    }

    private static async Task<long> CountLegacyRowsAsync(IdentityDbContext context)
    {
        var count = await context.Database.SqlQuery<long>($"""
            SELECT COUNT(*) AS "Value" FROM system_settings
            """).ToListAsync(TestContext.Current.CancellationToken);
        return count.Single();
    }

    private static async Task<long> CountSentinelRowAsync(IdentityDbContext context)
    {
        var count = await context.Database.SqlQuery<long>($"""
            SELECT COUNT(*) AS "Value" FROM system_settings
            WHERE key = 'Sms:OtpHmacKey' AND value = {LegacySentinelSecret}
            """).ToListAsync(TestContext.Current.CancellationToken);
        return count.Single();
    }

    private static async Task<long> CountAggregateAsync(IdentityDbContext context)
    {
        var count = await context.Database.SqlQuery<long>($"""
            SELECT COUNT(*) AS "Value" FROM service_settings
            WHERE service_id = {InstallationStores.ServiceIdValue}
            """).ToListAsync(TestContext.Current.CancellationToken);
        return count.Single();
    }

    private static async Task<long> CountSqliteTableAsync(IdentityDbContext context, string table)
    {
        var count = await context.Database.SqlQuery<long>($"""
            SELECT COUNT(*) AS "Value" FROM sqlite_master
            WHERE type = 'table' AND name = {table}
            """).ToListAsync(TestContext.Current.CancellationToken);
        return count.Single();
    }

    private static async Task<long> CountPostgreSqlTableAsync(IdentityDbContext context, string table)
    {
        var count = await context.Database.SqlQuery<long>($"""
            SELECT COUNT(*) AS "Value" FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = {table} AND n.nspname = current_schema()
            """).ToListAsync(TestContext.Current.CancellationToken);
        return count.Single();
    }

    private static IConfiguration EmptyConfiguration() =>
        new ConfigurationBuilder().AddInMemoryCollection().Build();

    // ---- SQLite matrix ----

    [Fact]
    public async Task Sqlite_UnmigratedLegacyRows_RefuseTheDropAndKeepEveryRow()
    {
        var path = NewSqlitePath();
        try
        {
            await using (var context = new IdentityDbContext(CreateSqliteOptions(path)))
            {
                await StageLegacyRowsAsync(context, SqliteLastPreRetirement);

                var exception = await Assert.ThrowsAsync<SqliteException>(
                    () => context.Database.MigrateAsync(TestContext.Current.CancellationToken));
                Assert.Contains(
                    "system_settings_retirement_guard",
                    exception.Message,
                    StringComparison.Ordinal);

                // Drop-before-check would leave zero rows; the rollback keeps the source whole.
                Assert.Equal(2, await CountLegacyRowsAsync(context));
                Assert.Equal(1, await CountSentinelRowAsync(context));
                Assert.Equal(0, await CountAggregateAsync(context));
            }

            // A retry against the same refused source refuses again — deterministic, never a
            // half-completed drop.
            TestSqlitePools.ClearAll();
            await using (var context = new IdentityDbContext(CreateSqliteOptions(path)))
            {
                await Assert.ThrowsAsync<SqliteException>(
                    () => context.Database.MigrateAsync(TestContext.Current.CancellationToken));
                Assert.Equal(2, await CountLegacyRowsAsync(context));
            }
        }
        finally
        {
            TestSqlitePools.ClearAll();
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public async Task Sqlite_BridgedDatabase_DropsTheTableKeepsTheAggregateAndActivates()
    {
        var path = NewSqlitePath();
        try
        {
            await using (var context = new IdentityDbContext(CreateSqliteOptions(path)))
            {
                await StageLegacyRowsAsync(context, SqliteLastPreRetirement);
                await StageBridgedStateAsync(context, RootSecret);

                await context.Database.MigrateAsync(TestContext.Current.CancellationToken);

                Assert.Equal(0, await CountSqliteTableAsync(context, "system_settings"));
                Assert.Equal(1, await CountAggregateAsync(context));
            }

            // The second instance boots against the dropped schema and activates normally without
            // ever touching the legacy table.
            TestSqlitePools.ClearAll();
            var bootstrap = new BootstrapConfiguration(
                ServiceId.Parse("signacore"),
                new BootstrapDatabaseConfiguration(
                    "SQLite",
                    null,
                    new SqliteConnectionStringBuilder { DataSource = path }.ConnectionString),
                RootSecret);
            var result = await InstallationStartup.RunAsync(
                bootstrap,
                EmptyConfiguration(),
                new Microsoft.Extensions.Hosting.Internal.HostingEnvironment
                {
                    ApplicationName = "SignaCore.Tests",
                    EnvironmentName = "Development"
                },
                NullLoggerFactory.Instance);
            Assert.Equal(InstallationPhase.Completed, result.Phase);
            Assert.Equal(1, result.RuntimeState.ConfigurationVersion);
            Assert.True(result.CurrentSnapshotAccessor.TryGetCurrent(out var activated));
            Assert.Equal(1, activated!.Version);
            Assert.Equal(
                BridgePlaintextHmacKey,
                activated.Values["sms.otp_hmac_key"].GetString());
        }
        finally
        {
            TestSqlitePools.ClearAll();
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public async Task Sqlite_FreshDatabase_AppliesTheGuardedDropInsideTheInitialChain()
    {
        var path = NewSqlitePath();
        try
        {
            await using var context = new IdentityDbContext(CreateSqliteOptions(path));
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);

            Assert.Equal(0, await CountSqliteTableAsync(context, "system_settings"));

            // The pending/code path is unchanged and no administrator is silently created.
            var resolution = await InstallationStateResolver.ResolveAsync(
                context, TestContext.Current.CancellationToken);
            Assert.Equal(InstallationPhase.PendingSetup, resolution.Phase);
            Assert.Equal(0, await context.Accounts.LongCountAsync(TestContext.Current.CancellationToken));
        }
        finally
        {
            TestSqlitePools.ClearAll();
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public async Task Sqlite_WrongRootKey_FailsStartupClosedAndTheRightKeyRecovers()
    {
        var path = NewSqlitePath();
        try
        {
            await using (var context = new IdentityDbContext(CreateSqliteOptions(path)))
            {
                await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
                await StageBridgedStateAsync(context, RootSecret);
            }

            // A wrong root key cannot read the sensitive envelope: startup fails closed before any
            // activation, with key names only and never the plaintext.
            TestSqlitePools.ClearAll();
            var bootstrap = new BootstrapConfiguration(
                ServiceId.Parse("signacore"),
                new BootstrapDatabaseConfiguration(
                    "SQLite",
                    null,
                    new SqliteConnectionStringBuilder { DataSource = path }.ConnectionString),
                "a-wrong-root-secret");
            var exception = await Assert.ThrowsAsync<SettingsSnapshotException>(
                () => InstallationStartup.RunAsync(
                    bootstrap,
                    EmptyConfiguration(),
                    new Microsoft.Extensions.Hosting.Internal.HostingEnvironment
                    {
                        ApplicationName = "SignaCore.Tests",
                        EnvironmentName = "Development"
                    },
                    NullLoggerFactory.Instance));
            Assert.Contains("sms.otp_hmac_key", exception.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(BridgePlaintextHmacKey, exception.Message, StringComparison.Ordinal);

            // The aggregate is untouched; a restart with the right key still activates.
            TestSqlitePools.ClearAll();
            bootstrap = new BootstrapConfiguration(
                ServiceId.Parse("signacore"),
                new BootstrapDatabaseConfiguration(
                    "SQLite",
                    null,
                    new SqliteConnectionStringBuilder { DataSource = path }.ConnectionString),
                RootSecret);
            var recovered = await InstallationStartup.RunAsync(
                bootstrap,
                EmptyConfiguration(),
                new Microsoft.Extensions.Hosting.Internal.HostingEnvironment
                {
                    ApplicationName = "SignaCore.Tests",
                    EnvironmentName = "Development"
                },
                NullLoggerFactory.Instance);
            Assert.Equal(InstallationPhase.Completed, recovered.Phase);
        }
        finally
        {
            TestSqlitePools.ClearAll();
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    // ---- PostgreSQL matrix (container-gated) ----

    [Fact]
    public async Task PostgreSql_UnmigratedLegacyRows_RefuseTheDropAndKeepEveryRow()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL retirement matrix.");

        await using var container = await StartPostgreSqlAsync();
        var options = PostgreSqlOptions(container);
        await using var context = new IdentityDbContext(options);
        await StageLegacyRowsAsync(context, PostgreSqlLastPreRetirement);

        var exception = await Assert.ThrowsAsync<PostgresException>(
            () => context.Database.MigrateAsync(TestContext.Current.CancellationToken));
        Assert.Contains(
            "refusing to drop system_settings",
            exception.MessageText,
            StringComparison.Ordinal);
        Assert.Contains("bridge build first", exception.MessageText, StringComparison.Ordinal);

        Assert.Equal(2, await CountLegacyRowsAsync(context));
        Assert.Equal(1, await CountSentinelRowAsync(context));
        Assert.Equal(0, await CountAggregateAsync(context));

        // The refusal is deterministic on retry.
        await Assert.ThrowsAsync<PostgresException>(
            () => context.Database.MigrateAsync(TestContext.Current.CancellationToken));
        Assert.Equal(2, await CountLegacyRowsAsync(context));

        // Caller cancellation before the migration keeps its original token and writes nothing —
        // the refused source stays a restart-safe retry.
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var cancelled = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => context.Database.MigrateAsync(cancellation.Token));
        Assert.Equal(cancellation.Token, cancelled.CancellationToken);
        Assert.Equal(2, await CountLegacyRowsAsync(context));
    }

    [Fact]
    public async Task PostgreSql_BridgedDatabase_DropsTheTableAndKeepsTheAggregate()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL retirement matrix.");

        await using var container = await StartPostgreSqlAsync();
        var options = PostgreSqlOptions(container);
        await using var context = new IdentityDbContext(options);
        await StageLegacyRowsAsync(context, PostgreSqlLastPreRetirement);
        await StageBridgedStateAsync(context, RootSecret);

        await context.Database.MigrateAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, await CountPostgreSqlTableAsync(context, "system_settings"));
        Assert.Equal(1, await CountAggregateAsync(context));
    }

    [Fact]
    public async Task PostgreSql_FreshDatabase_AppliesTheGuardedDropInsideTheInitialChain()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL retirement matrix.");

        await using var container = await StartPostgreSqlAsync();
        var options = PostgreSqlOptions(container);
        await using var context = new IdentityDbContext(options);
        await context.Database.MigrateAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, await CountPostgreSqlTableAsync(context, "system_settings"));

        var resolution = await InstallationStateResolver.ResolveAsync(
            context, TestContext.Current.CancellationToken);
        Assert.Equal(InstallationPhase.PendingSetup, resolution.Phase);
    }

    [Fact]
    public async Task PostgreSql_EmptyLegacyTableWithBusinessData_RunsTheProtectedImport()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL retirement matrix.");

        await using var container = await StartPostgreSqlAsync();
        var options = PostgreSqlOptions(container);
        await using (var context = new IdentityDbContext(options))
        {
            var migrator = context.Database.GetService<IMigrator>();
            await migrator.MigrateAsync(
                PostgreSqlLastPreRetirement, TestContext.Current.CancellationToken);
            context.Accounts.Add(new AccountEntity
            {
                Id = Guid.NewGuid(),
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            });
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
            context.ChangeTracker.Clear();
        }

        // The empty legacy table is dropped by the guard; the business data then takes the
        // protected import from the deployment configuration inside one transaction.
        var bootstrap = new BootstrapConfiguration(
            ServiceId.Parse("signacore"),
            new BootstrapDatabaseConfiguration("PostgreSQL", "15", container.GetConnectionString()),
            RootSecret);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                [SystemSettingKeys.PublicBaseUrl] = "https://identity.example.test",
                [SystemSettingKeys.JwtIssuer] = "https://identity.example.test",
                [SystemSettingKeys.AdminUsername] = "retirement-admin"
            }).Build();
        var result = await InstallationStartup.RunAsync(
            bootstrap,
            configuration,
            new Microsoft.Extensions.Hosting.Internal.HostingEnvironment
            {
                ApplicationName = "SignaCore.Tests",
                EnvironmentName = "Production"
            },
            NullLoggerFactory.Instance);

        Assert.Equal(InstallationPhase.Completed, result.Phase);
        Assert.Equal(1, result.RuntimeState.ConfigurationVersion);
        await using (var verification = new IdentityDbContext(options))
        {
            Assert.Equal(0, await CountPostgreSqlTableAsync(verification, "system_settings"));
            Assert.Equal(1, await CountAggregateAsync(verification));
            Assert.Equal(
                1,
                (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                        verification, TestContext.Current.CancellationToken))
                    .Count(log => log.Action == "installation.legacy_import.completed"));
        }
    }

    [Fact]
    public async Task PostgreSql_WrongRootKey_FailsStartupClosedAndTheRightKeyRecovers()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL retirement matrix.");

        await using var container = await StartPostgreSqlAsync();
        var options = PostgreSqlOptions(container);
        await using (var context = new IdentityDbContext(options))
        {
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
            await StageBridgedStateAsync(context, RootSecret);
        }

        // A wrong root key cannot read the sensitive envelope: startup fails closed before any
        // activation, with key names only and never the plaintext.
        var wrongKey = new BootstrapConfiguration(
            ServiceId.Parse("signacore"),
            new BootstrapDatabaseConfiguration("PostgreSQL", "15", container.GetConnectionString()),
            "a-wrong-root-secret");
        var exception = await Assert.ThrowsAsync<SettingsSnapshotException>(
            () => InstallationStartup.RunAsync(
                wrongKey,
                EmptyConfiguration(),
                TestEnvironment(),
                NullLoggerFactory.Instance));
        Assert.Contains("sms.otp_hmac_key", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(BridgePlaintextHmacKey, exception.Message, StringComparison.Ordinal);

        // The aggregate is untouched; a restart with the right key still activates.
        var bootstrap = new BootstrapConfiguration(
            ServiceId.Parse("signacore"),
            new BootstrapDatabaseConfiguration("PostgreSQL", "15", container.GetConnectionString()),
            RootSecret);
        var recovered = await InstallationStartup.RunAsync(
            bootstrap,
            EmptyConfiguration(),
            TestEnvironment(),
            NullLoggerFactory.Instance);
        Assert.Equal(InstallationPhase.Completed, recovered.Phase);
    }

    private static Microsoft.Extensions.Hosting.IHostEnvironment TestEnvironment() =>
        new Microsoft.Extensions.Hosting.Internal.HostingEnvironment
        {
            ApplicationName = "SignaCore.Tests",
            EnvironmentName = "Development"
        };

    private static async Task<PostgreSqlContainer> StartPostgreSqlAsync()
    {
        var image = Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } custom
            ? custom
            : "postgres:15-alpine";
        var container = new PostgreSqlBuilder(image)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();
        await container.StartAsync(TestContext.Current.CancellationToken);
        return container;
    }

    private static DbContextOptions<IdentityDbContext> PostgreSqlOptions(PostgreSqlContainer container)
    {
        var builder = new DbContextOptionsBuilder<IdentityDbContext>();
        builder.UseIdentityDatabase(new DatabaseOptions
        {
            Provider = "PostgreSQL",
            ServerVersion = "15",
            ConnectionString = container.GetConnectionString()
        });
        return builder.Options;
    }

    private static bool ShouldRunContainerMatrix() =>
        string.Equals(
            Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS"),
            "true",
            StringComparison.OrdinalIgnoreCase);
}
