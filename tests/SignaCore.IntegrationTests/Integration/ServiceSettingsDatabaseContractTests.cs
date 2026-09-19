using System.Text.Json;
using DotNet.Testcontainers.Containers;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle;
using ServiceMantle.Audit;
using ServiceMantle.Configuration;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
using SignaCore.Host;
using Microsoft.EntityFrameworkCore.Infrastructure;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;
using SignaCore.Host.Startup;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Database contracts of the shared ServiceMantle setting stack: the transactional update with
/// per-key audits, the closed failure results, version conflicts, caller cancellation, the
/// encrypted-at-rest boundary, and the upgrade of an existing database. The PostgreSQL concurrency
/// race runs only under <c>RUN_SIGNACORE_DATABASE_CONTRACTS=true</c>, matching the CI matrix.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class ServiceSettingsDatabaseContractTests
{
    private static readonly ServiceId Service = InstallationStores.ServiceId;

    private static readonly byte[] RootKey = System.Text.Encoding.UTF8.GetBytes(
        "signacore-shared-settings-contract-root-key");

    private static readonly ManagementAuditOperator Operator = ManagementAuditOperator.Create(
        WellKnownManagementAuditOperatorSources.InteractiveAdmin,
        "admin-00000000-0000-0000-0000-000000000000");

    private static ServiceSettingDefinitionRegistry CreateRegistry() => new(
        [new ServiceSettingDefinitions()],
        [new SignaCoreSettingCompositeValidator(isDevelopment: false)]);

    /// <summary>
    /// The smallest valid seed: the two setup-collected keys are required without defaults, the
    /// composite validator rejects a blank administrator username, and the SMS binder requires a
    /// usable HMAC key — so the first update of the empty aggregate must carry all of them.
    /// </summary>
    private static Dictionary<string, string?> SeedChanges() => new()
    {
        ["endpoints.public_base_url"] = "https://accounts.example.com",
        ["jwt.issuer"] = "https://accounts.example.com",
        ["admin.username"] = "contract-admin",
        // Valid base64 of 32 bytes; also the plaintext canary for the storage assertions.
        ["sms.otp_hmac_key"] = ValidHmacKey
    };

    private const string ValidHmacKey = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="; // 32 bytes of 0x00

    private static DbContextOptions<IdentityDbContext> CreateSqliteOptions(string path)
    {
        var databaseOptions = new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = new SqliteConnectionStringBuilder { DataSource = path }.ConnectionString
        };
        var builder = new DbContextOptionsBuilder<IdentityDbContext>();
        builder.UseIdentityDatabase(databaseOptions);
        return builder.Options;
    }

    private static async Task<DbContextOptions<IdentityDbContext>> CreateMigratedSqliteAsync()
    {
        var path = Path.Combine(Path.GetTempPath(), $"signacore-shared-settings-{Guid.NewGuid():N}.db");
        var options = CreateSqliteOptions(path);
        await using var context = new IdentityDbContext(options);
        await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
        return options;
    }

    private static async Task<ServiceSettingUpdateResult> UpdateAsync(
        DbContextOptions<IdentityDbContext> options,
        long expectedVersion,
        Dictionary<string, string?> changes,
        IServiceSettingRootKeySource? rootKeySource = null,
        IServiceSettingUpdateTransaction? transactionOverride = null,
        CancellationToken cancellationToken = default)
    {
        await using var context = new IdentityDbContext(options);
        await using var transaction = await context.Database.BeginTransactionAsync(cancellationToken);
        var result = await UpdateInTransactionAsync(
            context,
            transaction,
            expectedVersion,
            changes,
            rootKeySource,
            transactionOverride,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    private static async Task<ServiceSettingUpdateResult> UpdateInTransactionAsync(
        IdentityDbContext context,
        Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction transaction,
        long expectedVersion,
        Dictionary<string, string?> changes,
        IServiceSettingRootKeySource? rootKeySource = null,
        IServiceSettingUpdateTransaction? transactionOverride = null,
        CancellationToken cancellationToken = default)
    {
        var updateTransaction = transactionOverride ??
            new EfCoreServiceSettingUpdateTransaction<IdentityDbContext>(context);
        var service = new ServiceSettingUpdateService(
            Service,
            CreateRegistry(),
            updateTransaction,
            rootKeySource ?? new MasterKeyRootKeySource(new FixedMasterKey(RootKey)));
        var result = await service.UpdateAsync(
            new ServiceSettingUpdateCommand(expectedVersion, changes, Operator),
            cancellationToken);
        Assert.Equal(transaction.TransactionId, context.Database.CurrentTransaction!.TransactionId);
        return result;
    }

    // ---- A4: transactional update ----

    [Fact]
    public async Task AppliedUpdate_IncrementsVersionPersistsEnvelopeAndWritesKeyAudits()
    {
        var options = await CreateMigratedSqliteAsync();

        var result = await UpdateAsync(options, expectedVersion: 0, changes: SeedChanges());

        Assert.Equal(ServiceSettingUpdateStatus.Applied, result.Status);
        Assert.Equal(1, result.Version);

        await using var verify = new IdentityDbContext(options);
        var row = await verify.Database.SqlQuery<string>($"""
                SELECT values_json AS "Value" FROM service_settings WHERE service_id = 'signacore'
                """).SingleAsync(TestContext.Current.CancellationToken);
        using var document = JsonDocument.Parse(row);
        Assert.Equal("https://accounts.example.com", document.RootElement
            .GetProperty("endpoints.public_base_url").GetString());
        // The sensitive change is stored as the sealed envelope, never as plaintext.
        var protectedValue = document.RootElement.GetProperty("sms.otp_hmac_key").GetString();
        Assert.StartsWith("sm:v1:", protectedValue, StringComparison.Ordinal);
        Assert.DoesNotContain(ValidHmacKey, row, StringComparison.Ordinal);

        var audits = await verify.Database.SqlQuery<string>($"""
                SELECT action || '|' || target_type || '|' || target_id || '|' || operator_source
                    || '|' || metadata_json AS Value
                FROM service_audit_logs ORDER BY occurred_at_utc, id
                """).ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(4, audits.Count);
        Assert.All(audits, audit =>
        {
            Assert.StartsWith(
                "configuration.changed|configuration|signacore|interactive_admin",
                audit,
                StringComparison.Ordinal);
            Assert.DoesNotContain(ValidHmacKey, audit, StringComparison.Ordinal);
        });
        Assert.Contains(audits, audit => audit.Contains("\"key\":\"sms.otp_hmac_key\"", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SecondUpdate_IncludesPersistedValuesAndKeepsProtectedSensitiveValue()
    {
        var options = await CreateMigratedSqliteAsync();
        await UpdateAsync(options, 0, SeedChanges());

        var result = await UpdateAsync(options, 1, new Dictionary<string, string?>
        {
            ["jwt.token_expiration_hours"] = "4"
        });

        Assert.Equal(ServiceSettingUpdateStatus.Applied, result.Status);
        Assert.Equal(2, result.Version);

        await using var verify = new IdentityDbContext(options);
        var row = await verify.Database.SqlQuery<string>($"""
                SELECT values_json AS "Value" FROM service_settings WHERE service_id = 'signacore'
                """).SingleAsync(TestContext.Current.CancellationToken);
        Assert.Contains("\"jwt.token_expiration_hours\":\"4\"", row, StringComparison.Ordinal);
        // The untouched sensitive value survives re-protection.
        Assert.Contains("sm:v1:", row, StringComparison.Ordinal);
    }

    // ---- A4: failure matrix ----

    [Fact]
    public async Task ValidationFailure_LeavesZeroChangesAndZeroAudits()
    {
        var options = await CreateMigratedSqliteAsync();
        var changes = SeedChanges();
        changes["jwt.token_expiration_hours"] = "2.5";

        var result = await UpdateAsync(options, 0, changes);

        Assert.Equal(ServiceSettingUpdateStatus.ValidationFailed, result.Status);
        await AssertZeroChangesAndZeroAuditsAsync(options);
    }

    [Fact]
    public async Task CompositeFailure_LeavesZeroChangesAndZeroAudits()
    {
        var options = await CreateMigratedSqliteAsync();
        var changes = SeedChanges();
        changes["jwt.issuer"] = "https://other.example.com";

        var result = await UpdateAsync(options, 0, changes);

        Assert.Equal(ServiceSettingUpdateStatus.ValidationFailed, result.Status);
        await AssertZeroChangesAndZeroAuditsAsync(options);
    }

    [Fact]
    public async Task MissingRootKey_IsAProtectionFailureWithZeroChanges()
    {
        var options = await CreateMigratedSqliteAsync();

        var result = await UpdateAsync(
            options,
            0,
            SeedChanges(),
            rootKeySource: new ThrowingRootKeySource());

        Assert.Equal(ServiceSettingUpdateStatus.ProtectionFailed, result.Status);
        await AssertZeroChangesAndZeroAuditsAsync(options);
    }

    [Fact]
    public async Task MissingTable_IsAStorageFailure()
    {
        var options = await CreateMigratedSqliteAsync();
        await using (var context = new IdentityDbContext(options))
        {
            await context.Database.ExecuteSqlRawAsync(
                "DROP TABLE service_settings", TestContext.Current.CancellationToken);
        }

        var result = await UpdateAsync(options, 0, SeedChanges());

        Assert.Equal(ServiceSettingUpdateStatus.StorageFailed, result.Status);
    }

    [Fact]
    public async Task UpdateWithoutATransaction_IsRejectedAsTransactionRequired()
    {
        var options = await CreateMigratedSqliteAsync();
        await using var context = new IdentityDbContext(options);
        var service = new ServiceSettingUpdateService(
            Service,
            CreateRegistry(),
            new EfCoreServiceSettingUpdateTransaction<IdentityDbContext>(context),
            new MasterKeyRootKeySource(new FixedMasterKey(RootKey)));

        var result = await service.UpdateAsync(
            new ServiceSettingUpdateCommand(0, SeedChanges(), Operator),
            TestContext.Current.CancellationToken);

        Assert.Equal(ServiceSettingUpdateStatus.TransactionRequired, result.Status);
        await AssertZeroChangesAndZeroAuditsAsync(options);
    }

    [Fact]
    public async Task DirtyContext_IsRejectedAsContextNotClean()
    {
        var options = await CreateMigratedSqliteAsync();
        await using var context = new IdentityDbContext(options);
        await using var transaction = await context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken);
        context.Accounts.Add(new AccountEntity { Id = Guid.NewGuid(), IsActive = true });

        var result = await UpdateInTransactionAsync(
            context, transaction, 0, SeedChanges(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(ServiceSettingUpdateStatus.ContextNotClean, result.Status);
        await transaction.RollbackAsync(TestContext.Current.CancellationToken);
        await AssertZeroChangesAndZeroAuditsAsync(options);
    }

    private static async Task AssertZeroChangesAndZeroAuditsAsync(DbContextOptions<IdentityDbContext> options)
    {
        await using var verify = new IdentityDbContext(options);
        var settings = await verify.Database.SqlQuery<int>(
                $"""SELECT COUNT(*) AS "Value" FROM service_settings""")
            .ToListAsync(TestContext.Current.CancellationToken);
        var audits = await verify.Database.SqlQuery<int>(
                $"""SELECT COUNT(*) AS "Value" FROM service_audit_logs""")
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, settings.Single());
        Assert.Equal(0, audits.Single());
    }

    // ---- A5: version conflicts ----

    [Fact]
    public async Task StaleExpectedVersion_IsAConflictAndARetrySucceeds()
    {
        var options = await CreateMigratedSqliteAsync();
        await UpdateAsync(options, 0, SeedChanges());
        await UpdateAsync(options, 1, new Dictionary<string, string?> { ["jwt.audience"] = "retry-audience" });

        var result = await UpdateAsync(options, 1, new Dictionary<string, string?>
        {
            ["consul.host"] = "consul.example.com"
        });

        Assert.Equal(ServiceSettingUpdateStatus.VersionConflict, result.Status);

        var retried = await UpdateAsync(options, 2, new Dictionary<string, string?>
        {
            ["consul.host"] = "consul.example.com"
        });
        Assert.Equal(ServiceSettingUpdateStatus.Applied, retried.Status);
        Assert.Equal(3, retried.Version);
    }

    [Fact]
    public async Task PostgreSQLConcurrentUpdates_ProduceExactlyOneWinner()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL concurrency race.");

        var image = Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } custom
            ? custom
            : "postgres:15-alpine";
        await using var container = new PostgreSqlBuilder(image)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();
        await container.StartAsync(TestContext.Current.CancellationToken);

        var databaseOptions = new DatabaseOptions
        {
            Provider = "PostgreSQL",
            ServerVersion = "15",
            ConnectionString = container.GetConnectionString()
        };
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(databaseOptions);
        var options = optionsBuilder.Options;
        await using (var context = new IdentityDbContext(options))
        {
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
        }

        // Several independent scopes race for version 0; exactly one may apply, the rest must
        // observe a version conflict, and no update may be lost. Each competitor wraps its
        // transaction in the provider's execution strategy, exactly like the host's own
        // transactional paths (the Npgsql options enable retry-on-failure).
        const int competitors = 4;
        using var start = new SemaphoreSlim(0);
        using var allReady = new CountdownEvent(competitors);
        var results = new ServiceSettingUpdateResult[competitors];
        var tasks = Enumerable.Range(0, competitors).Select(async index =>
        {
            await using var context = new IdentityDbContext(options);
            var strategy = context.Database.CreateExecutionStrategy();
            allReady.Signal();
            await start.WaitAsync(TestContext.Current.CancellationToken);
            results[index] = await strategy.ExecuteAsync(async operationCancellationToken =>
            {
                await using var transaction = await context.Database.BeginTransactionAsync(
                    operationCancellationToken);
                var service = new ServiceSettingUpdateService(
                    Service,
                    CreateRegistry(),
                    new EfCoreServiceSettingUpdateTransaction<IdentityDbContext>(context),
                    new MasterKeyRootKeySource(new FixedMasterKey(RootKey)));
                var result = await service.UpdateAsync(
                    new ServiceSettingUpdateCommand(0, SeedChanges(), Operator),
                    operationCancellationToken);
                if (result.Succeeded)
                {
                    await transaction.CommitAsync(operationCancellationToken);
                }
                else
                {
                    await transaction.RollbackAsync(CancellationToken.None);
                }

                return result;
            }, TestContext.Current.CancellationToken);
        }).ToArray();
        Assert.True(allReady.Wait(TimeSpan.FromSeconds(30)));
        start.Release(competitors);
        await Task.WhenAll(tasks);

        Assert.True(
            results.Count(result => result.Status == ServiceSettingUpdateStatus.Applied) == 1,
            "statuses: " + string.Join(",", results.Select(result => result.Status)));
        Assert.Equal(
            competitors - 1,
            results.Count(result => result.Status == ServiceSettingUpdateStatus.VersionConflict));

        await using var verify = new IdentityDbContext(options);
        var version = await verify.Database.SqlQuery<long>($"""
                SELECT version AS "Value" FROM service_settings WHERE service_id = 'signacore'
                """).SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, version);
        var auditCount = await verify.Database.SqlQuery<int>(
                $"""SELECT COUNT(*) AS "Value" FROM service_audit_logs""")
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(4, auditCount.Single());
    }

    // ---- A6: cancellation and the sensitive boundary ----

    [Fact]
    public async Task PreCancelledToken_PropagatesCleanly()
    {
        var options = await CreateMigratedSqliteAsync();
        await using var context = new IdentityDbContext(options);
        await using var transaction = await context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            UpdateInTransactionAsync(
                context, transaction, 0, SeedChanges(), cancellationToken: cancellation.Token));
        Assert.Equal(cancellation.Token, exception.CancellationToken);
        await transaction.RollbackAsync(CancellationToken.None);
        await AssertZeroChangesAndZeroAuditsAsync(options);
    }

    [Fact]
    public async Task CancellationAfterLoad_PropagatesCleanlyAndRollsBack()
    {
        var options = await CreateMigratedSqliteAsync();
        await using var context = new IdentityDbContext(options);
        await using var transaction = await context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken);
        using var cancellation = new CancellationTokenSource();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            UpdateInTransactionAsync(
                context,
                transaction,
                0,
                SeedChanges(),
                transactionOverride: new CancellingAfterLoadTransaction(
                    new EfCoreServiceSettingUpdateTransaction<IdentityDbContext>(context),
                    cancellation),
                cancellationToken: cancellation.Token));

        // The caller's own token surfaces verbatim and nothing partially applied survives.
        Assert.Equal(cancellation.Token, exception.CancellationToken);
        await transaction.RollbackAsync(CancellationToken.None);
        await AssertZeroChangesAndZeroAuditsAsync(options);
    }

    [Fact]
    public async Task SensitiveValues_NeverAppearInStorageOrAudits()
    {
        var options = await CreateMigratedSqliteAsync();
        var changes = SeedChanges();
        changes["sms.profiles"] = """{"main":{"provider":"AlibabaCloud","accessKeyId":"CANARY-ak","accessKeySecret":"CANARY-sk","signName":"sign","templateId":"tpl"}}""";

        await UpdateAsync(options, 0, changes);

        await using var verify = new IdentityDbContext(options);
        var settingsRow = await verify.Database.SqlQuery<string>($"""
                SELECT values_json || '|' || COALESCE(updated_by, '') AS "Value" FROM service_settings
                """).SingleAsync(TestContext.Current.CancellationToken);
        var auditRows = string.Join('|', await verify.Database.SqlQuery<string>($"""
                SELECT COALESCE(metadata_json, '') || '|' || COALESCE(security_description, '') AS Value
                FROM service_audit_logs
                """).ToListAsync(TestContext.Current.CancellationToken));
        Assert.DoesNotContain("CANARY-ak", settingsRow + auditRows, StringComparison.Ordinal);
        Assert.DoesNotContain("CANARY-sk", settingsRow + auditRows, StringComparison.Ordinal);
    }

    // ---- A7: upgrade of an existing database ----

    [Fact]
    public async Task ExistingDatabaseUpgrade_LeavesLegacyTablesUntouchedAndStartsEmpty()
    {
        var path = Path.Combine(
            Path.GetTempPath(), $"signacore-shared-upgrade-{Guid.NewGuid():N}.db");
        var options = CreateSqliteOptions(path);
        var databaseOptions = new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = new SqliteConnectionStringBuilder { DataSource = path }.ConnectionString
        };

        await using (var context = new IdentityDbContext(options))
        {
            var migrator = context.GetService<IMigrator>();
            // The last migration before the shared setting stack.
            await migrator.MigrateAsync(
                "20260913104314_DropInstallationState", TestContext.Current.CancellationToken);

            // A pre-existing deployment: one account, one settings row, one audit row.
            var accountId = Guid.NewGuid();
            context.Accounts.Add(new AccountEntity
            {
                Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow
            });
            context.SystemSettings.Add(new SystemSettingEntity
            {
                Key = SystemSettingKeys.JwtIssuer,
                Value = "https://legacy.example.com",
                ValueType = "String",
                IsSecret = false,
                Version = 1,
                UpdatedAt = DateTimeOffset.UtcNow,
                UpdatedBy = "legacy-admin"
            });
            context.AuditLogs.Add(new AuditLogEntity
            {
                Id = Guid.NewGuid(),
                Action = "settings_updated",
                TargetType = "Settings",
                TargetId = "1",
                ActorId = accountId,
                ActorName = "legacy-admin",
                Description = "Legacy update",
                CreatedAt = DateTimeOffset.UtcNow
            });
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        long legacySettingsRows;
        string legacyAuditAction;
        await using (var context = new IdentityDbContext(options))
        {
            await new SignaCore.Host.Migration.SignaCoreMigrationExecutor(context, databaseOptions)
                .ExecuteAsync(TestContext.Current.CancellationToken);

            legacySettingsRows = await context.SystemSettings.LongCountAsync(
                TestContext.Current.CancellationToken);
            legacyAuditAction = await context.AuditLogs.AsNoTracking()
                .SingleAsync(TestContext.Current.CancellationToken)
                .ContinueWith(task => task.Result.Action, TestContext.Current.CancellationToken);
            var newSettings = await context.Database.SqlQuery<int>(
                    $"""SELECT COUNT(*) AS "Value" FROM service_settings""")
                .ToListAsync(TestContext.Current.CancellationToken);
            var newAudits = await context.Database.SqlQuery<int>(
                    $"""SELECT COUNT(*) AS "Value" FROM service_audit_logs""")
                .ToListAsync(TestContext.Current.CancellationToken);
            Assert.Equal(0, newSettings.Single());
            Assert.Equal(0, newAudits.Single());
        }

        Assert.Equal(1, legacySettingsRows);
        Assert.Equal("settings_updated", legacyAuditAction);

        // The fresh aggregate starts at version 0 and accepts its first update.
        var first = await UpdateAsync(options, 0, SeedChanges());
        Assert.Equal(ServiceSettingUpdateStatus.Applied, first.Status);
        Assert.Equal(1, first.Version);

        TestSqlitePools.ClearAll();
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    // ---- A8: the setup host registers the update path only ----

    [Fact]
    public async Task PendingSetupHost_RegistersOnlyTheSharedUpdatePath()
    {
        var workingDirectory = Path.Combine(
            Path.GetTempPath(), $"signacore-setup-nostack-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workingDirectory);
        var bootstrapFilePath = await InstallationTestSupport.PrepareUninstalledBootstrapAsync(
            workingDirectory,
            new DatabaseOptions
            {
                Provider = "SQLite",
                ConnectionString = new SqliteConnectionStringBuilder
                {
                    DataSource = Path.Combine(workingDirectory, "setup.db")
                }.ConnectionString
            },
            "setup-mode-root-secret");

        using var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("environment", "Production");
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath);
            });
        using var _ = factory.CreateClient();

        // The completion transaction writes the shared aggregate, so the update path is composed;
        // nothing that reads or publishes a runtime snapshot exists before the first snapshot can.
        Assert.Null(factory.Services.GetService<IServiceSettingStore>());
        Assert.Null(factory.Services.GetService<ServiceSettingSnapshotLoader>());
        Assert.Null(factory.Services.GetService<ServiceSettingQueryService>());
        Assert.NotNull(factory.Services.GetService<ServiceSettingUpdateService>());
        Assert.NotNull(factory.Services.GetService<IServiceSettingUpdateTransaction>());

        if (Directory.Exists(workingDirectory))
        {
            Directory.Delete(workingDirectory, recursive: true);
        }
    }

    private static bool ShouldRunContainerMatrix() =>
        string.Equals(
            Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS"),
            "true",
            StringComparison.OrdinalIgnoreCase);

    private sealed class FixedMasterKey(byte[] masterKey) : IMasterKeyProvider
    {
        public byte[] GetMasterKey() => masterKey;
    }

    private sealed class ThrowingRootKeySource : IServiceSettingRootKeySource
    {
        public ValueTask<string> GetRootKeyAsync(CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("no root key available");
    }

    /// <summary>Cancels the token right after the inner transaction loaded the aggregate.</summary>
    private sealed class CancellingAfterLoadTransaction(
        IServiceSettingUpdateTransaction inner,
        CancellationTokenSource cancellation) : IServiceSettingUpdateTransaction
    {
        public async ValueTask<ServiceSettingStoreSnapshot> LoadAsync(
            ServiceId serviceId,
            CancellationToken cancellationToken = default)
        {
            var snapshot = await inner.LoadAsync(serviceId, cancellationToken);
            await cancellation.CancelAsync();
            return snapshot;
        }

        public ValueTask<ServiceSettingUpdateResult> ApplyAsync(
            ServiceId serviceId,
            ServiceSettingStoreUpdate update,
            IReadOnlyList<ManagementAuditEvent> audits,
            CancellationToken cancellationToken = default) =>
            inner.ApplyAsync(serviceId, update, audits, cancellationToken);
    }
}
