using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ServiceMantle.Audit;
using ServiceMantle.Configuration;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

/// <summary>
/// The one-shot legacy-to-shared settings migration against a real SQLite database, the real shared
/// update service and the real definition registry: value equivalence through both protection
/// envelopes, all-or-nothing failure discipline, idempotent replay and value-free failure reports.
/// </summary>
public sealed class SharedSettingMigratorTests
{
    private static readonly ManagementAuditOperator MigrationOperator = ManagementAuditOperator.Create(
        WellKnownManagementAuditOperatorSources.System,
        "settings-migration");

    /// <summary>Distinctive plaintext markers proving that no report path leaks values.</summary>
    private const string HmacKeyPlaintext = "U2hhcmVkU2V0dGluZ01pZ3JhdG9yLUhtYWMtS2V5ISEh";
    private const string BypassCodePlaintext = "migration-bypass-code-plaintext";
    private const string SmsProfilesPlaintext =
        """{"main":{"provider":"AlibabaCloud","accessKeyId":"migration-access-key-id","accessKeySecret":"migration-access-key-secret","signName":"migration-sign","templateId":"migration-template"}}""";
    private const string WechatAppIdValue = "migration-wechat-appid";
    private const string WechatSecretPlaintext = "migration-wechat-secret-plaintext";
    private const string LdapDirectoriesPlaintext =
        """[{"key":"main","hosts":["ldap.migration.example"],"baseDn":"dc=migration,dc=example","bindUsername":"uid=migration","bindPassword":"migration-bind-password","port":636,"timeoutSeconds":10}]""";
    private const string ConsulTokenPlaintext = "migration-consul-token-plaintext";

    private static readonly string[] SecretPlaintextMarkers =
    [
        HmacKeyPlaintext,
        BypassCodePlaintext,
        SmsProfilesPlaintext,
        WechatAppIdValue,
        WechatSecretPlaintext,
        LdapDirectoriesPlaintext,
        ConsulTokenPlaintext
    ];

    [Fact]
    public async Task FullCatalog_MigratesIntoASingleVersionOneAggregate()
    {
        await using var harness = await MigrationHarness.CreateAsync();
        await harness.SeedLegacyRowsAsync();
        var legacyRowsBefore = await harness.ReadLegacyRowsAsync();

        await using (var transaction = await harness.Context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken))
        {
            var result = await harness.Migrator.MigrateAsync(
                harness.Context, MigrationOperator, TestContext.Current.CancellationToken);

            Assert.Equal(SharedSettingMigrationStatus.Migrated, result.Status);
            Assert.Equal(43, result.MigratedKeyCount);
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        }

        var aggregate = await harness.LoadAggregateAsync();
        Assert.NotNull(aggregate);
        Assert.Equal(1, aggregate!.Version);
        Assert.Equal("settings-migration", aggregate.UpdatedBy);
        Assert.True(aggregate.RestartRequired);

        var migrated = ParseValues(aggregate.ValuesJson);
        Assert.Equal(
            SharedSettingKeys.NormalizedByLegacyKey.Values.Order(StringComparer.Ordinal),
            migrated.Keys.Order(StringComparer.Ordinal));

        foreach (var row in legacyRowsBefore)
        {
            var normalizedKey = SharedSettingKeys.NormalizedByLegacyKey[row.Key];
            if (row.IsSecret)
            {
                // The aggregate must carry the shared envelope, which only the update service
                // produces, and it must decrypt to the exact legacy plaintext under the normalized
                // key as purpose.
                var sharedEnvelope = migrated[normalizedKey];
                Assert.StartsWith("sm:v1:", sharedEnvelope, StringComparison.Ordinal);
                Assert.NotEqual(row.Value, sharedEnvelope);
                var redecrypted = new SensitiveValueProtector(InstallationStores.ServiceId, normalizedKey)
                    .Unprotect(sharedEnvelope, harness.RootKey, TestContext.Current.CancellationToken);
                var legacyPlaintext = harness.Protector.Unprotect(row.Key, row.Value);
                Assert.Equal(legacyPlaintext, redecrypted);
            }
            else
            {
                Assert.Equal(row.Value, migrated[normalizedKey]);
            }
        }

        // The migration never modifies the legacy rows.
        var legacyRowsAfter = await harness.ReadLegacyRowsAsync();
        Assert.Equal(
            legacyRowsBefore.ToDictionary(row => row.Key, row => row.Value, StringComparer.Ordinal),
            legacyRowsAfter.ToDictionary(row => row.Key, row => row.Value, StringComparer.Ordinal));
    }

    [Fact]
    public async Task ReplayAfterSuccess_IsIdempotentAndWritesNothing()
    {
        await using var harness = await MigrationHarness.CreateAsync();
        await harness.SeedLegacyRowsAsync();
        await MigrateOnceAsync(harness);
        var before = await harness.LoadAggregateAsync();

        await using (var transaction = await harness.Context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken))
        {
            var result = await harness.Migrator.MigrateAsync(
                harness.Context, MigrationOperator, TestContext.Current.CancellationToken);

            Assert.Equal(SharedSettingMigrationStatus.AlreadyMigrated, result.Status);
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        }

        var after = await harness.LoadAggregateAsync();
        Assert.Equal(before!.Version, after!.Version);
        Assert.Equal(before.ValuesJson, after.ValuesJson);
        Assert.Equal(before.UpdatedBy, after.UpdatedBy);
    }

    [Fact]
    public async Task SecondMigrationAfterACommittedFirst_ConvergesToAlreadyMigrated()
    {
        await using var harness = await MigrationHarness.CreateAsync();
        await harness.SeedLegacyRowsAsync();
        await MigrateOnceAsync(harness);
        var first = await harness.LoadAggregateAsync();

        // A separate scope sees the committed aggregate and must lose the optimistic-version race.
        await using var second = harness.CreateSecondScope();
        await using (var transaction = await second.Context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken))
        {
            var result = await second.Migrator.MigrateAsync(
                second.Context, MigrationOperator, TestContext.Current.CancellationToken);

            Assert.Equal(SharedSettingMigrationStatus.AlreadyMigrated, result.Status);
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        }

        var winner = await harness.LoadAggregateAsync();
        Assert.Equal(first!.Version, winner!.Version);
        Assert.Equal(first.ValuesJson, winner.ValuesJson);
        Assert.Equal(first.UpdatedBy, winner.UpdatedBy);
    }

    [Fact]
    public async Task EmptyLegacyTable_ReturnsNothingToMigrate()
    {
        await using var harness = await MigrationHarness.CreateAsync();

        await using (var transaction = await harness.Context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken))
        {
            var result = await harness.Migrator.MigrateAsync(
                harness.Context, MigrationOperator, TestContext.Current.CancellationToken);

            Assert.Equal(SharedSettingMigrationStatus.NothingToMigrate, result.Status);
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        }

        Assert.Null(await harness.LoadAggregateAsync());
    }

    [Fact]
    public async Task WrongLegacyRootKey_FailsClosedWithSecretKeyNamesOnly()
    {
        await using var harness = await MigrationHarness.CreateAsync(
            migratorLegacyMasterKeyOverride: RandomNumberGenerator.GetBytes(32));
        await harness.SeedLegacyRowsAsync();

        SharedSettingMigrationResult result;
        await using (var transaction = await harness.Context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken))
        {
            result = await harness.Migrator.MigrateAsync(
                harness.Context, MigrationOperator, TestContext.Current.CancellationToken);

            Assert.Equal(SharedSettingMigrationStatus.Failed, result.Status);
            Assert.Equal(SharedSettingMigrationResult.UndecryptableSecretsClassification, result.FailureClassification);
            Assert.Equal(
                SystemSettingsCatalog.Definitions.Where(definition => definition.IsSecret)
                    .Select(definition => definition.Key)
                    .Order(StringComparer.Ordinal),
                result.FailedKeys.Order(StringComparer.Ordinal));
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        }

        Assert.Null(await harness.LoadAggregateAsync());
        AssertNoValueLeak(result.ToString());
    }

    [Fact]
    public async Task UnregisteredLegacyKey_FailsClosed()
    {
        await using var harness = await MigrationHarness.CreateAsync();
        await harness.SeedLegacyRowsAsync();
        harness.Context.SystemSettings.Add(new SystemSettingEntity
        {
            Key = "Legacy:Injected",
            Value = "injected-value",
            ValueType = SettingValueTypes.String,
            IsSecret = false,
            Version = 1,
            UpdatedAt = DateTimeOffset.UtcNow,
            UpdatedBy = "attacker"
        });
        await harness.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        harness.Context.ChangeTracker.Clear();

        await using (var transaction = await harness.Context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken))
        {
            var result = await harness.Migrator.MigrateAsync(
                harness.Context, MigrationOperator, TestContext.Current.CancellationToken);

            Assert.Equal(SharedSettingMigrationStatus.Failed, result.Status);
            Assert.Equal(SharedSettingMigrationResult.UnregisteredKeysClassification, result.FailureClassification);
            Assert.Equal(["Legacy:Injected"], result.FailedKeys);
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        }

        Assert.Null(await harness.LoadAggregateAsync());
    }

    [Fact]
    public async Task ConstraintViolatingValue_FailsClosedThroughSharedValidation()
    {
        await using var harness = await MigrationHarness.CreateAsync();
        await harness.SeedLegacyRowsAsync();
        await harness.UpdateLegacyRowAsync(SystemSettingKeys.LdapEnabled, "yes");

        SharedSettingMigrationResult result;
        await using (var transaction = await harness.Context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken))
        {
            result = await harness.Migrator.MigrateAsync(
                harness.Context, MigrationOperator, TestContext.Current.CancellationToken);

            Assert.Equal(SharedSettingMigrationStatus.Failed, result.Status);
            Assert.Equal("service_settings.validation_failed", result.FailureClassification);
            Assert.Contains("ldap.enabled", result.FailedKeys);
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        }

        Assert.Null(await harness.LoadAggregateAsync());
        AssertNoValueLeak(result.ToString());
    }

    [Fact]
    public async Task MissingCallerTransaction_FailsClosedThroughTransactionRequired()
    {
        await using var harness = await MigrationHarness.CreateAsync();
        await harness.SeedLegacyRowsAsync();

        var result = await harness.Migrator.MigrateAsync(
            harness.Context, MigrationOperator, TestContext.Current.CancellationToken);

        Assert.Equal(SharedSettingMigrationStatus.Failed, result.Status);
        Assert.Equal("service_settings.transaction_required", result.FailureClassification);
        Assert.Null(await harness.LoadAggregateAsync());
    }

    [Fact]
    public async Task CancellationDuringDecryption_PropagatesAndWritesNothing()
    {
        await using var harness = await MigrationHarness.CreateAsync();
        await harness.SeedLegacyRowsAsync();
        using var cancellation = new CancellationTokenSource();
        var cancelingMigrator = new SharedSettingMigrator(
            new CancelOnFirstUnprotectProtector(harness.Protector, cancellation),
            harness.BuildUpdateService(harness.Context));

        await using var transaction = await harness.Context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => cancelingMigrator.MigrateAsync(harness.Context, MigrationOperator, cancellation.Token));

        Assert.Null(await harness.LoadAggregateAsync());
    }

    private static async Task MigrateOnceAsync(MigrationHarness harness)
    {
        await using var transaction = await harness.Context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken);
        var result = await harness.Migrator.MigrateAsync(
            harness.Context, MigrationOperator, TestContext.Current.CancellationToken);
        Assert.Equal(SharedSettingMigrationStatus.Migrated, result.Status);
        await transaction.CommitAsync(TestContext.Current.CancellationToken);
    }

    private static void AssertNoValueLeak(string report)
    {
        foreach (var marker in SecretPlaintextMarkers)
        {
            Assert.DoesNotContain(marker, report, StringComparison.Ordinal);
        }
    }

    /// <summary>The shared aggregate row, read through provider-neutral SQL like the contract tests.</summary>
    private sealed class SharedSettingAggregateRow
    {
        public long Version { get; set; }

        public string ValuesJson { get; set; } = string.Empty;

        public string? UpdatedBy { get; set; }

        public bool RestartRequired { get; set; }
    }

    private static Dictionary<string, string> ParseValues(string valuesJson)
    {
        using var document = System.Text.Json.JsonDocument.Parse(valuesJson);
        return document.RootElement.EnumerateObject()
            .ToDictionary(
                property => property.Name,
                property => property.Value.GetString()!,
                StringComparer.Ordinal);
    }

    private sealed class CancelOnFirstUnprotectProtector(
        IConfigurationProtector inner,
        CancellationTokenSource cancellation) : IConfigurationProtector
    {
        public string Protect(string settingKey, string plaintext) => inner.Protect(settingKey, plaintext);

        public string Unprotect(string settingKey, string protectedValue)
        {
            cancellation.Cancel();
            return inner.Unprotect(settingKey, protectedValue);
        }
    }

    /// <summary>A SQLite in-memory database with the real legacy and shared setting stacks wired up.</summary>
    private sealed class MigrationHarness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly byte[] _masterKey;

        private MigrationHarness(
            SqliteConnection connection,
            byte[] masterKey,
            IdentityDbContext context,
            IConfigurationProtector protector,
            IConfigurationProtector? migratorLegacyProtector)
        {
            _connection = connection;
            _masterKey = masterKey;
            Context = context;
            Protector = protector;
            Migrator = new SharedSettingMigrator(
                migratorLegacyProtector ?? protector,
                BuildUpdateService(context));
        }

        internal IdentityDbContext Context { get; }

        /// <summary>The legacy protector with the master key the rows were seeded under.</summary>
        internal IConfigurationProtector Protector { get; }

        internal SharedSettingMigrator Migrator { get; }

        /// <summary>The shared root key (Base64 of the master key), as the host's root key source serves it.</summary>
        internal string RootKey => Convert.ToBase64String(_masterKey);

        internal static async Task<MigrationHarness> CreateAsync(
            byte[]? migratorLegacyMasterKeyOverride = null)
        {
            var masterKey = RandomNumberGenerator.GetBytes(32);
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var context = new IdentityDbContext(
                new DbContextOptionsBuilder<IdentityDbContext>()
                    .UseSqlite(connection)
                    .Options);
            await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            var protector = new AesGcmConfigurationProtector(new FixedMasterKeyProvider(masterKey));
            var migratorProtector = migratorLegacyMasterKeyOverride is null
                ? null
                : new AesGcmConfigurationProtector(new FixedMasterKeyProvider(migratorLegacyMasterKeyOverride));
            return new MigrationHarness(connection, masterKey, context, protector, migratorProtector);
        }

        internal ServiceSettingUpdateService BuildUpdateService(IdentityDbContext context) => new(
            InstallationStores.ServiceId,
            new ServiceSettingDefinitionRegistry(
                [new ServiceSettingDefinitions()],
                [new SignaCoreSettingCompositeValidator(false)]),
            new EfCoreServiceSettingUpdateTransaction<IdentityDbContext>(context),
            new MasterKeyRootKeySource(new FixedMasterKeyProvider(_masterKey)));

        /// <summary>Seeds the legacy table exactly the way a completed first-run installation does.</summary>
        internal async Task SeedLegacyRowsAsync()
        {
            var values = SystemSettingsCatalog.BuildDefaults();
            values[SystemSettingKeys.PublicBaseUrl] = "https://migration.example.com";
            values[SystemSettingKeys.JwtIssuer] = "https://migration.example.com";
            values[SystemSettingKeys.AdminUsername] = "migration-admin";
            values[SystemSettingKeys.SmsOtpHmacKey] = HmacKeyPlaintext;
            values[SystemSettingKeys.SmsBypassCode] = BypassCodePlaintext;
            values[SystemSettingKeys.SmsProfiles] = SmsProfilesPlaintext;
            values[SystemSettingKeys.WechatAppId] = WechatAppIdValue;
            values[SystemSettingKeys.WechatAppSecret] = WechatSecretPlaintext;
            values[SystemSettingKeys.LdapDirectories] = LdapDirectoriesPlaintext;
            values[SystemSettingKeys.ConsulToken] = ConsulTokenPlaintext;
            var store = new SystemSettingsStore(Protector);
            await store.WriteAsync(Context, values, 1, "setup", TestContext.Current.CancellationToken);
            await Context.SaveChangesAsync(TestContext.Current.CancellationToken);
            Context.ChangeTracker.Clear();
        }

        internal async Task UpdateLegacyRowAsync(string key, string value)
        {
            var row = await Context.SystemSettings.SingleAsync(
                setting => setting.Key == key, TestContext.Current.CancellationToken);
            row.Value = value;
            await Context.SaveChangesAsync(TestContext.Current.CancellationToken);
            Context.ChangeTracker.Clear();
        }

        internal async Task<List<SystemSettingEntity>> ReadLegacyRowsAsync() =>
            await Context.SystemSettings.AsNoTracking()
                .OrderBy(setting => setting.Key)
                .ToListAsync(TestContext.Current.CancellationToken);

        internal async Task<SharedSettingAggregateRow?> LoadAggregateAsync() =>
            await Context.Database.SqlQuery<SharedSettingAggregateRow>($"""
                SELECT version AS "Version", values_json AS "ValuesJson",
                       updated_by AS "UpdatedBy", restart_required AS "RestartRequired"
                FROM service_settings WHERE service_id = {InstallationStores.ServiceIdValue}
                """).SingleOrDefaultAsync(TestContext.Current.CancellationToken);

        /// <summary>
        /// A second scope on the same database with its own context, sharing the deployment master key.
        /// </summary>
        internal SecondScope CreateSecondScope()
        {
            var context = new IdentityDbContext(
                new DbContextOptionsBuilder<IdentityDbContext>()
                    .UseSqlite(_connection)
                    .Options);
            return new SecondScope(context, Protector, BuildUpdateService(context));
        }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await _connection.DisposeAsync();
        }

        private sealed class FixedMasterKeyProvider(byte[] masterKey) : IMasterKeyProvider
        {
            public byte[] GetMasterKey() => masterKey;
        }
    }

    private sealed class SecondScope(
        IdentityDbContext context,
        IConfigurationProtector legacyProtector,
        ServiceSettingUpdateService updateService) : IAsyncDisposable
    {
        internal IdentityDbContext Context { get; } = context;

        internal SharedSettingMigrator Migrator { get; } = new(legacyProtector, updateService);

        public async ValueTask DisposeAsync() => await Context.DisposeAsync();
    }
}
