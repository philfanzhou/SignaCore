using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.Audit;
using ServiceMantle.Configuration;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The one-shot legacy settings migration on the real composed host with a real completed
/// installation: the full 43-row catalog migrates into a single version-1 aggregate with value
/// equivalence through both protection envelopes, and replays converge to AlreadyMigrated without
/// overwriting the winner.
/// </summary>
public sealed class SharedSettingMigrationTests : IClassFixture<IdentityServerFixture>
{
    private static readonly ManagementAuditOperator MigrationOperator = ManagementAuditOperator.Create(
        WellKnownManagementAuditOperatorSources.System,
        "settings-migration");

    private readonly IdentityServerFixture _fixture;

    public SharedSettingMigrationTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task CompletedInstallation_MigratesOnceAndConvergesOnReplay()
    {
        // 0. The host's startup already migrated the legacy rows once (#548); delete the aggregate
        //    row to recreate the pre-migration state of a not-yet-migrated deployment.
        using (var scope = _fixture.Services.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<SignaCore.Database.IdentityDbContext>();
            await SharedSettingTestDatabase.DeleteAggregateAsync(
                context, TestContext.Current.CancellationToken);
            Assert.Null(await SharedSettingTestDatabase.LoadAggregateAsync(
                context, TestContext.Current.CancellationToken));
        }

        // 1. Precondition: the real first-run installation wrote the complete legacy catalog and the
        //    shared aggregate is still empty.
        List<SystemSettingEntity> legacyRows;
        using (var scope = _fixture.Services.CreateScope())
        {
            legacyRows = await ReadLegacyRowsAsync(scope);
            Assert.Equal(43, legacyRows.Count);
            Assert.Null(await SharedSettingMigrationDatabase.LoadAggregateAsync(scope));
        }

        // 2. The first migration creates exactly one aggregate row at version 1 inside the caller's
        //    transaction.
        using (var scope = _fixture.Services.CreateScope())
        {
            var result = await MigrateInCallerTransactionAsync(scope);
            Assert.Equal(SharedSettingMigrationStatus.Migrated, result.Status);
            Assert.Equal(43, result.MigratedKeyCount);
        }

        SharedSettingAggregateRow winner;
        string rootKey;
        IConfigurationProtector legacyProtector;
        using (var scope = _fixture.Services.CreateScope())
        {
            winner = (await SharedSettingMigrationDatabase.LoadAggregateAsync(scope))!;
            Assert.NotNull(winner);
            Assert.Equal(1, winner.Version);
            Assert.Equal("settings-migration", winner.UpdatedBy);
            rootKey = Convert.ToBase64String(
                scope.ServiceProvider.GetRequiredService<IMasterKeyProvider>().GetMasterKey());
            legacyProtector = scope.ServiceProvider.GetRequiredService<IConfigurationProtector>();
        }

        // 3. Value equivalence: every legacy key is present under its normalized name, non-secret
        //    values are byte-identical, and every migrated secret decrypts under the shared
        //    protector (purpose = normalized key) to the exact legacy plaintext.
        var migrated = ParseValues(winner);
        Assert.Equal(
            SharedSettingKeys.NormalizedByLegacyKey.Values.Order(StringComparer.Ordinal),
            migrated.Keys.Order(StringComparer.Ordinal));
        foreach (var row in legacyRows)
        {
            var normalizedKey = SharedSettingKeys.NormalizedByLegacyKey[row.Key];
            if (row.IsSecret)
            {
                Assert.StartsWith("sm:v1:", migrated[normalizedKey], StringComparison.Ordinal);
                var redecrypted = new SensitiveValueProtector(InstallationStores.ServiceId, normalizedKey)
                    .Unprotect(migrated[normalizedKey], rootKey, TestContext.Current.CancellationToken);
                var legacyPlaintext = legacyProtector.Unprotect(row.Key, row.Value);
                Assert.Equal(legacyPlaintext, redecrypted);
            }
            else
            {
                Assert.Equal(row.Value, migrated[normalizedKey]);
            }
        }

        // 4. A replay in its own scope and transaction converges to AlreadyMigrated without
        //    writing, changing the version or overwriting the winner.
        using (var scope = _fixture.Services.CreateScope())
        {
            var result = await MigrateInCallerTransactionAsync(scope);
            Assert.Equal(SharedSettingMigrationStatus.AlreadyMigrated, result.Status);
        }

        using (var scope = _fixture.Services.CreateScope())
        {
            var replayed = (await SharedSettingMigrationDatabase.LoadAggregateAsync(scope))!;
            Assert.Equal(winner.Version, replayed.Version);
            Assert.Equal(winner.ValuesJson, replayed.ValuesJson);
            Assert.Equal(winner.UpdatedBy, replayed.UpdatedBy);
        }
    }

    private async Task<SharedSettingMigrationResult> MigrateInCallerTransactionAsync(
        IServiceScope scope)
    {
        var context = scope.ServiceProvider.GetRequiredService<SignaCore.Database.IdentityDbContext>();
        var migrator = new SharedSettingMigrator(
            scope.ServiceProvider.GetRequiredService<IConfigurationProtector>(),
            scope.ServiceProvider.GetRequiredService<ServiceSettingUpdateService>());
        await using var transaction = await context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken);
        var result = await migrator.MigrateAsync(
            context, MigrationOperator, TestContext.Current.CancellationToken);
        await transaction.CommitAsync(TestContext.Current.CancellationToken);
        return result;
    }

    private static async Task<List<SystemSettingEntity>> ReadLegacyRowsAsync(IServiceScope scope) =>
        await scope.ServiceProvider.GetRequiredService<SignaCore.Database.IdentityDbContext>()
            .SystemSettings.AsNoTracking()
            .OrderBy(setting => setting.Key)
            .ToListAsync(TestContext.Current.CancellationToken);

    private static Dictionary<string, string> ParseValues(SharedSettingAggregateRow aggregate)
    {
        using var document = JsonDocument.Parse(aggregate.ValuesJson);
        return document.RootElement.EnumerateObject()
            .ToDictionary(
                property => property.Name,
                property => property.Value.GetString()!,
                StringComparer.Ordinal);
    }
}

/// <summary>
/// Fail-closed discipline on the real composed host: every refusal reports key names and
/// classifications only and leaves the shared aggregate byte-identical. The host's startup already
/// migrated the fixture once (#548), so each test captures the aggregate as its baseline and
/// stages its broken state inside the caller's transaction and rolls back, leaving the fixture
/// database a valid installation.
/// </summary>
public sealed class SharedSettingMigrationFailureTests : IClassFixture<IdentityServerFixture>
{
    private const string CorruptedEnvelope =
        "corrupted-envelope-marker-value-that-is-not-a-valid-envelope!!";

    private static readonly ManagementAuditOperator MigrationOperator = ManagementAuditOperator.Create(
        WellKnownManagementAuditOperatorSources.System,
        "settings-migration");

    private readonly IdentityServerFixture _fixture;

    public SharedSettingMigrationFailureTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task UndecryptableSecretEnvelope_FailsClosedWithKeyNamesOnly()
    {
        var (result, baseline) = await StageBrokenStateAndMigrateAsync(
            async context =>
            {
                var row = await context.SystemSettings.SingleAsync(
                    setting => setting.Key == SystemSettingKeys.SmsOtpHmacKey,
                    TestContext.Current.CancellationToken);
                row.Value = CorruptedEnvelope;
                await context.SaveChangesAsync(TestContext.Current.CancellationToken);
                context.ChangeTracker.Clear();
            });

        Assert.Equal(SharedSettingMigrationStatus.Failed, result.Status);
        Assert.Equal(SharedSettingMigrationResult.UndecryptableSecretsClassification, result.FailureClassification);
        Assert.Equal([SystemSettingKeys.SmsOtpHmacKey], result.FailedKeys);
        Assert.DoesNotContain(CorruptedEnvelope, result.ToString(), StringComparison.Ordinal);
        await AssertAggregateUnchangedAsync(baseline!);
    }

    [Fact]
    public async Task UnregisteredLegacyRow_FailsClosed()
    {
        var (result, baseline) = await StageBrokenStateAndMigrateAsync(
            async context =>
            {
                context.SystemSettings.Add(new SystemSettingEntity
                {
                    Key = "Legacy:Injected",
                    Value = "injected-value",
                    ValueType = SettingValueTypes.String,
                    IsSecret = false,
                    Version = 1,
                    UpdatedAt = DateTimeOffset.UtcNow,
                    UpdatedBy = "attacker"
                });
                await context.SaveChangesAsync(TestContext.Current.CancellationToken);
                context.ChangeTracker.Clear();
            });

        Assert.Equal(SharedSettingMigrationStatus.Failed, result.Status);
        Assert.Equal(SharedSettingMigrationResult.UnregisteredKeysClassification, result.FailureClassification);
        Assert.Equal(["Legacy:Injected"], result.FailedKeys);
        await AssertAggregateUnchangedAsync(baseline!);
    }

    [Fact]
    public async Task ConstraintViolatingValue_FailsClosedThroughSharedValidation()
    {
        var (result, baseline) = await StageBrokenStateAndMigrateAsync(
            async context =>
            {
                // The host's startup already migrated the fixture once (#548); drop the aggregate
                // inside the transaction so the broken source actually reaches the shared
                // validation on the single expected-version-0 write.
                await SharedSettingTestDatabase.DeleteAggregateAsync(
                    context, TestContext.Current.CancellationToken);
                var row = await context.SystemSettings.SingleAsync(
                    setting => setting.Key == SystemSettingKeys.LdapEnabled,
                    TestContext.Current.CancellationToken);
                row.Value = "yes";
                await context.SaveChangesAsync(TestContext.Current.CancellationToken);
                context.ChangeTracker.Clear();
            });

        Assert.Equal(SharedSettingMigrationStatus.Failed, result.Status);
        Assert.Equal("service_settings.validation_failed", result.FailureClassification);
        Assert.Contains("ldap.enabled", result.FailedKeys);
        await AssertAggregateUnchangedAsync(baseline!);
    }

    [Fact]
    public async Task EmptyLegacyTable_ReturnsNothingToMigrate()
    {
        var (result, baseline) = await StageBrokenStateAndMigrateAsync(
            context => context.SystemSettings.ExecuteDeleteAsync(TestContext.Current.CancellationToken));

        Assert.Equal(SharedSettingMigrationStatus.NothingToMigrate, result.Status);
        Assert.Null(result.FailureClassification);
        await AssertAggregateUnchangedAsync(baseline!);
    }

    [Fact]
    public async Task CanceledToken_PropagatesCancellationAndWritesNothing()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        SharedSettingAggregateRow? baseline;
        using (var scope = _fixture.Services.CreateScope())
        {
            var setupContext = scope.ServiceProvider
                .GetRequiredService<SignaCore.Database.IdentityDbContext>();
            baseline = await SharedSettingTestDatabase.LoadAggregateAsync(
                setupContext, TestContext.Current.CancellationToken);
        }

        using (var scope = _fixture.Services.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<SignaCore.Database.IdentityDbContext>();
            var migrator = new SharedSettingMigrator(
                scope.ServiceProvider.GetRequiredService<IConfigurationProtector>(),
                scope.ServiceProvider.GetRequiredService<ServiceSettingUpdateService>());
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => migrator.MigrateAsync(context, MigrationOperator, cancellation.Token));
        }

        await AssertAggregateUnchangedAsync(baseline!);
    }

    /// <summary>Stages broken state inside a caller-owned transaction, migrates, then rolls back.</summary>
    private async Task<(SharedSettingMigrationResult Result, SharedSettingAggregateRow? Baseline)>
        StageBrokenStateAndMigrateAsync(
            Func<SignaCore.Database.IdentityDbContext, Task> stageAsync)
    {
        using var scope = _fixture.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<SignaCore.Database.IdentityDbContext>();
        var migrator = new SharedSettingMigrator(
            scope.ServiceProvider.GetRequiredService<IConfigurationProtector>(),
            scope.ServiceProvider.GetRequiredService<ServiceSettingUpdateService>());

        await using var transaction = await context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken);
        var baseline = await SharedSettingTestDatabase.LoadAggregateAsync(
            context, TestContext.Current.CancellationToken);
        await stageAsync(context);
        var result = await migrator.MigrateAsync(
            context, MigrationOperator, TestContext.Current.CancellationToken);
        await transaction.RollbackAsync(TestContext.Current.CancellationToken);
        return (result, baseline);
    }

    private async Task AssertAggregateUnchangedAsync(SharedSettingAggregateRow baseline)
    {
        using var scope = _fixture.Services.CreateScope();
        var current = await SharedSettingMigrationDatabase.LoadAggregateAsync(scope);
        Assert.NotNull(current);
        Assert.Equal(baseline.Version, current!.Version);
        Assert.Equal(baseline.ValuesJson, current.ValuesJson);
        Assert.Equal(baseline.UpdatedBy, current.UpdatedBy);
    }
}

/// <summary>Reads the shared aggregate row through provider-neutral SQL like the contract tests.</summary>
internal sealed class SharedSettingAggregateRow
{
    public long Version { get; set; }

    public string ValuesJson { get; set; } = string.Empty;

    public string? UpdatedBy { get; set; }
}

internal static class SharedSettingMigrationDatabase
{
    public static async Task<SharedSettingAggregateRow?> LoadAggregateAsync(IServiceScope scope) =>
        await scope.ServiceProvider.GetRequiredService<SignaCore.Database.IdentityDbContext>()
            .Database.SqlQuery<SharedSettingAggregateRow>($"""
                SELECT version AS "Version", values_json AS "ValuesJson", updated_by AS "UpdatedBy"
                FROM service_settings WHERE service_id = {InstallationStores.ServiceIdValue}
                """).SingleOrDefaultAsync(TestContext.Current.CancellationToken);
}
