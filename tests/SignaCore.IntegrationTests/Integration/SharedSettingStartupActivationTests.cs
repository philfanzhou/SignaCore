using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.Audit;
using ServiceMantle.Configuration;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The #548 runtime switch on the real composed host: a deployment whose database holds only
/// legacy <c>system_settings</c> rows is migrated by the startup inside the initialization lock,
/// the activated shared snapshot is projected back onto the legacy colon-keyed configuration shape
/// byte-for-byte, and every host booted against the same persisted state observes the same
/// aggregate version and the same complete snapshot, with the version strictly monotonic across
/// updates.
/// </summary>
/// <remarks>
/// The three cases share one class-level <see cref="IdentityServerFixture"/> and therefore one
/// SQLite database, and <see cref="TwoHosts_ObserveTheSameVersionAndSnapshot_AndVersionsAdvanceMonotonically"/>
/// advances the persisted aggregate from v1 to v2. Every case that needs the pristine
/// post-migration state re-establishes it first (<see cref="BootFreshlyMigratedHostAsync"/>), so
/// no case depends on the intra-class execution order. The orderer of issue #320 cannot provide
/// that inside this class anymore: the class must run in the
/// <see cref="SqliteProcessState.CollectionName"/> collection (its fixture clears the process-wide
/// SQLite pools at disposal, issue #321), and xUnit applies class-level test-case orderers only to
/// classes of their own implicit collection — inside an explicit collection the attribute is
/// ignored and the discovery order, which differs per platform and build artifact, decides.
/// </remarks>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class SharedSettingStartupActivationTests : IClassFixture<IdentityServerFixture>
{
    private static readonly ManagementAuditOperator UpdateOperator = ManagementAuditOperator.Create(
        WellKnownManagementAuditOperatorSources.System,
        "activation-test");

    private readonly IdentityServerFixture _fixture;

    public SharedSettingStartupActivationTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    /// <summary>
    /// Boots a host against a freshly re-migrated aggregate: the shared class-fixture database is
    /// first reset to the not-yet-migrated state (the legacy rows stay byte-for-byte), so the
    /// booted host's startup performs the one-shot migration again and the aggregate is pristine
    /// v1 no matter which sibling cases ran before. Each case is thereby independent of the
    /// intra-class execution order.
    /// </summary>
    private async Task<WebApplicationFactory<Program>> BootFreshlyMigratedHostAsync()
    {
        using (var scope = _fixture.Services.CreateScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            await SharedSettingTestDatabase.DeleteAggregateAsync(
                database, TestContext.Current.CancellationToken);
        }

        var host = _fixture.WithTestServices(_ => { });
        _ = host.CreateClient();
        return host;
    }

    /// <summary>
    /// Acceptance: for every registered key (including the JSON-expanded sub-keys), the activated
    /// shared snapshot's reverse projection yields exactly the configuration entries the legacy
    /// snapshot path produced from the same stored corpus, and both render the same values through
    /// <c>IConfiguration</c>.
    /// </summary>
    [Fact]
    public async Task ActivatedProjection_IsEquivalentToTheLegacySnapshotPath()
    {
        using var host = await BootFreshlyMigratedHostAsync();

        // The legacy path over the fixture's original system_settings corpus.
        SystemSettingsSnapshot legacy;
        using (var scope = _fixture.Services.CreateScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var protector = scope.ServiceProvider.GetRequiredService<IConfigurationProtector>();
            legacy = await new SystemSettingsStore(protector).LoadAsync(
                database, configurationVersion: 1, TestContext.Current.CancellationToken);
        }

        // The activated shared snapshot, projected back onto legacy keys. Resolving the accessor
        // of the freshly migrated host also proves the bootstrap-activated instance is the one the
        // composed hosts observe, not a second empty one.
        var accessor = host.Services.GetRequiredService<IServiceSettingCurrentSnapshotAccessor>();
        Assert.True(accessor.TryGetCurrent(out var shared));
        var (_, projectedEntries) = SharedSettingConfigurationProjection.Project(shared!);

        Assert.Equal(
            legacy.ConfigurationEntries.Keys.Order(StringComparer.OrdinalIgnoreCase),
            projectedEntries.Keys.Order(StringComparer.OrdinalIgnoreCase));
        foreach (var key in legacy.ConfigurationEntries.Keys)
        {
            Assert.Equal(
                legacy.ConfigurationEntries[key],
                projectedEntries[key],
                StringComparer.OrdinalIgnoreCase);
        }

        // The same equivalence through the IConfiguration surface every consumer reads.
        var legacyConfiguration = new ConfigurationBuilder()
            .AddInMemoryCollection(legacy.ConfigurationEntries)
            .Build();
        var projectedConfiguration = new ConfigurationBuilder()
            .AddInMemoryCollection(projectedEntries)
            .Build();
        foreach (var key in legacy.ConfigurationEntries.Keys)
        {
            Assert.Equal(legacyConfiguration[key], projectedConfiguration[key]);
        }
    }

    /// <summary>
    /// Acceptance: two hosts booted against the same persisted state observe the same aggregate
    /// version and the same complete snapshot, and the version is strictly monotonic: after one
    /// shared update, the next activation observes a higher version carrying the new value.
    /// </summary>
    [Fact]
    public async Task TwoHosts_ObserveTheSameVersionAndSnapshot_AndVersionsAdvanceMonotonically()
    {
        // First instance on the freshly re-migrated database; its startup performed the one-shot
        // migration again, so the aggregate is pristine v1.
        using var firstHost = await BootFreshlyMigratedHostAsync();
        var firstAccessor = firstHost.Services.GetRequiredService<IServiceSettingCurrentSnapshotAccessor>();
        Assert.True(firstAccessor.TryGetCurrent(out var firstSnapshot));

        // Second instance on the same database: the aggregate already exists, so its startup skips
        // the migration and activates the same persisted version.
        using var secondHost = _fixture.WithTestServices(_ => { });
        _ = secondHost.CreateClient();
        var secondAccessor = secondHost.Services.GetRequiredService<IServiceSettingCurrentSnapshotAccessor>();
        Assert.True(secondAccessor.TryGetCurrent(out var secondSnapshot));

        Assert.Equal(firstSnapshot!.Version, secondSnapshot!.Version);

        // The same complete snapshot: compare both through the legacy-keyed projection so every
        // materialized value, including sensitive ones, is compared by content.
        var (_, firstEntries) = SharedSettingConfigurationProjection.Project(firstSnapshot);
        var (_, secondEntries) = SharedSettingConfigurationProjection.Project(secondSnapshot);
        Assert.Equal(
            firstEntries.Keys.Order(StringComparer.OrdinalIgnoreCase),
            secondEntries.Keys.Order(StringComparer.OrdinalIgnoreCase));
        foreach (var key in firstEntries.Keys)
        {
            Assert.Equal(firstEntries[key], secondEntries[key], StringComparer.OrdinalIgnoreCase);
        }

        // One shared update advances the aggregate version; a third activation observes the higher
        // version and the new value.
        using (var scope = firstHost.Services.CreateScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var update = scope.ServiceProvider.GetRequiredService<ServiceSettingUpdateService>();
            await using var transaction = await database.Database.BeginTransactionAsync(
                TestContext.Current.CancellationToken);
            var result = await update.UpdateAsync(
                new ServiceSettingUpdateCommand(
                    firstSnapshot.Version,
                    new Dictionary<string, string?> { ["jwt.token_expiration_hours"] = "4" },
                    UpdateOperator),
                TestContext.Current.CancellationToken);
            Assert.True(result.Succeeded);
            Assert.Equal(firstSnapshot.Version + 1, result.Version);
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        }

        using var thirdHost = _fixture.WithTestServices(_ => { });
        _ = thirdHost.CreateClient();
        var thirdAccessor = thirdHost.Services.GetRequiredService<IServiceSettingCurrentSnapshotAccessor>();
        Assert.True(thirdAccessor.TryGetCurrent(out var thirdSnapshot));
        Assert.Equal(firstSnapshot.Version + 1, thirdSnapshot!.Version);
        Assert.Equal(
            "4",
            thirdSnapshot.Values["jwt.token_expiration_hours"].GetNumber().ToString(
                System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// The fixture database keeps its legacy rows untouched: the startup migration re-protects
    /// into the shared aggregate and never modifies, deletes, or re-versions the legacy table.
    /// The pristine aggregate state is re-established first, so the case also holds when it runs
    /// after the version-advancing sibling.
    /// </summary>
    [Fact]
    public async Task StartupMigration_LeavesTheLegacyRowsUntouched()
    {
        using var host = await BootFreshlyMigratedHostAsync();

        using var scope = _fixture.Services.CreateScope();
        var database = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var rows = await database.SystemSettings
            .AsNoTracking()
            .OrderBy(setting => setting.Key)
            .ToListAsync(TestContext.Current.CancellationToken);

        Assert.Equal(43, rows.Count);
        Assert.All(rows, row => Assert.Equal(1, row.Version));
        Assert.Contains(rows, row => row.Key == SystemSettingKeys.AdminUsername);

        var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(
            database, TestContext.Current.CancellationToken);
        Assert.NotNull(aggregate);
        Assert.Equal(1, aggregate!.Version);
        Assert.Equal("settings-migration", aggregate.UpdatedBy);
        Assert.Equal(
            SharedSettingKeys.NormalizedByLegacyKey.Values.Order(StringComparer.Ordinal),
            SharedSettingTestDatabase.ParseValues(aggregate).Keys.Order(StringComparer.Ordinal));
    }
}
