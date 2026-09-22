using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
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
/// The retirement-era activation guarantees on the real composed host: the activated shared
/// snapshot's projection is equivalent entry-for-entry to what the retired legacy snapshot path
/// produced from the same corpus, every host booted against the same persisted state observes the
/// same aggregate version and the same complete snapshot, versions advance strictly monotonically
/// across shared updates, and the retired legacy table no longer exists in the fixture schema.
/// </summary>
/// <remarks>
/// The class shares one <see cref="IdentityServerFixture"/> and therefore one SQLite database
/// seeded directly through the shared update path (no startup migration of legacy rows).
/// <see cref="TwoHosts_ObserveTheSameVersionAndSnapshot_AndVersionsAdvanceMonotonically"/>
/// advances the persisted aggregate version, so every case states its expectations relative to the
/// observed snapshot instead of a pristine version. The orderer of issue #320 cannot provide
/// intra-class ordering here: the class must run in the
/// <see cref="SqliteProcessState.CollectionName"/> collection, and xUnit applies class-level
/// test-case orderers only to classes of their own implicit collection.
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
    /// The exact values the fixture seeded through the shared update path, in the legacy keyed
    /// form the projection must render.
    /// </summary>
    private static Dictionary<string, string> SeededCorpus() =>
        new(IdentityServerFixture.SeededSettingValues, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Expands the seeded corpus into configuration entries exactly the way the retired legacy
    /// snapshot loader did — scalars verbatim, JSON settings flattened — so the comparison keeps
    /// proving the projection preserves the legacy configuration shape.
    /// </summary>
    private static Dictionary<string, string?> ExpectedEntries()
    {
        var entries = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (legacyKey, value) in SeededCorpus())
        {
            var definition = ServiceSettingDefinitions.Find(
                SharedSettingKeys.NormalizedByLegacyKey[legacyKey])!;
            if (definition.ValueType == ServiceSettingValueType.Json)
            {
                JsonSettingFlattener.Flatten(legacyKey, value, entries);
            }
            else
            {
                entries[legacyKey] = value;
            }
        }

        return entries;
    }

    /// <summary>
    /// Acceptance: for every registered key (including the JSON-expanded sub-keys), the activated
    /// shared snapshot's projection yields exactly the configuration entries the retired legacy
    /// snapshot path produced from the same corpus, and both render the same values through
    /// <c>IConfiguration</c>.
    /// </summary>
    [Fact]
    public async Task ActivatedProjection_IsEquivalentToTheRetiredLegacySnapshotPath()
    {
        // The version-advancing sibling may have run first and moved jwt.token_expiration_hours
        // off the seeded corpus; restore the seeded value so the comparison below is exactly the
        // seeded corpus.
        using (var scope = _fixture.Services.CreateScope())
        {
            var database = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var update = scope.ServiceProvider.GetRequiredService<ServiceSettingUpdateService>();
            var current = await SharedSettingTestDatabase.LoadAggregateAsync(
                database, TestContext.Current.CancellationToken);
            Assert.NotNull(current);
            await using var transaction = await database.Database.BeginTransactionAsync(
                TestContext.Current.CancellationToken);
            var restored = await update.UpdateAsync(
                new ServiceSettingUpdateCommand(
                    current!.Version,
                    new Dictionary<string, string?> { ["jwt.token_expiration_hours"] = "2" },
                    UpdateOperator),
                TestContext.Current.CancellationToken);
            Assert.True(restored.Succeeded);
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        }

        using var host = _fixture.WithTestServices(_ => { });
        _ = host.CreateClient();

        // Resolving the accessor of the booted host proves the bootstrap-activated instance is
        // the one the composed hosts observe, not a second empty one.
        var accessor = host.Services.GetRequiredService<IServiceSettingCurrentSnapshotAccessor>();
        Assert.True(accessor.TryGetCurrent(out var shared));
        var (_, projectedEntries) = SharedSettingConfigurationProjection.Project(shared!);

        var expected = ExpectedEntries();
        Assert.Equal(
            expected.Keys.Order(StringComparer.OrdinalIgnoreCase),
            projectedEntries.Keys.Order(StringComparer.OrdinalIgnoreCase));
        foreach (var key in expected.Keys)
        {
            Assert.Equal(expected[key], projectedEntries[key], StringComparer.OrdinalIgnoreCase);
        }

        // The same equivalence through the IConfiguration surface every consumer reads.
        var legacyConfiguration = new ConfigurationBuilder()
            .AddInMemoryCollection(expected!)
            .Build();
        var projectedConfiguration = new ConfigurationBuilder()
            .AddInMemoryCollection(projectedEntries)
            .Build();
        foreach (var key in expected.Keys)
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
        using var firstHost = _fixture.WithTestServices(_ => { });
        _ = firstHost.CreateClient();
        var firstAccessor = firstHost.Services.GetRequiredService<IServiceSettingCurrentSnapshotAccessor>();
        Assert.True(firstAccessor.TryGetCurrent(out var firstSnapshot));

        // Second instance on the same database: the aggregate already exists, so its startup
        // activates the same persisted version without touching any retired table.
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
    /// The retired table is gone from the fixture schema and nothing recreates it: the hosts of
    /// this class booted repeatedly against the same database while this case ran, proving the
    /// normal startup path never reads or writes <c>system_settings</c> after the retirement.
    /// </summary>
    [Fact]
    public async Task RetiredLegacyTable_IsAbsentAndStaysAbsentAcrossBoots()
    {
        using var host = _fixture.WithTestServices(_ => { });
        _ = host.CreateClient();

        using var scope = _fixture.Services.CreateScope();
        var database = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var table = await database.Database.SqlQuery<long>($"""
            SELECT COUNT(*) AS "Value" FROM sqlite_master
            WHERE type = 'table' AND name = 'system_settings'
            """).ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, table.Single());

        // The persisted authority is the shared aggregate the fixture seeded directly.
        var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(
            database, TestContext.Current.CancellationToken);
        Assert.NotNull(aggregate);
        Assert.True(aggregate!.Version >= 1);
    }
}
