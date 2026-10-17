using ServiceMantle.Configuration;
using ServiceMantle;
using SignaCore.Domain.Keys;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

/// <summary>
/// Activation and projection guarantees of the managed console title <c>app.title</c> (#595):
/// an aggregate written before the key existed carries no row, the shared loader materializes
/// the definition default so startup does not fail, and the activated snapshot projects onto the
/// flat <c>APP_TITLE</c> configuration key the SPA title injector reads.
/// </summary>
public sealed class AppTitleSettingTests
{
    private const string RootSecret = "app-title-root-secret";

    [Fact]
    public async Task LegacyAggregate_WithoutTheAppTitleRow_MaterializesTheDefaultAndProjectsAppTitle()
    {
        // Rows exactly as an older release stored them: every seeded key, no app.title row.
        var snapshot = await LoadSnapshotAsync(titleOverride: null);
        Assert.True(snapshot.Values.TryGetValue("app.title", out var materialized));
        Assert.True(materialized!.HasValue);
        Assert.Equal("SignaCore", materialized.GetString());

        // The materialized default projects onto the flat configuration key the injector reads.
        var (_, projectedEntries) = SharedSettingConfigurationProjection.Project(snapshot);
        Assert.Equal("SignaCore", projectedEntries[SystemSettingKeys.AppTitle]);
    }

    [Fact]
    public async Task StoredAppTitleValue_ProjectsOntoTheAppTitleConfigurationKey()
    {
        // A persisted custom title survives activation and, because Program.cs layers the
        // projected entries last, wins over any process-provided APP_TITLE value.
        var snapshot = await LoadSnapshotAsync("Order Platform Console");
        Assert.True(snapshot.Values.TryGetValue("app.title", out var stored));
        Assert.Equal("Order Platform Console", stored!.GetString());

        var (_, projectedEntries) = SharedSettingConfigurationProjection.Project(snapshot);
        Assert.Equal("Order Platform Console", projectedEntries[SystemSettingKeys.AppTitle]);
    }

    /// <summary>
    /// Loads a snapshot through the real shared loader over the real product registry. A
    /// <c>null</c> title override omits the <c>APP_TITLE</c> row entirely — the corpus an older
    /// release persisted — while any other value stores that title as a normal row.
    /// </summary>
    private static async Task<ServiceSettingSnapshot> LoadSnapshotAsync(string? titleOverride)
    {
        var values = InstallationTestSupport.BuildCompletedInstallationValues("app_title_admin")
            .Where(pair => titleOverride is not null || pair.Key != SystemSettingKeys.AppTitle)
            .ToDictionary();
        if (titleOverride is not null)
        {
            values[SystemSettingKeys.AppTitle] = titleOverride;
        }

        var masterKeyProvider = new BootstrapMasterKeyProvider(RootSecret);
        var rootKey = await new MasterKeyRootKeySource(masterKeyProvider).GetRootKeyAsync();
        var registry = SharedSettingComposition.CreateRegistry(isDevelopment: false);
        var serviceId = ServiceId.Parse(ServiceMantleComposition.ServiceIdentifier);
        var rows = values
            .Select(pair =>
            {
                var key = SharedSettingKeys.NormalizedByLegacyKey[pair.Key];
                registry.TryGetDefinition(key, out var definition);
                return new PersistedServiceSettingValue(
                    key,
                    version: 1,
                    definition!.ValueType,
                    definition.IsSensitive
                        ? new SensitiveValueProtector(serviceId, key).Protect(pair.Value, rootKey)
                        : pair.Value);
            })
            .ToList();

        var read = new ServiceSettingSnapshotRead(serviceId, version: 1, rows);
        using var loader = new ServiceSettingSnapshotLoader(
            serviceId,
            new RetiredSettingKeyFilterSource(new FixedSource(read)),
            registry,
            new ServiceSettingCurrentSnapshotAccessor(),
            SharedSettingComposition.CreateRootKeySource(masterKeyProvider));
        var refresh = await loader.RefreshAsync();
        Assert.True(refresh.Succeeded, string.Join(
            ", ", refresh.Errors.Select(error => $"{error.Key}: {error.ErrorCode}")));
        return refresh.Snapshot!;
    }

    private sealed class FixedSource(ServiceSettingSnapshotRead read) : IServiceSettingSnapshotSource
    {
        public ValueTask<ServiceSettingSnapshotRead> LoadAsync(
            ServiceId serviceId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(read);
    }
}
