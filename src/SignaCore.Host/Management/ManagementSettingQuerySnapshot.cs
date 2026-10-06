using ServiceMantle.Configuration;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;

namespace SignaCore.Host.Management;

/// <summary>Owns the management observation loader, separate from the activated runtime snapshot.</summary>
internal sealed class ManagementSettingQuerySnapshot : IDisposable
{
    private readonly ServiceSettingSnapshotLoader loader;

    internal ManagementSettingQuerySnapshot(
        IServiceSettingStore store, IServiceSettingRootKeySource rootKey, bool isDevelopment)
    {
        var registry = SharedSettingComposition.CreateRegistry(isDevelopment);
        loader = new ServiceSettingSnapshotLoader(
            InstallationStores.ServiceId, new ServiceSettingStoreSnapshotSource(store, registry),
            registry, new ServiceSettingCurrentSnapshotAccessor(), rootKey);
        Query = new ServiceSettingQueryService(registry, loader);
    }

    internal ServiceSettingQueryService Query { get; }

    public void Dispose() => loader.Dispose();
}
