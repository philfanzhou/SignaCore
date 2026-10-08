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
            InstallationStores.ServiceId,
            // Retired keys are dropped from the stored read so a leftover row from an older
            // release cannot fail the diagnostic load with an unknown-key error.
            new RetiredSettingKeyFilterSource(new ServiceSettingStoreSnapshotSource(store, registry)),
            registry, new ServiceSettingCurrentSnapshotAccessor(), rootKey);
        Query = new ServiceSettingQueryService(registry, loader);
    }

    internal ServiceSettingQueryService Query { get; }

    /// <summary>
    /// One complete tolerant materialization for the diagnostics endpoint: the same isolated loader
    /// and accessor the current-values query uses, never the bootstrap/runtime authority. Only a
    /// fully successful materialization answers; any load, decrypt, or critical failure reports
    /// unavailability with no partial or stale data. The materialized values — including decrypted
    /// sensitive ones — exist only inside this call; the returned issues are closed key + error-code
    /// pairs with no values.
    /// </summary>
    internal async ValueTask<ManagementSettingDiagnostics> GetDiagnosticsAsync(
        CancellationToken cancellationToken)
    {
        var refresh = await loader.RefreshAsync(cancellationToken);
        if (!refresh.Succeeded || refresh.Snapshot is null)
            return ManagementSettingDiagnostics.Unavailable;

        var legacy = SignaCoreSettingCompositeValidator.BuildLegacySnapshot(refresh.Snapshot.Values);
        return ManagementSettingDiagnostics.Success(
            refresh.Snapshot.Version,
            SignaCoreSettingCompositeValidator.ValidateOptionalSettings(legacy).ToList());
    }

    public void Dispose() => loader.Dispose();
}

/// <summary>
/// The diagnostics read result: the version the complete save was observed at, the closed issue
/// list of that saved version's unusable optional rules, or an explicit unavailability with
/// nothing else. Issues never claim to describe the running sink.
/// </summary>
internal sealed record ManagementSettingDiagnostics(
    bool Succeeded, long Version, IReadOnlyList<ServiceSettingValidationError> Issues)
{
    internal static ManagementSettingDiagnostics Unavailable { get; } =
        new(false, 0, Array.Empty<ServiceSettingValidationError>());

    internal static ManagementSettingDiagnostics Success(
        long version, IReadOnlyList<ServiceSettingValidationError> issues) =>
        new(true, version, issues);
}
