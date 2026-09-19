using ServiceMantle.Audit;
using ServiceMantle.Configuration;
using SignaCore.Domain.Keys;

namespace SignaCore.Host.Configuration;

/// <summary>
/// The one composition point for the SignaCore product setting catalog on the shared ServiceMantle
/// contract, reused by the DI registrations and the bootstrap phase's self-built instances.
/// </summary>
/// <remarks>
/// The definition registry is a deterministic, stateless composition, so separate instances built
/// from this class are equivalent. The <see cref="ServiceSettingCurrentSnapshotAccessor"/>, by
/// contrast, is stateful: the bootstrap phase activates on one instance and pre-registers that
/// exact instance with DI so both observe the same process-local snapshot.
/// </remarks>
internal static class SharedSettingComposition
{
    /// <summary>The audit operator attributed to the one-shot legacy settings migration.</summary>
    internal static readonly ManagementAuditOperator MigrationOperator = ManagementAuditOperator.Create(
        WellKnownManagementAuditOperatorSources.System,
        "settings-migration");

    /// <summary>Builds the SignaCore definition registry with its composite validator.</summary>
    internal static ServiceSettingDefinitionRegistry CreateRegistry(bool isDevelopment) => new(
        [new ServiceSettingDefinitions()],
        [new SignaCoreSettingCompositeValidator(isDevelopment)]);

    /// <summary>Adapts the bootstrap master key to the shared sensitive-value root key contract.</summary>
    internal static MasterKeyRootKeySource CreateRootKeySource(IMasterKeyProvider masterKeyProvider) =>
        new(masterKeyProvider);
}
