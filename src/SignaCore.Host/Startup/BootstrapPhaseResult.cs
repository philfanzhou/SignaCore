using ServiceMantle.Bootstrap;
using ServiceMantle.Configuration;
using SignaCore.Domain.Keys;
using SignaCore.Host.Installation;

namespace SignaCore.Host.Startup;

/// <param name="SharedSnapshot">
/// The activated shared snapshot of a completed installation; null while the installation is not
/// completed. The runtime authority is the process-shared accessor, this value is the bootstrap
/// activation's record of it.
/// </param>
/// <param name="ConfigurationEntries">
/// The shared snapshot projected onto the legacy colon-keyed configuration entries, layered onto
/// <c>IConfiguration</c> by the host; null while no snapshot was activated.
/// </param>
internal sealed record BootstrapPhaseResult(
    BootstrapConfiguration Bootstrap,
    InstallationPhase Phase,
    InstallationRuntimeState RuntimeState,
    IMasterKeyProvider MasterKeyProvider,
    ServiceSettingSnapshot? SharedSnapshot,
    IReadOnlyDictionary<string, string?>? ConfigurationEntries,
    ServiceSettingCurrentSnapshotAccessor CurrentSnapshotAccessor,
    string? PlaintextSetupCode,
    DateTimeOffset? SetupCodeExpiresAt);
