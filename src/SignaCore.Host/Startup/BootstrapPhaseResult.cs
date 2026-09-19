using ServiceMantle.Bootstrap;
using ServiceMantle.Configuration;
using SignaCore.Domain.Keys;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;

namespace SignaCore.Host.Startup;

internal sealed record BootstrapPhaseResult(
    BootstrapConfiguration Bootstrap,
    InstallationPhase Phase,
    InstallationRuntimeState RuntimeState,
    IMasterKeyProvider MasterKeyProvider,
    IConfigurationProtector ConfigurationProtector,
    SystemSettingsStore SettingsStore,
    SystemSettingsSnapshot? Snapshot,
    ServiceSettingCurrentSnapshotAccessor CurrentSnapshotAccessor,
    string? PlaintextSetupCode,
    DateTimeOffset? SetupCodeExpiresAt);
