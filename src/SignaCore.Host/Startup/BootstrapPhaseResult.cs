using ServiceMantle.Bootstrap;
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
    string? PlaintextSetupCode,
    DateTimeOffset? SetupCodeExpiresAt);
