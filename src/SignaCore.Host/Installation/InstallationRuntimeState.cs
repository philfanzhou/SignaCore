namespace SignaCore.Host.Installation;

/// <summary>
/// Process-wide view of the installation, published for health checks and diagnostics. It reflects
/// what the bootstrap phase decided; it is not a second source of truth. Whether an installation
/// completed is always read from the persisted <c>service_installations</c> row, never from a
/// flag here: a losing instance of a completion race must observe the winner's commit.
/// </summary>
internal sealed class InstallationRuntimeState
{
    public InstallationRuntimeState(
        InstallationPhase phase,
        Guid installationId,
        int configurationVersion)
    {
        Phase = phase;
        InstallationId = installationId;
        ConfigurationVersion = configurationVersion;
    }

    public InstallationPhase Phase { get; }

    public Guid InstallationId { get; }

    /// <summary>The <c>configuration_version</c> the running snapshot was loaded at.</summary>
    public int ConfigurationVersion { get; }
}
