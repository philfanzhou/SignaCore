namespace SignaCore.Host.Installation;

/// <summary>
/// Process-wide view of the installation, published for health checks, diagnostics, and the setup
/// endpoints. It reflects what the bootstrap phase decided; it is not a second source of truth.
/// </summary>
internal sealed class InstallationRuntimeState
{
    private int _setupCompleted;

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

    /// <summary>
    /// True once this process has committed first-run setup and is shutting down so a supervisor can
    /// restart it into the normal host. The browser polls status against this.
    /// </summary>
    public bool SetupCompleted => Volatile.Read(ref _setupCompleted) == 1;

    public void MarkSetupCompleted() => Interlocked.Exchange(ref _setupCompleted, 1);
}
