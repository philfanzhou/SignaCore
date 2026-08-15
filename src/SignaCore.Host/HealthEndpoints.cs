namespace SignaCore.Host;

/// <summary>
/// Liveness and readiness have different deployment meanings, and conflating them is what lets a
/// pending-setup instance receive authentication traffic.
/// </summary>
public static class HealthEndpoints
{
    /// <summary>
    /// The process is running and can reach the database well enough to determine installation
    /// state. A launcher deploying a brand-new instance waits for this so the setup page can be
    /// reached.
    /// </summary>
    public const string Live = "/health/live";

    /// <summary>
    /// Installation is completed, the configuration snapshot is valid, database initialization is
    /// complete, and signing keys are ready. Load balancers and orchestrators must use this one.
    /// </summary>
    public const string Ready = "/health/ready";

    /// <summary>Compatibility alias for <see cref="Ready"/>.</summary>
    public const string Legacy = "/health";
}
