namespace SignaCore.Host.Installation;

/// <summary>
/// What the bootstrap phase concluded about this database. The distinction between
/// <see cref="PendingSetup"/> and <see cref="LegacyImportRequired"/> is a security boundary: a
/// database that already owns accounts must never expose unauthenticated first-run setup.
/// </summary>
internal enum InstallationPhase
{
    /// <summary>A new, empty database. Setup Mode runs and the one-time setup code gates completion.</summary>
    PendingSetup,

    /// <summary>Installation is complete; the normal host runs against the stored snapshot.</summary>
    Completed,

    /// <summary>
    /// No installation state, but meaningful business data exists. This is an upgrade of a
    /// pre-change deployment: the protected legacy import path runs, never Setup Mode.
    /// </summary>
    LegacyImportRequired
}
