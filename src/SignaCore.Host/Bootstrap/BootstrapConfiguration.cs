using SignaCore.Database;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// The validated bootstrap: the only deployment-provided application secrets in the system.
/// </summary>
/// <param name="Database">Provider, server version, and connection string.</param>
/// <param name="RootSecret">
/// External root key used to derive both the RSA private-key protection key and the
/// configuration-protection key. Never logged, never echoed in diagnostics.
/// </param>
/// <param name="Origin">Human-readable source, used only for startup diagnostics.</param>
internal sealed record BootstrapConfiguration(
    DatabaseOptions Database,
    string RootSecret,
    string Origin)
{
    /// <summary>
    /// Database host (or SQLite file name) for startup diagnostics. Credentials and the rest of the
    /// connection string are never included.
    /// </summary>
    public string DatabaseEndpointForDiagnostics => BootstrapDiagnostics.DescribeEndpoint(Database);
}
