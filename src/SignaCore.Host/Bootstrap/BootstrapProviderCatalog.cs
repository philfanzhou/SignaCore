using SignaCore.Host.Models;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// The provider and server-version combinations <see cref="Database.DatabaseOptions.Validate"/>
/// accepts, published so the bootstrap form offers exactly what the backend will take rather than a
/// list that drifts out of step with it.
/// </summary>
internal static class BootstrapProviderCatalog
{
    public static IReadOnlyList<BootstrapProviderDescriptor> Descriptors { get; } =
    [
        new()
        {
            Provider = "PostgreSQL",
            ServerVersions = ["15", "16", "17"],
            DefaultPort = 5432
        },
        new()
        {
            Provider = "SQLite",
            ServerVersions = [],
            DefaultPort = null,
            // SQLite is a single-writer file. It is a legitimate choice for one instance and is
            // never presented as supporting active multi-instance operation.
            SingleInstanceOnly = true
        }
    ];
}
