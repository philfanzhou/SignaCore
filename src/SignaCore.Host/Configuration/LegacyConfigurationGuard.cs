using SignaCore.Database;

namespace SignaCore.Host.Configuration;

/// <summary>
/// After the change, the database is authoritative for global settings and the bootstrap file is
/// authoritative for the database connection. Deployment-provided overrides of either are legacy and
/// are reported for a compatibility period so operators can remove them from their launchers.
/// </summary>
internal static class LegacyConfigurationGuard
{
    /// <summary>
    /// Managed settings still supplied by appsettings, environment variables, or the command line.
    /// The database snapshot is layered on top of them, so these values are inert — the warning
    /// exists so an operator editing them stops expecting an effect.
    /// </summary>
    public static IReadOnlyList<string> FindManagedOverrides(IConfiguration preSnapshotConfiguration)
    {
        return SystemSettingsCatalog.Definitions
            .Select(definition => definition.Key)
            .Where(key =>
                preSnapshotConfiguration[key] is not null ||
                preSnapshotConfiguration.GetSection(key).GetChildren().Any())
            .OrderBy(key => key, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// Database connection settings supplied outside the bootstrap file. They are ignored; the
    /// bootstrap file is the only place the connection is read from.
    /// </summary>
    public static bool HasDatabaseSectionOverride(IConfiguration preSnapshotConfiguration) =>
        preSnapshotConfiguration.GetSection(DatabaseOptions.SectionName).GetChildren().Any();
}
