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
        return ServiceSettingDefinitions.Table
            .Select(ServiceSettingDefinitions.LegacyKeyOf)
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

    /// <summary>
    /// Retired SMS environment variables from before the settings moved into the database. They no
    /// longer reach <c>SmsOptions</c>; a deployment that still sets them gets no effect and needs a
    /// warning instead.
    /// </summary>
    private static readonly string[] RetiredSmsEnvironmentVariables =
    [
        "SMS_BYPASS_CODE",
        "SMS_OTP_HMAC_KEY",
        "SMS_BYPASS_PHONES"
    ];

    /// <summary>
    /// Retired SMS environment variables that are still set. Their flat single-underscore names
    /// enter the configuration as flat keys that match no managed legacy key, so they need this
    /// explicit check. Presence only: the values are never returned or logged.
    /// </summary>
    public static IReadOnlyList<string> FindRetiredSmsEnvironmentVariables(
        IConfiguration preSnapshotConfiguration)
    {
        return RetiredSmsEnvironmentVariables
            .Where(name => preSnapshotConfiguration[name] is not null)
            .ToList();
    }
}
