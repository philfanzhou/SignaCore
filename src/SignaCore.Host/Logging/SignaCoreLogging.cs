using ServiceMantle.Configuration;
using ServiceMantle.Logging.Pipeline;
using ServiceMantle.Logging.Remote;
using ServiceMantle.Logging;

namespace SignaCore.Host.Logging;

/// <summary>
/// The one logging composition of all three hosts: the ServiceMantle Serilog pipeline, whose
/// structured-field sanitization cannot be turned off, and — on the normal host only — the shared
/// Grafana Loki sink behind the same sanitizer.
/// </summary>
/// <remarks>
/// SignaCore owns no sink, enricher, formatter, or sanitizer of its own. Category levels come from
/// the <c>Logging:LogLevel</c> section of the host configuration; the pipeline minimum stays at
/// Information. Service identity fields come from the ServiceMantle request log scope.
/// </remarks>
internal static class SignaCoreLogging
{
    /// <summary>
    /// The Console-only pipeline of the Bootstrap Configuration Mode and Setup hosts, which have no
    /// setting snapshot and therefore never ship logs anywhere else.
    /// </summary>
    internal static void AddSignaCoreConsoleLogging(this IHostApplicationBuilder builder) =>
        builder.AddServiceMantleSerilog(ConfigureSerilog);

    /// <summary>
    /// The normal host's pipeline. Loki is enabled only for an absolute HTTPS endpoint together with
    /// a usable Authorization value; every other stored combination keeps Loki off, and the caller
    /// reports an unusable one through <see cref="WriteLokiWarning"/> once the host is built.
    /// </summary>
    /// <remarks>
    /// The values are read from the activated setting snapshot itself, never from
    /// <c>IConfiguration</c>, so no launcher, environment variable, or appsettings file can supply a
    /// Loki address or credential.
    /// </remarks>
    internal static GrafanaLokiSettingState AddSignaCoreLogging(
        this IHostApplicationBuilder builder,
        ServiceSettingSnapshot snapshot)
    {
        builder.AddServiceMantleSerilog(ConfigureSerilog);

        return builder.AddServiceMantleGrafanaLokiFromSettings(snapshot);
    }

    /// <summary>
    /// Writes the fixed startup warning for stored Loki settings the host could not use. Only the
    /// category is logged — never the address or the credential.
    /// </summary>
    internal static void WriteLokiWarning(ILogger logger, GrafanaLokiSettingState state)
    {
        if (!state.IsUnusable)
        {
            return;
        }

        logger.LogWarning(
            "Remote log shipping to Loki is disabled because the stored Loki settings are not usable " +
            "({LokiSettingProblem}). Loki requires an absolute https URL and an Authorization value; " +
            "correct both in the settings page and restart the service.",
            state.Status == GrafanaLokiSettingStatus.EndpointInvalid ? "endpoint_not_https" : state.Category);
    }

    private static void ConfigureSerilog(SerilogOptions options) =>
        options.MinimumLevel = LogLevel.Information;
}
