using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using ServiceMantle.Configuration;
using ServiceMantle.Diagnostics.Export.Otlp;
using ServiceMantle.Web;
using SignaCore.Host.Security;

namespace SignaCore.Host.Telemetry;

/// <summary>
/// The normal host's telemetry composition: every provider, instrumentation, and exporter is
/// registered by ServiceMantle; SignaCore only selects which of its own signals join them.
/// </summary>
/// <remarks>
/// <para>
/// ServiceMantle owns the ASP.NET Core and HttpClient tracing, the runtime metrics, the OTLP trace
/// exporter, and the authorized Prometheus scrape endpoint, and it writes the only resource
/// attributes (<c>service.name</c>, <c>service.version</c>, <c>service.instance.id</c>).
/// </para>
/// <para>
/// Choosing signals is not shared infrastructure, so it stays here: the product meter and activity
/// source <c>SignaCore</c>, and the ASP.NET Core meters the former
/// <c>AddAspNetCoreInstrumentation()</c> metrics registration enabled, so the HTTP, Kestrel,
/// routing, and rate-limiting series keep being exported.
/// </para>
/// </remarks>
internal static class SignaCoreTelemetry
{
    /// <summary>The product meter and activity source name.</summary>
    internal const string ProductSignalName = "SignaCore";

    /// <summary>The scrape endpoint path, unchanged from the former local exporter.</summary>
    internal const string MetricsPath = "/metrics";

    /// <summary>
    /// The meters OpenTelemetry.Instrumentation.AspNetCore 1.19.0 enables for metrics on .NET 8+
    /// through <c>AddAspNetCoreInstrumentation()</c>; listed explicitly now that the metrics side of
    /// that call is gone.
    /// </summary>
    internal static readonly IReadOnlyList<string> AspNetCoreMeterNames =
    [
        "Microsoft.AspNetCore.Hosting",
        "Microsoft.AspNetCore.Server.Kestrel",
        "Microsoft.AspNetCore.Http.Connections",
        "Microsoft.AspNetCore.Routing",
        "Microsoft.AspNetCore.Diagnostics",
        "Microsoft.AspNetCore.RateLimiting",
        "Microsoft.AspNetCore.Authentication",
        "Microsoft.AspNetCore.Authorization",
        "Microsoft.AspNetCore.Identity",
        "Microsoft.AspNetCore.MemoryPool",
        "Microsoft.AspNetCore.Components",
        "Microsoft.AspNetCore.Components.Lifecycle",
        "Microsoft.AspNetCore.Components.Server.Circuits",
        "Microsoft.AspNetCore.SignalR.Server",
    ];

    /// <summary>
    /// Registers the ServiceMantle telemetry capabilities and the SignaCore signal selection. The
    /// OTLP endpoint is read from the activated setting snapshot, never from
    /// <c>IConfiguration</c>; a stored value OTLP cannot use keeps the exporter off and is reported
    /// by <see cref="WriteOtlpWarning"/> once the host is built.
    /// </summary>
    internal static OtlpSettingState AddSignaCoreTelemetry(
        this ServiceMantleBuilder mantle,
        ServiceSettingSnapshot snapshot)
    {
        mantle.AddServiceMantleMetrics();
        mantle.AddOpenTelemetryInstrumentation(options =>
        {
            options.Enabled = true;
            options.EnableAspNetCoreTracing = true;
            options.EnableHttpClientTracing = true;
            options.EnableRuntimeMetrics = true;
        });
        mantle.AddOpenTelemetryPrometheusEndpoint(options =>
        {
            options.Enabled = true;
            options.EndpointPath = MetricsPath;
            options.AuthorizationPolicyName = GatewayAppAuthenticationDefaults.Policy;
        });

        var otlp = mantle.AddOpenTelemetryOtlpExporterFromSettings(snapshot, options =>
        {
            // Traces only, over gRPC and without an authentication header, as before; metrics
            // are scraped through Prometheus and never pushed. The snapshot owns the endpoint.
            options.Traces.Enabled = true;
            options.Traces.Protocol = OtlpProtocol.Grpc;
        });

        // Each selection is a registered service the shared meter provider reads when it is
        // built, so the product selection is one removable, checkable fact.
        mantle.Services.AddSingleton(new MeterSelection([ProductSignalName]));
        mantle.Services.AddSingleton(new MeterSelection(AspNetCoreMeterNames));
        mantle.Services.ConfigureOpenTelemetryMeterProvider(static (services, metrics) =>
        {
            foreach (var selection in services.GetServices<MeterSelection>())
            {
                metrics.AddMeter([.. selection.MeterNames]);
            }
        });
        mantle.Services.ConfigureOpenTelemetryTracerProvider(tracing => tracing.AddSource(ProductSignalName));
        return otlp;
    }

    /// <summary>Writes the fixed, address-free warning for a stored OTLP endpoint the host cannot use.</summary>
    internal static void WriteOtlpWarning(ILogger logger, OtlpSettingState state)
    {
        if (!state.IsUnusable)
        {
            return;
        }

        logger.LogWarning(
            "OTLP trace export is disabled because the stored OpenTelemetry:OtlpEndpoint is not an " +
            "absolute https URL without user info, query, or fragment. Correct it in the settings " +
            "page and restart the service.");
    }

    /// <summary>Meters SignaCore selects for export through the shared ServiceMantle meter provider.</summary>
    internal sealed record MeterSelection(IReadOnlyList<string> MeterNames);
}
