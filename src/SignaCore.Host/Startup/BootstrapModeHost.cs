using Microsoft.AspNetCore.RateLimiting;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Controllers;
using SignaCore.Host.HealthChecks;
using SignaCore.Host.Middleware;

namespace SignaCore.Host.Startup;

/// <summary>
/// The minimal host that runs when no bootstrap file exists.
/// <para>
/// It composes nothing that needs a database, because there is no database yet: no identity
/// services, no key management, no JWT, no CORS, no telemetry exporters. That is the whole point —
/// an instance in this state cannot accidentally answer an authentication request, so it reports
/// liveness, reports readiness as false, and serves exactly one workflow.
/// </para>
/// </summary>
internal static class BootstrapModeHost
{
    public static void ConfigureServices(WebApplicationBuilder builder, BootstrapCodeAuthority codeAuthority)
    {
        var services = builder.Services;

        services.AddSingleton(codeAuthority);
        services.AddSingleton<BootstrapConfigurationService>();

        // Liveness with no checks: the process is up and serving, which is exactly what a launcher
        // needs in order to wait for the bootstrap page to become reachable.
        services.AddHealthChecks();

        services.AddRateLimiter(options =>
        {
            // The bootstrap endpoints are the only unauthenticated writes that exist in this host,
            // and they open database connections, so the one-time code gets a tight per-IP budget.
            options.AddPolicy(BootstrapController.RateLimitPolicy, context =>
                System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
                    context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
                    {
                        AutoReplenishment = true,
                        PermitLimit = 5,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0
                    }));
            options.OnRejected = async (context, _) =>
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.HttpContext.Response.ContentType = "application/json";
                await context.HttpContext.Response.WriteAsync(
                    """{"status":429,"title":"Too Many Requests","detail":"Too many bootstrap attempts. Please try again later."}""");
            };
        });

        services.AddControllers();
    }

    public static void ConfigurePipeline(WebApplication app, int httpPort)
    {
        app.UseMiddleware<CorrelationIdMiddleware>();
        app.UseMiddleware<ExceptionHandlingMiddleware>();
        app.UseRateLimiter();
        app.UseMiddleware<BootstrapModeGateMiddleware>();

        app.MapHealthChecks(HealthEndpoints.Live);

        // Readiness must stay false so a load balancer never routes authentication traffic to an
        // instance that has not been told which database it belongs to.
        app.MapGet(HealthEndpoints.Ready, () => Results.Text(
            "Unhealthy",
            "text/plain",
            statusCode: StatusCodes.Status503ServiceUnavailable));
        app.MapGet(HealthEndpoints.Legacy, () => Results.Text(
            "Unhealthy",
            "text/plain",
            statusCode: StatusCodes.Status503ServiceUnavailable));

        app.MapControllers();

        AdminSpaBranch.Map(app, httpPort);
    }
}
