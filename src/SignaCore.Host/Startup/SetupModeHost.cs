using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host.Configuration;
using SignaCore.Host.Controllers;
using SignaCore.Host.HealthChecks;
using SignaCore.Host.Installation;
using SignaCore.Host.Middleware;

namespace SignaCore.Host.Startup;

/// <summary>
/// The minimal host that runs while installation is <c>Pending</c>.
/// <para>
/// It composes only what first-run setup needs: the database, password hashing and policy, the setup
/// endpoints, health endpoints, and the static admin SPA. Nothing that depends on the (not yet
/// existing) configuration snapshot — JWT, CORS, LDAP, SMS, WeChat, telemetry exporters, key
/// management — is constructed here, which is precisely why setup cannot start a half-configured
/// identity service.
/// </para>
/// </summary>
internal static class SetupModeHost
{
    public static void ConfigureServices(
        WebApplicationBuilder builder,
        BootstrapPhaseResult bootstrap)
    {
        var services = builder.Services;

        services.AddSingleton(bootstrap.Bootstrap.Database);
        services.AddSingleton(bootstrap.RuntimeState);
        services.AddSingleton(bootstrap.MasterKeyProvider);
        services.AddSingleton(bootstrap.ConfigurationProtector);
        services.AddSingleton(bootstrap.SettingsStore);

        services.AddDbContext<IdentityDbContext>(options =>
            options.UseIdentityDatabase(bootstrap.Bootstrap.Database));

        services.RegisterPasswordHashingDefaults();
        services.AddScoped<InstallationSetupService>();

        services.AddHealthChecks()
            .AddDbContextCheck<IdentityDbContext>(
                "database",
                tags: [HealthCheckTags.Live]);

        services.AddRateLimiter(options =>
        {
            // Setup verification is the only unauthenticated write in the whole surface, so the
            // one-time code gets its own tight per-IP budget rather than the global one.
            options.AddPolicy(SetupController.RateLimitPolicy, context =>
                System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
                    context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
                    {
                        AutoReplenishment = true,
                        PermitLimit = 5,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0
                    }));
            // The bootstrap endpoints are mapped here too and answer "already configured"; their
            // policy still has to exist or the endpoint cannot be built.
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
                    """{"status":429,"title":"Too Many Requests","detail":"Too many setup attempts. Please try again later."}""");
            };
        });

        services.AddControllers();
    }

    public static void ConfigurePipeline(WebApplication app, int httpPort)
    {
        app.UseMiddleware<CorrelationIdMiddleware>();
        app.UseMiddleware<ExceptionHandlingMiddleware>();
        app.UseRateLimiter();
        app.UseMiddleware<SetupModeGateMiddleware>();

        // Liveness answers "can this process reach its database and determine state", which is
        // exactly what a launcher needs so it can wait for the setup page to become reachable.
        app.MapHealthChecks(HealthEndpoints.Live, new()
        {
            Predicate = registration => registration.Tags.Contains(HealthCheckTags.Live)
        });

        // Readiness must stay false during setup so a load balancer never routes authentication
        // traffic to an instance that has no configuration.
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
