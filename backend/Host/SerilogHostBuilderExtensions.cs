using Microsoft.Extensions.Hosting;
using Serilog;

namespace QuantumZhou.Identity.Host;

public static class SerilogHostBuilderExtensions
{
    public static IHostBuilder UseAgentSerilog(
        this IHostBuilder hostBuilder,
        string serviceName,
        string serviceVersion = "1.0.0")
    {
        return hostBuilder.UseSerilog((context, services, loggerConfiguration) =>
        {
            loggerConfiguration
                .Enrich.FromLogContext()
                .Enrich.WithMachineName()
                .Enrich.WithThreadId()
                .Enrich.WithProperty("ServiceName", serviceName)
                .Enrich.WithProperty("ServiceVersion", serviceVersion)
                .Enrich.WithProperty("InstanceId", Environment.MachineName)
                .ReadFrom.Configuration(context.Configuration)
                .ReadFrom.Services(services);
        });
    }
}
