using Steeltoe.Discovery.Consul;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Optional Consul service registration. There is no Consul configuration source any more — the KV
/// loader and its plaintext local cache were removed when the business database became the
/// configuration authority.
/// </summary>
internal static class ProgramConsulExtensions
{
    /// <summary>
    /// Registers the Steeltoe Consul discovery client when <c>Consul:Discovery:Enabled</c> is true in
    /// the active settings snapshot. Steeltoe binds the <c>Consul:</c> and <c>Consul:Discovery:</c>
    /// sections directly, and those keys now come from <c>system_settings</c>.
    /// </summary>
    public static IServiceCollection AddConsulDiscoveryIfEnabled(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        if (!ConsulOptions.IsDiscoveryEnabled(configuration))
        {
            return services;
        }

        services.AddConsulDiscoveryClient();
        return services;
    }
}
