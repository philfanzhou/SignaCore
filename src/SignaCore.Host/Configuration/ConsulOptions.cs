namespace SignaCore.Host.Configuration;

/// <summary>
/// Consul service registration/discovery settings.
/// <para>
/// Consul KV is no longer a configuration authority: the business database holds global settings,
/// and there is no local plaintext configuration cache any more. What remains is optional service
/// discovery, whose own runtime settings are themselves loaded from <c>system_settings</c> after the
/// database bootstrap phase.
/// </para>
/// </summary>
internal sealed class ConsulOptions
{
    public string Host { get; set; } = "host.docker.internal";

    public int Port { get; set; } = 8500;

    /// <summary>Consul ACL token. Stored as a secret setting; never logged in clear.</summary>
    public string? Token { get; set; }

    public bool DiscoveryEnabled { get; set; }

    public static bool IsDiscoveryEnabled(IConfiguration configuration) =>
        configuration.GetValue(SystemSettingKeys.ConsulDiscoveryEnabled, false);

    public static ConsulOptions Bind(IConfiguration configuration)
    {
        var options = new ConsulOptions();
        configuration.GetSection("Consul").Bind(options);
        options.DiscoveryEnabled = IsDiscoveryEnabled(configuration);
        return options;
    }
}
