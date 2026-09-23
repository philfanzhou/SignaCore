using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using SignaCore.Host.Configuration;
using Steeltoe.Common.Discovery;
using Steeltoe.Discovery.Consul;
using Steeltoe.Discovery.Consul.Configuration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

/// <summary>
/// Characterization of the current Consul wiring — the pre-switch state, not the target design.
/// <para>
/// Pins the service-registration decision of <see cref="ProgramConsulExtensions"/> on both sides
/// of <c>Consul:Discovery:Enabled</c>, and pins how the settings catalog's persisted defaults
/// (<c>register=false</c>, <c>deregister=false</c>) explicitly override the Steeltoe client's own
/// defaults once the snapshot is projected into configuration. A pure query-only client is the
/// shipped default: nothing registers on startup and nothing deregisters on shutdown.
/// </para>
/// </summary>
public sealed class ConsulDiscoveryCharacterizationTests
{
    [Fact]
    public void AddConsulDiscoveryIfEnabled_WhenDiscoveryIsDisabled_RegistersNoConsulServices()
    {
        var services = new ServiceCollection();
        var before = services.Count;

        services.AddConsulDiscoveryIfEnabled(BuildConfiguration("false"));

        Assert.Equal(before, services.Count);
    }

    [Fact]
    public void AddConsulDiscoveryIfEnabled_WhenDiscoveryIsEnabled_RegistersTheSteeltoeClient()
    {
        var services = new ServiceCollection();

        services.AddConsulDiscoveryIfEnabled(BuildConfiguration("true"));

        Assert.Contains(services, descriptor => descriptor.ServiceType == typeof(IDiscoveryClient));
        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(IHostedService) &&
            descriptor.ImplementationType?.Name == "DiscoveryClientHostedService");
    }

    /// <summary>
    /// The catalog defaults that reach the Consul client as explicit configuration values. These
    /// are runtime facts of the shipped corpus: flipping only <c>consul.discovery.enabled</c> on
    /// leaves the host a query-only discovery client that never registers nor deregisters.
    /// </summary>
    [Fact]
    public void CatalogDefaults_ThatOverrideTheSteeltoeClient_ArePinned()
    {
        var defaults = ServiceSettingDefinitions.BuildLegacyDefaults();

        Assert.Equal("false", defaults[SystemSettingKeys.ConsulDiscoveryEnabled]);
        Assert.Equal("false", defaults[SystemSettingKeys.ConsulDiscoveryRegister]);
        Assert.Equal("false", defaults[SystemSettingKeys.ConsulDiscoveryDeregister]);
        Assert.Equal("SignaCore", defaults[SystemSettingKeys.ConsulDiscoveryServiceName]);
        Assert.Equal("/health/ready", defaults[SystemSettingKeys.ConsulDiscoveryHealthCheckPath]);
        Assert.Equal("host.docker.internal", defaults[SystemSettingKeys.ConsulHost]);
        Assert.Equal("8500", defaults[SystemSettingKeys.ConsulPort]);
        Assert.Equal(string.Empty, defaults[SystemSettingKeys.ConsulToken]);
    }

    /// <summary>
    /// Steeltoe binds the projected snapshot itself: the persisted <c>register=false</c> and
    /// <c>deregister=false</c> win over the client's own <c>Register=true</c>/<c>Deregister=true</c>
    /// defaults, retry stays off (single fail-fast attempt), and the registration payload a live
    /// agent would receive is derived from the catalog: instance id <c>SignaCore-{8 digits}</c>
    /// under service name <c>SignaCore</c>, with a health check pointing at <c>/health/ready</c>.
    /// </summary>
    [Fact]
    public void SteeltoeBoundToTheProjectedCatalog_StaysAQueryOnlyClientWithTheCatalogPayload()
    {
        const string token = "consul-token-for-characterization";
        var entries = ServiceSettingDefinitions.BuildLegacyDefaults()
            .ToDictionary(pair => pair.Key, pair => pair.Value);
        entries[SystemSettingKeys.ConsulDiscoveryEnabled] = "true";
        entries[SystemSettingKeys.ConsulHost] = "127.0.0.1";
        entries[SystemSettingKeys.ConsulPort] = "18500";
        entries[SystemSettingKeys.ConsulToken] = token;
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(entries!)
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddConsulDiscoveryClient();
        using var provider = services.BuildServiceProvider();

        var discovery = provider.GetRequiredService<IOptionsMonitor<ConsulDiscoveryOptions>>().CurrentValue;
        Assert.True(discovery.Enabled);
        Assert.False(discovery.Register);
        Assert.False(discovery.Deregister);
        Assert.False(discovery.Retry.Enabled);
        Assert.True(discovery.FailFast);
        Assert.Equal("SignaCore", discovery.ServiceName);
        Assert.Equal("/health/ready", discovery.HealthCheckPath);
        Assert.True(discovery.RegisterHealthCheck);
        // The post-configure step generates the default instance id — ServiceName, a separator,
        // and 8 random digits, normalized for Consul (the separator it emits is a hyphen).
        Assert.Matches("^SignaCore-[0-9]{8}$", discovery.InstanceId);

        var consulClient = provider.GetRequiredService<IOptions<Steeltoe.Discovery.Consul.Configuration.ConsulOptions>>().Value;
        Assert.Equal("127.0.0.1", consulClient.Host);
        Assert.Equal(18500, consulClient.Port);
        Assert.Equal(token, consulClient.Token);

        // Resolving the client constructs the registrar too; with the persisted register=false it
        // performs no registration attempt, so the local instance is observable without an agent.
        // The health check URL itself is verified end to end by the in-process agent tests in
        // SignaCore.IntegrationTests.
        var discoveryClient = provider.GetRequiredService<IDiscoveryClient>();
        var localInstance = discoveryClient.GetLocalServiceInstance();
        Assert.NotNull(localInstance);
        Assert.Equal("SignaCore", localInstance!.ServiceId);
        Assert.Matches("^SignaCore-[0-9]{8}$", localInstance.InstanceId);
    }

    private static IConfiguration BuildConfiguration(string discoveryEnabled) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [SystemSettingKeys.ConsulDiscoveryEnabled] = discoveryEnabled
            })
            .Build();
}
