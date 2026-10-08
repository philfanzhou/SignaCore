using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ServiceMantle.Web.Management;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Host.Management;
using SignaCore.Host;
using SignaCore.Tests.Domain.Keys;
using Xunit;

namespace SignaCore.Tests.Host;

[Collection(MasterKeyStateCollection.Name)]
public class ProductionSecurityDefaultsTests
{
    [Fact]
    public void AdminCookie_FollowsTheServiceMantleWebDefaults()
    {
        using var provider = BuildManagementSessionServices();

        var options = provider
            .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(ManagementSessionDefaults.AuthenticationScheme);

        // Since ServiceMantle.Web 0.3.2 the management cookie keeps the shared defaults: the
        // Secure attribute follows the request scheme (transport is a deployment decision, so no
        // code-level Always policy is written back) and the name carries no __Host- prefix, which
        // ends every existing admin session exactly once at the upgrade. HttpOnly stays on and
        // SameSite is never relaxed to None.
        Assert.Equal(CookieSecurePolicy.SameAsRequest, options.Cookie.SecurePolicy);
        Assert.True(options.Cookie.HttpOnly);
        Assert.NotEqual(SameSiteMode.None, options.Cookie.SameSite);
        Assert.Equal(ManagementSessionDefaults.CookieName, options.Cookie.Name);
        Assert.Equal("ServiceMantle.Management", options.Cookie.Name);
    }

    [Fact]
    public void AdminCookie_KeepsTheLegacyTwelveHourSlidingLifetime()
    {
        using var provider = BuildManagementSessionServices();

        var options = provider
            .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(ManagementSessionDefaults.AuthenticationScheme);

        Assert.Equal(TimeSpan.FromHours(12), options.ExpireTimeSpan);
        Assert.True(options.SlidingExpiration);
    }

    [Fact]
    public void AdminCors_InProductionWithoutConfiguredOrigins_DoesNotAllowCredentials()
    {
        using var provider = BuildServices(Environments.Production);

        var policy = provider.GetRequiredService<IOptions<CorsOptions>>()
            .Value.GetPolicy("AdminWeb");

        Assert.NotNull(policy);
        Assert.Empty(policy.Origins);
        Assert.False(policy.SupportsCredentials);
    }

    [Fact]
    public void ProductionStartup_RejectsNonHttpsIssuer()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            BuildServices(
                Environments.Production,
                new Dictionary<string, string?> { ["Jwt:Issuer"] = "SignaCore" }));

        Assert.Contains("absolute HTTPS URL", exception.Message);
    }

    [Fact]
    public void ProductionStartup_AllowsExplicitLegacyIssuerCompatibilitySwitch()
    {
        using var provider = BuildServices(
            Environments.Production,
            new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "SignaCore",
                ["Security:AllowNonHttpsIssuer"] = "true"
            });

        Assert.NotNull(provider);
    }

    [Fact]
    public void ProductionStartup_RejectsIssuerThatDiffersFromPublicBaseUrl()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            BuildServices(
                Environments.Production,
                new Dictionary<string, string?>
                {
                    ["Jwt:Issuer"] = "https://issuer.example.test",
                    [PublicOrigin.ConfigurationKey] = "https://public.example.test"
                }));

        Assert.Contains("must match", exception.Message);
    }

    [Fact]
    public void ProductionStartup_AcceptsIssuerMatchingPublicBaseUrl()
    {
        using var provider = BuildServices(
            Environments.Production,
            new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "https://identity.example.test/",
                [PublicOrigin.ConfigurationKey] = "  https://identity.example.test  "
            });

        Assert.NotNull(provider);
    }

    private static ServiceProvider BuildServices(
        string environmentName,
        IDictionary<string, string?>? overrides = null)
    {
        // Database connection and root secret now come from the bootstrap file rather than from
        // application configuration, so they are passed directly instead of through IConfiguration.
        var values = new Dictionary<string, string?>
        {
            ["Jwt:Issuer"] = "https://identity.example.test"
        };
        foreach (var pair in overrides ?? new Dictionary<string, string?>())
        {
            values[pair.Key] = pair.Value;
        }

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityInfrastructure(
            configuration,
            new StubHostEnvironment { EnvironmentName = environmentName },
            new DatabaseOptions
            {
                Provider = "PostgreSQL",
                ServerVersion = "15",
                ConnectionString = "Host=localhost;Database=identity;Username=postgres;Password=test"
            },
            new BootstrapMasterKeyProvider("production-security-defaults-tests-root-secret"));
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// The normal host's management-session composition, exactly as Program.cs wires it: the
    /// management cookie the admin console rides is registered by AddSignaCoreManagementSession,
    /// not by AddIdentityInfrastructure.
    /// </summary>
    private static ServiceProvider BuildManagementSessionServices()
    {
        var databaseOptions = new DatabaseOptions
        {
            Provider = "PostgreSQL",
            ServerVersion = "15",
            ConnectionString = "Host=localhost;Database=identity;Username=postgres;Password=test"
        };
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSignaCoreServiceMantle().AddSignaCoreManagementSession(databaseOptions);
        return services.BuildServiceProvider();
    }

    private sealed class StubHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "SignaCore.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
