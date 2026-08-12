using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using SignaCore.Domain.Keys;
using SignaCore.Host;
using SignaCore.Tests.Domain.Keys;
using Xunit;

namespace SignaCore.Tests.Host;

[Collection(MasterKeyStateCollection.Name)]
public class ProductionSecurityDefaultsTests
{
    [Fact]
    public void AdminCookie_InProduction_IsAlwaysSecure()
    {
        using var provider = BuildServices(Environments.Production);

        var options = provider
            .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);

        Assert.Equal(CookieSecurePolicy.Always, options.Cookie.SecurePolicy);
        Assert.True(options.Cookie.HttpOnly);
        Assert.Equal(SameSiteMode.Lax, options.Cookie.SameSite);
    }

    [Fact]
    public void AdminCookie_InDevelopment_FollowsRequestScheme()
    {
        using var provider = BuildServices(Environments.Development);

        var options = provider
            .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);

        Assert.Equal(CookieSecurePolicy.SameAsRequest, options.Cookie.SecurePolicy);
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
    public void ForwardedHeaders_TrustOnlyConfiguredProxy()
    {
        using var provider = BuildServices(
            Environments.Production,
            new Dictionary<string, string?>
            {
                ["ReverseProxy:KnownProxies:0"] = "10.20.30.40"
            });

        var options = provider.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;

        Assert.Contains(System.Net.IPAddress.Parse("10.20.30.40"), options.KnownProxies);
        Assert.Equal(1, options.ForwardLimit);
        Assert.True(options.RequireHeaderSymmetry);
    }

    [Fact]
    public void ForwardedHeaders_RejectInvalidConfiguredProxy()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
        {
            using var provider = BuildServices(
                Environments.Production,
                new Dictionary<string, string?>
                {
                    ["ReverseProxy:KnownProxies:0"] = "not-an-ip-address"
                });
            _ = provider.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;
        });

        Assert.Contains("invalid IP address", exception.Message);
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

    [Fact]
    public void ProductionStartup_RejectsDevelopmentDatabaseFallback()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            BuildServices(
                Environments.Production,
                new Dictionary<string, string?>
                {
                    ["Database:ConnectionString"] =
                        "Host=localhost;Port=5432;Database=signacore;Username=postgres"
                }));

        Assert.Contains("development database", exception.Message);
    }

    [Fact]
    public void ProductionMasterKeyProvider_RejectsMissingEnvironmentSecretWhenResolved()
    {
        var previous = Environment.GetEnvironmentVariable("RSA_MASTER_KEY");
        try
        {
            Environment.SetEnvironmentVariable("RSA_MASTER_KEY", null);
            using var provider = BuildServices(Environments.Production);

            var exception = Assert.Throws<InvalidOperationException>(() =>
                provider.GetRequiredService<IMasterKeyProvider>());

            Assert.Contains("RSA_MASTER_KEY is required", exception.Message);
        }
        finally
        {
            Environment.SetEnvironmentVariable("RSA_MASTER_KEY", previous);
        }
    }

    private static ServiceProvider BuildServices(
        string environmentName,
        IDictionary<string, string?>? overrides = null)
    {
        var values = new Dictionary<string, string?>
        {
            ["Database:Provider"] = "PostgreSQL",
            ["Database:ServerVersion"] = "15",
            ["Database:ConnectionString"] =
                "Host=localhost;Database=identity;Username=postgres;Password=test",
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
            new StubHostEnvironment { EnvironmentName = environmentName });
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
