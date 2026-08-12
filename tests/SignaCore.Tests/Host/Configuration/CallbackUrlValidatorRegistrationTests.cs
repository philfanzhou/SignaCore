using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using SignaCore.Domain;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

public class CallbackUrlValidatorRegistrationTests
{
    [Fact]
    public void AddIdentityInfrastructure_InProductionByDefault_RejectsNonHttpsCallbacks()
    {
        var validator = ResolveValidator(allowPrivateAddresses: null);

        var result = validator.Validate("http://10.0.0.1/callback");

        Assert.False(result.IsValid);
        Assert.Contains("HTTPS", result.ErrorMessage);
    }

    [Fact]
    public void AddIdentityInfrastructure_WithAllowPrivateAddressesFalse_RejectsPrivateCallbackAddresses()
    {
        var validator = ResolveValidator(allowPrivateAddresses: false);

        var result = validator.Validate("https://10.0.0.1/callback");

        Assert.False(result.IsValid);
        Assert.Contains("private/internal IP", result.ErrorMessage);
    }

    [Fact]
    public void AddIdentityInfrastructure_InDevelopmentByDefault_AllowsPrivateHttpCallbacks()
    {
        var validator = ResolveValidator(
            allowPrivateAddresses: null,
            environmentName: Environments.Development);

        Assert.True(validator.Validate("http://10.0.0.1/callback").IsValid);
    }

    [Fact]
    public void AddIdentityInfrastructure_WithExplicitProductionOverrides_AllowsPrivateHttpCallbacks()
    {
        var validator = ResolveValidator(
            allowPrivateAddresses: true,
            requireHttps: false);

        Assert.True(validator.Validate("http://10.0.0.1/callback").IsValid);
    }

    private static CallbackUrlValidator ResolveValidator(
        bool? allowPrivateAddresses,
        string environmentName = "Production",
        bool? requireHttps = null)
    {
        var values = new Dictionary<string, string?>
        {
            ["Database:Provider"] = "PostgreSQL",
            ["Database:ServerVersion"] = "15",
            ["Database:ConnectionString"] =
                "Host=localhost;Database=identity;Username=postgres;Password=test",
            ["Jwt:Issuer"] = "https://identity.example.test"
        };

        if (allowPrivateAddresses.HasValue)
        {
            values["Callback:AllowPrivateAddresses"] =
                allowPrivateAddresses.Value ? "true" : "false";
        }

        if (requireHttps.HasValue)
        {
            values["Callback:RequireHttps"] = requireHttps.Value ? "true" : "false";
        }

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityInfrastructure(
            configuration,
            new StubHostEnvironment { EnvironmentName = environmentName });

        return services.BuildServiceProvider().GetRequiredService<CallbackUrlValidator>();
    }

    private sealed class StubHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "SignaCore.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } =
            new NullFileProvider();
    }
}
