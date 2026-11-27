using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using SignaCore.Database;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

public class CallbackUrlValidatorRegistrationTests
{
    [Fact]
    public async Task AddIdentityInfrastructure_ByDefault_AcceptsPlainHttpCallbacks()
    {
        // RequireHttps defaults to false (ADR 0008): the transport is a deployment decision, and
        // the SSRF gate (private-address refusal) carries the protection.
        var validator = ResolveValidator(allowPrivateAddresses: null);

        var result = await validator.ValidateAsync("http://93.184.216.34/callback", TestContext.Current.CancellationToken);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task AddIdentityInfrastructure_WithAllowPrivateAddressesFalse_RejectsPrivateCallbackAddresses()
    {
        var validator = ResolveValidator(allowPrivateAddresses: false);

        var result = await validator.ValidateAsync("https://10.0.0.1/callback", TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Contains("private/internal IP", result.ErrorMessage);
    }

    [Fact]
    public async Task AddIdentityInfrastructure_InDevelopmentByDefault_AllowsPrivateHttpCallbacks()
    {
        var validator = ResolveValidator(
            allowPrivateAddresses: null,
            environmentName: Environments.Development);

        Assert.True((await validator.ValidateAsync("http://10.0.0.1/callback", TestContext.Current.CancellationToken)).IsValid);
    }

    [Fact]
    public async Task AddIdentityInfrastructure_WithExplicitProductionOverrides_AllowsPrivateHttpCallbacks()
    {
        var validator = ResolveValidator(
            allowPrivateAddresses: true,
            requireHttps: false);

        Assert.True((await validator.ValidateAsync("http://10.0.0.1/callback", TestContext.Current.CancellationToken)).IsValid);
    }

    private static CallbackUrlValidator ResolveValidator(
        bool? allowPrivateAddresses,
        string environmentName = "Production",
        bool? requireHttps = null)
    {
        var values = new Dictionary<string, string?>
        {
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
            new StubHostEnvironment { EnvironmentName = environmentName },
            new DatabaseOptions
            {
                Provider = "PostgreSQL",
                ServerVersion = "15",
                ConnectionString = "Host=localhost;Database=identity;Username=postgres;Password=test"
            },
            new BootstrapMasterKeyProvider("callback-validator-registration-tests-root-secret"));

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
