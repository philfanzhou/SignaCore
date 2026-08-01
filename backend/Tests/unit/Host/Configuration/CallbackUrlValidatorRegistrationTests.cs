using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Host;
using Xunit;

namespace QuantumZhou.Identity.Tests.Host.Configuration;

public class CallbackUrlValidatorRegistrationTests
{
    [Fact]
    public void AddIdentityInfrastructure_ByDefault_AllowsPrivateCallbackAddresses()
    {
        var validator = ResolveValidator(allowPrivateAddresses: null);

        Assert.True(validator.Validate("http://10.0.0.1/callback").IsValid);
    }

    [Fact]
    public void AddIdentityInfrastructure_WithAllowPrivateAddressesFalse_RejectsPrivateCallbackAddresses()
    {
        var validator = ResolveValidator(allowPrivateAddresses: false);

        var result = validator.Validate("http://10.0.0.1/callback");

        Assert.False(result.IsValid);
        Assert.Contains("private/internal IP", result.ErrorMessage);
    }

    private static CallbackUrlValidator ResolveValidator(bool? allowPrivateAddresses)
    {
        var values = new Dictionary<string, string?>
        {
            ["Database:Provider"] = "PostgreSQL",
            ["Database:ServerVersion"] = "15",
            ["Database:ConnectionString"] =
                "Host=localhost;Database=identity;Username=postgres;Password=test"
        };

        if (allowPrivateAddresses.HasValue)
        {
            values["Callback:AllowPrivateAddresses"] =
                allowPrivateAddresses.Value ? "true" : "false";
        }

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityInfrastructure(configuration, new StubHostEnvironment());

        return services.BuildServiceProvider().GetRequiredService<CallbackUrlValidator>();
    }

    private sealed class StubHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "QuantumZhou.Identity.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } =
            new NullFileProvider();
    }
}
