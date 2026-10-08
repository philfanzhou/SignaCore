using ServiceMantle.Configuration;
using ServiceMantle.Diagnostics.Export.Otlp;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle;
using SignaCore.Host;
using System.Reflection;
using SignaCore.Host.Configuration;
using SignaCore.Host.Telemetry;
using Xunit;

namespace SignaCore.Tests.Host.Telemetry;

/// <summary>
/// The OTLP endpoint rule shared by the normal host's startup decision and the management update
/// validation, and the update-only enforcement boundary.
/// </summary>
public sealed class OtlpEndpointStateTests
{
    [Theory]
    [InlineData(null, false, false)]
    [InlineData("", false, false)]
    [InlineData("  ", false, false)]
    [InlineData("https://collector.example.com:4317", true, false)]
    [InlineData("https://collector.example.com:4317/", true, false)]
    [InlineData("http://collector.example.com:4317", true, false)]
    [InlineData("https://user:pass@collector.example.com", false, true)]
    [InlineData("https://collector.example.com/?x=1", false, true)]
    [InlineData("https://collector.example.com/#x", false, true)]
    [InlineData("ftp://collector.example.com:4317", false, true)]
    [InlineData("collector.example.com:4317", false, true)]
    public void Classify_YieldsOneStatePerStoredValue(string? value, bool enabled, bool unusable)
    {
        var state = OtlpSettingState.Classify(value);

        Assert.Equal(enabled, state.Endpoint is not null);
        Assert.Equal(unusable, state.IsUnusable);
        Assert.DoesNotContain("collector.example.com", state.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://user:pass@collector.example.com", SignaCoreSettingCompositeValidator.RuntimeInvalidCode)]
    [InlineData("https://collector.example.com/?x=1", SignaCoreSettingCompositeValidator.RuntimeInvalidCode)]
    [InlineData("https://collector.example.com/#x", SignaCoreSettingCompositeValidator.RuntimeInvalidCode)]
    [InlineData("ftp://collector.example.com:4317", SignaCoreSettingCompositeValidator.RuntimeInvalidCode)]
    [InlineData("collector.example.com:4317", SignaCoreSettingCompositeValidator.RuntimeInvalidCode)]
    public void UpdateValidation_RejectsUnusableEndpointsWithClosedCodes(string endpoint, string code)
    {
        var error = Assert.Single(Validate(endpoint, validateManagementUpdateRules: true));

        Assert.Equal("opentelemetry.otlp_endpoint", error.Key);
        Assert.Equal(code, error.ErrorCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("https://collector.example.com:4317")]
    [InlineData("http://collector.example.com:4317")]
    public void UpdateValidation_AcceptsEmptyOrHttpOrHttpsEndpoints(string? endpoint)
    {
        Assert.Empty(Validate(endpoint, validateManagementUpdateRules: true));
    }

    [Fact]
    public void SnapshotValidation_KeepsAcceptingAPlainHttpEndpointAnOlderReleaseStored()
    {
        // Plain http used to be tolerated only at startup; since ServiceMantle 0.3.2 it is a
        // first-class usable endpoint everywhere.
        const string endpoint = "http://collector.example.com:4317";

        Assert.Empty(Validate(endpoint, validateManagementUpdateRules: false));
        Assert.Empty(SharedSettingComposition.CreateRegistry(isDevelopment: false)
            .Validate(Candidate(endpoint))
            .Errors);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("http://collector.example.com:4317", true)]
    [InlineData("https://collector.example.com:4317", true)]
    public void Composition_OnlyUsableSnapshotEnablesGrpcTraces(string? endpoint, bool enabled)
    {
        var result = SharedSettingComposition.CreateRegistry(false).Validate(Candidate(endpoint));
        Assert.True(result.IsValid);
        var snapshot = (ServiceSettingSnapshot)Activator.CreateInstance(typeof(ServiceSettingSnapshot),
            BindingFlags.Instance | BindingFlags.NonPublic, null,
            [ServiceId.Parse("signacore"), 1L, result.Values!, new byte[32]], null)!;
        var services = new ServiceCollection();
        var mantle = services.AddSignaCoreServiceMantle();
        var state = mantle.AddSignaCoreTelemetry(snapshot);
        Assert.Equal(enabled, state.Endpoint is not null);
        Assert.Equal(enabled, services.Any(d => d.ServiceType.Name == "OtlpRuntime"));
        var registrations = services.Where(d => d.ServiceType.Name == "OtlpRegistration").ToArray();
        if (!enabled)
        {
            Assert.Empty(registrations);
            return;
        }
        var registration = Assert.Single(registrations).ImplementationInstance!;
        var traces = registration.GetType().GetProperty("Traces")!.GetValue(registration)!;
        var metrics = registration.GetType().GetProperty("Metrics")!.GetValue(registration)!;
        Assert.True((bool)traces.GetType().GetProperty("Enabled")!.GetValue(traces)!);
        Assert.Equal("Grpc", traces.GetType().GetProperty("Protocol")!.GetValue(traces)!.ToString());
        Assert.Equal(new Uri(endpoint!), traces.GetType().GetProperty("Endpoint")!.GetValue(traces));
        Assert.False((bool)metrics.GetType().GetProperty("Enabled")!.GetValue(metrics)!);
    }

    private static IReadOnlyList<ServiceSettingValidationError> Validate(
        string? endpoint,
        bool validateManagementUpdateRules) =>
        new ServiceSettingDefinitionRegistry(
                SharedSettingComposition.CreateDefinitionProviders(),
                [new SignaCoreSettingCompositeValidator(isDevelopment: false, validateManagementUpdateRules)])
            .Validate(Candidate(endpoint))
            .Errors;

    private static Dictionary<string, string?> Candidate(string? endpoint)
    {
        var values = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (legacyKey, value) in ServiceSettingDefinitions.BuildLegacyDefaults())
        {
            var definition = ServiceSettingDefinitions.Find(SharedSettingKeys.NormalizedByLegacyKey[legacyKey])!;
            if (definition.IsSensitive || (definition.IsOptional && value.Length == 0))
            {
                continue;
            }

            values[definition.Key] = value;
        }

        values["endpoints.public_base_url"] = "https://accounts.example.com";
        values["jwt.issuer"] = "https://accounts.example.com";
        values["admin.username"] = "root-admin";
        if (endpoint is not null)
        {
            values["opentelemetry.otlp_endpoint"] = endpoint;
        }

        return values;
    }
}
