using ServiceMantle.Configuration;
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
    [InlineData("http://collector.example.com:4317", false, true)]
    [InlineData("https://user:pass@collector.example.com", false, true)]
    [InlineData("https://collector.example.com/?x=1", false, true)]
    [InlineData("https://collector.example.com/#x", false, true)]
    [InlineData("collector.example.com:4317", false, true)]
    public void Classify_YieldsOneStatePerStoredValue(string? value, bool enabled, bool unusable)
    {
        var state = OtlpEndpointState.Classify(value);

        Assert.Equal(enabled, state.Endpoint is not null);
        Assert.Equal(unusable, state.IsUnusable);
        Assert.DoesNotContain("collector.example.com", state.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://collector.example.com:4317", SignaCoreSettingCompositeValidator.HttpsRequiredCode)]
    [InlineData("https://user:pass@collector.example.com", SignaCoreSettingCompositeValidator.RuntimeInvalidCode)]
    [InlineData("https://collector.example.com/?x=1", SignaCoreSettingCompositeValidator.RuntimeInvalidCode)]
    [InlineData("https://collector.example.com/#x", SignaCoreSettingCompositeValidator.RuntimeInvalidCode)]
    [InlineData("collector.example.com:4317", SignaCoreSettingCompositeValidator.RuntimeInvalidCode)]
    public void UpdateValidation_RejectsUnusableEndpointsWithClosedCodes(string endpoint, string code)
    {
        var error = Assert.Single(Validate(endpoint, validateTelemetrySettings: true));

        Assert.Equal("opentelemetry.otlp_endpoint", error.Key);
        Assert.Equal(code, error.ErrorCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("https://collector.example.com:4317")]
    public void UpdateValidation_AcceptsEmptyOrHttpsEndpoints(string? endpoint)
    {
        Assert.Empty(Validate(endpoint, validateTelemetrySettings: true));
    }

    [Fact]
    public void SnapshotValidation_KeepsAcceptingAPlainHttpEndpointAnOlderReleaseStored()
    {
        const string endpoint = "http://collector.example.com:4317";

        Assert.Empty(Validate(endpoint, validateTelemetrySettings: false));
        Assert.Empty(SharedSettingComposition.CreateRegistry(isDevelopment: false)
            .Validate(Candidate(endpoint))
            .Errors);
    }

    private static IReadOnlyList<ServiceSettingValidationError> Validate(
        string? endpoint,
        bool validateTelemetrySettings) =>
        new ServiceSettingDefinitionRegistry(
                [new ServiceSettingDefinitions()],
                [new SignaCoreSettingCompositeValidator(isDevelopment: false, validateTelemetrySettings)])
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
