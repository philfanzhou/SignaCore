using ServiceMantle.Configuration;
using SignaCore.Database;
using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

/// <summary>
/// The diagnostics overload of <c>ValidateOptionalSettings</c> must be the same state rule the
/// candidate path uses: the same legacy-keyed inputs produce the same closed key + fixed-code
/// issues, over exactly the three optional telemetry keys and the three fixed codes.
/// </summary>
public sealed class OptionalSettingsDiagnosticsRuleTests
{
    private static readonly IReadOnlyList<string> ClosedKeys =
    [
        "loki.uri", "loki.authorization", "opentelemetry.otlp_endpoint"
    ];

    private static readonly IReadOnlyList<string> ClosedCodes =
    [
        SignaCoreSettingCompositeValidator.RequiredCode,
        SignaCoreSettingCompositeValidator.HttpsRequiredCode,
        SignaCoreSettingCompositeValidator.RuntimeInvalidCode
    ];

    public static TheoryData<string, Dictionary<string, string>, (string Key, string Code)[]> Cases => new()
    {
        {
            "empty-values",
            new Dictionary<string, string>(),
            Array.Empty<(string, string)>()
        },
        {
            "whitespace-values",
            new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = "  ",
                [SystemSettingKeys.LokiAuthorization] = " ",
                [SystemSettingKeys.OpenTelemetryOtlpEndpoint] = ""
            },
            Array.Empty<(string, string)>()
        },
        {
            "loki-http-uri",
            new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = "http://loki.example.com:3100",
                [SystemSettingKeys.LokiAuthorization] = "Basic dGVzdDpjYW5hcnk="
            },
            [("loki.uri", SignaCoreSettingCompositeValidator.HttpsRequiredCode)]
        },
        {
            "loki-non-absolute-uri",
            new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = "loki.example.com/loki/api/v1/push",
                [SystemSettingKeys.LokiAuthorization] = "Basic dGVzdDpjYW5hcnk="
            },
            [("loki.uri", SignaCoreSettingCompositeValidator.RuntimeInvalidCode)]
        },
        {
            "loki-authorization-without-uri",
            new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiAuthorization] = "Basic dGVzdDpjYW5hcnk="
            },
            [("loki.uri", SignaCoreSettingCompositeValidator.RequiredCode)]
        },
        {
            "loki-uri-without-authorization",
            new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = "https://loki.example.com"
            },
            [("loki.authorization", SignaCoreSettingCompositeValidator.RequiredCode)]
        },
        {
            "loki-unusable-authorization",
            new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = "https://loki.example.com",
                [SystemSettingKeys.LokiAuthorization] = "bad\nheader"
            },
            [("loki.authorization", SignaCoreSettingCompositeValidator.RuntimeInvalidCode)]
        },
        {
            "otlp-http-endpoint",
            new Dictionary<string, string>
            {
                [SystemSettingKeys.OpenTelemetryOtlpEndpoint] = "http://collector.example.com:4317"
            },
            [("opentelemetry.otlp_endpoint", SignaCoreSettingCompositeValidator.HttpsRequiredCode)]
        },
        {
            "otlp-non-absolute-endpoint",
            new Dictionary<string, string>
            {
                [SystemSettingKeys.OpenTelemetryOtlpEndpoint] = "collector.example.com:4317"
            },
            [("opentelemetry.otlp_endpoint", SignaCoreSettingCompositeValidator.RuntimeInvalidCode)]
        },
        {
            "both-groups-invalid",
            new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = "http://loki.example.com",
                [SystemSettingKeys.OpenTelemetryOtlpEndpoint] = "http://collector.example.com"
            },
            [
                ("loki.uri", SignaCoreSettingCompositeValidator.HttpsRequiredCode),
                ("loki.authorization", SignaCoreSettingCompositeValidator.RequiredCode),
                ("opentelemetry.otlp_endpoint", SignaCoreSettingCompositeValidator.HttpsRequiredCode)
            ]
        },
        {
            "both-groups-valid",
            new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = "https://loki.example.com",
                [SystemSettingKeys.LokiAuthorization] = "Basic dGVzdDpjYW5hcnk=",
                [SystemSettingKeys.OpenTelemetryOtlpEndpoint] = "https://collector.example.com:4317"
            },
            Array.Empty<(string, string)>()
        }
    };

    [Theory]
    [MemberData(nameof(Cases))]
    public void DiagnosticsOverload_ProducesTheClosedIssues(
        string name, Dictionary<string, string> legacyValues, (string Key, string Code)[] expected)
    {
        Assert.NotEmpty(name);

        var issues = SignaCoreSettingCompositeValidator
            .ValidateOptionalSettings(legacyValues)
            .Select(error => (error.Key!, error.ErrorCode))
            .OrderBy(issue => issue.Item1, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(
            expected.OrderBy(issue => issue.Key, StringComparer.Ordinal).ToList(),
            issues);
    }

    [Fact]
    public void EveryIssue_UsesARegisteredKeyAndAFixedCode()
    {
        var issues = SignaCoreSettingCompositeValidator.ValidateOptionalSettings(
            new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = "http://loki.example.com",
                [SystemSettingKeys.LokiAuthorization] = "Basic dGVzdDpjYW5hcnk=",
                [SystemSettingKeys.OpenTelemetryOtlpEndpoint] = "not a url"
            }).ToList();

        Assert.NotEmpty(issues);
        foreach (var issue in issues)
        {
            Assert.Contains(issue.Key, ClosedKeys);
            Assert.Contains(issue.ErrorCode, ClosedCodes);
        }
    }

    [Fact]
    public void PreserveFlags_SkipExactlyTheSelectedGroup()
    {
        var legacy = new Dictionary<string, string>
        {
            [SystemSettingKeys.LokiUri] = "http://loki.example.com",
            [SystemSettingKeys.LokiAuthorization] = "Basic dGVzdDpjYW5hcnk=",
            [SystemSettingKeys.OpenTelemetryOtlpEndpoint] = "http://collector.example.com"
        };

        var both = SignaCoreSettingCompositeValidator
            .ValidateOptionalSettings(legacy, preserveLoki: true, preserveOtlp: true)
            .ToList();
        var lokiOnly = SignaCoreSettingCompositeValidator
            .ValidateOptionalSettings(legacy, preserveOtlp: true)
            .ToList();

        Assert.Empty(both);
        Assert.Equal(
            [("loki.uri", SignaCoreSettingCompositeValidator.HttpsRequiredCode)],
            lokiOnly.Select(error => (error.Key!, error.ErrorCode)).ToList());
    }
}
