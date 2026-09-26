using ServiceMantle.Configuration;
using SignaCore.Host.Configuration;
using SignaCore.Host.Logging;
using Xunit;

namespace SignaCore.Tests.Host.Logging;

/// <summary>
/// The Loki setting rules shared by the normal host's startup decision and the management update
/// validation: one row per stored combination, and the update-only enforcement boundary.
/// </summary>
public sealed class LokiSettingsTests
{
    private const string Endpoint = "https://loki.example.com";
    private const string Authorization = "Basic bG9raTpjYW5hcnk=";

    [Theory]
    [InlineData(null, null, "Disabled")]
    [InlineData("", "", "Disabled")]
    [InlineData(" ", " ", "Disabled")]
    [InlineData(Endpoint, Authorization, "Enabled")]
    [InlineData("https://loki.example.com:3100/base/", Authorization, "Enabled")]
    [InlineData("http://loki.example.com:3100", Authorization, "EndpointInvalid")]
    [InlineData("http://loki.example.com:3100", "", "EndpointInvalid")]
    [InlineData("https://user:pass@loki.example.com", Authorization, "EndpointInvalid")]
    [InlineData("https://loki.example.com/?tenant=a", Authorization, "EndpointInvalid")]
    [InlineData("https://loki.example.com/#x", Authorization, "EndpointInvalid")]
    [InlineData("loki.example.com", Authorization, "EndpointInvalid")]
    [InlineData(Endpoint, "", "AuthorizationMissing")]
    [InlineData(Endpoint, null, "AuthorizationMissing")]
    [InlineData(Endpoint, "Basic a\nb", "AuthorizationInvalid")]
    [InlineData("", Authorization, "EndpointMissing")]
    public void Classify_YieldsOneStatePerStoredCombination(
        string? uri,
        string? authorization,
        string expectedStatus)
    {
        var expected = Enum.Parse<LokiSettingStatus>(expectedStatus);
        var state = LokiSettings.Classify(uri, authorization);

        Assert.Equal(expected, state.Status);
        Assert.Equal(expected is not (LokiSettingStatus.Enabled or LokiSettingStatus.Disabled), state.IsUnusable);
        if (expected == LokiSettingStatus.Enabled)
        {
            Assert.Equal(Uri.UriSchemeHttps, state.Endpoint!.Scheme);
            Assert.Equal(authorization, state.Authorization);
        }
        else
        {
            Assert.Null(state.Endpoint);
            Assert.Null(state.Authorization);
        }
    }

    [Fact]
    public void Classify_TooLongAuthorization_IsUnusable()
    {
        var state = LokiSettings.Classify(Endpoint, "Bearer " + new string('a', 4_096));

        Assert.Equal(LokiSettingStatus.AuthorizationInvalid, state.Status);
    }

    [Fact]
    public void State_NeverRendersTheEndpointOrTheCredential()
    {
        var state = LokiSettings.Classify(Endpoint, Authorization);

        Assert.DoesNotContain("loki.example.com", state.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Authorization, state.ToString(), StringComparison.Ordinal);
        Assert.Equal("enabled", state.Category);
    }

    [Fact]
    public void Resolver_AnswersOnlyTheSignaCoreLokiName()
    {
        var resolver = new SignaCoreLogging.LokiAuthorizationResolver(Authorization);

        Assert.Equal(Authorization, resolver.ResolveAuthorizationHeader("signacore-loki"));
        Assert.Null(resolver.ResolveAuthorizationHeader("SIGNACORE-LOKI"));
        Assert.Null(resolver.ResolveAuthorizationHeader("other"));
        Assert.DoesNotContain(Authorization, resolver.ToString(), StringComparison.Ordinal);
    }

    public static TheoryData<string?, string?, string?, string?> RejectedCandidates => new()
    {
        { "http://loki.example.com:3100", Authorization, "loki.uri", SignaCoreSettingCompositeValidator.HttpsRequiredCode },
        { "https://user:pass@loki.example.com", Authorization, "loki.uri", SignaCoreSettingCompositeValidator.RuntimeInvalidCode },
        { "https://loki.example.com/?tenant=a", Authorization, "loki.uri", SignaCoreSettingCompositeValidator.RuntimeInvalidCode },
        { "https://loki.example.com/#fragment", Authorization, "loki.uri", SignaCoreSettingCompositeValidator.RuntimeInvalidCode },
        { "loki.example.com", Authorization, "loki.uri", SignaCoreSettingCompositeValidator.RuntimeInvalidCode },
        { Endpoint, null, "loki.authorization", SignaCoreSettingCompositeValidator.RequiredCode },
        { null, Authorization, "loki.uri", SignaCoreSettingCompositeValidator.RequiredCode },
        { Endpoint, "Basic a\u0007b", "loki.authorization", SignaCoreSettingCompositeValidator.RuntimeInvalidCode },
    };

    [Theory]
    [MemberData(nameof(RejectedCandidates))]
    public void UpdateValidation_RejectsUnusableLokiPairsWithClosedCodes(
        string? uri,
        string? authorization,
        string? expectedKey,
        string? expectedCode)
    {
        var errors = Validate(uri, authorization, validateRemoteLogSettings: true);

        var error = Assert.Single(errors);
        Assert.Equal(expectedKey, error.Key);
        Assert.Equal(expectedCode, error.ErrorCode);
        Assert.DoesNotContain(errors, item => item.ToString()!.Contains("loki.example.com", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData(Endpoint, Authorization)]
    public void UpdateValidation_AcceptsEmptyOrUsablePairs(string? uri, string? authorization)
    {
        Assert.Empty(Validate(uri, authorization, validateRemoteLogSettings: true));
    }

    [Theory]
    [InlineData("http://loki.example.com:3100", null)]
    [InlineData(Endpoint, null)]
    public void SnapshotValidation_KeepsAcceptingValuesAnOlderReleaseStored(string? uri, string? authorization)
    {
        // The startup load, the legacy import, and the bootstrap probe build their registry
        // without the Loki rules, so an upgraded installation still starts.
        Assert.Empty(Validate(uri, authorization, validateRemoteLogSettings: false));
        Assert.Empty(SharedSettingComposition.CreateRegistry(isDevelopment: false)
            .Validate(Candidate(uri, authorization))
            .Errors);
    }

    private static IReadOnlyList<ServiceSettingValidationError> Validate(
        string? uri,
        string? authorization,
        bool validateRemoteLogSettings) =>
        new ServiceSettingDefinitionRegistry(
                [new ServiceSettingDefinitions()],
                [new SignaCoreSettingCompositeValidator(isDevelopment: false, validateRemoteLogSettings)])
            .Validate(Candidate(uri, authorization))
            .Errors;

    private static Dictionary<string, string?> Candidate(string? uri, string? authorization)
    {
        var values = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (legacyKey, value) in ServiceSettingDefinitions.BuildLegacyDefaults())
        {
            var definition = ServiceSettingDefinitions.Find(SharedSettingKeys.NormalizedByLegacyKey[legacyKey])!;
            if (definition.IsOptional && value.Length == 0 || definition.IsSensitive)
            {
                continue;
            }

            values[definition.Key] = value;
        }

        values["endpoints.public_base_url"] = "https://accounts.example.com";
        values["jwt.issuer"] = "https://accounts.example.com";
        values["admin.username"] = "root-admin";
        if (uri is not null)
        {
            values["loki.uri"] = uri;
        }

        if (authorization is not null)
        {
            values["loki.authorization"] = authorization;
        }

        return values;
    }
}
