using ServiceMantle.Configuration;
using ServiceMantle.Logging.Remote;
using ServiceMantle.Logging;
using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ServiceMantle;
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
    [InlineData("http://loki.example.com:3100", Authorization, "Enabled")]
    [InlineData("http://loki.example.com:3100", "", "AuthorizationMissing")]
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
        var expected = Enum.Parse<GrafanaLokiSettingStatus>(expectedStatus);
        var state = GrafanaLokiSettingState.Classify(uri, authorization);

        Assert.Equal(expected, state.Status);
        Assert.Equal(expected is not (GrafanaLokiSettingStatus.Enabled or GrafanaLokiSettingStatus.Disabled), state.IsUnusable);
        if (expected == GrafanaLokiSettingStatus.Enabled)
        {
            // The endpoint keeps the stored scheme verbatim: plain http and https are equal.
            Assert.Equal(new Uri(uri!).Scheme, state.Endpoint!.Scheme);
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
        var state = GrafanaLokiSettingState.Classify(Endpoint, "Bearer " + new string('a', 4_096));

        Assert.Equal(GrafanaLokiSettingStatus.AuthorizationInvalid, state.Status);
    }

    [Theory]
    [InlineData("https://loki.example.com", "Basic bG9raTpjYW5hcnk=", false)]
    [InlineData("http://loki.example.com:3100", "Basic bG9raTpjYW5hcnk=", false)]
    [InlineData("https://loki.example.com", null, true)]
    [InlineData("http://loki.example.com:3100", null, true)]
    public void Classify_PlainHttpAndHttpsAreEqualAcrossTheAuthenticationModes(
        string uri, string? authorization, bool allowNoAuthentication)
    {
        var state = GrafanaLokiSettingState.Classify(uri, authorization, allowNoAuthentication);

        Assert.Equal(GrafanaLokiSettingStatus.Enabled, state.Status);
        Assert.Equal(new Uri(uri).Scheme, state.Endpoint!.Scheme);
        // The no-authentication mode carries no credential; the authenticated mode keeps it.
        Assert.Equal(allowNoAuthentication ? null : authorization, state.Authorization);
    }

    [Theory]
    [InlineData("http://loki.example.com:3100", "Basic bG9raTpjYW5hcnk=", false)]
    [InlineData("https://loki.example.com", null, true)]
    [InlineData("http://loki.example.com:3100", null, true)]
    public void UpdateValidation_PlainHttpAndNoAuthentication_AreAcceptedAsStored(
        string uri, string? authorization, bool allowNoAuthentication)
    {
        Assert.Empty(Validate(uri, authorization, allowNoAuthentication, true));
    }

    [Fact]
    public void UpdateValidation_TheRetiredInsecureSwitch_IsAnUnknownKey()
    {
        // loki.allow_insecure_http is retired: updating it is the generic unknown-key rejection,
        // never a typed Boolean rule, and the key never re-enters the catalog.
        var candidate = Candidate(Endpoint, Authorization);
        candidate[RetiredSettingKeys.LokiAllowInsecureHttp] = "true";

        var result = new ServiceSettingDefinitionRegistry(
                SharedSettingComposition.CreateDefinitionProviders(),
                [new SignaCoreSettingCompositeValidator(isDevelopment: false, validateManagementUpdateRules: true)])
            .Validate(candidate);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error =>
            error.ErrorCode == WellKnownServiceSettingValidationErrorCodes.Unknown);
    }

    [Fact]
    public void UpdateValidation_NoAuthenticationWithAStoredCredential_IsRejected()
    {
        var errors = Validate(
            Endpoint, "Basic bG9raTpjYW5hcnk=", allowNoAuthentication: true,
            validateManagementUpdateRules: true);

        var error = Assert.Single(errors);
        Assert.Equal("loki.authorization", error.Key);
        Assert.Equal(SignaCoreSettingCompositeValidator.RuntimeInvalidCode, error.ErrorCode);
    }

    [Fact]
    public void State_NeverRendersTheEndpointOrTheCredential()
    {
        var state = GrafanaLokiSettingState.Classify(Endpoint, Authorization);

        Assert.DoesNotContain("loki.example.com", state.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Authorization, state.ToString(), StringComparison.Ordinal);
        Assert.Equal("enabled", state.Category);
    }

    [Theory]
    [InlineData(null, null, false)]
    [InlineData("http://loki.example.com", Authorization, true)]
    [InlineData(Endpoint, Authorization, true)]
    public void Composition_UsesSharedResolverOnlyWhenEnabled(string? endpoint, string? authorization, bool enabled)
    {
        var validation = SharedSettingComposition.CreateRegistry(false).Validate(Candidate(endpoint, authorization));
        Assert.True(validation.IsValid);
        var snapshot = (ServiceSettingSnapshot)Activator.CreateInstance(typeof(ServiceSettingSnapshot),
            BindingFlags.Instance | BindingFlags.NonPublic, null,
            [ServiceId.Parse("signacore"), 1L, validation.Values!, new byte[32]], null)!;
        var builder = Microsoft.Extensions.Hosting.Host.CreateApplicationBuilder();
        // A launcher value cannot turn shipping on or replace the activated snapshot.
        builder.Configuration["Loki:Uri"] = "https://launcher.example.com";
        var state = builder.AddSignaCoreLogging(snapshot);
        Assert.Equal(enabled, state.Status == GrafanaLokiSettingStatus.Enabled);
        using var services = builder.Services.BuildServiceProvider();
        var resolvers = services.GetServices<IRemoteLogAuthorizationResolver>().ToArray();
        if (!enabled)
        {
            Assert.Empty(resolvers);
            return;
        }
        var resolver = Assert.Single(resolvers);
        Assert.IsType<FixedRemoteLogAuthorizationResolver>(resolver);
        Assert.Equal(authorization, resolver.ResolveAuthorizationHeader(
            ServiceMantleGrafanaLokiHostApplicationBuilderExtensions.SettingDrivenAuthorizationResolverName));
        Assert.Null(resolver.ResolveAuthorizationHeader("other"));
        Assert.DoesNotContain(authorization!, resolver.ToString()!, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(4096, true)]
    [InlineData(4097, false)]
    public void AuthorizationBoundary_MatchesClassificationAndManagement(int length, bool usable)
    {
        var authorization = new string('x', length);
        Assert.Equal(usable, GrafanaLokiSettingState.Classify(Endpoint, authorization).Status == GrafanaLokiSettingStatus.Enabled);
        Assert.Equal(usable, Validate(Endpoint, authorization, true).Count == 0);
    }

    public static TheoryData<string?, string?, string?, string?> RejectedCandidates => new()
    {
        { "https://user:pass@loki.example.com", Authorization, "loki.uri", SignaCoreSettingCompositeValidator.RuntimeInvalidCode },
        { "http://user:pass@loki.example.com:3100", Authorization, "loki.uri", SignaCoreSettingCompositeValidator.RuntimeInvalidCode },
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
        var errors = Validate(uri, authorization, validateManagementUpdateRules: true);

        var error = Assert.Single(errors);
        Assert.Equal(expectedKey, error.Key);
        Assert.Equal(expectedCode, error.ErrorCode);
        Assert.DoesNotContain(errors, item => item.ToString()!.Contains("loki.example.com", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData(Endpoint, Authorization)]
    [InlineData("http://loki.example.com:3100", Authorization)]
    public void UpdateValidation_AcceptsEmptyOrUsablePairs(string? uri, string? authorization)
    {
        Assert.Empty(Validate(uri, authorization, validateManagementUpdateRules: true));
    }

    [Theory]
    [InlineData("http://loki.example.com:3100", null)]
    [InlineData("http://loki.example.com:3100", Authorization)]
    [InlineData(Endpoint, null)]
    public void SnapshotValidation_KeepsAcceptingValuesAnOlderReleaseStored(string? uri, string? authorization)
    {
        // The startup load, the legacy import, and the bootstrap probe build their registry
        // without the Loki rules, so an upgraded installation still starts.
        Assert.Empty(Validate(uri, authorization, validateManagementUpdateRules: false));
        Assert.Empty(SharedSettingComposition.CreateRegistry(isDevelopment: false)
            .Validate(Candidate(uri, authorization))
            .Errors);
    }

    private static IReadOnlyList<ServiceSettingValidationError> Validate(
        string? uri,
        string? authorization,
        bool validateManagementUpdateRules) =>
        Validate(uri, authorization, allowNoAuthentication: false,
            validateManagementUpdateRules);

    private static IReadOnlyList<ServiceSettingValidationError> Validate(
        string? uri,
        string? authorization,
        bool allowNoAuthentication,
        bool validateManagementUpdateRules)
    {
        var candidate = Candidate(uri, authorization);
        if (allowNoAuthentication)
        {
            candidate["loki.allow_no_authentication"] = "true";
        }

        return new ServiceSettingDefinitionRegistry(
                SharedSettingComposition.CreateDefinitionProviders(),
                [new SignaCoreSettingCompositeValidator(isDevelopment: false, validateManagementUpdateRules)])
            .Validate(candidate)
            .Errors;
    }

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
