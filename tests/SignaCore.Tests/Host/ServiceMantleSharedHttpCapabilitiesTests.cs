using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Moq;
using ServiceMantle.AspNetCore.Health;
using ServiceMantle.AspNetCore.Logging;
using ServiceMantle.Health;
using ServiceMantle.Logging;
using SignaCore.Domain.Keys;
using SignaCore.Host;
using SignaCore.Host.HealthChecks;
using SignaCore.Host.Http;
using SignaCore.Tests.Host.HealthChecks;
using Xunit;

namespace SignaCore.Tests.Host;

/// <summary>
/// Pins the normal host's shared ServiceMantle registration boundary: the health capability, the
/// signing-key contributor, the product sensitive Header set, the security response headers and the
/// shared rate-limit policies start cleanly without a snapshot source or a mapped endpoint, stay out
/// of the Bootstrap and Setup hosts, and fail closed when the registration itself is invalid.
/// </summary>
public sealed class ServiceMantleSharedHttpCapabilitiesTests
{
    private const string AppSecretValue = "gateway-app-secret-sentinel";

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task SharedHttpCapabilities_PassEveryStartupValidator_WithoutASnapshotSourceOrMappedEndpoints()
    {
        await using var provider = ReadinessComposition.Build(
            (services, _) => services.AddSingleton(ReadyKeyManager().Object));

        Assert.Null(provider.GetService<IServiceHealthSnapshotSource>());
        await ReadinessComposition.StartValidatorsAsync(provider, Token);

        var contributor = Assert.Single(provider.GetServices<IServiceReadinessContributor>());
        Assert.IsType<SigningKeyReadinessContributor>(contributor);
        Assert.Equal(SigningKeyReadinessContributor.SigningKeyOrder, contributor.Order);
        Assert.NotNull(provider.GetService<SensitiveHeaderRegistry>());
        Assert.NotNull(provider.GetService<RequestHeaderDiagnosticProjector>());
        // Startup validators registered as hosted services. #102 adds the shared rate-limiting
        // validator (the security response headers register none) on top of the set the normal host
        // already started with; every one of them passes because StartValidatorsAsync did not throw.
        Assert.Equal(4, provider.GetServices<IHostedService>().Count());
    }

    /// <summary>
    /// The Bootstrap and Setup hosts call <c>AddSignaCoreServiceMantle</c> only, and neither
    /// registers <see cref="IKeyManager"/>; the readiness validator resolves every contributor when
    /// the host starts, so the capability must stay out of those containers.
    /// </summary>
    [Fact]
    public void HostIdentityAlone_RegistersNoReadinessOrSensitiveHeaderCapability()
    {
        var shared = ReadinessComposition.Configure();
        var identityOnly = ReadinessComposition.Configure(sharedHttpCapabilities: false);

        Assert.Contains(shared, descriptor => descriptor.ServiceType == typeof(IServiceReadinessContributor));
        Assert.DoesNotContain(identityOnly, descriptor => descriptor.ServiceType == typeof(IServiceReadinessContributor));
        Assert.DoesNotContain(identityOnly, descriptor => descriptor.ServiceType == typeof(IServiceReadinessDecisionSource));
        Assert.DoesNotContain(identityOnly, descriptor => descriptor.ServiceType == typeof(SensitiveHeaderRegistry));
        Assert.DoesNotContain(
            identityOnly,
            descriptor => descriptor.ServiceType == typeof(IHostedService) &&
                descriptor.ImplementationType?.Name is "HealthStartupValidator" or "SensitiveHeaderStartupValidator");
    }

    [Fact]
    public void SharedHttpCapabilities_RegisterTheDecisionSourceAsScopedAndTheContributorAsSingleton()
    {
        var services = ReadinessComposition.Configure();

        Assert.Equal(
            ServiceLifetime.Scoped,
            Assert.Single(services, descriptor => descriptor.ServiceType == typeof(IServiceReadinessDecisionSource)).Lifetime);
        Assert.Equal(
            ServiceLifetime.Singleton,
            Assert.Single(services, descriptor => descriptor.ServiceType == typeof(IServiceReadinessContributor)).Lifetime);
    }

    [Fact]
    public async Task HealthStartupValidator_FailsClosed_OnASecondContributorUsingTheSigningKeyOrder()
    {
        await using var provider = ReadinessComposition.Build((services, _) =>
        {
            services.AddSingleton(ReadyKeyManager().Object);
            services.AddSingleton<IServiceReadinessContributor>(new ScriptedReadinessContributor(
                SigningKeyReadinessContributor.SigningKeyOrder,
                (_, _) => ValueTask.FromResult(ServiceReadinessContributorResult.Ready())));
        });

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ReadinessComposition.StartValidatorsAsync(provider, Token));

        Assert.Equal("ServiceMantle readiness contributor registration is invalid.", exception.Message);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void SensitiveHeaderRegistry_RegistersTheProductAppSecretHeader_CaseInsensitively()
    {
        using var provider = ReadinessComposition.Build((services, _) => services.AddSingleton(ReadyKeyManager().Object));
        var registry = provider.GetRequiredService<SensitiveHeaderRegistry>();

        Assert.True(registry.IsSensitive(IdentityHeaders.AppSecret));
        Assert.True(registry.IsSensitive("x-admin-appsecret"));
        Assert.True(registry.IsSensitive("X-ADMIN-APPSECRET"));
        Assert.Contains(IdentityHeaders.AppSecret, registry.DeniedHeaderNames, StringComparer.OrdinalIgnoreCase);

        // The AppId is a routing identifier, not a credential; denying it would hide diagnostics.
        Assert.False(registry.IsSensitive(IdentityHeaders.AppId));
    }

    [Fact]
    public void SensitiveHeaderRegistry_KeepsTheBuiltInDeniedNames()
    {
        using var provider = ReadinessComposition.Build((services, _) => services.AddSingleton(ReadyKeyManager().Object));
        var registry = provider.GetRequiredService<SensitiveHeaderRegistry>();

        foreach (var builtIn in StructuredLogSanitizerDefaults.BuiltInDeniedHeaderNames)
        {
            Assert.True(registry.IsSensitive(builtIn));
        }

        Assert.All(registry.DeniedHeaderNames, name => Assert.DoesNotContain(AppSecretValue, name, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("not a header token")]
    [InlineData("X-Admin-AppSecret: injected")]
    [InlineData("X-Admin/AppSecret")]
    public async Task SensitiveHeaderStartupValidator_FailsClosed_OnAnInvalidDeniedName(string name)
    {
        await using var provider = ReadinessComposition.Build((services, builder) =>
        {
            services.AddSingleton(ReadyKeyManager().Object);
            builder.AddSensitiveHeaders(options => options.DeniedHeaderNames = [name]);
        });

        var exception = await Assert.ThrowsAsync<SensitiveHeaderConfigurationException>(
            () => ReadinessComposition.StartValidatorsAsync(provider, Token));

        Assert.Equal(WellKnownSensitiveHeaderConfigurationErrorCodes.InvalidName, exception.ErrorCode);
        Assert.DoesNotContain(name, exception.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("injected", exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task SensitiveHeaderStartupValidator_FailsClosed_OnAnEmptyDeniedName()
    {
        await using var provider = ReadinessComposition.Build((services, builder) =>
        {
            services.AddSingleton(ReadyKeyManager().Object);
            builder.AddSensitiveHeaders(options => options.DeniedHeaderNames = [string.Empty]);
        });

        var exception = await Assert.ThrowsAsync<SensitiveHeaderConfigurationException>(
            () => ReadinessComposition.StartValidatorsAsync(provider, Token));

        Assert.Equal(WellKnownSensitiveHeaderConfigurationErrorCodes.InvalidName, exception.ErrorCode);
    }

    [Fact]
    public async Task SensitiveHeaderStartupValidator_FailsClosed_OnASeparatelyRegisteredSanitizer()
    {
        await using var provider = ReadinessComposition.Build((services, _) =>
        {
            services.AddSingleton(ReadyKeyManager().Object);
            services.AddSingleton(new StructuredLogSanitizer());
        });

        var exception = await Assert.ThrowsAsync<SensitiveHeaderConfigurationException>(
            () => ReadinessComposition.StartValidatorsAsync(provider, Token));

        Assert.Equal(WellKnownSensitiveHeaderConfigurationErrorCodes.SanitizerConflict, exception.ErrorCode);
    }

    [Fact]
    public void RequestHeaderDiagnosticProjector_RedactsTheRegisteredAppSecretValue()
    {
        using var provider = ReadinessComposition.Build((services, _) => services.AddSingleton(ReadyKeyManager().Object));
        var projector = provider.GetRequiredService<RequestHeaderDiagnosticProjector>();
        var headers = new HeaderDictionary
        {
            [IdentityHeaders.AppSecret] = AppSecretValue,
            [IdentityHeaders.AppId] = "gateway-app",
            ["Authorization"] = "Bearer " + AppSecretValue,
            ["X-Correlation-Id"] = "projection-request",
        };

        var projection = projector.Project(headers);
        var serialized = JsonSerializer.Serialize(projection);

        Assert.Equal(
            StructuredLogSanitizer.RedactedValue,
            projection.Single(entry => string.Equals(entry.Key, IdentityHeaders.AppSecret, StringComparison.OrdinalIgnoreCase)).Value);
        Assert.DoesNotContain(AppSecretValue, serialized, StringComparison.Ordinal);
        Assert.Contains(StructuredLogSanitizer.RedactedValue, serialized, StringComparison.Ordinal);
        // A non-sensitive value stays readable, so redaction is a name decision and not a blanket wipe.
        Assert.Contains("gateway-app", serialized, StringComparison.Ordinal);
        Assert.Contains("projection-request", serialized, StringComparison.Ordinal);
    }

    private static Mock<IKeyManager> ReadyKeyManager()
    {
        var mock = new Mock<IKeyManager>();
        mock.SetupGet(manager => manager.InitializationCompleted).Returns(Task.CompletedTask);
        return mock;
    }
}
