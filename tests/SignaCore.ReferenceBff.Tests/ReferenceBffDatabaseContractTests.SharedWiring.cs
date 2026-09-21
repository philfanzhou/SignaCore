extern alias BffSample;
using System.Xml.Linq;
using BffSample::SignaCore.ReferenceBff;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ServiceMantle;
using ServiceMantle.AspNetCore.Logging;
using ServiceMantle.Audit;
using ServiceMantle.Installation;
using ServiceMantle.Logging;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.ReferenceBff.Database;
using Xunit;
using Xunit.Sdk;

namespace SignaCore.ReferenceBff.Tests;

public sealed partial class ReferenceBffDatabaseContractTests
{
    // Keep provenance and effective-policy acceptance together. A package reference or a loaded
    // assembly alone says nothing about the implementation the running consumer actually uses.
    [Theory]
    [InlineData("installation")]
    [InlineData("setup-code")]
    [InlineData("audit")]
    [InlineData("key-ring")]
    [InlineData("headers")]
    [InlineData("logging")]
    public async Task SharedWiring_RealHostUsesSharedImplementations(string capability)
    {
        await using var database = await BffDatabase.CreateMigratedAsync("SQLite");
        await using var authority = await FakeAuthority.StartAsync();
        await using var host = SetupHost(database, "SQLite", authority);
        using var client = host.CreateClient();
        using var scope = host.Services.CreateScope();
        AssertSharedWiring(scope.ServiceProvider, capability);
    }

    [Theory]
    [InlineData("installation")]
    [InlineData("setup-code")]
    [InlineData("audit")]
    [InlineData("key-ring")]
    [InlineData("headers")]
    [InlineData("logging")]
    public async Task SharedWiring_ReplacementFailsTheSameAcceptanceAssertion(string mutation)
    {
        await using var database = await BffDatabase.CreateMigratedAsync("SQLite");
        await using var authority = await FakeAuthority.StartAsync();
        await using var host = SetupHost(database, "SQLite", authority, services =>
        {
            switch (mutation)
            {
                case "installation":
                    services.AddScoped<IServiceInstallationStore>(sp => new LocalInstallation(
                        ActivatorUtilities.CreateInstance<EfCoreServiceInstallationStore<ReferenceBffDbContext>>(sp)));
                    break;
                case "setup-code":
                    services.AddScoped<IServiceSetupCodeStore>(sp => new LocalSetupCode(
                        ActivatorUtilities.CreateInstance<EfCoreServiceSetupCodeStore<ReferenceBffDbContext>>(sp)));
                    break;
                case "audit":
                    services.AddScoped<IManagementAuditWriter>(sp => new LocalAudit(
                        ActivatorUtilities.CreateInstance<EfCoreManagementAuditWriter<ReferenceBffDbContext>>(sp)));
                    break;
                case "key-ring":
                    services.Configure<KeyManagementOptions>(options =>
                        options.XmlRepository = new LocalKeyRing(options.XmlRepository!));
                    break;
                case "headers":
                    // Registrations are additive: adding [] to the real collection would NOT
                    // remove the BFF header. Substitute a valid registry without that registration.
                    var isolated = new ServiceCollection();
                    isolated.AddServiceMantle(ReferenceBffServiceMantle.ServiceId,
                        InstanceId.Parse("wiring-negative")).AddSensitiveHeaders(o => o.DeniedHeaderNames = []);
                    using (var provider = isolated.BuildServiceProvider())
                    {
                        var registry = provider.GetRequiredService<SensitiveHeaderRegistry>();
                        _ = registry.DeniedHeaderNames;
                        services.AddSingleton(registry);
                    }
                    break;
                case "logging":
                    var original = Assert.Single(services, d => d.ServiceType == typeof(ILoggerProvider));
                    services.RemoveAll<ILoggerProvider>();
                    services.AddSingleton<ILoggerProvider>(sp => new LocalLoggerProvider(
                        (ILoggerProvider)ActivatorUtilities.CreateInstance(sp, original.ImplementationType!)));
                    break;

            }
        });
        // Startup and resolution are OUTSIDE the expected assertion failure. A broken host,
        // constructor or missing service must fail this test instead of counting as detection.
        using var client = host.CreateClient();
        using var scope = host.Services.CreateScope();
        var capability = mutation;
        var assertion = Record.Exception(() => AssertSharedWiring(scope.ServiceProvider, capability));
        var failure = Assert.IsAssignableFrom<XunitException>(assertion);
        Assert.Contains(mutation == "headers" ? "BFF CSRF" : "ServiceMantle implementation",
            failure.Message, StringComparison.Ordinal);
    }

    private static void AssertSharedWiring(IServiceProvider services, string capability)
    {
        switch (capability)
        {
            case "installation": Shared(services.GetRequiredService<IServiceInstallationStore>()); break;
            case "setup-code": Shared(services.GetRequiredService<IServiceSetupCodeStore>()); break;
            case "audit": Shared(services.GetRequiredService<IManagementAuditWriter>()); break;
            case "key-ring":
                // The effective repository is an option, not an IXmlRepository DI registration.
                Assert.Null(services.GetService<IXmlRepository>());
                var repository = services.GetRequiredService<IOptions<KeyManagementOptions>>().Value.XmlRepository;
                Assert.NotNull(repository);
                Shared(repository);
                break;
            case "headers":
                var registry = services.GetRequiredService<SensitiveHeaderRegistry>();
                Shared(registry);
                Assert.True(registry.IsSensitive(BffSetupHosting.CsrfHeader), "BFF CSRF header must be registered.");
                Assert.True(registry.IsSensitive("Authorization"));
                Assert.True(registry.IsSensitive("Cookie"));
                break;
            case "logging":
                Shared(services.GetRequiredService<ServiceLogContext>());
                var sanitizer = services.GetRequiredService<StructuredLogSanitizer>();
                Shared(sanitizer);
                Shared(Assert.Single(services.GetServices<ILoggerProvider>()));
                var fields = sanitizer.SanitizeFields(new Dictionary<string, object?> { ["password"] = "opaque-probe" });
                Assert.DoesNotContain("opaque-probe", fields.Values);
                break;
            default: throw new ArgumentOutOfRangeException(nameof(capability));
        }
    }

    private static void Shared(object implementation) => Assert.True(
        implementation.GetType().Assembly.GetName().Name?.StartsWith("ServiceMantle", StringComparison.Ordinal) == true,
        "The effective service must be a ServiceMantle implementation.");

    // Transparent local implementations retain behavior, so behavioral tests alone cannot detect
    // these substitutions. No copied persistence algorithm or second production implementation.
    private sealed class LocalInstallation(IServiceInstallationStore inner) : IServiceInstallationStore
    {
        public ValueTask<ServiceInstallationState?> FindAsync(ServiceId id, CancellationToken ct = default) => inner.FindAsync(id, ct);
        public ValueTask<ServiceInstallationState> CreatePendingAsync(ServiceId id, CancellationToken ct = default) => inner.CreatePendingAsync(id, ct);
        public ValueTask<ServiceInstallationState> MarkCompletedAsync(ServiceId id, CancellationToken ct = default) => inner.MarkCompletedAsync(id, ct);
    }

    private sealed class LocalSetupCode(IServiceSetupCodeStore inner) : IServiceSetupCodeStore
    {
        public ValueTask<SetupCodeIssueResult> CreateAsync(ServiceId id, CancellationToken ct = default) => inner.CreateAsync(id, ct);
        public ValueTask<SetupCodeIssueResult> RotateAsync(ServiceId id, CancellationToken ct = default) => inner.RotateAsync(id, ct);
        public ValueTask<SetupCodeValidationResult> ValidateAsync(ServiceId id, string code, CancellationToken ct = default) => inner.ValidateAsync(id, code, ct);
        public ValueTask<SetupCodeConsumptionResult> StageConsumeAsync(ServiceId id, string code, CancellationToken ct = default) => inner.StageConsumeAsync(id, code, ct);
    }

    private sealed class LocalAudit(IManagementAuditWriter inner) : IManagementAuditWriter
    {
        public ValueTask<ManagementAuditRecord> RecordAsync(ManagementAuditEvent entry, CancellationToken ct = default) => inner.RecordAsync(entry, ct);
    }

    private sealed class LocalKeyRing(IXmlRepository inner) : IXmlRepository
    {
        public IReadOnlyCollection<XElement> GetAllElements() => inner.GetAllElements();
        public void StoreElement(XElement element, string friendlyName) => inner.StoreElement(element, friendlyName);
    }

    private sealed class LocalLoggerProvider(ILoggerProvider inner) : ILoggerProvider, ISupportExternalScope
    {
        public ILogger CreateLogger(string categoryName) => inner.CreateLogger(categoryName);
        public void SetScopeProvider(IExternalScopeProvider provider) => ((ISupportExternalScope)inner).SetScopeProvider(provider);
        public void Dispose() => inner.Dispose();
    }
}
