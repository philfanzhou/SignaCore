using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.Configuration;
using ServiceMantle.Discovery.Configuration;
using ServiceMantle.Discovery.Registration;
using ServiceMantle;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

/// <summary>
/// Projection of the eleven <c>consul.*</c> product keys onto the shared <c>discovery.*</c>
/// catalog, and the composition of the typed shared Consul entry (ServiceMantle #104).
/// <para>
/// The product snapshot is built through the real shared loader over the real product catalog, so
/// every projection assertion starts from the same materialized shapes the normal host sees. The
/// derived view must stay isolated: no global definitions, no global accessor replacement, and the
/// one derived snapshot carries the product version.
/// </para>
/// </summary>
public sealed class ConsulDiscoveryCompositionTests
{
    private const string RootSecret = "consul-projection-root-secret";

    [Fact]
    public async Task EnabledRegister_WithExplicitAdvertisement_MapsEveryKey()
    {
        // The per-instance process values override the database advertisement key by key (#594).
        var projection = await DeriveAsync(
            AdvertisementAddress: "10.1.2.3",
            AdvertisementPort: 9443,
            AdvertisementScheme: "https",
            Overrides:
            [
                ("consul.host", "127.0.0.1"),
                ("consul.port", "8500"),
                ("consul.token", "the-acl-token"),
                ("consul.discovery.enabled", "true"),
                ("consul.discovery.register", "true"),
                ("consul.discovery.deregister", "true"),
                ("consul.discovery.service_name", "SignaCore"),
                ("consul.discovery.health_check_path", "/health/ready"),
                // The database advertisement keys are present but must lose to the process values.
                ("consul.discovery.health_scheme", "http"),
                ("consul.discovery.ip_address", "192.0.2.77"),
                ("consul.discovery.port", "8080")
            ]);

        var values = await AssertValidViewAsync(projection.Read);
        Assert.Equal("true", values[ConsulSettingDefinitions.Enabled]);
        Assert.Equal("http://127.0.0.1:8500/", values[ConsulSettingDefinitions.Endpoint]);
        Assert.Equal("SignaCore", values[ConsulSettingDefinitions.ServiceName]);
        Assert.Equal("10.1.2.3", values[ConsulSettingDefinitions.Address]);
        Assert.Equal("9443", values[ConsulSettingDefinitions.Port]);
        Assert.Equal("/health/ready", values[ConsulSettingDefinitions.HealthPath]);
        Assert.Equal("https", values[ConsulSettingDefinitions.HealthScheme]);

        // The credential is re-protected under the discovery.credential purpose and round-trips
        // with the same root key; it is never carried as plaintext.
        var envelope = Assert.IsType<string>(values[ConsulSettingDefinitions.Token]);
        Assert.StartsWith("sm:v1:", envelope, StringComparison.Ordinal);
        Assert.DoesNotContain("the-acl-token", envelope, StringComparison.Ordinal);

        Assert.Equal("10.1.2.3", projection.AdvertisementAddress);
        Assert.Equal(9443, projection.AdvertisementPort);
    }

    [Theory]
    [InlineData("true", "true", "true")]
    [InlineData("true", "false", "false")]
    [InlineData("false", "true", "false")]
    [InlineData("false", "false", "false")]
    public async Task EnabledRegisterCombinations_DecideDiscoveryEnabledOnlyWhenBothAreTrue(
        string enabled, string register, string expected)
    {
        var projection = await DeriveAsync(
            AdvertisementAddress: "10.1.2.3",
            AdvertisementPort: 9443,
            AdvertisementScheme: null,
            Overrides:
            [
                ("consul.discovery.enabled", enabled),
                ("consul.discovery.register", register),
                ("consul.discovery.deregister", "true")
            ]);

        var values = await AssertValidViewAsync(projection.Read);
        Assert.Equal(expected, values[ConsulSettingDefinitions.Enabled]);
        if (expected == "false")
        {
            Assert.Null(projection.AdvertisementAddress);
            Assert.Null(projection.AdvertisementPort);
        }
    }

    [Fact]
    public async Task EnabledRegister_WithoutDeregister_IsRefusedWithTheFixedCode()
    {
        var exception = await Assert.ThrowsAsync<ConsulDiscoveryConfigurationException>(() =>
            DeriveAsync(
                AdvertisementAddress: "10.1.2.3",
                AdvertisementPort: 9443,
                AdvertisementScheme: null,
                Overrides:
                [
                    ("consul.discovery.enabled", "true"),
                    ("consul.discovery.register", "true"),
                    ("consul.discovery.deregister", "false")
                ]));

        Assert.Equal(
            ConsulDiscoveryConfigurationException.DeregisterRequired, exception.ErrorCode);
    }

    [Fact]
    public async Task EnabledRegister_WithOnlyTheDatabaseAdvertisement_DerivesTheCompleteValidView()
    {
        // No process overrides at all: the database keys alone must satisfy the advertisement
        // statement, including the scheme's own database default (#594).
        var projection = await DeriveAsync(
            AdvertisementAddress: null,
            AdvertisementPort: null,
            AdvertisementScheme: null,
            Overrides:
            [
                ("consul.discovery.enabled", "true"),
                ("consul.discovery.register", "true"),
                ("consul.discovery.deregister", "true"),
                ("consul.discovery.ip_address", "192.0.2.10"),
                ("consul.discovery.port", "8081"),
                ("consul.discovery.health_scheme", "https")
            ]);

        var values = await AssertValidViewAsync(projection.Read);
        Assert.Equal("true", values[ConsulSettingDefinitions.Enabled]);
        Assert.Equal("192.0.2.10", values[ConsulSettingDefinitions.Address]);
        Assert.Equal("8081", values[ConsulSettingDefinitions.Port]);
        Assert.Equal("https", values[ConsulSettingDefinitions.HealthScheme]);
        Assert.Equal("192.0.2.10", projection.AdvertisementAddress);
        Assert.Equal(8081, projection.AdvertisementPort);
    }

    [Theory]
    [InlineData("10.1.2.3", null)]   // process address only: the port is missing everywhere
    [InlineData(null, 9443)]         // process port only: the address is missing everywhere
    [InlineData(null, null)]         // neither source provides anything
    public async Task EnabledRegister_WithoutAnAdvertisementFromEitherSource_IsRefusedWithTheFixedCode(
        string? advertisementAddress, int? advertisementPort)
    {
        var exception = await Assert.ThrowsAsync<ConsulDiscoveryConfigurationException>(() =>
            DeriveAsync(
                AdvertisementAddress: advertisementAddress,
                AdvertisementPort: advertisementPort,
                AdvertisementScheme: null,
                Overrides:
                [
                    ("consul.discovery.enabled", "true"),
                    ("consul.discovery.register", "true"),
                    ("consul.discovery.deregister", "true")
                ]));

        Assert.Equal(
            ConsulDiscoveryConfigurationException.AdvertisementRequired, exception.ErrorCode);
    }

    [Fact]
    public async Task EnabledRegister_WithADatabaseAddressButTheSeededZeroPort_IsRefusedWithTheFixedCode()
    {
        // The seeded database port 0 means "not provided": a half-configured database
        // advertisement must keep the fixed advertisement code, never derive a port 0.
        var exception = await Assert.ThrowsAsync<ConsulDiscoveryConfigurationException>(() =>
            DeriveAsync(
                AdvertisementAddress: null,
                AdvertisementPort: null,
                AdvertisementScheme: null,
                Overrides:
                [
                    ("consul.discovery.enabled", "true"),
                    ("consul.discovery.register", "true"),
                    ("consul.discovery.deregister", "true"),
                    ("consul.discovery.ip_address", "192.0.2.10")
                ]));

        Assert.Equal(
            ConsulDiscoveryConfigurationException.AdvertisementRequired, exception.ErrorCode);
    }

    [Fact]
    public async Task LegacyRow_WithoutTheHealthSchemeKey_MaterializesTheHttpDefault()
    {
        // An aggregate written before the key existed carries no health-scheme row: the shared
        // loader materializes the definition default, startup does not fail, and the derived view
        // advertises plain HTTP (#594).
        var product = await BuildProductSnapshotAsync(
            [
                ("consul.discovery.enabled", "true"),
                ("consul.discovery.register", "true"),
                ("consul.discovery.deregister", "true"),
                ("consul.discovery.ip_address", "192.0.2.10"),
                ("consul.discovery.port", "8081")
            ],
            omitKeys: new HashSet<string> { "consul.discovery.health_scheme" });

        Assert.True(product.Values.TryGetValue(
            "consul.discovery.health_scheme", out var materialized) && materialized.HasValue);
        Assert.Equal("http", materialized!.GetString());

        var projection = ConsulDiscoveryProjection.Derive(
            product,
            advertisementAddress: null,
            advertisementPort: null,
            advertisementScheme: null,
            await new MasterKeyRootKeySource(new BootstrapMasterKeyProvider(RootSecret))
                .GetRootKeyAsync());
        var values = await AssertValidViewAsync(projection.Read);
        Assert.Equal("http", values[ConsulSettingDefinitions.HealthScheme]);
    }

    [Fact]
    public async Task StoredRetiredPreferIpAddressRow_IsDroppedOnRead()
    {
        // An older release stored the retired prefer-IP row. The activation-shaped read drops it
        // before materialization, so the load succeeds and the projection never sees the key.
        var product = await BuildProductSnapshotAsync(
            [
                ("consul.discovery.enabled", "true"),
                ("consul.discovery.register", "true"),
                ("consul.discovery.deregister", "true"),
                ("consul.discovery.ip_address", "192.0.2.10"),
                ("consul.discovery.port", "8081")
            ],
            extraRows: [(RetiredSettingKeys.ConsulDiscoveryPreferIpAddress,
                ServiceSettingValueType.Boolean, "true")]);

        Assert.DoesNotContain(
            RetiredSettingKeys.ConsulDiscoveryPreferIpAddress,
            product.Values.Keys,
            StringComparer.Ordinal);
        var projection = ConsulDiscoveryProjection.Derive(
            product,
            advertisementAddress: null,
            advertisementPort: null,
            advertisementScheme: null,
            await new MasterKeyRootKeySource(new BootstrapMasterKeyProvider(RootSecret))
                .GetRootKeyAsync());
        Assert.Equal("192.0.2.10", projection.AdvertisementAddress);
        Assert.Equal(8081, projection.AdvertisementPort);
    }

    [Fact]
    public async Task UpdateValidation_TheRetiredPreferIpAddressSwitch_IsAnUnknownKey()
    {
        // consul.discovery.prefer_ip_address is retired: updating it is the generic unknown-key
        // rejection, never a typed Boolean rule, and the key never re-enters the catalog.
        var candidate = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (legacyKey, value) in ServiceSettingDefinitions.BuildLegacyDefaults())
        {
            var definition = ServiceSettingDefinitions.Find(
                SharedSettingKeys.NormalizedByLegacyKey[legacyKey])!;
            if ((definition.IsOptional && value.Length == 0) || definition.IsSensitive)
            {
                continue;
            }

            candidate[definition.Key] = value;
        }

        candidate["endpoints.public_base_url"] = "https://accounts.example.com";
        candidate["jwt.issuer"] = "https://accounts.example.com";
        candidate["admin.username"] = "root-admin";
        candidate[RetiredSettingKeys.ConsulDiscoveryPreferIpAddress] = "true";

        var result = new ServiceSettingDefinitionRegistry(
                SharedSettingComposition.CreateDefinitionProviders(),
                [new SignaCoreSettingCompositeValidator(isDevelopment: false, validateManagementUpdateRules: true)])
            .Validate(candidate);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error =>
            error.Key == RetiredSettingKeys.ConsulDiscoveryPreferIpAddress &&
            error.ErrorCode == WellKnownServiceSettingValidationErrorCodes.Unknown);
    }

    [Theory]
    [InlineData("localhost", "http://localhost:8500/")]
    [InlineData("127.0.0.1", "http://127.0.0.1:8500/")]
    [InlineData("consul.internal", "https://consul.internal:8500/")]
    [InlineData("https://consul.example.com", "https://consul.example.com")]
    public async Task EndpointConstruction_FollowsTheHostForm(string host, string expectedEndpoint)
    {
        var projection = await DeriveAsync(
            AdvertisementAddress: "10.1.2.3",
            AdvertisementPort: 9443,
            AdvertisementScheme: null,
            Overrides: [("consul.host", host)]);

        var values = await AssertValidViewAsync(projection.Read);
        Assert.Equal(expectedEndpoint, values[ConsulSettingDefinitions.Endpoint]);
    }

    [Fact]
    public async Task UnsetOrBlankToken_StaysUnsetInTheDerivedView()
    {
        foreach (var token in new[] { (string?)"", "  " })
        {
            var overrides = new List<(string, string)>
            {
                ("consul.discovery.enabled", "true"),
                ("consul.discovery.register", "true"),
                ("consul.discovery.deregister", "true")
            };
            if (token is not null)
            {
                // The product catalog treats the sensitive key as optional; a stored blank value is
                // projected exactly like an unset one.
                overrides.Add(("consul.token", token));
            }

            var projection = await DeriveAsync(
                AdvertisementAddress: "10.1.2.3",
                AdvertisementPort: 9443,
                AdvertisementScheme: null,
                Overrides: [.. overrides]);

            var keys = projection.Read.Values.Select(value => value.Key).ToHashSet();
            Assert.DoesNotContain(ConsulSettingDefinitions.Token, keys);
        }
    }

    [Fact]
    public async Task DisabledView_KeepsTheCompleteTypedSchema_WithoutSemanticValidation()
    {
        // Enabled-only inputs are deliberately broken here; the disabled combination must still
        // produce a complete, loadable view and never reach a client.
        var projection = await DeriveAsync(
            AdvertisementAddress: null,
            AdvertisementPort: null,
            AdvertisementScheme: null,
            Overrides:
            [
                ("consul.discovery.enabled", "false"),
                ("consul.discovery.register", "true"),
                ("consul.discovery.deregister", "false"),
                ("consul.host", "not a valid host"),
                ("consul.discovery.ip_address", ""),
                ("consul.discovery.port", "0")
            ]);

        var values = await AssertValidViewAsync(projection.Read);
        Assert.Equal("false", values[ConsulSettingDefinitions.Enabled]);
        Assert.Equal(string.Empty, values[ConsulSettingDefinitions.Address]);
        Assert.Equal("0", values[ConsulSettingDefinitions.Port]);
        Assert.Null(projection.AdvertisementAddress);
    }

    [Fact]
    public async Task DisabledView_FallsBackToTheLegacyInstanceKeys()
    {
        var projection = await DeriveAsync(
            AdvertisementAddress: null,
            AdvertisementPort: null,
            AdvertisementScheme: null,
            Overrides:
            [
                ("consul.discovery.enabled", "false"),
                ("consul.discovery.ip_address", "192.0.2.9"),
                ("consul.discovery.port", "7777")
            ]);

        var values = await AssertValidViewAsync(projection.Read);
        Assert.Equal("192.0.2.9", values[ConsulSettingDefinitions.Address]);
        Assert.Equal("7777", values[ConsulSettingDefinitions.Port]);
    }

    [Fact]
    public async Task EnabledView_WithAServiceNameTheSharedCatalogRejects_FailsTheSharedValidation()
    {
        // The product catalog carries no Consul name-shape constraint of its own, so an underscored
        // name reaches the derived view and is refused by the shared combination validation: the
        // composition surfaces the fixed snapshot-invalid code and never activates a client.
        var product = await BuildProductSnapshotAsync(
            [("consul.discovery.enabled", "true"),
             ("consul.discovery.register", "true"),
             ("consul.discovery.deregister", "true"),
             ("consul.discovery.service_name", "signa_core_underscore")]);
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                [ConsulDiscoveryComposition.AdvertisementAddressKey] = "10.1.2.3",
                [ConsulDiscoveryComposition.AdvertisementPortKey] = "9443"
            }).Build();

        var exception = await Assert.ThrowsAsync<ConsulDiscoveryConfigurationException>(() =>
            services.AddConsulDiscoveryLifecycleAsync(
                configuration, product, new BootstrapMasterKeyProvider(RootSecret)));

        Assert.Equal(ConsulDiscoveryConfigurationException.SnapshotInvalid, exception.ErrorCode);
        Assert.Empty(services);
    }

    [Fact]
    public async Task Composition_RegistersTheTypedAccessor_WithoutGlobalCatalogInjection()
    {
        var product = await BuildProductSnapshotAsync(
            [("consul.discovery.enabled", "true"),
             ("consul.discovery.register", "true"),
             ("consul.discovery.deregister", "true")]);
        var services = new ServiceCollection();
        var globalAccessor = new ServiceSettingCurrentSnapshotAccessor();
        services.AddSingleton<IServiceSettingCurrentSnapshotAccessor>(globalAccessor);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                [ConsulDiscoveryComposition.AdvertisementAddressKey] = "10.1.2.3",
                [ConsulDiscoveryComposition.AdvertisementPortKey] = "9443"
            }).Build();

        await services.AddConsulDiscoveryLifecycleAsync(
            configuration, product, new BootstrapMasterKeyProvider(RootSecret));

        // The typed entry: the dedicated accessor singleton, the shared lifecycle hosted service,
        // and no Consul definitions injected into the global product registry.
        var accessor = services.Single(descriptor =>
            descriptor.ServiceType == typeof(ConsulDiscoverySnapshotAccessor));
        Assert.Equal(ServiceLifetime.Singleton, accessor.Lifetime);
        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService) &&
            descriptor.ImplementationFactory is not null);
        Assert.DoesNotContain(services, descriptor =>
            descriptor.ServiceType == typeof(IServiceSettingDefinitionProvider) &&
            descriptor.ImplementationType == typeof(ConsulSettingDefinitions));

        using var provider = services.BuildServiceProvider();
        Assert.Same(globalAccessor, provider.GetRequiredService<IServiceSettingCurrentSnapshotAccessor>());
        var activated = provider.GetRequiredService<ConsulDiscoverySnapshotAccessor>();
        Assert.True(activated.TryGetCurrent(out var snapshot));
        Assert.Equal(product.Version, snapshot!.Version);
        var expectedTypes = new Dictionary<string, ServiceSettingValueType>
        {
            [ConsulSettingDefinitions.Enabled] = ServiceSettingValueType.Boolean,
            [ConsulSettingDefinitions.Endpoint] = ServiceSettingValueType.String,
            [ConsulSettingDefinitions.Token] = ServiceSettingValueType.String,
            [ConsulSettingDefinitions.ServiceName] = ServiceSettingValueType.String,
            [ConsulSettingDefinitions.Address] = ServiceSettingValueType.String,
            [ConsulSettingDefinitions.Port] = ServiceSettingValueType.Number,
            [ConsulSettingDefinitions.HealthPath] = ServiceSettingValueType.String,
            [ConsulSettingDefinitions.HealthScheme] = ServiceSettingValueType.String
        };
        Assert.Equal(
            expectedTypes.Keys.Order(StringComparer.Ordinal),
            snapshot.Values.Keys.Order(StringComparer.Ordinal));
        Assert.All(expectedTypes, expected =>
            Assert.Equal(expected.Value, snapshot.Values[expected.Key].ValueType));
        Assert.DoesNotContain("consul.host", snapshot.Values.Keys, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain(snapshot.Values.Keys, key =>
            key.StartsWith("consul.", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("http://consul.internal:8500/")]
    [InlineData("http://192.0.2.7:8500/")]
    public async Task Composition_NonLoopbackHttp_IsAcceptedByTheSharedCatalog(string host)
    {
        // ServiceMantle 0.3.2 removed the insecure-transport switch: the shared catalog accepts a
        // plain-HTTP agent endpoint structurally, so an explicit root URI registers as-is. The
        // former switch name in the process configuration is not a shared catalog key any more
        // and is simply ignored.
        var product = await BuildProductSnapshotAsync(
            [("consul.discovery.enabled", "true"),
             ("consul.discovery.register", "true"),
             ("consul.discovery.deregister", "true"),
             ("consul.host", host)]);
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                [ConsulDiscoveryComposition.AdvertisementAddressKey] = "10.1.2.3",
                [ConsulDiscoveryComposition.AdvertisementPortKey] = "9443",
                // The retired switch name is not a shared catalog or process input.
                ["discovery.allow-insecure-http"] = "true"
            }).Build();

        await services.AddConsulDiscoveryLifecycleAsync(
            configuration, product, new BootstrapMasterKeyProvider(RootSecret));

        Assert.Contains(services, descriptor =>
            descriptor.ServiceType == typeof(ConsulDiscoverySnapshotAccessor));
        using var provider = services.BuildServiceProvider();
        var activated = provider.GetRequiredService<ConsulDiscoverySnapshotAccessor>();
        Assert.True(activated.TryGetCurrent(out var snapshot));
        var endpoint = snapshot!.Values[ConsulSettingDefinitions.Endpoint];
        Assert.True(endpoint.HasValue);
        Assert.Equal(host, endpoint.GetString());
    }

    [Fact]
    public async Task Composition_WithTheRefusedCombination_FailsBeforeAnyRegistration()
    {
        var product = await BuildProductSnapshotAsync(
            [("consul.discovery.enabled", "true"),
             ("consul.discovery.register", "true"),
             ("consul.discovery.deregister", "false")]);
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                [ConsulDiscoveryComposition.AdvertisementAddressKey] = "10.1.2.3",
                [ConsulDiscoveryComposition.AdvertisementPortKey] = "9443"
            }).Build();

        var exception = await Assert.ThrowsAsync<ConsulDiscoveryConfigurationException>(() =>
            services.AddConsulDiscoveryLifecycleAsync(
                configuration, product, new BootstrapMasterKeyProvider(RootSecret)));

        Assert.Equal(ConsulDiscoveryConfigurationException.DeregisterRequired, exception.ErrorCode);
        Assert.Empty(services);
    }

    /// <summary>Runs the derived read through the real shared loader with the shared Consul catalog.</summary>
    private static async Task<IReadOnlyDictionary<string, string>> AssertValidViewAsync(
        ServiceSettingSnapshotRead read)
    {
        var definitions = new ConsulSettingDefinitions();
        var registry = new ServiceSettingDefinitionRegistry(
            new IServiceSettingDefinitionProvider[] { definitions },
            new IServiceSettingCompositeValidator[] { definitions });
        var accessor = new ServiceSettingCurrentSnapshotAccessor();
        using var loader = new ServiceSettingSnapshotLoader(
            ServiceId.Parse(ServiceMantleComposition.ServiceIdentifier),
            new FixedSource(read),
            registry,
            accessor,
            new MasterKeyRootKeySource(new BootstrapMasterKeyProvider(RootSecret)));
        var refresh = await loader.RefreshAsync();
        Assert.True(refresh.Succeeded, string.Join(
            ", ", refresh.Errors.Select(error => $"{error.Key}: {error.ErrorCode}")));

        // The raw persisted view is what the projection contract pins; the loader's materialized
        // copy only proves the view is loadable.
        return read.Values.ToDictionary(value => value.Key, value => value.Value);
    }

    private static async Task<ConsulDiscoveryProjectionResult> DeriveAsync(
        string? AdvertisementAddress,
        int? AdvertisementPort,
        string? AdvertisementScheme,
        (string Key, string Value)[] Overrides)
    {
        var product = await BuildProductSnapshotAsync(Overrides);
        return ConsulDiscoveryProjection.Derive(
            product,
            AdvertisementAddress,
            AdvertisementPort,
            AdvertisementScheme,
            await new MasterKeyRootKeySource(new BootstrapMasterKeyProvider(RootSecret))
                .GetRootKeyAsync());
    }

    /// <summary>
    /// Builds a completed-installation-shaped product snapshot through the real shared loader over
    /// the real product catalog, mirroring the bootstrap activation path. Sensitive values are
    /// protected exactly like the shared update path protects them. The activation-shaped read
    /// path drops retired-key rows and materializes definition defaults, so <paramref name="omitKeys"/>
    /// proves default materialization and <paramref name="extraRows"/> proves stored-row tolerance.
    /// </summary>
    private static async Task<ServiceSettingSnapshot> BuildProductSnapshotAsync(
        (string Key, string Value)[] overrides,
        IReadOnlySet<string>? omitKeys = null,
        IEnumerable<(string Key, ServiceSettingValueType Type, string Value)>? extraRows = null)
    {
        var values = InstallationTestSupport.BuildCompletedInstallationValues("consul_admin")
            .ToDictionary(pair => pair.Key, pair => pair.Value);
        foreach (var (key, value) in overrides)
        {
            values[SharedSettingKeys.LegacyByNormalizedKey[key]] = value;
        }

        var masterKeyProvider = new BootstrapMasterKeyProvider(RootSecret);
        var rootKey = await new MasterKeyRootKeySource(masterKeyProvider).GetRootKeyAsync();
        var registry = SharedSettingComposition.CreateRegistry(isDevelopment: false);
        var accessor = new ServiceSettingCurrentSnapshotAccessor();
        var serviceId = ServiceId.Parse(ServiceMantleComposition.ServiceIdentifier);
        var rows = values
            .Where(pair => omitKeys is null ||
                !omitKeys.Contains(SharedSettingKeys.NormalizedByLegacyKey[pair.Key]))
            .Select(pair =>
            {
                var key = SharedSettingKeys.NormalizedByLegacyKey[pair.Key];
                registry.TryGetDefinition(key, out var definition);
                return new PersistedServiceSettingValue(
                    key,
                    version: 1,
                    definition!.ValueType,
                    definition.IsSensitive
                        ? new SensitiveValueProtector(serviceId, key).Protect(pair.Value, rootKey)
                        : pair.Value);
            })
            .Concat(extraRows?.Select(row => new PersistedServiceSettingValue(
                row.Key, version: 1, row.Type, row.Value)) ?? []);
        var read = new ServiceSettingSnapshotRead(serviceId, version: 1, rows);
        using var loader = new ServiceSettingSnapshotLoader(
            serviceId,
            new RetiredSettingKeyFilterSource(new FixedSource(read)),
            registry,
            accessor,
            SharedSettingComposition.CreateRootKeySource(masterKeyProvider));
        var refresh = await loader.RefreshAsync();
        Assert.True(refresh.Succeeded, string.Join(
            ", ", refresh.Errors.Select(error => $"{error.Key}: {error.ErrorCode}")));
        return refresh.Snapshot!;
    }

    private sealed class FixedSource(ServiceSettingSnapshotRead read) : IServiceSettingSnapshotSource
    {
        public ValueTask<ServiceSettingSnapshotRead> LoadAsync(
            ServiceId serviceId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(read);
    }
}
