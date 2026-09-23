using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle;
using ServiceMantle.Configuration;
using ServiceMantle.Consul;
using SignaCore.Domain.Keys;

namespace SignaCore.Host.Configuration;

/// <summary>
/// The fixed configuration codes of the snapshot-driven Consul composition. Key names and codes
/// only; no message ever carries a setting value.
/// </summary>
internal sealed class ConsulDiscoveryConfigurationException(string errorCode, string? detail = null)
    : Exception(
        $"The Consul discovery configuration is invalid ({errorCode})." +
        (detail is null ? string.Empty : " " + detail))
{
    public string ErrorCode { get; } = errorCode;

    internal const string DeregisterRequired = "signacore.consul.deregister_required";
    internal const string AdvertisementRequired = "signacore.consul.advertisement_required";
    internal const string SnapshotInvalid = "signacore.consul.snapshot_invalid";
}

/// <summary>
/// The caller-owned accessor the typed shared Consul entry reads. It exposes exactly the one
/// derived <c>discovery.*</c> snapshot activated at composition time and never the global product
/// snapshot.
/// </summary>
internal sealed class ConsulDiscoverySnapshotAccessor : IServiceSettingCurrentSnapshotAccessor
{
    private readonly ServiceSettingCurrentSnapshotAccessor inner;

    internal ConsulDiscoverySnapshotAccessor(ServiceSettingCurrentSnapshotAccessor inner) =>
        this.inner = inner;

    /// <inheritdoc />
    public bool TryGetCurrent(out ServiceSettingSnapshot? snapshot) => inner.TryGetCurrent(out snapshot);
}

/// <summary>
/// Composes the shared snapshot-driven Consul registration lifecycle from the activated product
/// snapshot, replacing the retired Steeltoe wiring in the normal host only.
/// </summary>
/// <remarks>
/// <para>
/// The product stays the only configuration authority: the eleven <c>consul.*</c> product keys are
/// projected in memory into the eight shared <c>discovery.*</c> keys and activated on the dedicated
/// accessor through the shared loader, so the shared combination validation runs unchanged on the
/// derived view. Nothing is persisted, and the global catalog, accessor, store, and query services
/// are untouched — the typed entry injects none of them.
/// </para>
/// <para>
/// The per-instance advertisement comes from the process configuration
/// (<c>ServiceDiscovery:Address</c>, <c>ServiceDiscovery:Port</c>, <c>ServiceDiscovery:HealthScheme</c>;
/// the usual double-underscore environment-variable form works). There is deliberately no address
/// or port auto-detection. Registration changes of every kind take effect after a restart: the
/// derived snapshot is activated once at composition time and captured once by the lifecycle.
/// </para>
/// </remarks>
internal static class ConsulDiscoveryComposition
{
    internal const string AdvertisementAddressKey = "ServiceDiscovery:Address";
    internal const string AdvertisementPortKey = "ServiceDiscovery:Port";
    internal const string AdvertisementSchemeKey = "ServiceDiscovery:HealthScheme";

    /// <summary>
    /// Derives the dedicated snapshot from the bootstrap-activated product snapshot and registers
    /// the shared Consul lifecycle with the typed accessor entry.
    /// </summary>
    /// <exception cref="ConsulDiscoveryConfigurationException">
    /// The enabled combination is refused by this composition, or the derived snapshot did not
    /// pass the shared loader's validation.
    /// </exception>
    internal static async Task<IServiceCollection> AddConsulDiscoveryLifecycleAsync(
        this IServiceCollection services,
        IConfiguration configuration,
        ServiceSettingSnapshot productSnapshot,
        IMasterKeyProvider masterKeyProvider)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(productSnapshot);
        ArgumentNullException.ThrowIfNull(masterKeyProvider);

        var rootKeySource = new MasterKeyRootKeySource(masterKeyProvider);
        var rootKey = await rootKeySource.GetRootKeyAsync(CancellationToken.None).ConfigureAwait(false);

        var projection = ConsulDiscoveryProjection.Derive(
            productSnapshot,
            configuration[AdvertisementAddressKey],
            configuration[AdvertisementPortKey] is { Length: > 0 } portText &&
                int.TryParse(portText, out var port) ? port : null,
            configuration[AdvertisementSchemeKey],
            rootKey);

        // The dedicated registry carries the shared Consul catalog and its combination validator
        // only; the product's global registry is not involved and receives no new definitions.
        var definitions = new ConsulSettingDefinitions();
        var registry = new ServiceSettingDefinitionRegistry(
            new IServiceSettingDefinitionProvider[] { definitions },
            new IServiceSettingCompositeValidator[] { definitions });

        var inner = new ServiceSettingCurrentSnapshotAccessor();
        using var loader = new ServiceSettingSnapshotLoader(
            ServiceId.Parse(ServiceMantleComposition.ServiceIdentifier),
            new InMemorySnapshotSource(projection.Read),
            registry,
            inner,
            rootKeySource);
        var refresh = await loader.RefreshAsync(CancellationToken.None).ConfigureAwait(false);
        if (!refresh.Succeeded || refresh.Snapshot is null)
        {
            // Safe classification codes only: the underlying values may include the ACL token.
            var details = string.Join(
                ", ", refresh.Errors.Select(error => $"{error.Key ?? "<snapshot>"} ({error.ErrorCode})"));
            throw new ConsulDiscoveryConfigurationException(
                ConsulDiscoveryConfigurationException.SnapshotInvalid,
                $"The derived snapshot did not pass the shared validation: {details}.");
        }

        var accessor = new ConsulDiscoverySnapshotAccessor(inner);
        services.AddSingleton(accessor);
        return services.AddServiceMantleConsul<ConsulDiscoverySnapshotAccessor>(
            configureLifecycle: null,
            configureAdvertisement: projection.AdvertisementAddress is null ? null : options =>
            {
                options.Address = projection.AdvertisementAddress;
                options.Port = projection.AdvertisementPort;
            });
    }

    /// <summary>Returns the one fixed in-memory read; the loader queries it exactly once.</summary>
    private sealed class InMemorySnapshotSource(ServiceSettingSnapshotRead read)
        : IServiceSettingSnapshotSource
    {
        public ValueTask<ServiceSettingSnapshotRead> LoadAsync(
            ServiceId serviceId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(read);
        }
    }
}

/// <summary>The in-memory projection of the eleven Consul product keys onto the shared catalog.</summary>
internal static class ConsulDiscoveryProjection
{
    /// <summary>Derives the eight-key read and the instance advertisement from the product snapshot.</summary>
    /// <exception cref="ConsulDiscoveryConfigurationException">
    /// The enabled combination requires deregistration or the explicit advertisement and it is not
    /// configured. Semantic validation of the enabled view is owned by the shared loader.
    /// </exception>
    internal static ConsulDiscoveryProjectionResult Derive(
        ServiceSettingSnapshot product,
        string? advertisementAddress,
        int? advertisementPort,
        string? advertisementScheme,
        string rootKey)
    {
        ArgumentNullException.ThrowIfNull(product);
        if (product.ServiceId != ServiceId.Parse(ServiceMantleComposition.ServiceIdentifier))
        {
            throw new ConsulDiscoveryConfigurationException(
                ConsulDiscoveryConfigurationException.SnapshotInvalid);
        }

        var host = Text(product, "consul.host");
        var agentPort = Number(product, "consul.port");
        var enabled = product.Values.TryGetValue("consul.discovery.enabled", out var enabledValue) &&
                      enabledValue.HasValue && enabledValue.GetBoolean();
        var register = product.Values.TryGetValue("consul.discovery.register", out var registerValue) &&
                       registerValue.HasValue && registerValue.GetBoolean();
        var deregister = product.Values.TryGetValue("consul.discovery.deregister", out var deregisterValue) &&
                         deregisterValue.HasValue && deregisterValue.GetBoolean();
        var wantsRegistration = enabled && register;

        // The shared owner always deregisters on readiness loss and shutdown. A deployment that
        // enabled registration but kept the legacy deregister=false switch is refused instead of
        // silently ignoring the switch, so no stale-registration mode can survive the switch-over.
        if (wantsRegistration && !deregister)
        {
            throw new ConsulDiscoveryConfigurationException(
                ConsulDiscoveryConfigurationException.DeregisterRequired);
        }

        if (wantsRegistration && (advertisementAddress is null || advertisementPort is null))
        {
            throw new ConsulDiscoveryConfigurationException(
                ConsulDiscoveryConfigurationException.AdvertisementRequired);
        }

        // The scheme is part of the process-level advertisement statement, not a product setting.
        var scheme = advertisementScheme is { Length: > 0 } ? advertisementScheme : "http";

        var values = new List<PersistedServiceSettingValue>
        {
            new(ConsulSettingDefinitions.Enabled, product.Version, ServiceSettingValueType.Boolean,
                wantsRegistration ? "true" : "false"),
            new(ConsulSettingDefinitions.Endpoint, product.Version, ServiceSettingValueType.String,
                BuildEndpointUri(host, agentPort)),
            new(ConsulSettingDefinitions.ServiceName, product.Version, ServiceSettingValueType.String,
                Text(product, "consul.discovery.service_name")),
            // The disabled view still carries a complete typed schema for the shared catalog, but
            // its values are never semantically validated and never reach a client: only the
            // service-level fallbacks fill in, never invented values.
            new(ConsulSettingDefinitions.Address, product.Version, ServiceSettingValueType.String,
                advertisementAddress ?? OptionalText(product, "consul.discovery.ip_address") ?? string.Empty),
            new(ConsulSettingDefinitions.Port, product.Version, ServiceSettingValueType.Number,
                (advertisementPort ?? Number(product, "consul.discovery.port"))
                    .ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new(ConsulSettingDefinitions.HealthPath, product.Version, ServiceSettingValueType.String,
                Text(product, "consul.discovery.health_check_path")),
            new(ConsulSettingDefinitions.HealthScheme, product.Version, ServiceSettingValueType.String, scheme)
        };

        // The decrypted token is re-protected under the shared discovery.credential purpose for the
        // loader's envelope contract and never leaves memory in any other form. An unset or blank
        // token stays unset; the shared binding treats the missing key as an anonymous client.
        var token = OptionalText(product, "consul.token");
        if (!string.IsNullOrWhiteSpace(token))
        {
            values.Add(new PersistedServiceSettingValue(
                ConsulSettingDefinitions.Token,
                product.Version,
                ServiceSettingValueType.String,
                new SensitiveValueProtector(product.ServiceId, ConsulSettingDefinitions.Token)
                    .Protect(token!, rootKey)));
        }

        return new ConsulDiscoveryProjectionResult(
            new ServiceSettingSnapshotRead(product.ServiceId, product.Version, values),
            AdvertisementAddress: wantsRegistration ? advertisementAddress : null,
            AdvertisementPort: wantsRegistration ? advertisementPort : null);
    }

    /// <summary>
    /// Builds the agent endpoint text from the product keys. An explicit root URI is used verbatim;
    /// a bare host becomes HTTP on the loopback names only — every other bare host is pinned to
    /// HTTPS, mirroring the shared binding's transport guarantee instead of weakening it.
    /// </summary>
    private static string BuildEndpointUri(string host, decimal port)
    {
        if (host.Contains("://", StringComparison.Ordinal))
        {
            return host;
        }

        var scheme = IsLoopbackHost(host) ? "http" : "https";
        var formattedHost = host.Contains(':') ? $"[{host}]" : host;
        return
            $"{scheme}://{formattedHost}:{port.ToString(System.Globalization.CultureInfo.InvariantCulture)}/";
    }

    private static bool IsLoopbackHost(string host) =>
        "localhost".Equals(host, StringComparison.OrdinalIgnoreCase) ||
        (IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address));

    private static string Text(ServiceSettingSnapshot product, string key)
    {
        if (!product.Values.TryGetValue(key, out var value) ||
            !value.HasValue || value.ValueType != ServiceSettingValueType.String)
        {
            throw new ConsulDiscoveryConfigurationException(
                ConsulDiscoveryConfigurationException.SnapshotInvalid,
                $"The product snapshot is missing a usable '{key}' value.");
        }

        return value.GetString();
    }

    private static string? OptionalText(ServiceSettingSnapshot product, string key) =>
        product.Values.TryGetValue(key, out var value) && value.HasValue
            ? value.GetString()
            : null;

    private static decimal Number(ServiceSettingSnapshot product, string key)
    {
        if (!product.Values.TryGetValue(key, out var value) ||
            !value.HasValue || value.ValueType != ServiceSettingValueType.Number)
        {
            throw new ConsulDiscoveryConfigurationException(
                ConsulDiscoveryConfigurationException.SnapshotInvalid,
                $"The product snapshot is missing a usable '{key}' value.");
        }

        return value.GetNumber();
    }
}

/// <summary>The derived read and the instance advertisement of one projection.</summary>
/// <param name="Read">The complete eight-key persisted view, versioned like the product snapshot.</param>
/// <param name="AdvertisementAddress">
/// The explicit advertised address, or null when registration is not enabled.</param>
/// <param name="AdvertisementPort">The explicit advertised port, or null likewise.</param>
internal sealed record ConsulDiscoveryProjectionResult(
    ServiceSettingSnapshotRead Read,
    string? AdvertisementAddress,
    int? AdvertisementPort);
