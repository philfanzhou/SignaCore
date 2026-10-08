using ServiceMantle;
using ServiceMantle.Audit;
using ServiceMantle.Configuration;
using ServiceMantle.Diagnostics.Export.Otlp;
using ServiceMantle.Logging.Remote;
using SignaCore.Host.Configuration;

namespace SignaCore.Host.Management;

/// <summary>
/// A single update's baseline-aware validation, captured by the shared service's transaction load.
/// No pre-read, additional transaction, retry, or runtime publication is performed.
/// </summary>
internal sealed class ManagementSettingRecovery : IServiceSettingUpdateTransaction
{
    private readonly IServiceSettingUpdateTransaction transaction;
    private readonly IServiceSettingRootKeySource rootKey;
    private readonly ServiceSettingDefinitionRegistry baselineRegistry;
    private readonly ServiceSettingUpdateCommand command;
    private readonly RecoveryValidator validator;

    internal ManagementSettingRecovery(
        IServiceSettingUpdateTransaction transaction, IServiceSettingRootKeySource rootKey,
        bool isDevelopment, ServiceSettingUpdateCommand command)
    {
        this.transaction = transaction;
        this.rootKey = rootKey;
        this.command = command;
        baselineRegistry = SharedSettingComposition.CreateRegistry(isDevelopment);
        validator = new RecoveryValidator(isDevelopment, command.Changes.Keys.Select(key =>
            baselineRegistry.TryGetDefinition(key, out var definition) ? definition!.Key : key));
        Registry = new ServiceSettingDefinitionRegistry(
            SharedSettingComposition.CreateDefinitionProviders(), [validator]);
    }

    internal ServiceSettingDefinitionRegistry Registry { get; }

    public async ValueTask<ServiceSettingStoreSnapshot> LoadAsync(
        ServiceId serviceId, CancellationToken cancellationToken)
    {
        var loaded = await transaction.LoadAsync(serviceId, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        // Retired keys (RetiredSettingKeys) are dropped from the baseline read: the shared update
        // service fails closed on any stored key without a definition, so a leftover row from an
        // older release must not turn every management update into a storage failure. The stored
        // row itself is untouched; dropping it is the operator's one-row cleanup.
        var current = new ServiceSettingStoreSnapshot(
            loaded.ServiceId,
            loaded.Version,
            loaded.Values.Where(pair => !RetiredSettingKeys.IsRetired(pair.Key))
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal),
            loaded.UpdatedAtUtc,
            loaded.UpdatedBy,
            loaded.RestartRequired);
        // Preserve the shared service's version/mismatch/exhaustion priority. An absent aggregate
        // has no legacy group to preserve and uses the default strict candidate validation.
        if (current.ServiceId == serviceId && current.Version == command.ExpectedVersion
            && current.Version > 0 && current.Version < long.MaxValue)
        {
            using var loader = new ServiceSettingSnapshotLoader(serviceId,
                new BaselineSource(current, baselineRegistry), baselineRegistry,
                new ServiceSettingCurrentSnapshotAccessor(), rootKey);
            var refresh = await loader.RefreshAsync(cancellationToken);
            if (!refresh.Succeeded)
                throw new InvalidOperationException("The stored setting baseline is unavailable.");
            validator.SetBaseline(refresh.Snapshot!);
        }
        return current;
    }

    public ValueTask<ServiceSettingUpdateResult> ApplyAsync(
        ServiceId serviceId, ServiceSettingStoreUpdate update,
        IReadOnlyList<ManagementAuditEvent> auditEvents, CancellationToken cancellationToken) =>
        transaction.ApplyAsync(serviceId, update, auditEvents, cancellationToken);

    private sealed class BaselineSource(
        ServiceSettingStoreSnapshot baseline, ServiceSettingDefinitionRegistry registry)
        : IServiceSettingSnapshotSource
    {
        public ValueTask<ServiceSettingSnapshotRead> LoadAsync(
            ServiceId serviceId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var values = baseline.Values.Select(pair =>
            {
                if (!registry.TryGetDefinition(pair.Key, out var definition))
                    throw new InvalidOperationException("The stored setting baseline is unavailable.");
                return new PersistedServiceSettingValue(
                    pair.Key, baseline.Version, definition!.ValueType, pair.Value);
            });
            return ValueTask.FromResult(new ServiceSettingSnapshotRead(
                baseline.ServiceId, baseline.Version, values));
        }
    }

    // This validator belongs only to this invocation. Decrypted group values never enter DI,
    // request metadata, logs, errors, or audit payloads.
    private sealed class RecoveryValidator(bool isDevelopment, IEnumerable<string> changedKeys)
        : IServiceSettingCompositeValidator
    {
        // Touching any Loki key — including the explicit no-authentication opt-in — selects the
        // whole group for strict evaluation; the legacy waiver never applies to an explicitly
        // changed group.
        private static readonly string[] LokiGroupKeys =
        [
            GrafanaLokiSettingDefinitions.Endpoint,
            GrafanaLokiSettingDefinitions.Authorization,
            GrafanaLokiSettingDefinitions.AllowNoAuthentication
        ];

        private readonly HashSet<string> touched = new(changedKeys, StringComparer.OrdinalIgnoreCase);
        private readonly SignaCoreSettingCompositeValidator core = new(isDevelopment);
        private string? uri, authorization, endpoint;
        private bool allowNoAuthentication;
        private bool preserveLoki, preserveOtlp;

        internal void SetBaseline(ServiceSettingSnapshot snapshot)
        {
            uri = Read(snapshot.Values, GrafanaLokiSettingDefinitions.Endpoint);
            authorization = Read(snapshot.Values, GrafanaLokiSettingDefinitions.Authorization);
            allowNoAuthentication = ReadBoolean(snapshot.Values, GrafanaLokiSettingDefinitions.AllowNoAuthentication);
            endpoint = Read(snapshot.Values, OtlpSettingDefinitions.Endpoint);
            preserveLoki = !touched.Overlaps(LokiGroupKeys)
                && GrafanaLokiSettingState.Classify(uri, authorization, allowNoAuthentication)
                    .IsUnusable;
            preserveOtlp = !touched.Contains(OtlpSettingDefinitions.Endpoint)
                && OtlpSettingState.Classify(endpoint).IsUnusable;
        }

        public IEnumerable<ServiceSettingValidationError> Validate(ServiceSettingValidationContext context)
        {
            var errors = core.Validate(context).ToList();
            bool Same(string key, string? original) => string.Equals(
                context.TryGetValue(key, out var value) && value!.HasValue ? value.GetString() : null,
                original, StringComparison.Ordinal);
            // A Boolean key missing from the complete candidate keeps the registered default
            // (false), which is exactly what an older-release baseline stored.
            bool SameBoolean(string key, bool original) =>
                context.TryGetValue(key, out var value) && value!.HasValue
                    ? value.GetBoolean() == original
                    : !original;
            errors.AddRange(SignaCoreSettingCompositeValidator.ValidateOptionalSettings(context,
                preserveLoki && Same(GrafanaLokiSettingDefinitions.Endpoint, uri)
                    && Same(GrafanaLokiSettingDefinitions.Authorization, authorization)
                    && SameBoolean(GrafanaLokiSettingDefinitions.AllowNoAuthentication, allowNoAuthentication),
                preserveOtlp && Same(OtlpSettingDefinitions.Endpoint, endpoint)));
            return errors;
        }

        private static string? Read(IReadOnlyDictionary<string, ServiceSettingValue> values, string key) =>
            values.TryGetValue(key, out var value) && value.HasValue ? value.GetString() : null;

        private static bool ReadBoolean(IReadOnlyDictionary<string, ServiceSettingValue> values, string key) =>
            values.TryGetValue(key, out var value) && value.HasValue && value.GetBoolean();
    }
}
