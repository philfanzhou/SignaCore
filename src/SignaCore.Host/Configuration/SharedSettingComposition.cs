using ServiceMantle.Audit;
using ServiceMantle.Configuration;
using ServiceMantle.Diagnostics.Export.Otlp;
using ServiceMantle.Logging.Remote;
using SignaCore.Domain.Keys;

namespace SignaCore.Host.Configuration;

/// <summary>
/// The one composition point for the SignaCore product setting catalog on the shared ServiceMantle
/// contract, reused by the DI registrations and the bootstrap phase's self-built instances.
/// </summary>
/// <remarks>
/// The definition registry is a deterministic, stateless composition, so separate instances built
/// from this class are equivalent. The <see cref="ServiceSettingCurrentSnapshotAccessor"/>, by
/// contrast, is stateful: the bootstrap phase activates on one instance and pre-registers that
/// exact instance with DI so both observe the same process-local snapshot.
/// </remarks>
internal static class SharedSettingComposition
{
    /// <summary>
    /// The audit operator attributed to the protected legacy configuration upgrade import — the
    /// one that reads the deployment <c>IConfiguration</c> of a pre-change deployment and writes it
    /// into the shared aggregate as its first version.
    /// </summary>
    internal static readonly ManagementAuditOperator LegacyImportOperator = ManagementAuditOperator.Create(
        WellKnownManagementAuditOperatorSources.System,
        "legacy-import");

    /// <summary>Builds the SignaCore definition registry with its composite validator.</summary>
    internal static ServiceSettingDefinitionRegistry CreateRegistry(
        bool isDevelopment, bool validateManagementUpdateRules = false) => new(
        CreateDefinitionProviders(),
        [new SignaCoreSettingCompositeValidator(isDevelopment, validateManagementUpdateRules)]);

    // Capability registrations contribute generic strict validators. The product registry selects
    // its error-code adapter explicitly so startup/legacy/bootstrap remain tolerant, while updates
    // retain every product cross-key rule and the existing signacore.setting.* codes.
    internal static IEnumerable<IServiceSettingDefinitionProvider> CreateDefinitionProviders() =>
        [new ServiceSettingDefinitions(), new GrafanaLokiSettingDefinitions(), new OtlpSettingDefinitions()];

    /// <summary>
    /// Validates one complete legacy-keyed candidate dictionary (the fixed 45-key input form of
    /// first-run setup, the legacy import, and the test installation fixtures): input completeness
    /// and integer text form first, then the shared registry that owns every other rule.
    /// </summary>
    internal static IReadOnlyList<ServiceSettingValidationError> ValidateCompleteCandidate(
        IReadOnlyDictionary<string, string> legacyValues,
        bool isDevelopment = false) =>
        SettingCandidateValidation.Validate(legacyValues, isDevelopment);

    /// <summary>Adapts the bootstrap master key to the shared sensitive-value root key contract.</summary>
    internal static MasterKeyRootKeySource CreateRootKeySource(IMasterKeyProvider masterKeyProvider) =>
        new(masterKeyProvider);

    /// <summary>
    /// Converts a complete legacy-keyed candidate into the shared update changes of a first
    /// aggregate write (first-run setup, the legacy import, and the test seeding). Sensitive keys
    /// whose value is empty are omitted: the shared contract defines a sensitive key as unset when
    /// absent, so a brand-new aggregate never stores an encrypted empty string that the shared
    /// no-authentication classification would later read as a stored credential.
    /// </summary>
    internal static Dictionary<string, string?> BuildSeedChanges(
        IReadOnlyDictionary<string, string> legacyValues)
    {
        var changes = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (legacyKey, value) in legacyValues)
        {
            var normalizedKey = SharedSettingKeys.NormalizedByLegacyKey[legacyKey];
            if (ServiceSettingDefinitions.Find(normalizedKey)?.IsSensitive == true && value.Length == 0)
            {
                continue;
            }

            changes[normalizedKey] = value;
        }

        return changes;
    }
}
