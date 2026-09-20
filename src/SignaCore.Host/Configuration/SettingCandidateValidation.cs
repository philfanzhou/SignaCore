using ServiceMantle.Configuration;
using SignaCore.Database.Entity;

namespace SignaCore.Host.Configuration;

/// <summary>
/// The internal pre-validation entry for complete legacy-keyed setting candidates: the two input
/// shapes the shared registry cannot express — every catalog key must be present (completeness
/// precedes defaults, so a missing key with a default cannot be silently filled in) and every
/// Number value must be integer text — followed by the fixed <see cref="SharedSettingKeys"/>
/// mapping onto the shared registry, which owns every type, range, and cross-key rule.
/// </summary>
/// <remarks>
/// This adapter owns input shaping only; it must never grow a second copy of a catalog, a range,
/// or a cross-key rule. All failures are closed, key-scoped codes and never contain values.
/// </remarks>
internal static class SettingCandidateValidation
{
    internal const string MissingCode = "signacore.setting.missing";

    public static IReadOnlyList<ServiceSettingValidationError> Validate(
        IReadOnlyDictionary<string, string> legacyValues,
        bool isDevelopment = false)
    {
        var errors = new List<ServiceSettingValidationError>();
        var normalizedValues = new Dictionary<string, string?>(StringComparer.Ordinal);

        foreach (var definition in SystemSettingsCatalog.Definitions)
        {
            if (!legacyValues.TryGetValue(definition.Key, out var value))
            {
                errors.Add(new ServiceSettingValidationError(
                    SharedSettingKeys.NormalizedByLegacyKey[definition.Key],
                    MissingCode));
                continue;
            }

            if (definition.ValueType == SettingValueTypes.Number &&
                !IntegerSettingConstraint.IsIntegerText(value))
            {
                errors.Add(new ServiceSettingValidationError(
                    SharedSettingKeys.NormalizedByLegacyKey[definition.Key],
                    ServiceSettingDefinitions.IntegerErrorCode));
            }

            normalizedValues[SharedSettingKeys.NormalizedByLegacyKey[definition.Key]] = value;
        }

        errors.AddRange(SharedSettingComposition.CreateRegistry(isDevelopment)
            .Validate(normalizedValues)
            .Errors);
        return errors;
    }
}
