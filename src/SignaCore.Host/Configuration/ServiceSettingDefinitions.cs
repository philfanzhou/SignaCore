using System.Text.Json;
using ServiceMantle.Configuration;
using SignaCore.Database.Entity;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Registers the SignaCore product settings on the shared ServiceMantle setting contract.
/// </summary>
/// <remarks>
/// Every legacy catalog entry maps to exactly one normalized key (see <see cref="SharedSettingKeys"/>)
/// with the same value type and restart flag. Declared differences, fixed by task #101:
/// sensitive definitions carry no default value and are not required (missing means unset), and
/// legacy empty-string / empty-document defaults are not carried over — those keys are likewise
/// optional and start unset, so a legacy snapshot carrying the empty default and a new-stack
/// snapshot with the key unset accept and reject the same updates. Keys whose empty default was
/// not migrated are therefore not required either. Number keys keep the legacy integer semantics
/// through <see cref="IntegerSettingConstraint"/> and the legacy ranges through
/// <see cref="NumberRangeSettingConstraint"/>; the JSON keys with a fixed root kind use
/// <see cref="JsonRootKindSettingConstraint"/>. Cross-key rules stay in
/// <see cref="SignaCoreSettingCompositeValidator"/>.
/// </remarks>
internal sealed class ServiceSettingDefinitions : IServiceSettingDefinitionProvider
{
    internal const string IntegerErrorCode = "signacore.setting.integer";

    private static readonly IReadOnlyDictionary<string, (decimal Minimum, decimal Maximum)> Ranges =
        new Dictionary<string, (decimal, decimal)>(StringComparer.Ordinal)
        {
            ["jwt.token_expiration_hours"] = (1, 24),
            ["refresh_token.expiration_days"] = (1, 365),
            ["password_hasher.work_factor"] = (10, 15)
        };

    private static readonly IReadOnlyDictionary<string, JsonValueKind> JsonRootKinds =
        new Dictionary<string, JsonValueKind>(StringComparer.Ordinal)
        {
            ["admin_web.allowed_origins"] = JsonValueKind.Array,
            ["callback.allowed_domains"] = JsonValueKind.Array,
            ["sms.bypass_phones"] = JsonValueKind.Array,
            ["reverse_proxy.known_proxies"] = JsonValueKind.Array,
            ["ldap.directories"] = JsonValueKind.Array,
            ["sms.profiles"] = JsonValueKind.Object
        };

    public IEnumerable<ServiceSettingDefinition> GetDefinitions()
    {
        foreach (var legacy in SystemSettingsCatalog.Definitions)
        {
            var key = SharedSettingKeys.NormalizedByLegacyKey[legacy.Key];
            var isSensitive = legacy.IsSecret;
            var defaultValue = CarryDefaultValue(legacy, isSensitive);

            yield return new ServiceSettingDefinition(
                key,
                MapValueType(legacy.ValueType),
                isRequired: !IsOptional(legacy),
                isSensitive: isSensitive,
                defaultValue: defaultValue,
                requiresRestart: legacy.RestartRequired,
                constraints: BuildConstraints(key, legacy.ValueType));
        }
    }

    /// <summary>
    /// Optional keys: sensitive ones (missing means unset) and the keys whose legacy empty default
    /// was not migrated. Everything else keeps the legacy "must be present in the active snapshot"
    /// requirement.
    /// </summary>
    internal static bool IsOptional(SystemSettingDefinition legacy) =>
        legacy.IsSecret ||
        (legacy.DefaultValue is { } value && IsEmptyDefault(legacy.ValueType, value));

    /// <summary>
    /// Sensitive definitions cannot carry defaults (package contract), and the legacy empty-string
    /// or empty-document defaults are deliberately not migrated: those keys start unset and the
    /// composite validator treats them exactly as the legacy validator treated the empty value.
    /// </summary>
    private static string? CarryDefaultValue(SystemSettingDefinition legacy, bool isSensitive)
    {
        if (isSensitive)
        {
            return null;
        }

        return legacy.DefaultValue is { } value && !IsEmptyDefault(legacy.ValueType, value)
            ? value
            : null;
    }

    internal static bool IsEmptyDefault(string valueType, string value) => valueType switch
    {
        SettingValueTypes.String => value.Length == 0,
        SettingValueTypes.Json => value is "[]" or "{}",
        _ => false
    };

    private static ServiceSettingValueType MapValueType(string valueType) => valueType switch
    {
        SettingValueTypes.String => ServiceSettingValueType.String,
        SettingValueTypes.Number => ServiceSettingValueType.Number,
        SettingValueTypes.Boolean => ServiceSettingValueType.Boolean,
        SettingValueTypes.Json => ServiceSettingValueType.Json,
        _ => throw new InvalidOperationException($"Unsupported legacy value type: {valueType}")
    };

    private static IEnumerable<IServiceSettingValueConstraint> BuildConstraints(
        string key,
        string legacyValueType)
    {
        if (legacyValueType == SettingValueTypes.Number)
        {
            yield return new IntegerSettingConstraint();
            if (Ranges.TryGetValue(key, out var range))
            {
                yield return new NumberRangeSettingConstraint(range.Minimum, range.Maximum);
            }
        }
        else if (legacyValueType == SettingValueTypes.Json &&
                 JsonRootKinds.TryGetValue(key, out var rootKind))
        {
            yield return new JsonRootKindSettingConstraint([rootKind]);
        }
    }
}
