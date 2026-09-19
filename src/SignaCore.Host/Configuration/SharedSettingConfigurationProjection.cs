using System.Globalization;
using System.Text.Json;
using ServiceMantle.Configuration;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Projects an activated shared setting snapshot back onto the legacy colon-keyed configuration
/// shape, so every existing consumer of <c>IConfiguration</c> keeps reading the same keys.
/// </summary>
/// <remarks>
/// <para>
/// The shared aggregate is keyed by normalized names (<c>ldap.directories</c>); the legacy
/// snapshot path stored colon keys (<c>Ldap:Directories</c>) and expanded JSON settings into
/// configuration sub-keys. This projection renders every materialized value in the same legacy
/// wire format the composite validator uses, maps it through
/// <see cref="SharedSettingKeys.LegacyByNormalizedKey"/>, and reuses
/// <see cref="JsonSettingFlattener.Flatten(string, string, System.Collections.Generic.IDictionary{string, string?})"/>
/// for the JSON expansion, so an activated shared snapshot and the legacy snapshot path produce
/// byte-identical configuration entries over the same stored corpus.
/// </para>
/// <para>
/// Optional keys the aggregate never stored (missing means unset) are skipped, exactly like a
/// missing legacy row. An activated value without a legacy mapping is an internal consistency
/// violation and fails closed; it is never silently dropped.
/// </para>
/// </remarks>
internal static class SharedSettingConfigurationProjection
{
    /// <summary>
    /// Projects the activated snapshot into legacy-keyed values and expandable configuration
    /// entries.
    /// </summary>
    public static (IReadOnlyDictionary<string, string> Values, IReadOnlyDictionary<string, string?> ConfigurationEntries)
        Project(ServiceSettingSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var entries = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (normalizedKey, value) in snapshot.Values)
        {
            if (!SharedSettingKeys.LegacyByNormalizedKey.TryGetValue(normalizedKey, out var legacyKey))
            {
                throw new InvalidOperationException(
                    $"The activated shared setting '{normalizedKey}' has no legacy configuration key.");
            }

            if (!value.HasValue)
            {
                continue;
            }

            var rendered = Render(value);
            values[legacyKey] = rendered;
            if (value.ValueType == ServiceSettingValueType.Json)
            {
                JsonSettingFlattener.Flatten(legacyKey, rendered, entries);
            }
            else
            {
                entries[legacyKey] = rendered;
            }
        }

        return (values, entries);
    }

    /// <summary>
    /// The legacy wire format: integers and booleans in their canonical invariant text, JSON in
    /// its canonical serialized form — the same rendering the composite validator and the shared
    /// update service apply.
    /// </summary>
    private static string Render(ServiceSettingValue value) => value.ValueType switch
    {
        ServiceSettingValueType.String => value.GetString(),
        ServiceSettingValueType.Number => value.GetNumber().ToString("G29", CultureInfo.InvariantCulture),
        ServiceSettingValueType.Boolean => value.GetBoolean() ? "true" : "false",
        ServiceSettingValueType.Json => JsonSerializer.Serialize(value.GetJson()),
        _ => throw new InvalidOperationException($"Unsupported setting value type: {value.ValueType}.")
    };
}
