using SignaCore.Database.Entity;

namespace SignaCore.Host.Configuration;

/// <summary>
/// The thin product input adapter of the protected legacy upgrade import: it reads the deployment
/// <see cref="IConfiguration"/> of a pre-change deployment once and forms one unique, complete,
/// legacy-keyed candidate for all 43 catalog keys.
/// </summary>
/// <remarks>
/// <para>
/// This adapter owns exactly the product input rules the old importer owned — catalog defaults,
/// trimming, the fixed key aliases with canonical-key precedence, JSON section and scalar reading,
/// the plain-HTTP compatibility opt-in, and the required-key completeness check with key names
/// only. It never persists anything and never opens a transaction: mapping through
/// <see cref="SharedSettingKeys"/>, validation, sensitive-value protection, and the single
/// transactional write all belong to the shared update path that consumes its output.
/// </para>
/// <para>
/// A pre-change deployment that served plain HTTP had no HTTPS requirement to opt out of, so
/// importing it as-is would fail closed on an upgrade that changed nothing. The adapter records the
/// insecure transport the deployment was already using, loudly, rather than silently relaxing the
/// rule; the setting is visible and editable in the administration console afterwards.
/// </para>
/// </remarks>
internal static class LegacyConfigurationInput
{
    /// <summary>
    /// Reads the complete import candidate from the deployment configuration.
    /// </summary>
    /// <returns>The complete legacy-keyed values and how many keys the deployment supplied.</returns>
    /// <exception cref="SettingsSnapshotException">
    /// A required setting with no default is missing from the deployment configuration. The
    /// message carries key names only.
    /// </exception>
    public static (Dictionary<string, string> Values, int ImportedKeyCount) ReadCompleteInput(
        IConfiguration configuration,
        ILogger logger)
    {
        var values = SystemSettingsCatalog.BuildDefaults();
        var imported = new List<string>();

        foreach (var definition in SystemSettingsCatalog.Definitions)
        {
            var legacyValue = ReadLegacyValue(configuration, definition);
            if (legacyValue is null)
            {
                continue;
            }

            values[definition.Key] = legacyValue;
            imported.Add(definition.Key);
        }

        // The issuer used to default to the literal "SignaCore" and was allowed to diverge from the
        // public base URL. Import the deployment's real values rather than inventing them, and let
        // the shared update validation reject the combination if the deployment never configured
        // them properly.
        var missing = SystemSettingsCatalog.Definitions
            .Where(definition => !definition.HasDefault && !values.ContainsKey(definition.Key))
            .Select(definition => definition.Key)
            .ToList();

        if (missing.Count > 0)
        {
            throw new SettingsSnapshotException(
                "Legacy configuration import cannot complete because required settings are missing " +
                $"from the current deployment configuration: {string.Join(", ", missing)}. " +
                "Set them for one more start (appsettings or environment variables) so they can be " +
                "imported into the database, then remove them.",
                missing);
        }

        // See the class remarks: preserve the deployment's existing plain-HTTP behavior, loudly.
        if (values.TryGetValue(SystemSettingKeys.PublicBaseUrl, out var importedBaseUrl) &&
            SettingsSnapshotValidator.TryNormalizeBaseUrl(importedBaseUrl, out var normalizedBaseUrl, out _) &&
            normalizedBaseUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !IsExplicitlyTrue(values, SystemSettingKeys.SecurityAllowNonHttpsIssuer))
        {
            values[SystemSettingKeys.SecurityAllowNonHttpsIssuer] = "true";
            logger.LogWarning(
                "The imported deployment advertises a plain-HTTP public base URL, so {Key} has been " +
                "enabled to preserve its existing behavior. Move this deployment to HTTPS and turn " +
                "the setting off.",
                SystemSettingKeys.SecurityAllowNonHttpsIssuer);
        }

        return (values, imported.Count);
    }

    private static bool IsExplicitlyTrue(IReadOnlyDictionary<string, string> values, string key) =>
        values.TryGetValue(key, out var raw) && bool.TryParse(raw, out var parsed) && parsed;

    /// <summary>
    /// Keys whose pre-change name differs from the catalog name. Read in order, first hit wins.
    /// </summary>
    private static readonly Dictionary<string, string[]> LegacyKeyAliases = new(StringComparer.Ordinal)
    {
        [SystemSettingKeys.AdminUsername] = [SystemSettingKeys.LegacyAdminBootstrapUsername]
    };

    private static string? ReadLegacyValue(
        IConfiguration configuration,
        SystemSettingDefinition definition)
    {
        LegacyKeyAliases.TryGetValue(definition.Key, out var aliases);
        var candidateKeys = new[] { definition.Key }.Concat(aliases ?? []);

        foreach (var key in candidateKeys)
        {
            if (definition.ValueType == SettingValueTypes.Json)
            {
                var exported = ConfigurationJsonExporter.Export(configuration.GetSection(key));
                if (exported is not null)
                {
                    return exported;
                }

                continue;
            }

            var value = configuration[key];
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return null;
    }
}
