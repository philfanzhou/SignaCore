using ServiceMantle.Configuration;

namespace SignaCore.Host.Configuration;

/// <summary>
/// The thin product input adapter of the protected legacy upgrade import: it reads the deployment
/// <see cref="IConfiguration"/> of a pre-change deployment once and forms one unique, complete,
/// legacy-keyed candidate for all definition-table keys.
/// </summary>
/// <remarks>
/// <para>
/// This adapter owns exactly the product input rules the old importer owned — the legacy
/// defaults of the definition table, trimming, the fixed key aliases with canonical-key
/// precedence, JSON section and scalar reading, and the required-key completeness check with
/// key names only. It never persists anything and never
/// opens a transaction: mapping through <see cref="SharedSettingKeys"/>, validation,
/// sensitive-value protection, and the single transactional write all belong to the shared update
/// path that consumes its output.
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
        var values = ServiceSettingDefinitions.BuildLegacyDefaults();
        var imported = new List<string>();

        foreach (var definition in ServiceSettingDefinitions.Table)
        {
            var legacyKey = ServiceSettingDefinitions.LegacyKeyOf(definition);
            var legacyValue = ReadLegacyValue(configuration, definition);
            if (legacyValue is null)
            {
                continue;
            }

            values[legacyKey] = legacyValue;
            imported.Add(legacyKey);
        }

        // The issuer used to default to the literal "SignaCore" and was allowed to diverge from the
        // public base URL. Import the deployment's real values rather than inventing them, and let
        // the shared update validation reject the combination if the deployment never configured
        // them properly.
        var missing = ServiceSettingDefinitions.Table
            .Where(definition => !definition.HasLegacyDefault &&
                                 !values.ContainsKey(ServiceSettingDefinitions.LegacyKeyOf(definition)))
            .Select(ServiceSettingDefinitions.LegacyKeyOf)
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

        return (values, imported.Count);
    }

    /// <summary>
    /// Keys whose pre-change name differs from the catalog name. Read in order, first hit wins.
    /// </summary>
    private static readonly Dictionary<string, string[]> LegacyKeyAliases = new(StringComparer.Ordinal)
    {
        [SystemSettingKeys.AdminUsername] = [SystemSettingKeys.LegacyAdminBootstrapUsername]
    };

    private static string? ReadLegacyValue(
        IConfiguration configuration,
        ProductSettingDefinition definition)
    {
        var legacyKey = ServiceSettingDefinitions.LegacyKeyOf(definition);
        LegacyKeyAliases.TryGetValue(legacyKey, out var aliases);
        var candidateKeys = new[] { legacyKey }.Concat(aliases ?? []);

        foreach (var key in candidateKeys)
        {
            if (definition.ValueType == ServiceSettingValueType.Json)
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
