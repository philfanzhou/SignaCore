using System.Data;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Host.Configuration;

/// <summary>
/// One-time import that upgrades a pre-change deployment without ever exposing first-run setup.
/// <para>
/// The current effective legacy configuration — appsettings, environment variables, and whatever the
/// launcher injected — is read, validated, and stored transactionally. Installation is marked
/// <c>Completed</c> only after the imported snapshot is valid; an incomplete import fails closed with
/// the list of missing keys, creates no administrator, and does not open <c>/setup</c>.
/// </para>
/// </summary>
internal static class LegacyConfigurationImporter
{
    public static async Task<InstallationStateEntity> ImportAsync(
        IdentityDbContext db,
        IConfiguration configuration,
        SystemSettingsStore settingsStore,
        ILogger logger,
        CancellationToken cancellationToken = default)
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
        // validation reject the combination if the deployment never configured them properly.
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

        // A pre-change deployment that served plain HTTP had no HTTPS requirement to opt out of, so
        // importing it as-is would fail closed on an upgrade that changed nothing. Record the
        // insecure transport it was already using, loudly, rather than silently relaxing the rule:
        // the setting is now visible and editable in the administration console.
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

        SettingsSnapshotValidator.ThrowIfInvalid(values);

        await using var transaction = await db.Database.BeginTransactionAsync(
            IsolationLevel.Serializable,
            cancellationToken);

        const int configurationVersion = 1;
        await settingsStore.WriteAsync(db, values, configurationVersion, "legacy-import", cancellationToken);

        var now = DateTimeOffset.UtcNow;
        var state = new InstallationStateEntity
        {
            Id = InstallationStateEntity.SingletonId,
            Status = InstallationStatus.Completed,
            InstallationId = Guid.NewGuid(),
            SetupCodeHash = null,
            SetupCodeExpiresAt = null,
            CompletedAt = now,
            ConfigurationVersion = configurationVersion
        };
        db.InstallationStates.Add(state);

        db.AuditLogs.Add(new AuditLogEntity
        {
            Id = Guid.NewGuid(),
            Action = "installation.legacy_import.completed",
            TargetType = "Installation",
            TargetId = state.InstallationId.ToString(),
            ActorName = "legacy-import",
            Description =
                $"Imported {imported.Count} legacy settings into system_settings. " +
                $"ConfigurationVersion={configurationVersion}.",
            CreatedAt = now
        });

        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        db.ChangeTracker.Clear();

        logger.LogInformation(
            "Legacy configuration import completed: InstallationId={InstallationId}, " +
            "ImportedKeyCount={ImportedKeyCount}, ConfigurationVersion={Version}",
            state.InstallationId,
            imported.Count,
            configurationVersion);

        return state;
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
