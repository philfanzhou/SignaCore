using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Reads and writes the global settings snapshot in the business database.
/// <para>
/// Secret values are encrypted on write and decrypted on read; nothing here logs a setting value,
/// and failures report only keys.
/// </para>
/// </summary>
internal sealed class SystemSettingsStore
{
    private readonly IConfigurationProtector _protector;

    public SystemSettingsStore(IConfigurationProtector protector)
    {
        _protector = protector;
    }

    /// <summary>
    /// Loads every stored setting, decrypts secrets, and expands JSON settings into configuration
    /// keys. Throws when any single row cannot be materialised: an activated snapshot is all-or-nothing.
    /// </summary>
    public async Task<SystemSettingsSnapshot> LoadAsync(
        IdentityDbContext db,
        int configurationVersion,
        CancellationToken cancellationToken = default)
    {
        var rows = await db.SystemSettings
            .AsNoTracking()
            .OrderBy(setting => setting.Key)
            .ToListAsync(cancellationToken);

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var entries = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var undecryptable = new List<string>();
        var malformed = new List<string>();

        foreach (var row in rows)
        {
            string value;
            if (row.IsSecret)
            {
                try
                {
                    value = _protector.Unprotect(row.Key, row.Value);
                }
                catch (CryptographicException)
                {
                    undecryptable.Add(row.Key);
                    continue;
                }
            }
            else
            {
                value = row.Value;
            }

            values[row.Key] = value;

            if (row.ValueType == SettingValueTypes.Json)
            {
                try
                {
                    JsonSettingFlattener.Flatten(row.Key, value, entries);
                }
                catch (System.Text.Json.JsonException)
                {
                    malformed.Add(row.Key);
                }
            }
            else
            {
                entries[row.Key] = value;
            }
        }

        if (undecryptable.Count > 0)
        {
            throw new SettingsSnapshotException(
                "Stored secret settings could not be decrypted with the configured root key. " +
                "Verify that the bootstrap master key matches the one this database was initialized " +
                $"with. Affected keys: {string.Join(", ", undecryptable)}.",
                undecryptable);
        }

        if (malformed.Count > 0)
        {
            throw new SettingsSnapshotException(
                $"Stored settings contain malformed JSON. Affected keys: {string.Join(", ", malformed)}.",
                malformed);
        }

        return new SystemSettingsSnapshot(configurationVersion, values, entries);
    }

    /// <summary>
    /// Upserts the supplied settings. The caller owns the transaction so a snapshot write can be
    /// committed together with the installation-state change that activates it.
    /// </summary>
    public async Task WriteAsync(
        IdentityDbContext db,
        IReadOnlyDictionary<string, string> values,
        int configurationVersion,
        string? updatedBy,
        CancellationToken cancellationToken = default)
    {
        // Materialize the keys: the provider translates Contains over a plain array, and a dictionary
        // key collection is not something every provider is guaranteed to handle.
        var keys = values.Keys.ToArray();
        var existing = await db.SystemSettings
            .Where(setting => keys.Contains(setting.Key))
            .ToDictionaryAsync(setting => setting.Key, StringComparer.OrdinalIgnoreCase, cancellationToken);

        var now = DateTimeOffset.UtcNow;

        foreach (var (key, plaintext) in values)
        {
            var definition = SystemSettingsCatalog.Find(key)
                ?? throw new InvalidOperationException(
                    $"'{key}' is not a database-backed setting.");

            var storedValue = definition.ValueType == SettingValueTypes.Json
                ? JsonSettingFlattener.Canonicalize(plaintext)
                : plaintext;

            if (definition.IsSecret)
            {
                storedValue = _protector.Protect(key, storedValue);
            }

            if (existing.TryGetValue(key, out var row))
            {
                row.Value = storedValue;
                row.ValueType = definition.ValueType;
                row.IsSecret = definition.IsSecret;
                row.Version = configurationVersion;
                row.UpdatedAt = now;
                row.UpdatedBy = updatedBy;
            }
            else
            {
                db.SystemSettings.Add(new SystemSettingEntity
                {
                    Key = key,
                    Value = storedValue,
                    ValueType = definition.ValueType,
                    IsSecret = definition.IsSecret,
                    Version = configurationVersion,
                    UpdatedAt = now,
                    UpdatedBy = updatedBy
                });
            }
        }
    }
}
