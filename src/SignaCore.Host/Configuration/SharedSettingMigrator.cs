using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using ServiceMantle.Audit;
using ServiceMantle.Configuration;
using SignaCore.Database;
using SignaCore.Domain.Keys;

namespace SignaCore.Host.Configuration;

/// <summary>Closed outcomes of the one-shot legacy settings migration.</summary>
internal enum SharedSettingMigrationStatus
{
    /// <summary>The aggregate was created by this call inside the caller's transaction.</summary>
    Migrated,

    /// <summary>The aggregate already exists (or a concurrent writer won); nothing was written.</summary>
    AlreadyMigrated,

    /// <summary>There are no legacy setting rows to migrate.</summary>
    NothingToMigrate,

    /// <summary>The migration was refused before or during the write; the aggregate is untouched.</summary>
    Failed
}

/// <summary>A value-free migration report: outcome, counts, key names and a closed classification.</summary>
/// <remarks>
/// Reports never carry setting values: failures are described by key names and classification codes
/// only, so they are safe to log and to surface in startup diagnostics.
/// </remarks>
internal sealed class SharedSettingMigrationResult
{
    /// <summary>Classification for legacy rows whose key is not registered in <see cref="SharedSettingKeys"/>.</summary>
    public const string UnregisteredKeysClassification = "signacore.setting_migration.unregistered_keys";

    /// <summary>Classification for secret envelopes the configured root key cannot decrypt.</summary>
    public const string UndecryptableSecretsClassification = "signacore.setting_migration.undecryptable_secrets";

    private SharedSettingMigrationResult(
        SharedSettingMigrationStatus status,
        int migratedKeyCount,
        string? failureClassification,
        IReadOnlyList<string> failedKeys)
    {
        Status = status;
        MigratedKeyCount = migratedKeyCount;
        FailureClassification = failureClassification;
        FailedKeys = failedKeys;
    }

    /// <summary>Gets the closed migration outcome.</summary>
    public SharedSettingMigrationStatus Status { get; }

    /// <summary>Gets how many legacy rows were written into the aggregate on a <see cref="SharedSettingMigrationStatus.Migrated"/> result.</summary>
    public int MigratedKeyCount { get; }

    /// <summary>Gets the failure classification on a <see cref="SharedSettingMigrationStatus.Failed"/> result.</summary>
    public string? FailureClassification { get; }

    /// <summary>Gets the key names a failure report is about; never values.</summary>
    public IReadOnlyList<string> FailedKeys { get; }

    public static SharedSettingMigrationResult Migrated(int keyCount) =>
        new(SharedSettingMigrationStatus.Migrated, keyCount, null, []);

    public static SharedSettingMigrationResult AlreadyMigrated() =>
        new(SharedSettingMigrationStatus.AlreadyMigrated, 0, null, []);

    public static SharedSettingMigrationResult NothingToMigrate() =>
        new(SharedSettingMigrationStatus.NothingToMigrate, 0, null, []);

    public static SharedSettingMigrationResult Failed(string classification, IReadOnlyList<string> failedKeys)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(classification);
        ArgumentNullException.ThrowIfNull(failedKeys);
        return new(SharedSettingMigrationStatus.Failed, 0, classification, failedKeys);
    }

    /// <inheritdoc />
    public override string ToString() =>
        $"SharedSettingMigrationResult(Status={Status}, MigratedKeyCount={MigratedKeyCount}, " +
        $"FailureClassification={FailureClassification ?? "-"}, FailedKeys={string.Join(", ", FailedKeys)})";
}

/// <summary>
/// One-shot migration of the legacy <c>system_settings</c> rows into the shared
/// <c>service_settings</c> aggregate.
/// </summary>
/// <remarks>
/// <para>
/// Every legacy row is mapped through <see cref="SharedSettingKeys"/>, secret envelopes are opened
/// with the legacy <see cref="IConfigurationProtector"/> keyed by the legacy colon key, and the
/// complete plaintext batch is handed to <see cref="ServiceSettingUpdateService"/> in a single
/// update (expected version 0). The update service owns definition validation and re-protects
/// sensitive values with the shared protector, whose purpose is the normalized key; this component
/// never constructs that protector itself. The caller owns the transaction (begin and commit) and
/// the installation lock; this component takes no lock, never commits, and never modifies the
/// legacy rows.
/// </para>
/// <para>
/// Failure discipline is fail-closed and value-free: all rows are decrypted and all keys are
/// checked before anything is written, so a refusal never leaves a partial aggregate. Source
/// problems are reported even when the aggregate already exists — a re-run against a broken source
/// fails closed instead of silently claiming success.
/// </para>
/// <para>
/// Idempotency and concurrent double-migration go through the shared optimistic-version path: the
/// single write attempt carries expected version 0, so an aggregate that already exists (written by
/// an earlier run or won by a concurrent instance) fails with a version conflict, which this
/// component reports as <see cref="SharedSettingMigrationStatus.AlreadyMigrated"/> without writing
/// or overwriting anything.
/// </para>
/// </remarks>
internal sealed class SharedSettingMigrator(
    IConfigurationProtector legacyProtector,
    ServiceSettingUpdateService updateService)
{
    /// <summary>Migrates the complete legacy settings table into the shared aggregate.</summary>
    /// <exception cref="OperationCanceledException">The caller requested cancellation.</exception>
    public async Task<SharedSettingMigrationResult> MigrateAsync(
        IdentityDbContext database,
        ManagementAuditOperator migrationOperator,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(migrationOperator);
        cancellationToken.ThrowIfCancellationRequested();

        var rows = await database.SystemSettings
            .AsNoTracking()
            .OrderBy(row => row.Key)
            .ToListAsync(cancellationToken);
        if (rows.Count == 0)
        {
            return SharedSettingMigrationResult.NothingToMigrate();
        }

        var unregistered = new List<string>();
        foreach (var row in rows)
        {
            if (!SharedSettingKeys.NormalizedByLegacyKey.ContainsKey(row.Key))
            {
                unregistered.Add(row.Key);
            }
        }
        if (unregistered.Count > 0)
        {
            return SharedSettingMigrationResult.Failed(
                SharedSettingMigrationResult.UnregisteredKeysClassification,
                unregistered);
        }

        var changes = new Dictionary<string, string?>(StringComparer.Ordinal);
        var undecryptable = new List<string>();
        foreach (var row in rows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var normalizedKey = SharedSettingKeys.NormalizedByLegacyKey[row.Key];
            if (!row.IsSecret)
            {
                changes[normalizedKey] = row.Value;
                continue;
            }

            try
            {
                changes[normalizedKey] = legacyProtector.Unprotect(row.Key, row.Value);
            }
            catch (CryptographicException)
            {
                undecryptable.Add(row.Key);
            }
        }
        if (undecryptable.Count > 0)
        {
            return SharedSettingMigrationResult.Failed(
                SharedSettingMigrationResult.UndecryptableSecretsClassification,
                undecryptable);
        }

        var update = await updateService.UpdateAsync(
            new ServiceSettingUpdateCommand(0, changes, migrationOperator),
            cancellationToken);
        if (update.Succeeded)
        {
            return SharedSettingMigrationResult.Migrated(changes.Count);
        }
        if (update.Status == ServiceSettingUpdateStatus.VersionConflict)
        {
            return SharedSettingMigrationResult.AlreadyMigrated();
        }
        return SharedSettingMigrationResult.Failed(
            ToDiagnosticCode(update.Status),
            [.. update.Errors
                .Select(error => error.Key)
                .OfType<string>()
                .Distinct(StringComparer.Ordinal)]);
    }

    /// <summary>Renders a closed update status as a stable, value-free diagnostic code.</summary>
    private static string ToDiagnosticCode(ServiceSettingUpdateStatus status)
    {
        var builder = new System.Text.StringBuilder("service_settings.");
        foreach (var character in status.ToString())
        {
            if (char.IsUpper(character) && builder.Length > "service_settings.".Length)
            {
                builder.Append('_');
            }
            builder.Append(char.ToLowerInvariant(character));
        }
        return builder.ToString();
    }
}
