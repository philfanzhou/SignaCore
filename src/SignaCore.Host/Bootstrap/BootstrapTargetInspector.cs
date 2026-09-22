using System.Data.Common;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using ServiceMantle.Configuration;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;

namespace SignaCore.Host.Bootstrap;

/// <summary>What a candidate database turned out to be.</summary>
internal enum BootstrapTargetKind
{
    /// <summary>Unreachable, or reachable but refusing the supplied credentials.</summary>
    Unreachable,

    /// <summary>Reachable and holding no SignaCore data — it may not exist yet, which is fine.</summary>
    Empty,

    /// <summary>A SignaCore database whose installation has not been completed.</summary>
    PendingInstallation,

    /// <summary>A completed SignaCore installation.</summary>
    CompletedInstallation,

    /// <summary>SignaCore business data predating the installation-state row.</summary>
    LegacyData
}

/// <summary>Whether the supplied root key can actually read what the target already protects.</summary>
internal enum MasterKeyCompatibility
{
    /// <summary>The database holds no encrypted material, so any key is acceptable.</summary>
    NoProtectedData,

    Compatible,

    Incompatible
}

internal sealed record BootstrapTargetInspection(
    BootstrapTargetKind Kind,
    MasterKeyCompatibility KeyCompatibility,
    Guid? InstallationId,
    string Endpoint,
    string? FailureReason)
{
    public bool CanConnect => Kind != BootstrapTargetKind.Unreachable;

    public bool HasProtectedData => KeyCompatibility != MasterKeyCompatibility.NoProtectedData;
}

/// <summary>
/// Opens a candidate business database, classifies what is in it, and reports whether a supplied
/// root key can decrypt what is already there.
/// <para>
/// This runs before anything is written, both during bootstrap configuration and when an
/// authenticated operator repoints an installed instance. It never creates or migrates the target,
/// and it never returns any part of the connection string, the credentials, or the key.
/// </para>
/// </summary>
internal static class BootstrapTargetInspector
{
    private const string PostgreSqlInvalidCatalogName = "3D000";

    public static async Task<BootstrapTargetInspection> InspectAsync(
        DatabaseOptions database,
        string? candidateRootSecret,
        CancellationToken cancellationToken = default)
    {
        var endpoint = BootstrapDiagnostics.DescribeEndpoint(database);

        var reachability = await ProbeAsync(database, cancellationToken);
        if (reachability is { Reachable: false, TargetIsAbsent: false })
        {
            return new BootstrapTargetInspection(
                BootstrapTargetKind.Unreachable,
                MasterKeyCompatibility.NoProtectedData,
                InstallationId: null,
                endpoint,
                reachability.Reason);
        }

        if (reachability.TargetIsAbsent)
        {
            // The named database (or SQLite file) does not exist yet. The server accepted the
            // credentials, so this is a usable target that startup will create.
            return new BootstrapTargetInspection(
                BootstrapTargetKind.Empty,
                MasterKeyCompatibility.NoProtectedData,
                InstallationId: null,
                endpoint,
                FailureReason: null);
        }

        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(database);
        await using var db = new IdentityDbContext(optionsBuilder.Options);

        var state = await TryLoadInstallationStateAsync(db, cancellationToken);
        BootstrapTargetKind kind;
        if (state is null)
        {
            kind = await HasAnyBusinessDataAsync(db, cancellationToken)
                ? BootstrapTargetKind.LegacyData
                : BootstrapTargetKind.Empty;
        }
        else if (state.Status == InstallationStatus.Completed &&
                 await IsAdoptedWithoutImportAsync(db, cancellationToken))
        {
            // Completed by the AddServiceInstallations backfill, but the legacy import has not run:
            // startup still has to import configuration before this is a working installation.
            kind = BootstrapTargetKind.LegacyData;
        }
        else
        {
            kind = state.Status == InstallationStatus.Completed
                ? BootstrapTargetKind.CompletedInstallation
                : BootstrapTargetKind.PendingInstallation;
        }

        var compatibility = await EvaluateKeyCompatibilityAsync(db, candidateRootSecret, cancellationToken);

        return new BootstrapTargetInspection(
            kind,
            compatibility,
            // The durable installation identity is the service id; there is no per-installation
            // Guid to report anymore.
            InstallationId: null,
            endpoint,
            FailureReason: null);
    }

    private sealed record Reachability(bool Reachable, bool TargetIsAbsent, string? Reason);

    /// <summary>
    /// Distinguishes the three outcomes that need different messages: the server refused us, the
    /// server accepted us but the database is not there yet, or everything is available.
    /// </summary>
    private static async Task<Reachability> ProbeAsync(
        DatabaseOptions database,
        CancellationToken cancellationToken)
    {
        try
        {
            switch (database.ProviderKind)
            {
                case DatabaseProvider.PostgreSql:
                {
                    await using var connection = new NpgsqlConnection(database.ConnectionString);
                    try
                    {
                        await connection.OpenAsync(cancellationToken);
                    }
                    catch (PostgresException exception)
                        when (exception.SqlState == PostgreSqlInvalidCatalogName)
                    {
                        return await ProbeServerOnlyAsync(database, cancellationToken);
                    }

                    return new Reachability(true, false, null);
                }

                case DatabaseProvider.Sqlite:
                {
                    var dataSource = new SqliteConnectionStringBuilder(database.ConnectionString).DataSource;
                    var fullPath = Path.GetFullPath(dataSource);
                    if (!File.Exists(fullPath))
                    {
                        var directory = Path.GetDirectoryName(fullPath);
                        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                        {
                            // The directory is created at startup; only report a path the runtime
                            // identity could never create.
                            var parent = Path.GetDirectoryName(directory);
                            if (!string.IsNullOrEmpty(parent) && !Directory.Exists(parent))
                            {
                                return new Reachability(
                                    false,
                                    false,
                                    $"The directory '{parent}' does not exist on this instance.");
                            }
                        }

                        return new Reachability(false, true, null);
                    }

                    await using var connection = new SqliteConnection(database.ConnectionString);
                    await connection.OpenAsync(cancellationToken);
                    return new Reachability(true, false, null);
                }

                default:
                    return new Reachability(false, false, "Unsupported database provider.");
            }
        }
        catch (Exception exception) when (exception is DbException or InvalidOperationException
                                              or TimeoutException or IOException)
        {
            return new Reachability(false, false, Describe(exception));
        }
    }

    /// <summary>
    /// Confirms the server itself accepts the credentials when the named database is missing, so
    /// "database not created yet" is never reported as "server unreachable".
    /// </summary>
    private static async Task<Reachability> ProbeServerOnlyAsync(
        DatabaseOptions database,
        CancellationToken cancellationToken)
    {
        if (database.ProviderKind != DatabaseProvider.PostgreSql)
        {
            // A file-backed provider has no server to probe separately.
            return new Reachability(false, false, null);
        }

        try
        {
            var maintenance = new NpgsqlConnectionStringBuilder(database.ConnectionString)
            {
                Database = "postgres",
                Pooling = false
            };
            await using var connection = new NpgsqlConnection(maintenance.ConnectionString);
            await connection.OpenAsync(cancellationToken);
            return new Reachability(false, true, null);
        }
        catch (Exception exception) when (exception is DbException or InvalidOperationException
                                              or TimeoutException)
        {
            return new Reachability(false, false, Describe(exception));
        }
    }

    private static async Task<ServiceInstallationEntity?> TryLoadInstallationStateAsync(
        IdentityDbContext db,
        CancellationToken cancellationToken)
    {
        try
        {
            return await db.ServiceInstallations
                .AsNoTracking()
                .FirstOrDefaultAsync(
                    row => row.ServiceId == InstallationStores.ServiceIdValue,
                    cancellationToken);
        }
        catch (DbException)
        {
            // The table does not exist: either an empty database or a schema predating it.
            return null;
        }
    }

    /// <summary>
    /// A completed installation whose shared settings aggregate was never written is a
    /// backfill-adopted legacy database, not a working install.
    /// </summary>
    private static async Task<bool> IsAdoptedWithoutImportAsync(
        IdentityDbContext db,
        CancellationToken cancellationToken)
    {
        try
        {
            return await SharedSettingAggregate.ReadVersionAsync(db, cancellationToken) is null &&
                await HasAnyBusinessDataAsync(db, cancellationToken);
        }
        catch (DbException)
        {
            return false;
        }
    }

    private static async Task<bool> HasAnyBusinessDataAsync(
        IdentityDbContext db,
        CancellationToken cancellationToken)
    {
        try
        {
            return await InstallationStateResolver.HasBusinessDataAsync(db, cancellationToken);
        }
        catch (DbException)
        {
            return false;
        }
    }

    /// <summary>
    /// One sensitive shared-settings envelope of this service, with the normalized key it is
    /// protected under.
    /// </summary>
    private sealed record SharedSensitiveEnvelope(string Key, string Envelope);

    /// <summary>
    /// The sensitive configuration envelopes this service persisted in its shared
    /// <c>service_settings</c> aggregate. The aggregate row's metadata alone proves nothing: only
    /// values under defined sensitive keys are envelopes, and a row whose values cannot even be
    /// enumerated is reported as unreadable so the caller refuses instead of guessing.
    /// </summary>
    private static async Task<(List<SharedSensitiveEnvelope> Envelopes, bool AggregateUnreadable)>
        LoadSharedSensitiveEnvelopesAsync(
            IdentityDbContext db,
            CancellationToken cancellationToken)
    {
        try
        {
            var valuesJson = await db.Database
                .SqlQuery<string>($"""
                    SELECT "values_json" AS "Value" FROM service_settings
                    WHERE service_id = {InstallationStores.ServiceIdValue}
                    """)
                .SingleOrDefaultAsync(cancellationToken);
            if (valuesJson is null)
            {
                return ([], AggregateUnreadable: false);
            }

            Dictionary<string, string> values;
            try
            {
                values = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(
                    valuesJson) ?? [];
            }
            catch (System.Text.Json.JsonException)
            {
                return ([], AggregateUnreadable: true);
            }

            var envelopes = new List<SharedSensitiveEnvelope>();
            foreach (var definition in SharedSettingComposition
                         .CreateRegistry(isDevelopment: false)
                         .Definitions
                         .Where(definition => definition.IsSensitive))
            {
                if (values.TryGetValue(definition.Key, out var envelope) &&
                    !string.IsNullOrEmpty(envelope))
                {
                    envelopes.Add(new SharedSensitiveEnvelope(definition.Key, envelope));
                }
            }

            return (envelopes, AggregateUnreadable: false);
        }
        catch (DbException)
        {
            // The shared table does not exist: either an empty database or a schema predating it,
            // so this protected-data class holds nothing here.
            return ([], AggregateUnreadable: false);
        }
    }

    /// <summary>
    /// Verifies one already-protected value with the candidate key. Both protected data classes are
    /// tried because a database can hold signing keys before it holds any secret setting.
    /// </summary>
    private static async Task<MasterKeyCompatibility> EvaluateKeyCompatibilityAsync(
        IdentityDbContext db,
        string? candidateRootSecret,
        CancellationToken cancellationToken)
    {
        var (sensitiveEnvelopes, aggregateUnreadable) =
            await LoadSharedSensitiveEnvelopesAsync(db, cancellationToken);

        List<SecurityKeyEntity> signingKeys;
        try
        {
            signingKeys = await db.SecurityKeys
                .AsNoTracking()
                .OrderByDescending(key => key.CreatedAt)
                .Take(1)
                .ToListAsync(cancellationToken);
        }
        catch (DbException)
        {
            signingKeys = [];
        }

        if (aggregateUnreadable)
        {
            // An aggregate row exists but its persisted values cannot be enumerated: treat it as
            // protected data no key may be blessed for, rather than silently falling back to
            // "no protected data".
            return MasterKeyCompatibility.Incompatible;
        }

        if (sensitiveEnvelopes.Count == 0 && signingKeys.Count == 0)
        {
            return MasterKeyCompatibility.NoProtectedData;
        }

        if (string.IsNullOrWhiteSpace(candidateRootSecret))
        {
            return MasterKeyCompatibility.Incompatible;
        }

        var masterKeyProvider = new BootstrapMasterKeyProvider(candidateRootSecret);
        var rootKeySource = SharedSettingComposition.CreateRootKeySource(masterKeyProvider);

        foreach (var envelope in sensitiveEnvelopes)
        {
            try
            {
                _ = new SensitiveValueProtector(InstallationStores.ServiceId, envelope.Key)
                    .Unprotect(
                        envelope.Envelope,
                        await rootKeySource.GetRootKeyAsync(cancellationToken),
                        cancellationToken);
                return MasterKeyCompatibility.Compatible;
            }
            catch (Exception exception)
                when (exception is SensitiveValueProtectionException or ArgumentException)
            {
                return MasterKeyCompatibility.Incompatible;
            }
        }

        foreach (var key in signingKeys)
        {
            try
            {
                _ = new AesGcmPrivateKeyProtector(masterKeyProvider)
                    .Unprotect(key.EncryptedPrivateKeyParams, key.EncryptionSalt);
                return MasterKeyCompatibility.Compatible;
            }
            catch (Exception exception) when (exception is CryptographicException or FormatException)
            {
                return MasterKeyCompatibility.Incompatible;
            }
        }

        return MasterKeyCompatibility.NoProtectedData;
    }

    /// <summary>
    /// Provider exception messages are deliberately not surfaced: some provider versions include
    /// connection-string fragments in parse or authentication failures. The already-redacted
    /// endpoint gives the operator the target, while this category gives the corrective direction.
    /// </summary>
    private static string Describe(Exception exception)
    {
        return exception switch
        {
            TimeoutException => "The connection attempt timed out.",
            IOException => "The database endpoint could not be reached.",
            DbException => "The database server rejected the connection or did not respond.",
            _ => "The database connection settings are invalid."
        };
    }
}
