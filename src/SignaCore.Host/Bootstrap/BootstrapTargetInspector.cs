using System.Data.Common;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using MySqlConnector;
using Npgsql;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
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
    private const int MySqlUnknownDatabase = 1049;

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
        var kind = state is not null
            ? state.Status == InstallationStatus.Completed
                ? BootstrapTargetKind.CompletedInstallation
                : BootstrapTargetKind.PendingInstallation
            : await HasAnyBusinessDataAsync(db, cancellationToken)
                ? BootstrapTargetKind.LegacyData
                : BootstrapTargetKind.Empty;

        var compatibility = await EvaluateKeyCompatibilityAsync(db, candidateRootSecret, cancellationToken);

        return new BootstrapTargetInspection(
            kind,
            compatibility,
            state?.InstallationId,
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

                case DatabaseProvider.MySql:
                case DatabaseProvider.MariaDb:
                {
                    await using var connection = new MySqlConnection(database.ConnectionString);
                    try
                    {
                        await connection.OpenAsync(cancellationToken);
                    }
                    catch (MySqlException exception) when (exception.Number == MySqlUnknownDatabase)
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
        try
        {
            switch (database.ProviderKind)
            {
                case DatabaseProvider.PostgreSql:
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

                default:
                {
                    var maintenance = new MySqlConnectionStringBuilder(database.ConnectionString)
                    {
                        Database = string.Empty,
                        Pooling = false
                    };
                    await using var connection = new MySqlConnection(maintenance.ConnectionString);
                    await connection.OpenAsync(cancellationToken);
                    return new Reachability(false, true, null);
                }
            }
        }
        catch (Exception exception) when (exception is DbException or InvalidOperationException
                                              or TimeoutException)
        {
            return new Reachability(false, false, Describe(exception));
        }
    }

    private static async Task<InstallationStateEntity?> TryLoadInstallationStateAsync(
        IdentityDbContext db,
        CancellationToken cancellationToken)
    {
        try
        {
            return await db.InstallationStates
                .AsNoTracking()
                .FirstOrDefaultAsync(row => row.Id == InstallationStateEntity.SingletonId, cancellationToken);
        }
        catch (DbException)
        {
            // The table does not exist: either an empty database or a schema predating it.
            return null;
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
    /// Decrypts one already-protected value with the candidate key. Both protected data classes are
    /// tried because a database can hold signing keys before it holds any secret setting.
    /// </summary>
    private static async Task<MasterKeyCompatibility> EvaluateKeyCompatibilityAsync(
        IdentityDbContext db,
        string? candidateRootSecret,
        CancellationToken cancellationToken)
    {
        List<SystemSettingEntity> secretSettings;
        try
        {
            secretSettings = await db.SystemSettings
                .AsNoTracking()
                .Where(setting => setting.IsSecret && setting.Value != "")
                .OrderBy(setting => setting.Key)
                .Take(1)
                .ToListAsync(cancellationToken);
        }
        catch (DbException)
        {
            secretSettings = [];
        }

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

        if (secretSettings.Count == 0 && signingKeys.Count == 0)
        {
            return MasterKeyCompatibility.NoProtectedData;
        }

        if (string.IsNullOrWhiteSpace(candidateRootSecret))
        {
            return MasterKeyCompatibility.Incompatible;
        }

        var masterKeyProvider = new BootstrapMasterKeyProvider(candidateRootSecret);

        foreach (var setting in secretSettings)
        {
            try
            {
                _ = new AesGcmConfigurationProtector(masterKeyProvider).Unprotect(setting.Key, setting.Value);
                return MasterKeyCompatibility.Compatible;
            }
            catch (CryptographicException)
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
