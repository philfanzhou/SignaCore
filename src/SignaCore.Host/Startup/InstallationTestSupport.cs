using Microsoft.EntityFrameworkCore;
using ServiceMantle.Bootstrap;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;

namespace SignaCore.Host.Startup;

/// <summary>
/// Test-only composition entry point.
/// <para>
/// Production hosts read the bootstrap from its fixed path and reach a completed installation only
/// through first-run setup. Integration tests need a database that is already installed before the
/// host starts, so this writes an equivalent bootstrap file through the same shared store the
/// production write path uses and performs the same migration, settings-seeding, and
/// administrator-creation steps the real path performs — through the real components, so a test
/// host never diverges from a production host.
/// </para>
/// </summary>
internal static class InstallationTestSupport
{
    /// <summary>
    /// Prepares a completed installation and returns the path of the bootstrap file that names it.
    /// Pass that path as the <c>Bootstrap:FilePath</c> host setting.
    /// </summary>
    public static async Task<string> PrepareCompletedInstallationAsync(
        string bootstrapDirectory,
        DatabaseOptions database,
        string rootSecret,
        string adminUsername,
        string adminPassword,
        IReadOnlyDictionary<string, string>? settingOverrides = null,
        CancellationToken cancellationToken = default)
    {
        var bootstrapFilePath = WriteBootstrapFile(bootstrapDirectory, database, rootSecret);

        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(database);
        await using var db = new IdentityDbContext(optionsBuilder.Options);

        await StartupDatabase.EnsureDatabaseExistsAsync(database, cancellationToken);
        await db.Database.MigrateAsync(cancellationToken);

        var values = SystemSettingsCatalog.BuildDefaults();
        // TestServer serves plain HTTP on http://localhost, so the snapshot has to permit a
        // non-HTTPS issuer the way a deliberate legacy migration would.
        values[SystemSettingKeys.PublicBaseUrl] = "http://localhost";
        values[SystemSettingKeys.JwtIssuer] = "http://localhost";
        values[SystemSettingKeys.SecurityAllowNonHttpsIssuer] = "true";
        values[SystemSettingKeys.AdminUsername] = adminUsername;

        foreach (var (key, value) in settingOverrides ?? new Dictionary<string, string>())
        {
            values[key] = value;
        }

        var candidateErrors = SharedSettingComposition.ValidateCompleteCandidate(values);
        if (candidateErrors.Count > 0)
        {
            // Key names and closed classification codes only: the offending key may be a secret.
            throw new SettingsSnapshotException(
                "The prepared configuration snapshot is not valid:" + Environment.NewLine +
                string.Join(
                    Environment.NewLine,
                    candidateErrors.Select(error => $"  - {error.Key}: {error.ErrorCode}")),
                candidateErrors
                    .Select(error => error.Key)
                    .Where(key => key is not null)
                    .Distinct()
                    .ToList()!);
        }

        var protector = new AesGcmConfigurationProtector(new BootstrapMasterKeyProvider(rootSecret));
        var store = new SystemSettingsStore(protector);
        await store.WriteAsync(db, values, configurationVersion: 1, adminUsername, cancellationToken);

        var now = DateTimeOffset.UtcNow;
        var accountId = Guid.NewGuid();
        db.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = now,
            Remark = "Initial administrator created by test support"
        });
        db.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = adminUsername,
            PasswordHash = new BCryptPasswordHasher(
                    new PasswordHasherOptions { WorkFactor = IdentityConstants.BCryptWorkFactor })
                .HashPassword(adminPassword),
            CreatedAt = now
        });

        db.ServiceInstallations.Add(new ServiceInstallationEntity
        {
            ServiceId = InstallationStores.ServiceIdValue,
            Status = InstallationStatus.Completed,
            CreatedAtUtc = now.UtcDateTime,
            CompletedAtUtc = now.UtcDateTime,
            Version = 1
        });

        await db.SaveChangesAsync(cancellationToken);

        return bootstrapFilePath;
    }

    /// <summary>
    /// Writes only the bootstrap file, leaving the database uninitialized so the host enters
    /// Setup Mode.
    /// </summary>
    public static Task<string> PrepareUninstalledBootstrapAsync(
        string bootstrapDirectory,
        DatabaseOptions database,
        string rootSecret,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(WriteBootstrapFile(bootstrapDirectory, database, rootSecret));

    /// <summary>
    /// Writes the canonical bootstrap file through the shared store — the same write path the
    /// bootstrap editor uses — so test hosts always read what production writes. The store refuses
    /// to overwrite an existing file, and this helper owns the whole directory, so a stale file
    /// from an earlier preparation is removed first.
    /// </summary>
    private static string WriteBootstrapFile(
        string bootstrapDirectory,
        DatabaseOptions database,
        string rootSecret)
    {
        Directory.CreateDirectory(bootstrapDirectory);
        var bootstrapFilePath = Path.Combine(
            bootstrapDirectory,
            $"{ServiceMantleComposition.ServiceIdentifier}.bootstrap.json");
        if (File.Exists(bootstrapFilePath))
        {
            File.Delete(bootstrapFilePath);
        }

        var store = new BootstrapFileStore(
            InstallationStores.ServiceId,
            SignaCoreBootstrapStore.CreateProviderRegistry(),
            bootstrapFilePath);
        store.Create(new BootstrapConfiguration(
            InstallationStores.ServiceId,
            new BootstrapDatabaseConfiguration(database.Provider, database.ServerVersion, database.ConnectionString),
            rootSecret));
        return bootstrapFilePath;
    }
}
