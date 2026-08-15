using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Host.Configuration;

namespace SignaCore.Host.Startup;

/// <summary>
/// Test-only composition entry point.
/// <para>
/// Production hosts read the bootstrap from its fixed path and reach a completed installation only
/// through first-run setup. Integration tests need a database that is already installed before the
/// host starts, so this writes an equivalent bootstrap file and performs the same migration,
/// settings-seeding, and administrator-creation steps the real path performs — through the real
/// components, so a test host never diverges from a production host.
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
        Directory.CreateDirectory(bootstrapDirectory);
        var bootstrapFilePath = Path.Combine(bootstrapDirectory, BootstrapLoaderFileName);

        await File.WriteAllTextAsync(
            bootstrapFilePath,
            JsonSerializer.Serialize(
                new
                {
                    Database = new
                    {
                        database.Provider,
                        database.ServerVersion,
                        database.ConnectionString
                    },
                    MasterKey = rootSecret
                },
                new JsonSerializerOptions { WriteIndented = true }),
            cancellationToken);

        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(database);
        await using var db = new IdentityDbContext(optionsBuilder.Options);

        await DatabaseProvisioner.EnsureDatabaseExistsAsync(database, cancellationToken);
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

        SettingsSnapshotValidator.ThrowIfInvalid(values);

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

        db.InstallationStates.Add(new InstallationStateEntity
        {
            Id = InstallationStateEntity.SingletonId,
            Status = InstallationStatus.Completed,
            InstallationId = Guid.NewGuid(),
            CompletedAt = now,
            ConfigurationVersion = 1
        });

        await db.SaveChangesAsync(cancellationToken);

        return bootstrapFilePath;
    }

    /// <summary>
    /// Writes only the bootstrap file, leaving the database uninitialized so the host enters
    /// Setup Mode.
    /// </summary>
    public static async Task<string> PrepareUninstalledBootstrapAsync(
        string bootstrapDirectory,
        DatabaseOptions database,
        string rootSecret,
        CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(bootstrapDirectory);
        var bootstrapFilePath = Path.Combine(bootstrapDirectory, BootstrapLoaderFileName);

        await File.WriteAllTextAsync(
            bootstrapFilePath,
            JsonSerializer.Serialize(
                new
                {
                    Database = new
                    {
                        database.Provider,
                        database.ServerVersion,
                        database.ConnectionString
                    },
                    MasterKey = rootSecret
                },
                new JsonSerializerOptions { WriteIndented = true }),
            cancellationToken);

        return bootstrapFilePath;
    }

    private const string BootstrapLoaderFileName = Bootstrap.BootstrapLoader.FileName;
}
