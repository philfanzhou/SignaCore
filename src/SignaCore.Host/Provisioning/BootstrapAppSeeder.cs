using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;

namespace SignaCore.Host.Provisioning;

/// <summary>
/// Optional application-registration pre-seeding from the deployment-mounted
/// <c>bootstrap-apps.json</c> file.
/// <para>
/// This is a product capability rather than migration orchestration: a deployment creates its
/// applications by mounting the file at <c>BootstrapApps:FilePath</c>, and the administration
/// console remains the alternative way to create the very same registrations.
/// </para>
/// </summary>
internal static class BootstrapAppSeeder
{
    private const string DefaultBootstrapAppsFilePath = "/app/data/bootstrap-apps.json";

    /// <summary>
    /// Optional application-registration pre-seeding: reads the bootstrap-apps.json file mounted by
    /// the deployment scripts. A missing file is the normal case and is only logged at INFO; a read
    /// or parse failure is only logged as a Warning and does not interrupt startup, because this is
    /// a convenience mechanism and application registrations can also be created afterwards from
    /// the administration console.
    /// </summary>
    internal static async Task SeedBootstrapAppsAsync(
        IConfiguration configuration,
        IdentityDbContext db,
        ILogger logger,
        bool isDevelopment)
    {
        var filePath = configuration["BootstrapApps:FilePath"] ?? DefaultBootstrapAppsFilePath;
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            logger.LogInformation(
                "Bootstrap apps file not found: {FilePath}. Skipping app pre-seeding.",
                filePath);
            return;
        }

        try
        {
            var json = await File.ReadAllTextAsync(filePath);
            var bootstrapApps = System.Text.Json.JsonSerializer.Deserialize<BootstrapAppsOptions>(
                json,
                new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

            foreach (var entry in bootstrapApps?.Apps ?? [])
            {
                await SeedBootstrapAppAsync(entry, db, logger, isDevelopment);
            }
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "Failed to read or process bootstrap apps file: {FilePath}",
                filePath);
        }
    }

    private static async Task SeedBootstrapAppAsync(
        BootstrapAppEntry entry,
        IdentityDbContext db,
        ILogger logger,
        bool isDevelopment)
    {
        if (string.IsNullOrWhiteSpace(entry.AppId) || string.IsNullOrWhiteSpace(entry.AppSecret))
        {
            logger.LogWarning("Bootstrap app entry skipped: AppId or AppSecret is empty.");
            return;
        }

        var normalizedAppId = IdentityValueNormalizer.Normalize(entry.AppId);
        var alreadyExists = await db.AppRegistrations
            .AsNoTracking()
            .AnyAsync(app => app.AppIdNormalized == normalizedAppId);
        if (alreadyExists)
        {
            logger.LogInformation(
                "Bootstrap app registration already exists: AppId={AppId}, AppName={AppName}",
                entry.AppId,
                entry.AppName);
            return;
        }

        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = entry.AppId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(entry.AppSecret),
            AppName = entry.AppName,
            CallbackUrl = entry.CallbackUrl,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        // An entry without the optional section keeps the fail-closed upgrade defaults, so a file
        // written before interactive configuration existed pre-seeds exactly what it always did.
        // The domain applier owns every rule; validation runs before the row is tracked, so a
        // rejected entry adds no partial registration.
        if (entry.Oidc != null)
        {
            try
            {
                // The change lists are irrelevant here: the application itself is new, so adding it
                // below stages its registrations with it.
                OidcClientConfigurationApplier.Apply(app, entry.Oidc, isDevelopment);
            }
            catch (OidcClientConfigurationException exception)
            {
                logger.LogWarning(
                    "Bootstrap app entry skipped: AppId={AppId} has an unacceptable interactive OIDC configuration. {Reason}",
                    entry.AppId,
                    exception.Message);
                return;
            }
        }

        db.AppRegistrations.Add(app);
        await db.SaveChangesAsync();

        logger.LogInformation(
            "Bootstrap app registration created: AppId={AppId}, AppName={AppName}",
            entry.AppId,
            entry.AppName);
    }
}
