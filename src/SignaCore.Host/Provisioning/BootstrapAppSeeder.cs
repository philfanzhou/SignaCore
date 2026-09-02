using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain;
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
        IAuditService auditService,
        IPasswordHasher passwordHasher,
        ILogger logger,
        bool isDevelopment,
        CancellationToken cancellationToken = default)
    {
        var filePath = configuration["BootstrapApps:FilePath"] ?? DefaultBootstrapAppsFilePath;
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            logger.LogInformation(
                "Bootstrap apps file not found: {FilePath}. Skipping app pre-seeding.",
                filePath);
            return;
        }

        BootstrapAppsOptions? bootstrapApps;
        try
        {
            var json = await File.ReadAllTextAsync(filePath, cancellationToken);
            bootstrapApps = System.Text.Json.JsonSerializer.Deserialize<BootstrapAppsOptions>(
                json,
                new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                "Failed to read or parse bootstrap apps file: {FilePath}. " +
                "Zero entries were processed. ErrorType={ErrorType}",
                filePath,
                exception.GetType().Name);
            return;
        }

        var created = 0;
        var skippedExisting = 0;
        var skippedInvalid = 0;
        var failedEntries = new List<BootstrapAppFailure>();

        foreach (var entry in bootstrapApps?.Apps ?? [])
        {
            if (entry == null)
            {
                skippedInvalid++;
                logger.LogWarning("Bootstrap app entry skipped: entry is null.");
                continue;
            }

            try
            {
                var result = await SeedBootstrapAppAsync(
                    entry,
                    db,
                    auditService,
                    passwordHasher,
                    logger,
                    isDevelopment,
                    cancellationToken);
                switch (result)
                {
                    case BootstrapAppSeedResult.Created:
                        created++;
                        break;
                    case BootstrapAppSeedResult.SkippedExisting:
                        skippedExisting++;
                        break;
                    case BootstrapAppSeedResult.SkippedInvalid:
                        skippedInvalid++;
                        break;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                failedEntries.Add(new BootstrapAppFailure(
                    LogValueSanitizer.Sanitize(entry.AppId),
                    exception.GetType().Name));
                // A failed SaveChanges can leave Added/Modified entities in the tracker. Clear them
                // so this entry cannot be retried accidentally by the next entry's commit.
                db.ChangeTracker.Clear();
            }
        }

        LogSummary(
            logger,
            created,
            skippedExisting,
            skippedInvalid,
            failedEntries);
    }

    private static async Task<BootstrapAppSeedResult> SeedBootstrapAppAsync(
        BootstrapAppEntry entry,
        IdentityDbContext db,
        IAuditService auditService,
        IPasswordHasher passwordHasher,
        ILogger logger,
        bool isDevelopment,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(entry.AppId) || string.IsNullOrWhiteSpace(entry.AppSecret))
        {
            logger.LogWarning("Bootstrap app entry skipped: AppId or AppSecret is empty.");
            return BootstrapAppSeedResult.SkippedInvalid;
        }

        var normalizedAppId = IdentityValueNormalizer.Normalize(entry.AppId);
        var alreadyExists = await db.AppRegistrations
            .AsNoTracking()
            .AnyAsync(app => app.AppIdNormalized == normalizedAppId, cancellationToken);
        if (alreadyExists)
        {
            logger.LogInformation(
                "Bootstrap app registration already exists: AppId={AppId}, AppName={AppName}",
                entry.AppId,
                entry.AppName);
            return BootstrapAppSeedResult.SkippedExisting;
        }

        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = entry.AppId,
            AppSecretHash = passwordHasher.HashPassword(entry.AppSecret),
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
                return BootstrapAppSeedResult.SkippedInvalid;
            }
        }

        db.AppRegistrations.Add(app);
        await auditService.RecordActionAsync(
            "app_created",
            "AppRegistration",
            app.AppId,
            actorId: null,
            actorName: "bootstrap",
            description: $"Bootstrap pre-seed created app: {app.AppName}",
            clientIp: null,
            after: new
            {
                app.AppId,
                app.AppName,
                app.CallbackUrl,
                CallbackExpiresAt = app.CallbackExpiresAt?.ToUnixTimeSeconds(),
                app.IsActive
            });
        await db.SaveChangesAsync(cancellationToken);

        logger.LogInformation(
            "Bootstrap app registration created: AppId={AppId}, AppName={AppName}",
            entry.AppId,
            entry.AppName);

        return BootstrapAppSeedResult.Created;
    }

    private static void LogSummary(
        ILogger logger,
        int created,
        int skippedExisting,
        int skippedInvalid,
        IReadOnlyList<BootstrapAppFailure> failedEntries)
    {
        var failures = failedEntries.Count == 0
            ? "none"
            : string.Join(
                ", ",
                failedEntries.Select(entry => $"{entry.AppId} ({entry.Reason})"));
        const string message =
            "Bootstrap app pre-seeding completed: created={Created}, " +
            "skipped-existing={SkippedExisting}, skipped-invalid={SkippedInvalid}, failed={Failed}, " +
            "FailedEntries={FailedEntries}";

        if (failedEntries.Count == 0)
        {
            logger.LogInformation(
                message,
                created,
                skippedExisting,
                skippedInvalid,
                failedEntries.Count,
                failures);
            return;
        }

        logger.LogWarning(
            message,
            created,
            skippedExisting,
            skippedInvalid,
            failedEntries.Count,
            failures);
    }

    private enum BootstrapAppSeedResult
    {
        Created,
        SkippedExisting,
        SkippedInvalid
    }

    private sealed record BootstrapAppFailure(string AppId, string Reason);
}
