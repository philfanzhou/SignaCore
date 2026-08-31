using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;

namespace SignaCore.Host;

/// <summary>
/// Application-phase database work.
/// <para>
/// Provisioning, migrations, and installation-state resolution now belong to the bootstrap phase
/// (<c>Startup/BootstrapPhase</c>), which runs before any application configuration exists. What is
/// left here is data seeding that depends on the composed application: the optional
/// bootstrap-apps.json pre-seed.
/// </para>
/// <para>
/// The initial administrator is no longer created from <c>ADMIN_BOOTSTRAP_*</c>. First-run setup
/// creates it behind the one-time setup code, so a deployment no longer has to hand the launcher an
/// administrator password.
/// </para>
/// </summary>
internal static class DatabaseInitializer
{
    private const string DefaultBootstrapAppsFilePath = "/app/data/bootstrap-apps.json";

    public static async Task InitializeAsync(
        IServiceProvider serviceProvider,
        IConfiguration configuration)
    {
        var logger = serviceProvider
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger(typeof(DatabaseInitializer).FullName!);

        using var scope = serviceProvider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var isDevelopment = scope.ServiceProvider
            .GetRequiredService<IHostEnvironment>()
            .IsDevelopment();

        try
        {
            await SeedBootstrapAppsAsync(configuration, db, logger, isDevelopment);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Database initialization failed");
            throw;
        }
    }

    internal static async Task ProtectLegacyRefreshTokensAsync(
        IdentityDbContext db,
        ILogger logger)
    {
        const int batchSize = 500;
        var protectedCount = 0;
        while (true)
        {
            var legacyTokens = await db.RefreshTokens
                .Where(token =>
                    !token.TokenValue.StartsWith(RefreshTokenDigest.Prefix) ||
                    token.TokenValue.Length != RefreshTokenDigest.EncodedLength)
                .OrderBy(token => token.Id)
                .Take(batchSize)
                .ToListAsync();
            if (legacyTokens.Count == 0)
            {
                break;
            }

            foreach (var token in legacyTokens)
            {
                token.TokenValue = RefreshTokenDigest.Compute(token.TokenValue);
            }

            await db.SaveChangesAsync();
            protectedCount += legacyTokens.Count;
            db.ChangeTracker.Clear();
        }

        if (protectedCount > 0)
        {
            logger.LogInformation(
                "Protected {Count} legacy refresh tokens with one-way digests.",
                protectedCount);
        }
    }

    /// <summary>
    /// 可选的应用注册预置：读取部署脚本挂载的 bootstrap-apps.json。
    /// 文件不存在属正常情况，只打 INFO；读取或解析失败只打 Warning 不中断启动，
    /// 因为它是便利机制，应用注册也可以事后从管理控制台补建。
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
