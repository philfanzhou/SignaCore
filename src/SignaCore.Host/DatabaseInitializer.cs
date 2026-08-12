using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;

namespace SignaCore.Host;

/// <summary>
/// 启动时的数据库初始化入口：建库 → 持迁移锁 → 跑迁移 → 预置管理员 → 预置应用注册。
/// 任何一步失败都会向上抛出，由 <c>Program</c> 直接终止启动（不降级、不跳过）。
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
        var databaseOptions = scope.ServiceProvider.GetRequiredService<DatabaseOptions>();

        try
        {
            await DatabaseProvisioner.EnsureDatabaseExistsAsync(databaseOptions);
            await using var migrationLock =
                await DatabaseProvisioner.AcquireMigrationLockAsync(databaseOptions);

            await MigrateAsync(db, databaseOptions, logger);
            await ProtectLegacyRefreshTokensAsync(db, logger);
            await EnsureBootstrapAdminAsync(scope.ServiceProvider, db, logger);
            await SeedBootstrapAppsAsync(configuration, db, logger);
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

    private static async Task MigrateAsync(
        IdentityDbContext db,
        DatabaseOptions databaseOptions,
        ILogger logger)
    {
        var pendingMigrations = (await db.Database.GetPendingMigrationsAsync()).ToList();
        if (pendingMigrations.Count > 0)
        {
            logger.LogInformation(
                "Applying {Count} pending migrations...",
                pendingMigrations.Count);
        }

        await SchemaMigrator.MigrateAsync(db, databaseOptions);
    }

    /// <summary>
    /// 按 <c>AdminBootstrap:*</c> 预置初始管理员。用户名规范化后比对，已存在则跳过（幂等）。
    /// 用户名和密码必须同时配置或同时留空，只配一个视为配置错误。
    /// </summary>
    private static async Task EnsureBootstrapAdminAsync(
        IServiceProvider scopedServices,
        IdentityDbContext db,
        ILogger logger)
    {
        var options = scopedServices.GetRequiredService<IOptions<AdminBootstrapOptions>>().Value;
        var username = options.Username.Trim();
        var password = options.Password;

        if (string.IsNullOrWhiteSpace(username) && string.IsNullOrWhiteSpace(password))
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            throw new InvalidOperationException(
                "AdminBootstrap.Username and AdminBootstrap.Password must both be configured.");
        }

        var passwordPolicy = scopedServices.GetRequiredService<IPasswordPolicy>();
        if (!passwordPolicy.Validate(password, out var passwordError))
        {
            throw new InvalidOperationException(
                $"Admin bootstrap password is invalid: {passwordError}");
        }

        var normalizedUsername = IdentityValueNormalizer.Normalize(username);
        var alreadyExists = await db.PasswordCredentials
            .AsNoTracking()
            .AnyAsync(item => item.UsernameNormalized == normalizedUsername);
        if (alreadyExists)
        {
            logger.LogInformation(
                "Bootstrap admin account already exists: Username={Username}",
                username);
            return;
        }

        var passwordHasher = scopedServices.GetRequiredService<IPasswordHasher>();
        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            Remark = "Bootstrap admin account"
        };
        db.Accounts.Add(account);
        db.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            Username = username,
            PasswordHash = passwordHasher.HashPassword(password),
            CreatedAt = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync();

        logger.LogInformation("Bootstrap admin account created: Username={Username}", username);
    }

    /// <summary>
    /// 可选的应用注册预置：读取部署脚本挂载的 bootstrap-apps.json。
    /// 文件不存在属正常情况，只打 INFO；读取或解析失败只打 Warning 不中断启动，
    /// 因为它是便利机制，应用注册也可以事后从管理控制台补建。
    /// </summary>
    private static async Task SeedBootstrapAppsAsync(
        IConfiguration configuration,
        IdentityDbContext db,
        ILogger logger)
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
                await SeedBootstrapAppAsync(entry, db, logger);
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
        ILogger logger)
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

        db.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = entry.AppId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(entry.AppSecret),
            AppName = entry.AppName,
            CallbackUrl = entry.CallbackUrl,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync();

        logger.LogInformation(
            "Bootstrap app registration created: AppId={AppId}, AppName={AppName}",
            entry.AppId,
            entry.AppName);
    }
}
