using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Domain.Services.Sms;

namespace QuantumZhou.Identity.Host;

/// <summary>
/// 全库 schema 迁移入口——所有 provider 的 EF 迁移都从这里跑。
/// PostgreSQL 走 expand-contract 路径：先跑 expand 迁移、做归一化碰撞预检并回填
/// <c>*_normalized</c> 列，再 <c>MigrateAsync</c> 补齐剩余迁移；其余 provider 直接 <c>MigrateAsync</c>。
/// </summary>
internal static class SchemaMigrator
{
    private const string ExpandMigrationId =
        "20260730134106_AddNormalizedIdentityValues";
    private const string ContractMigrationId =
        "20260730134156_EnforceNormalizedIdentityValues";
    private const string SingleOtpMigrationId =
        "20260730135237_EnforceSingleOtpPerPhone";

    public static async Task MigrateAsync(
        IdentityDbContext dbContext,
        DatabaseOptions databaseOptions,
        CancellationToken cancellationToken = default)
    {
        var pendingMigrations = (await dbContext.Database
                .GetPendingMigrationsAsync(cancellationToken))
            .ToHashSet(StringComparer.Ordinal);

        var appliedMigrations = (await dbContext.Database
            .GetAppliedMigrationsAsync(cancellationToken)).ToHashSet(StringComparer.Ordinal);
        var hasNormalizedLoginSchema = appliedMigrations.Any(
            id => id.EndsWith("_EnforceNormalizedIdentityValues", StringComparison.Ordinal));
        if (hasNormalizedLoginSchema &&
            pendingMigrations.Any(id => id.EndsWith("_EnableAppScopedSmsLogin", StringComparison.Ordinal)))
        {
            var smsLogins = await dbContext.UserLogins.AsNoTracking()
                .Where(login => login.ProviderNameNormalized == "SMS")
                .ToListAsync(cancellationToken);
            EnsureUnique(
                smsLogins,
                login => MainlandChinaPhoneNumber.TryNormalize(login.ProviderUserId, out var normalized)
                    ? normalized
                    : login.ProviderUserId,
                login => login.ProviderUserId,
                "SMS phone identity");
        }

        if (databaseOptions.ProviderKind != DatabaseProvider.PostgreSql)
        {
            await dbContext.Database.MigrateAsync(cancellationToken);
            return;
        }

        if (pendingMigrations.Contains(ExpandMigrationId))
        {
            var migrator = dbContext.GetService<IMigrator>();
            await migrator.MigrateAsync(ExpandMigrationId, cancellationToken);
        }

        if (pendingMigrations.Contains(ExpandMigrationId) ||
            pendingMigrations.Contains(ContractMigrationId))
        {
            await ValidateAndBackfillAsync(dbContext, cancellationToken);
        }

        if (pendingMigrations.Contains(SingleOtpMigrationId))
        {
            var duplicatePhone = await dbContext.Otps
                .AsNoTracking()
                .GroupBy(otp => otp.Phone)
                .Where(group => group.Count() > 1)
                .Select(group => group.Key)
                .FirstOrDefaultAsync(cancellationToken);
            if (duplicatePhone is not null)
            {
                throw new InvalidOperationException(
                    $"Database upgrade found multiple OTP rows for phone '{duplicatePhone}'.");
            }
        }

        await dbContext.Database.MigrateAsync(cancellationToken);
    }

    /// <summary>
    /// 把 expand 迁移新增的 *_normalized 列从 NULL 填成非空值。
    /// expand 迁移只加列不回填，而实体把这些列映射为非空 string，
    /// 存量行会在下面的 ToListAsync 上抛 "Column '...' is null"，
    /// 导致回填代码被它自己要回填的 NULL 卡死（空库无行，所以只在有数据的库上暴露）。
    /// 这里写入的值随后会被 C# 侧用 IdentityValueNormalizer 重算覆盖，
    /// 唯一性校验也始终基于源列重算，因此本步骤只需保证列非空。
    /// </summary>
    private static async Task SeedNormalizedColumnsAsync(
        IdentityDbContext dbContext,
        CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE password_credentials
               SET username_normalized = upper(normalize(username, NFC))
             WHERE username_normalized IS NULL;
            UPDATE login_attempts
               SET username_normalized = upper(normalize(username, NFC))
             WHERE username_normalized IS NULL;
            UPDATE app_registrations
               SET app_id_normalized = upper(normalize(app_id, NFC))
             WHERE app_id_normalized IS NULL;
            UPDATE user_logins
               SET provider_name_normalized = upper(normalize(provider_name, NFC))
             WHERE provider_name_normalized IS NULL;
            """;

        await dbContext.Database.ExecuteSqlRawAsync(sql, cancellationToken);
    }

    private static async Task ValidateAndBackfillAsync(
        IdentityDbContext dbContext,
        CancellationToken cancellationToken)
    {
        await SeedNormalizedColumnsAsync(dbContext, cancellationToken);

        var credentials = await dbContext.PasswordCredentials
            .AsNoTracking()
            .Select(item => new { item.Id, item.Username })
            .ToListAsync(cancellationToken);
        EnsureUnique(
            credentials,
            item => IdentityValueNormalizer.Normalize(item.Username),
            item => item.Username,
            "username");

        var loginAttempts = await dbContext.LoginAttempts
            .AsNoTracking()
            .Select(item => new { item.Id, item.Username })
            .ToListAsync(cancellationToken);
        EnsureUnique(
            loginAttempts,
            item => IdentityValueNormalizer.Normalize(item.Username),
            item => item.Username,
            "login-attempt username");

        var appRegistrations = await dbContext.AppRegistrations
            .AsNoTracking()
            .Select(item => new { item.Id, item.AppId })
            .ToListAsync(cancellationToken);
        EnsureUnique(
            appRegistrations,
            item => IdentityValueNormalizer.Normalize(item.AppId),
            item => item.AppId,
            "AppId");

        var userLogins = await dbContext.UserLogins
            .AsNoTracking()
            .Select(item => new { item.Id, item.ProviderName, item.ProviderUserId })
            .ToListAsync(cancellationToken);
        EnsureUnique(
            userLogins,
            item => (
                IdentityValueNormalizer.Normalize(item.ProviderName),
                item.ProviderUserId),
            item => $"{item.ProviderName}/{item.ProviderUserId}",
            "external provider identity");

        var accounts = await dbContext.Accounts
            .AsNoTracking()
            .Select(item => new { item.Id, item.Nickname, item.Remark })
            .ToListAsync(cancellationToken);

        dbContext.ChangeTracker.Clear();

        foreach (var credential in credentials)
        {
            var entity = new PasswordCredentialEntity
            {
                Id = credential.Id,
                Username = credential.Username
            };
            dbContext.Attach(entity);
            dbContext.Entry(entity).Property(item => item.UsernameNormalized).IsModified = true;
        }

        foreach (var loginAttempt in loginAttempts)
        {
            var entity = new LoginAttemptEntity
            {
                Id = loginAttempt.Id,
                Username = loginAttempt.Username
            };
            dbContext.Attach(entity);
            dbContext.Entry(entity).Property(item => item.UsernameNormalized).IsModified = true;
        }

        foreach (var appRegistration in appRegistrations)
        {
            var entity = new AppRegistrationEntity
            {
                Id = appRegistration.Id,
                AppId = appRegistration.AppId
            };
            dbContext.Attach(entity);
            dbContext.Entry(entity).Property(item => item.AppIdNormalized).IsModified = true;
        }

        foreach (var userLogin in userLogins)
        {
            var entity = new UserLoginEntity
            {
                Id = userLogin.Id,
                ProviderName = userLogin.ProviderName
            };
            dbContext.Attach(entity);
            dbContext.Entry(entity).Property(item => item.ProviderNameNormalized).IsModified = true;
        }

        foreach (var account in accounts)
        {
            var entity = new AccountEntity
            {
                Id = account.Id,
                Nickname = account.Nickname,
                Remark = account.Remark
            };
            dbContext.Attach(entity);
            dbContext.Entry(entity).Property(item => item.NicknameNormalized).IsModified = true;
            dbContext.Entry(entity).Property(item => item.RemarkNormalized).IsModified = true;
        }

        await dbContext.SaveChangesAsync(cancellationToken);
        dbContext.ChangeTracker.Clear();
    }

    private static void EnsureUnique<TItem, TKey>(
        IEnumerable<TItem> items,
        Func<TItem, TKey> keySelector,
        Func<TItem, string> displaySelector,
        string valueName)
        where TKey : notnull
    {
        var values = new Dictionary<TKey, string>();
        foreach (var item in items)
        {
            var key = keySelector(item);
            var displayValue = displaySelector(item);
            if (values.TryGetValue(key, out var existingValue))
            {
                throw new InvalidOperationException(
                    $"Database upgrade found a normalized {valueName} collision " +
                    $"between '{existingValue}' and '{displayValue}'.");
            }

            values.Add(key, displayValue);
        }
    }
}
