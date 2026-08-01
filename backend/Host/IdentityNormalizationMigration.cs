using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Host;

internal static class IdentityNormalizationMigration
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
        if (databaseOptions.ProviderKind != DatabaseProvider.PostgreSql)
        {
            await dbContext.Database.MigrateAsync(cancellationToken);
            return;
        }

        var pendingMigrations = (await dbContext.Database
                .GetPendingMigrationsAsync(cancellationToken))
            .ToHashSet(StringComparer.Ordinal);

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
            .ToListAsync(cancellationToken);
        EnsureUnique(
            credentials,
            item => IdentityValueNormalizer.Normalize(item.Username),
            item => item.Username,
            "username");

        var loginAttempts = await dbContext.LoginAttempts
            .ToListAsync(cancellationToken);
        EnsureUnique(
            loginAttempts,
            item => IdentityValueNormalizer.Normalize(item.Username),
            item => item.Username,
            "login-attempt username");

        var appRegistrations = await dbContext.AppRegistrations
            .ToListAsync(cancellationToken);
        EnsureUnique(
            appRegistrations,
            item => IdentityValueNormalizer.Normalize(item.AppId),
            item => item.AppId,
            "AppId");

        var userLogins = await dbContext.UserLogins
            .ToListAsync(cancellationToken);
        EnsureUnique(
            userLogins,
            item => (
                IdentityValueNormalizer.Normalize(item.ProviderName),
                item.ProviderUserId),
            item => $"{item.ProviderName}/{item.ProviderUserId}",
            "external provider identity");

        var accounts = await dbContext.Accounts.ToListAsync(cancellationToken);

        foreach (var credential in credentials)
        {
            credential.UsernameNormalized =
                IdentityValueNormalizer.Normalize(credential.Username);
        }

        foreach (var loginAttempt in loginAttempts)
        {
            loginAttempt.UsernameNormalized =
                IdentityValueNormalizer.Normalize(loginAttempt.Username);
        }

        foreach (var appRegistration in appRegistrations)
        {
            appRegistration.AppIdNormalized =
                IdentityValueNormalizer.Normalize(appRegistration.AppId);
        }

        foreach (var userLogin in userLogins)
        {
            userLogin.ProviderNameNormalized =
                IdentityValueNormalizer.Normalize(userLogin.ProviderName);
        }

        foreach (var account in accounts)
        {
            account.NicknameNormalized =
                IdentityValueNormalizer.NormalizeNullable(account.Nickname);
            account.RemarkNormalized =
                IdentityValueNormalizer.NormalizeNullable(account.Remark);
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
