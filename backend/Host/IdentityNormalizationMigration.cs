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

    private static async Task ValidateAndBackfillAsync(
        IdentityDbContext dbContext,
        CancellationToken cancellationToken)
    {
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
