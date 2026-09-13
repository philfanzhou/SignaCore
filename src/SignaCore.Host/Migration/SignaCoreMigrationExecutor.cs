using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services.Sms;
using ServiceMantle.Migration;

namespace SignaCore.Host.Migration;

/// <summary>
/// SignaCore's adapter from the shared migration orchestration boundary to its own schema workflow.
/// <see cref="InspectAsync"/> performs the limited read-only observation defined by the startup
/// migration gate; <see cref="ExecuteAsync"/> runs the full SignaCore migration workflow: the
/// PostgreSQL expand/backfill/contract phases with the normalized-collision checks, the SMS phone
/// identity pre-check, and the OTP uniqueness pre-check, before the final EF migration sweep.
/// The borrowed <see cref="IdentityDbContext"/> is never disposed by this adapter; the backfill
/// steps clear the change tracker so no consumer entity survives the execution.
/// </summary>
internal sealed class SignaCoreMigrationExecutor : IDatabaseMigrationExecutor
{
    private const string ExpandMigrationId =
        "20260730134106_AddNormalizedIdentityValues";
    private const string ContractMigrationId =
        "20260730134156_EnforceNormalizedIdentityValues";
    private const string SingleOtpMigrationId =
        "20260730135237_EnforceSingleOtpPerPhone";

    private const string DefaultHistoryTableName = "__EFMigrationsHistory";
    private const string HistoryLockTableName = "__EFMigrationsHistoryLock";

    private readonly IdentityDbContext _database;
    private readonly DatabaseOptions _databaseOptions;

    public SignaCoreMigrationExecutor(IdentityDbContext database, DatabaseOptions databaseOptions)
    {
        _database = database ?? throw new ArgumentNullException(nameof(database));
        _databaseOptions = databaseOptions ?? throw new ArgumentNullException(nameof(databaseOptions));
    }

    /// <inheritdoc />
    public async ValueTask<MigrationObservationState> InspectAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (_databaseOptions.ProviderKind == DatabaseProvider.Sqlite &&
                !SqliteTargetFileExists())
            {
                // No connection is opened for a missing file: the read-only observation must not
                // create it. DatabaseOptions validation already rejects in-memory targets.
                return MigrationObservationState.Empty;
            }

            var applied = (await _database.Database.GetAppliedMigrationsAsync(cancellationToken))
                .OrderBy(id => id, StringComparer.Ordinal)
                .ToList();
            var lineage = _database.Database.GetMigrations()
                .OrderBy(id => id, StringComparer.Ordinal)
                .ToList();

            if (applied.Count == 0)
            {
                var hasApplicationObjects = await HasApplicationObjectsAsync(cancellationToken);
                return hasApplicationObjects
                    ? MigrationObservationState.InspectionFailed
                    : MigrationObservationState.Empty;
            }

            var known = lineage.ToHashSet(StringComparer.Ordinal);
            if (applied.Any(id => !known.Contains(id)))
            {
                return MigrationObservationState.VersionTooNew;
            }

            if (applied.Count > lineage.Count ||
                !lineage.Take(applied.Count).SequenceEqual(applied, StringComparer.Ordinal))
            {
                return MigrationObservationState.InspectionFailed;
            }

            return applied.Count == lineage.Count
                ? MigrationObservationState.CurrentVersionCompatible
                : MigrationObservationState.PendingMigration;
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            // Observation could not reliably read or identify the history/object catalogs on the
            // target. Fail closed without executing or taking over the database.
            return MigrationObservationState.InspectionFailed;
        }
    }

    /// <inheritdoc />
    public async ValueTask ExecuteAsync(CancellationToken cancellationToken = default)
    {
        // Whole-database schema migration for every provider, formerly SchemaMigrator.MigrateAsync.
        // PostgreSQL takes the expand-contract path: run the expand migration, backfill and
        // collision-check the *_normalized columns, then migrate the rest; other providers migrate
        // directly after their product-specific pre-checks.
        var pendingMigrations = (await _database.Database
                .GetPendingMigrationsAsync(cancellationToken))
            .ToHashSet(StringComparer.Ordinal);

        var appliedMigrations = (await _database.Database
                .GetAppliedMigrationsAsync(cancellationToken)).ToHashSet(StringComparer.Ordinal);
        var hasNormalizedLoginSchema = appliedMigrations.Any(
            id => id.EndsWith("_EnforceNormalizedIdentityValues", StringComparison.Ordinal));
        if (hasNormalizedLoginSchema &&
            pendingMigrations.Any(id => id.EndsWith("_EnableAppScopedSmsLogin", StringComparison.Ordinal)))
        {
            var smsLogins = await _database.UserLogins.AsNoTracking()
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

        if (_databaseOptions.ProviderKind != DatabaseProvider.PostgreSql)
        {
            await _database.Database.MigrateAsync(cancellationToken);
            return;
        }

        if (pendingMigrations.Contains(ExpandMigrationId))
        {
            var migrator = _database.GetService<IMigrator>();
            await migrator.MigrateAsync(ExpandMigrationId, cancellationToken);
        }

        if (pendingMigrations.Contains(ExpandMigrationId) ||
            pendingMigrations.Contains(ContractMigrationId))
        {
            await ValidateAndBackfillAsync(_database, cancellationToken);
        }

        if (pendingMigrations.Contains(SingleOtpMigrationId))
        {
            var duplicatePhone = await _database.Otps
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

        await _database.Database.MigrateAsync(cancellationToken);
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

    private bool SqliteTargetFileExists()
    {
        var builder = new SqliteConnectionStringBuilder(_databaseOptions.ConnectionString);
        var path = builder.DataSource;

        if (path.StartsWith("file:", StringComparison.Ordinal))
        {
            // Best-effort URI path extraction so an existing file: target is not misclassified as
            // Empty; ordinary local paths remain the supported spelling.
            var cut = path.IndexOfAny(['?', '#']);
            path = cut >= 0 ? path["file:".Length..cut] : path["file:".Length..];
        }

        // File.Exists is false both for missing files and for directories; a directory (or any
        // other non-file entry) is not a normal local path the existing flow could create, so it
        // fails closed instead of counting as an empty creatable target.
        if (Directory.Exists(path))
        {
            throw new InvalidOperationException(
                "The SQLite data source is not a local database file path.");
        }

        return File.Exists(path);
    }

    /// <summary>
    /// Counts application tables/views in the same schema the connection's migration history uses.
    /// The EF history table and EF's own lock table are not application objects; any other object
    /// counts even when it holds no data.
    /// </summary>
    private async Task<bool> HasApplicationObjectsAsync(CancellationToken cancellationToken)
    {
        var relationalOptions = _database.GetService<IDbContextOptions>()
            .FindExtension<RelationalOptionsExtension>();
        var historyTableName = relationalOptions?.MigrationsHistoryTableName ?? DefaultHistoryTableName;

        return _databaseOptions.ProviderKind switch
        {
            DatabaseProvider.PostgreSql => await HasPostgreSqlApplicationObjectsAsync(
                relationalOptions?.MigrationsHistoryTableSchema,
                historyTableName,
                cancellationToken),
            DatabaseProvider.Sqlite => await HasSqliteApplicationObjectsAsync(
                historyTableName,
                cancellationToken),
            _ => throw new InvalidOperationException("Unsupported database provider.")
        };
    }

    private async Task<bool> HasPostgreSqlApplicationObjectsAsync(
        string? configuredHistorySchema,
        string historyTableName,
        CancellationToken cancellationToken)
    {
        // When a history-table schema is configured, the history table lives there and the object
        // catalog is observed in that schema. Otherwise the effective schema is resolved on the
        // same connection the history query uses, so both observations share one target; failing
        // to locate it fails closed.
        var sql = configuredHistorySchema is null
            ? """
              SELECT COUNT(*) AS "Value" FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = current_schema()
                AND c.relname NOT IN ({0}, {1})
                AND c.relkind IN ('r', 'v', 'm', 'f', 'p')
              """
            : """
              SELECT COUNT(*) AS "Value" FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = {2}
                AND c.relname NOT IN ({0}, {1})
                AND c.relkind IN ('r', 'v', 'm', 'f', 'p')
              """;

        var count = await _database.Database
            .SqlQueryRaw<long>(sql, historyTableName, HistoryLockTableName, configuredHistorySchema!)
            .FirstAsync(cancellationToken);
        return count > 0;
    }

    private async Task<bool> HasSqliteApplicationObjectsAsync(
        string historyTableName,
        CancellationToken cancellationToken)
    {
        var count = await _database.Database
            .SqlQueryRaw<long>(
                """
                SELECT COUNT(*) AS "Value" FROM sqlite_master
                WHERE type IN ('table', 'view')
                  AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'
                  AND name NOT IN ({0}, {1})
                """,
                historyTableName,
                HistoryLockTableName)
            .FirstAsync(cancellationToken);
        return count > 0;
    }
}
