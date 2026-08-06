using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using Xunit;

namespace QuantumZhou.Identity.IntegrationTests.Integration;

public sealed class SqliteDatabaseContractTests
{
    [Fact]
    public async Task SmsMigration_DropsLegacyEphemeralOtpRowsBeforeAddingAppForeignKey()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"quantumzhou-sms-migration-{Guid.NewGuid():N}.db");
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = $"Data Source={databasePath}"
        });

        try
        {
            await using var context = new IdentityDbContext(optionsBuilder.Options);
            var migrator = context.Database.GetService<IMigrator>();
            await migrator.MigrateAsync("20260805151934_EnableAppScopedLdapLogin");
            var now = (DateTimeOffset.UtcNow.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;
            await context.Database.ExecuteSqlRawAsync(
                "INSERT INTO otps (id, phone, code, expires_at, attempts, lockout_until, created_at) VALUES ({0}, {1}, {2}, {3}, 0, 0, {3})",
                Guid.NewGuid(), "13800138000", "123456", now);

            await migrator.MigrateAsync();

            Assert.Empty(await context.Otps.AsNoTracking().ToListAsync());
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath)) File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task MigrationAndCrud_PreserveUtcInstantAtMicrosecondPrecision()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"quantumzhou-identity-{Guid.NewGuid():N}.db");

        try
        {
            var databaseOptions = new DatabaseOptions
            {
                Provider = "SQLite",
                ConnectionString = $"Data Source={databasePath}"
            };
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);

            var sourceInstant = new DateTimeOffset(
                2026,
                7,
                30,
                12,
                34,
                56,
                TimeSpan.FromHours(8)).AddTicks(1234560);
            var accountId = Guid.NewGuid();

            await using (var writeContext = new IdentityDbContext(optionsBuilder.Options))
            {
                await writeContext.Database.MigrateAsync();
                writeContext.Accounts.Add(new AccountEntity
                {
                    Id = accountId,
                    IsActive = true,
                    CreatedAt = sourceInstant
                });
                await writeContext.SaveChangesAsync();

                writeContext.RefreshTokens.Add(new RefreshTokenEntity
                {
                    Id = Guid.NewGuid(),
                    AccountId = accountId,
                    TokenValue = Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
                    CreatedAt = sourceInstant,
                    ExpiresAt = sourceInstant.AddHours(1),
                    AppId = string.Empty
                });
                await Assert.ThrowsAsync<DbUpdateException>(
                    () => writeContext.SaveChangesAsync());
            }

            await using var readContext = new IdentityDbContext(optionsBuilder.Options);
            var account = await readContext.Accounts
                .AsNoTracking()
                .SingleAsync(item => item.Id == accountId);

            Assert.Equal(TimeSpan.Zero, account.CreatedAt.Offset);
            Assert.Equal(sourceInstant.UtcTicks / 10, account.CreatedAt.UtcTicks / 10);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath))
            {
                File.Delete(databasePath);
            }
        }
    }

    [Fact]
    public async Task CaseInsensitiveKeysAndConcurrentConsumption_AreProviderIndependent()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"quantumzhou-identity-{Guid.NewGuid():N}.db");
        var databaseOptions = new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = $"Data Source={databasePath};Default Timeout=30"
        };
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(databaseOptions);

        try
        {
            var accountId = Guid.NewGuid();
            var appRegistrationId = Guid.NewGuid();
            const string refreshToken = "CaseSensitiveRefreshToken";
            const string phone = "13800138000";
            const string otpCode = "123456";

            await using (var seedContext = new IdentityDbContext(optionsBuilder.Options))
            {
                await seedContext.Database.MigrateAsync();
                seedContext.AppRegistrations.Add(new AppRegistrationEntity
                {
                    Id = appRegistrationId,
                    AppId = "database-contract-app",
                    AppSecretHash = "hash",
                    AppName = "Database Contract",
                    IsActive = true,
                    CreatedAt = DateTimeOffset.UtcNow
                });
                seedContext.Accounts.Add(new AccountEntity
                {
                    Id = accountId,
                    IsActive = true,
                    CreatedAt = DateTimeOffset.UtcNow
                });
                seedContext.PasswordCredentials.Add(new PasswordCredentialEntity
                {
                    Id = Guid.NewGuid(),
                    AccountId = accountId,
                    Username = "Cafe\u0301",
                    PasswordHash = "hash",
                    CreatedAt = DateTimeOffset.UtcNow
                });
                seedContext.RefreshTokens.Add(new RefreshTokenEntity
                {
                    Id = Guid.NewGuid(),
                    AccountId = accountId,
                    TokenValue = refreshToken,
                    CreatedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                    AppId = "database-contract-app"
                });
                seedContext.Otps.Add(new OtpEntity
                {
                    Id = Guid.NewGuid(),
                    AppRegistrationId = appRegistrationId,
                    Phone = phone,
                    CodeMac = otpCode,
                    Status = OtpStatus.Sent,
                    Provider = "Test",
                    ProfileKey = "test",
                    HourWindowStartedAt = DateTimeOffset.UtcNow,
                    DayWindowStartedAt = DateTimeOffset.UtcNow,
                    CreatedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
                    LockoutUntil = DateTimeOffset.UnixEpoch
                });
                await seedContext.SaveChangesAsync();
            }

            await using (var queryContext = new IdentityDbContext(optionsBuilder.Options))
            {
                var credentialRepository =
                    new PasswordCredentialRepository(queryContext);
                var credential =
                    await credentialRepository.GetByUsernameAsync("CAFÉ");
                Assert.NotNull(credential);
                Assert.Equal("Cafe\u0301", credential.Username);
            }

            var rotateResults = await Task.WhenAll(
                TryRotateAsync(optionsBuilder.Options, refreshToken, accountId),
                TryRotateAsync(optionsBuilder.Options, refreshToken, accountId));
            Assert.Equal(1, rotateResults.Count(result => result));

            await using (var assertionContext = new IdentityDbContext(optionsBuilder.Options))
            {
                Assert.Single(await assertionContext.RefreshTokens
                    .Where(token => !token.IsRevoked)
                    .ToListAsync());
            }

            var consumeResults = await Task.WhenAll(
                TryConsumeOtpAsync(optionsBuilder.Options, appRegistrationId, phone, otpCode),
                TryConsumeOtpAsync(optionsBuilder.Options, appRegistrationId, phone, otpCode));
            Assert.Equal(1, consumeResults.Count(result => result));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath))
            {
                File.Delete(databasePath);
            }
        }
    }

    private static async Task<bool> TryRotateAsync(
        DbContextOptions<IdentityDbContext> options,
        string token,
        Guid accountId)
    {
        await using var context = new IdentityDbContext(options);
        var repository = new RefreshTokenRepository(context);
        return await repository.TryRotateAsync(token, new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            TokenValue = Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AppId = "database-contract-app"
        });
    }

    private static async Task<bool> TryConsumeOtpAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid appRegistrationId,
        string phone,
        string code)
    {
        await using var context = new IdentityDbContext(options);
        var repository = new OtpRepository(context);
        return await repository.TryConsumeAsync(
            appRegistrationId,
            phone,
            code,
            DateTimeOffset.UtcNow,
            maxAttempts: 5);
    }
}
