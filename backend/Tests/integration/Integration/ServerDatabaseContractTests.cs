using DotNet.Testcontainers.Containers;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Host;
using Testcontainers.MySql;
using Testcontainers.PostgreSql;
using Xunit;
using Xunit.Abstractions;

namespace QuantumZhou.Identity.IntegrationTests.Integration;

public sealed class ServerDatabaseContractTests
{
    private readonly ITestOutputHelper _output;

    public ServerDatabaseContractTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Theory]
    [InlineData("PostgreSQL")]
    [InlineData("MySQL")]
    [InlineData("MariaDB")]
    public async Task ProviderContract_MigrationCrudNormalizationAndConcurrency(
        string provider)
    {
        if (!ShouldRunContainerMatrix())
        {
            _output.WriteLine(
                $"SKIPPED {provider}: set RUN_IDENTITY_DATABASE_CONTRACTS=true to run the container matrix.");
            return;
        }

        var container = CreateContainer(provider);
        await using (container)
        {
            await container.StartAsync();
            var databaseOptions = CreateDatabaseOptions(
                provider,
                GetConnectionString(container));
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);

            await RunContractAsync(optionsBuilder.Options);
        }
    }

    [Fact]
    public async Task PostgreSqlLegacyHistory_UpgradesInPlace()
    {
        if (!ShouldRunContainerMatrix())
        {
            _output.WriteLine(
                "SKIPPED PostgreSQL legacy upgrade: set RUN_IDENTITY_DATABASE_CONTRACTS=true.");
            return;
        }

        var container = new PostgreSqlBuilder()
            .WithImage("postgres:15-alpine")
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync();
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);

            await using var context = new IdentityDbContext(optionsBuilder.Options);
            var migrator = context.GetService<IMigrator>();
            await migrator.MigrateAsync(
                "20260504150448_AddAppIdToRefreshToken");

            var accountId = Guid.NewGuid();
            var credentialId = Guid.NewGuid();
            await context.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO accounts (id, is_active, created_at, total_login_count)
                VALUES ({accountId}, TRUE, {DateTimeOffset.UtcNow}, 0);

                INSERT INTO password_credentials
                    (id, account_id, username, password_hash, created_at)
                VALUES
                    ({credentialId}, {accountId}, {"LegacyUser"}, {"hash"}, {DateTimeOffset.UtcNow});
                """);

            await SchemaMigrator.MigrateAsync(
                context,
                databaseOptions);

            var credential = await context.PasswordCredentials
                .AsNoTracking()
                .SingleAsync(item => item.Id == credentialId);
            Assert.Equal("LEGACYUSER", credential.UsernameNormalized);

            var appliedMigrations = (await context.Database
                    .GetAppliedMigrationsAsync())
                .ToHashSet(StringComparer.Ordinal);
            Assert.Contains(
                "20260502023354_InitialCreate",
                appliedMigrations);
            Assert.Contains(
                "20260504150448_AddAppIdToRefreshToken",
                appliedMigrations);
            Assert.Contains(
                "20260730134156_EnforceNormalizedIdentityValues",
                appliedMigrations);
        }
    }

    private static IContainer CreateContainer(string provider)
    {
        return provider switch
        {
            "PostgreSQL" => new PostgreSqlBuilder()
                .WithImage("postgres:15-alpine")
                .WithDatabase("identity")
                .WithUsername("postgres")
                .WithPassword("postgres")
                .Build(),
            "MySQL" => new MySqlBuilder()
                .WithImage("mysql:8.4")
                .WithDatabase("identity")
                .WithUsername("identity")
                .WithPassword("identity")
                .Build(),
            "MariaDB" => new MySqlBuilder()
                .WithImage("mariadb:11.4")
                .WithDatabase("identity")
                .WithUsername("identity")
                .WithPassword("identity")
                .Build(),
            _ => throw new InvalidOperationException($"Unsupported provider: {provider}")
        };
    }

    private static string GetConnectionString(IContainer container)
    {
        return container switch
        {
            PostgreSqlContainer postgreSql => postgreSql.GetConnectionString(),
            MySqlContainer mySql => mySql.GetConnectionString(),
            _ => throw new InvalidOperationException("Unsupported test container.")
        };
    }

    private static DatabaseOptions CreateDatabaseOptions(
        string provider,
        string connectionString)
    {
        return new DatabaseOptions
        {
            Provider = provider,
            ServerVersion = provider switch
            {
                "PostgreSQL" => "15",
                "MySQL" => "8.4",
                "MariaDB" => "11.4",
                _ => throw new InvalidOperationException(
                    $"Unsupported provider: {provider}")
            },
            ConnectionString = connectionString
        };
    }

    private static async Task RunContractAsync(
        DbContextOptions<IdentityDbContext> options)
    {
        var accountId = Guid.NewGuid();
        var sourceInstant = new DateTimeOffset(
            2026,
            7,
            30,
            12,
            34,
            56,
            TimeSpan.FromHours(8)).AddTicks(1234560);
        const string token = "CaseSensitiveRefreshToken";
        const string phone = "13800138000";
        const string otpCode = "123456";

        await using (var seedContext = new IdentityDbContext(options))
        {
            await seedContext.Database.MigrateAsync();
            seedContext.Accounts.Add(new AccountEntity
            {
                Id = accountId,
                IsActive = true,
                CreatedAt = sourceInstant
            });
            seedContext.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = Guid.NewGuid(),
                AccountId = accountId,
                Username = "Cafe\u0301",
                PasswordHash = "hash",
                CreatedAt = sourceInstant
            });
            seedContext.RefreshTokens.Add(new RefreshTokenEntity
            {
                Id = Guid.NewGuid(),
                AccountId = accountId,
                TokenValue = token,
                CreatedAt = sourceInstant,
                ExpiresAt = sourceInstant.AddHours(1)
            });
            seedContext.Otps.Add(new OtpEntity
            {
                Id = Guid.NewGuid(),
                Phone = phone,
                Code = otpCode,
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
                LockoutUntil = DateTimeOffset.UnixEpoch
            });
            await seedContext.SaveChangesAsync();
        }

        await using (var queryContext = new IdentityDbContext(options))
        {
            var credentialRepository =
                new PasswordCredentialRepository(queryContext);
            var credential =
                await credentialRepository.GetByUsernameAsync("CAF脡");
            Assert.NotNull(credential);

            var account = await queryContext.Accounts
                .AsNoTracking()
                .SingleAsync(item => item.Id == accountId);
            Assert.Equal(TimeSpan.Zero, account.CreatedAt.Offset);
            Assert.Equal(sourceInstant.UtcTicks / 10, account.CreatedAt.UtcTicks / 10);
        }

        var rotateResults = await Task.WhenAll(
            TryRotateAsync(options, token, accountId),
            TryRotateAsync(options, token, accountId));
        Assert.Equal(1, rotateResults.Count(result => result));

        await using (var assertionContext = new IdentityDbContext(options))
        {
            Assert.Single(await assertionContext.RefreshTokens
                .Where(refreshToken => !refreshToken.IsRevoked)
                .ToListAsync());
        }

        var consumeResults = await Task.WhenAll(
            TryConsumeOtpAsync(options, phone, otpCode),
            TryConsumeOtpAsync(options, phone, otpCode));
        Assert.Equal(1, consumeResults.Count(result => result));
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
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
        });
    }

    private static async Task<bool> TryConsumeOtpAsync(
        DbContextOptions<IdentityDbContext> options,
        string phone,
        string code)
    {
        await using var context = new IdentityDbContext(options);
        var repository = new OtpRepository(context);
        return await repository.TryConsumeAsync(
            phone,
            code,
            DateTimeOffset.UtcNow,
            maxAttempts: 5);
    }

    private static bool ShouldRunContainerMatrix()
    {
        return string.Equals(
            Environment.GetEnvironmentVariable(
                "RUN_IDENTITY_DATABASE_CONTRACTS"),
            "true",
            StringComparison.OrdinalIgnoreCase);
    }
}
