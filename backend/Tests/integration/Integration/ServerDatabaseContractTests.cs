using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
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

            await WaitUntilConnectableAsync(optionsBuilder.Options);
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
                .WithWaitStrategy(CreateMySqlWaitStrategy())
                .Build(),
            "MariaDB" => new MySqlBuilder()
                .WithImage("mariadb:11.4")
                .WithDatabase("identity")
                .WithUsername("identity")
                .WithPassword("identity")
                .WithWaitStrategy(CreateMySqlWaitStrategy())
                .Build(),
            _ => throw new InvalidOperationException($"Unsupported provider: {provider}")
        };
    }

    /// <summary>
    /// Testcontainers.MySql 3.8.0 的默认就绪探针要在容器里跑 <c>mysql</c> 客户端，
    /// 并依赖模块写入 <c>/etc/mysql/my.cnf</c> 的一份 client 配置来补凭据。该模块的默认
    /// 镜像是 mysql:8.0，而本测试钉的是 mysql:8.4 / mariadb:11.4，这套配合在新镜像上失效：
    /// CI 实测探针每秒重试、5 分钟不通过，而同一时刻数据库其实 10 秒就可用了。
    ///
    /// 改成只等 TCP 3306 就绪——官方镜像初始化阶段的临时服务器是 <c>port: 0</c>（仅 socket），
    /// 只有真正的服务器才监听 3306，所以这个判据能准确区分两个阶段，且完全不碰 mysql 客户端，
    /// MySQL 与 MariaDB 通用。端口就绪之后再由 <see cref="WaitUntilConnectableAsync"/>
    /// 用测试真正要用的连接串做一次应用级确认。
    /// </summary>
    private static IWaitForContainerOS CreateMySqlWaitStrategy()
    {
        return Wait.ForUnixContainer().UntilPortIsAvailable(3306);
    }

    /// <summary>
    /// 用测试真正要用的连接串重试连接，直到成功或超时。
    /// 容器"端口已监听"与"能用这套凭据连上目标库"之间仍有窗口，这一步把它填掉；
    /// 失败时抛出的是真实的连接异常，而不是像等待策略那样静默重试到被 blame-hang 掐断。
    /// </summary>
    private async Task WaitUntilConnectableAsync(DbContextOptions<IdentityDbContext> options)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(120);
        Exception? lastError = null;

        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                await using var context = new IdentityDbContext(options);
                if (await context.Database.CanConnectAsync())
                {
                    return;
                }
            }
            catch (Exception exception)
            {
                lastError = exception;
            }

            await Task.Delay(TimeSpan.FromSeconds(1));
        }

        throw new InvalidOperationException(
            $"Database did not become connectable within 120s. Last error: {lastError?.Message ?? "CanConnectAsync kept returning false"}",
            lastError);
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

        // 用东八区表达一个瞬间，再转成 UTC 写入：验证"同一瞬间无论用哪个偏移表达，
        // 落库后都是同一个 UTC 值且微秒精度不丢"。
        //
        // 这里必须显式 ToUniversalTime()，不能直接写非零偏移的值：Npgsql 对
        // timestamp with time zone 只接受 Offset=0，写非零偏移会抛
        // ArgumentException（"only offset 0 (UTC) is supported"）。MySQL 侧则会接受，
        // 也就是说"能不能写非 UTC 偏移"本身是 provider 之间的行为差异。
        // 产品代码全程使用 DateTimeOffset.UtcNow，不依赖这个差异；此处对齐产品的写入方式。
        var sourceInstant = new DateTimeOffset(
            2026,
            7,
            30,
            12,
            34,
            56,
            TimeSpan.FromHours(8)).AddTicks(1234560).ToUniversalTime();
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
            // 写入的是分解形式 "Café"（e + 组合重音符），查询用预组合的大写形式
            // "CAFÉ"（É）：验证 IdentityValueNormalizer 的 FormC + ToUpperInvariant
            // 在各 provider 上行为一致。
            //
            // 这里刻意用 \u00C9 转义而不是直接写 É：该字面量曾被误按 GBK 解码再存回 UTF-8，
            // É(C3 89) 变成了汉字"脡"(U+8121)，于是查询的是一个从未写入过的值，
            // MySQL / MariaDB 用例因此长期失败。非 ASCII 字面量一律用转义，避免重蹈覆辙。
            var credential =
                await credentialRepository.GetByUsernameAsync("CAF\u00C9");
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
