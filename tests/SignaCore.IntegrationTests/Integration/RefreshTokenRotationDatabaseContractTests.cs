using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// 守住 <see cref="RefreshTokenRepository.TryRotateAsync"/> 在**重试型 execution strategy**
/// 下的行为。生产上 PostgreSQL / MySQL / MariaDB 都开了 <c>EnableRetryOnFailure()</c>
/// （见 <see cref="IdentityDatabaseOptionsExtensions"/>），此时 EF Core 禁止在"调用方自己开的事务"
/// 里执行命令，旋转 refresh token 会在第一条命令上抛
/// <c>InvalidOperationException: ... does not support user-initiated transactions</c>，
/// 经 ExceptionHandlingMiddleware 变成 HTTP 409——就是 refresh token 原子换票失败的现场。
/// <para>
/// 真实 provider 的矩阵在 <see cref="ServerDatabaseContractTests"/>（需要 Docker/Testcontainers）。
/// 这里改用 SQLite + 手工注入的重试型 strategy：抛异常的判定在 EF Core 通用的
/// <c>ExecutionStrategy.OnFirstExecution</c> 里，与 provider 无关，因此无容器环境也能复现并守住回归。
/// 类名带 <c>DatabaseContractTests</c> 后缀是有意的——CI 的 Database Contract Test 阶段按
/// <c>FullyQualifiedName~DatabaseContractTests</c> 过滤，本组用例不需要 Docker，任何环境都会跑到。
/// </para>
/// </summary>
public sealed class RefreshTokenRotationDatabaseContractTests
{
    /// <summary>
    /// 修复前：TryRotateAsync 直接 BeginTransactionAsync，第一条 ExecuteUpdateAsync 就抛
    /// InvalidOperationException。修复后：整个事务跑在 execution strategy 里，正常旋转。
    /// </summary>
    [Fact]
    public async Task TryRotate_UnderRetryingExecutionStrategy_RotatesInsteadOfThrowing()
    {
        using var database = new SqliteTestDatabase();
        var options = database.BuildOptions();
        var accountId = await database.SeedAsync(options, TokenValue);

        bool rotated;
        await using (var context = new IdentityDbContext(options))
        {
            var repository = new RefreshTokenRepository(context);
            rotated = await repository.TryRotateAsync(
                TokenValue,
                CreateReplacement(accountId, ReplacementTokenValue));
        }

        Assert.True(rotated);
        await AssertRotatedExactlyOnceAsync(options);
    }

    /// <summary>
    /// 首次尝试在插入 replacement 时遭遇"瞬时故障"，strategy 重跑整个 lambda。
    /// 重试后 ChangeTracker 必须仍把 replacement 当成待插入实体重新落库，
    /// 且最终只留下一条有效 replacement——不能出现"旧 token 已撤销、replacement 丢失"的半完成状态，
    /// 也不能重复插入导致主键/token 冲突。
    /// </summary>
    [Fact]
    public async Task TryRotate_WhenFirstAttemptFailsTransiently_InsertsReplacementExactlyOnce()
    {
        var interceptor = new TransientFailureInterceptor(failuresToInject: 1);
        using var database = new SqliteTestDatabase();
        var options = database.BuildOptions(interceptor);
        var accountId = await database.SeedAsync(database.BuildOptions(), TokenValue);

        bool rotated;
        await using (var context = new IdentityDbContext(options))
        {
            var repository = new RefreshTokenRepository(context);
            rotated = await repository.TryRotateAsync(
                TokenValue,
                CreateReplacement(accountId, ReplacementTokenValue));
        }

        Assert.Equal(1, interceptor.InjectedFailures);
        Assert.True(rotated);
        await AssertRotatedExactlyOnceAsync(database.BuildOptions());
    }

    private const string TokenValue = "RotationRetrySourceToken";
    private const string ReplacementTokenValue = "RotationRetryReplacementToken";

    private static async Task AssertRotatedExactlyOnceAsync(
        DbContextOptions<IdentityDbContext> options)
    {
        await using var context = new IdentityDbContext(options);
        var tokens = await context.RefreshTokens.AsNoTracking().ToListAsync();

        Assert.Equal(2, tokens.Count);
        Assert.True(Assert.Single(
            tokens,
            token => token.TokenValue == RefreshTokenDigest.Compute(TokenValue)).IsRevoked);
        Assert.False(
            Assert.Single(
                tokens,
                token => token.TokenValue == RefreshTokenDigest.Compute(ReplacementTokenValue)).IsRevoked);
    }

    private static RefreshTokenEntity CreateReplacement(Guid accountId, string tokenValue)
    {
        return new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            TokenValue = tokenValue,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AppId = "rotation-contract-app"
        };
    }

    /// <summary>
    /// 文件型 SQLite 测试库 + 生产同款迁移链，可按需挂上重试型 execution strategy 与拦截器。
    /// </summary>
    private sealed class SqliteTestDatabase : IDisposable
    {
        private readonly string _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-rotation-{Guid.NewGuid():N}.db");

        public DbContextOptions<IdentityDbContext> BuildOptions(
            IInterceptor? interceptor = null)
        {
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseSqlite(
                $"Data Source={_databasePath};Default Timeout=30",
                providerOptions =>
                {
                    providerOptions.MigrationsAssembly(
                        "SignaCore.Database.Migrations.Sqlite");
                    // SQLite 没有 EnableRetryOnFailure，这里手工装一个会重试的 strategy，
                    // 等价于 PostgreSQL/MySQL 生产配置下的 RetriesOnFailure == true。
                    providerOptions.ExecutionStrategy(
                        dependencies => new TestRetryingExecutionStrategy(dependencies));
                });

            if (interceptor != null)
            {
                optionsBuilder.AddInterceptors(interceptor);
            }

            return optionsBuilder.Options;
        }

        public async Task<Guid> SeedAsync(
            DbContextOptions<IdentityDbContext> options,
            string tokenValue)
        {
            var accountId = Guid.NewGuid();
            await using var context = new IdentityDbContext(options);
            await context.Database.MigrateAsync();
            context.Accounts.Add(new AccountEntity
            {
                Id = accountId,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            });
            context.RefreshTokens.Add(new RefreshTokenEntity
            {
                Id = Guid.NewGuid(),
                AccountId = accountId,
                TokenValue = RefreshTokenDigest.Compute(tokenValue),
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                AppId = "rotation-contract-app"
            });
            await context.SaveChangesAsync();
            return accountId;
        }

        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(_databasePath))
            {
                File.Delete(_databasePath);
            }
        }
    }

    /// <summary>
    /// 只重试 <see cref="TransientFailureInterceptor"/> 注入的标记异常。
    /// 关键在于 <c>MaxRetryCount &gt; 0</c>，使 EF Core 的 <c>RetriesOnFailure</c> 为 true，
    /// 从而触发与 NpgsqlRetryingExecutionStrategy 相同的 user-initiated transaction 检查。
    /// </summary>
    private sealed class TestRetryingExecutionStrategy : ExecutionStrategy
    {
        public TestRetryingExecutionStrategy(ExecutionStrategyDependencies dependencies)
            : base(dependencies, maxRetryCount: 3, maxRetryDelay: TimeSpan.FromMilliseconds(1))
        {
        }

        protected override bool ShouldRetryOn(Exception exception)
        {
            return exception is InjectedTransientException
                || exception.InnerException is InjectedTransientException;
        }
    }

    private sealed class InjectedTransientException : Exception
    {
        public InjectedTransientException()
            : base("Injected transient database failure.")
        {
        }
    }

    /// <summary>
    /// 在写入 refresh_tokens 的 INSERT 上注入前 N 次瞬时故障，模拟提交前掉线。
    /// </summary>
    private sealed class TransientFailureInterceptor : DbCommandInterceptor
    {
        private readonly int _failuresToInject;

        public TransientFailureInterceptor(int failuresToInject)
        {
            _failuresToInject = failuresToInject;
        }

        public int InjectedFailures { get; private set; }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfShouldFail(command);
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfShouldFail(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }

        private void ThrowIfShouldFail(DbCommand command)
        {
            if (InjectedFailures >= _failuresToInject
                || !command.CommandText.Contains(
                    "INSERT INTO \"refresh_tokens\"",
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            InjectedFailures++;
            throw new InjectedTransientException();
        }
    }
}
