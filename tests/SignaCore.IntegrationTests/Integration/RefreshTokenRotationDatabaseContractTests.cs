using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// Pins the behaviour of <see cref="RefreshTokenRepository.TryRotateAsync"/> under a <b>retrying
/// execution strategy</b>. In production PostgreSQL enables <c>EnableRetryOnFailure()</c> (see
/// <see cref="IdentityDatabaseOptionsExtensions"/>), and EF Core then forbids running commands
/// inside a transaction the caller started itself, so rotating a refresh token throws on its first
/// command with
/// <c>InvalidOperationException: ... does not support user-initiated transactions</c>, which
/// ExceptionHandlingMiddleware turns into an HTTP 409 — the exact scene of a failed atomic refresh
/// token rotation.
/// <para>
/// The real provider matrix lives in <see cref="ServerDatabaseContractTests"/>, which needs
/// Docker/Testcontainers. These tests use SQLite plus a hand-installed retrying strategy instead:
/// the decision that throws lives in EF Core's provider-agnostic
/// <c>ExecutionStrategy.OnFirstExecution</c>, so the regression can be reproduced and held without a
/// container environment. The <c>DatabaseContractTests</c> suffix in the class name is deliberate —
/// CI's Database Contract Test stage filters on
/// <c>FullyQualifiedName~DatabaseContractTests</c>, and this group needs no Docker, so it runs in
/// every environment.
/// </para>
/// </summary>
public sealed class RefreshTokenRotationDatabaseContractTests
{
    /// <summary>
    /// Before the fix: TryRotateAsync called BeginTransactionAsync directly and the first
    /// ExecuteUpdateAsync threw InvalidOperationException. After the fix: the whole transaction runs
    /// inside the execution strategy and the rotation succeeds.
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
    /// The first attempt hits an injected transient failure while inserting the replacement, and the
    /// strategy replays the whole lambda. After the retry the ChangeTracker still has to treat the
    /// replacement as pending and insert it again, and exactly one valid replacement may remain: no
    /// half-finished "old token revoked, replacement lost" state, and no duplicate insert colliding
    /// on the primary key or the token value.
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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RefreshService_CancellationAtCommit_PreservesAtomicRotation(bool afterCommit)
    {
        using var cancellation = new CancellationTokenSource();
        using var database = new SqliteTestDatabase();
        var accountId = await database.SeedAsync(database.BuildOptions(), TokenValue);
        var interceptor = new CommitCancellationInterceptor(cancellation, afterCommit);
        await using (var context = new IdentityDbContext(database.BuildOptions(interceptor)))
        {
            var service = new RefreshTokenService(new RefreshTokenRepository(context), new RefreshTokenOptions());
            var operation = () => service.HandleRefreshTokenAsync(
                IdentityConstants.GrantTypeRefreshToken, TokenValue, new AccountEntity { Id = accountId },
                "rotation-contract-app", cancellationToken: cancellation.Token);
            if (afterCommit)
                Assert.False(string.IsNullOrEmpty(await operation()));
            else
                await Assert.ThrowsAnyAsync<OperationCanceledException>(operation);
        }

        Assert.Equal(1, interceptor.CommitAttempts);
        await using var verification = new IdentityDbContext(database.BuildOptions());
        var tokens = await verification.RefreshTokens.AsNoTracking().ToListAsync();
        Assert.Equal(afterCommit ? 2 : 1, tokens.Count);
        Assert.Equal(afterCommit, tokens.Single(token =>
            token.TokenValue == RefreshTokenDigest.Compute(TokenValue)).IsRevoked);
        if (afterCommit)
            Assert.Single(tokens, token => !token.IsRevoked);
    }

    private sealed class CommitCancellationInterceptor(CancellationTokenSource cancellation, bool afterCommit)
        : DbTransactionInterceptor
    {
        public int CommitAttempts { get; private set; }

        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction, TransactionEventData eventData, InterceptionResult result,
            CancellationToken cancellationToken = default)
        {
            Assert.Equal(cancellation.Token, cancellationToken);
            CommitAttempts++;
            if (!afterCommit)
            {
                cancellation.Cancel();
                cancellationToken.ThrowIfCancellationRequested();
            }
            return ValueTask.FromResult(result);
        }

        public override Task TransactionCommittedAsync(
            DbTransaction transaction, TransactionEndEventData eventData,
            CancellationToken cancellationToken = default)
        {
            cancellation.Cancel();
            return Task.CompletedTask;
        }
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
    /// A file-backed SQLite test database on the same migration chain as production, onto which a
    /// retrying execution strategy and interceptors can be attached as needed.
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
                    // SQLite has no EnableRetryOnFailure, so a retrying strategy is installed by
                    // hand here, which is equivalent to RetriesOnFailure == true under the
                    // production PostgreSQL configuration.
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
    /// Retries only the marker exception injected by <see cref="TransientFailureInterceptor"/>. What
    /// matters is <c>MaxRetryCount &gt; 0</c>, which makes EF Core's <c>RetriesOnFailure</c> true and
    /// therefore triggers the same user-initiated transaction check as
    /// NpgsqlRetryingExecutionStrategy.
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
    /// Injects transient failures into the first N INSERTs against refresh_tokens, simulating a
    /// connection lost just before the commit.
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
