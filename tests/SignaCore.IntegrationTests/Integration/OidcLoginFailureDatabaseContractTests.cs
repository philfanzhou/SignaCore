using System.Data.Common;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The commit-boundary contract of the <c>EV-17</c> credential-failure unit
/// (<see cref="OidcLoginFailureRecorder"/>): cancellation before the commit leaves no counter or
/// audit residue (<c>EV-18</c>, <c>SC-20</c>), a committed unit stays authoritative, a transient
/// failure replays the whole execution-strategy unit exactly once, and a cancelled continuation
/// lookup writes nothing. Exception and log strings carry none of the submitted values.
/// <para>
/// Like <see cref="RefreshTokenRotationDatabaseContractTests"/>, these tests use SQLite plus a
/// hand-installed retrying strategy equivalent to the production PostgreSQL
/// <c>EnableRetryOnFailure()</c> configuration, so the <c>DatabaseContractTests</c> suffix runs
/// them in CI's database matrix without Docker.
/// </para>
/// </summary>
public sealed class OidcLoginFailureDatabaseContractTests
{
    private const string CanaryUsername = "failure-recorder-canary-user";
    private const string FailureReason = "Wrong username or password";
    private const string CanaryAppId = "failure-contract-app";
    private const string CanaryClientIp = "203.0.113.7";
    private const string CanaryUserAgent = "failure-contract-agent";
    private const string CanaryCorrelationId = "failure-contract-correlation";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheFailureUnit_IsAtomicAtTheCommitBoundary(bool afterCommit)
    {
        using var cancellation = new CancellationTokenSource();
        using var database = new SqliteTestDatabase();
        await database.MigrateAsync();
        var interceptor = new CommitCancellationInterceptor(cancellation, afterCommit);
        await using var context = new IdentityDbContext(database.BuildOptions(interceptor));
        var recorder = CreateRecorder(context);

        var operation = () => recorder.RecordFailureAsync(
            new LoginAttemptChange(LoginAttemptChangeKind.RecordFailure, CanaryUsername),
            CanaryUsername,
            FailureReason,
            CanaryAppId,
            CanaryClientIp,
            CanaryUserAgent,
            CanaryCorrelationId,
            cancellation.Token);

        if (afterCommit)
        {
            // A committed unit stays authoritative even when cancellation is observed right after
            // the commit (SC-20).
            await operation();
        }
        else
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(operation);
        }

        Assert.Equal(1, interceptor.CommitAttempts);
        await using var verification = new IdentityDbContext(database.BuildOptions());
        var attempts = await verification.LoginAttempts.AsNoTracking().ToListAsync();
        var histories = await verification.LoginHistories.AsNoTracking().ToListAsync();
        if (afterCommit)
        {
            Assert.Equal(1, Assert.Single(attempts).FailedAttempts);
            Assert.Single(histories);
        }
        else
        {
            Assert.Empty(attempts);
            Assert.Empty(histories);
        }
    }

    /// <summary>
    /// One injected transient failure before the commit makes the execution strategy replay the
    /// whole unit; the counter ends at exactly one increment and exactly one audit row survives.
    /// </summary>
    [Fact]
    public async Task TheFailureUnit_ReplaysExactlyOnceAfterATransientFailure()
    {
        var interceptor = new TransientFailureInterceptor(failuresToInject: 1);
        using var database = new SqliteTestDatabase();
        await database.MigrateAsync();
        await using (var context = new IdentityDbContext(database.BuildOptions(interceptor)))
        {
            var recorder = CreateRecorder(context);
            await recorder.RecordFailureAsync(
                new LoginAttemptChange(LoginAttemptChangeKind.RecordFailure, CanaryUsername),
                CanaryUsername,
                FailureReason,
                CanaryAppId,
                CanaryClientIp,
                CanaryUserAgent,
                CanaryCorrelationId);
        }

        Assert.Equal(1, interceptor.InjectedFailures);
        await using var verification = new IdentityDbContext(database.BuildOptions());
        var attempt = Assert.Single(await verification.LoginAttempts.AsNoTracking().ToListAsync());
        Assert.Equal(1, attempt.FailedAttempts);
        Assert.Null(attempt.LockoutUntil);
        var history = Assert.Single(await verification.LoginHistories.AsNoTracking().ToListAsync());
        Assert.Equal(CanaryUsername, history.Username);
        Assert.Equal(OidcLoginFailureRecorder.OidcLoginAuthMethod, history.AuthMethod);
    }

    [Fact]
    public async Task CancellationDuringTheContinuationLookup_WritesNothing()
    {
        using var database = new SqliteTestDatabase();
        await database.MigrateAsync();
        await using var context = new IdentityDbContext(database.BuildOptions());

        var applicationId = Guid.NewGuid();
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = applicationId,
            AppId = CanaryAppId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword("failure-contract-secret"),
            AppName = "Failure Contract App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = "openid profile"
        });
        await context.SaveChangesAsync();

        var store = new AuthorizationRequestStore(
            new AuthorizationRequestRepository(context),
            new EfCoreUnitOfWork(context));
        var creation = await store.CreateAsync(
            new OidcAuthorizationValidationResult.Accepted(
                CanaryAppId,
                applicationId,
                "https://bff.failure.test/callback",
                "openid",
                "state-canary",
                "nonce-canary",
                "challenge-canary"),
            DateTimeOffset.UtcNow.AddMinutes(-1));
        var before = await DumpAsync(database.BuildOptions());

        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.GetActiveAsync(creation.LoginHandle, DateTimeOffset.UtcNow, cancellation.Token));

        Assert.Equal(before, await DumpAsync(database.BuildOptions()));
    }

    [Fact]
    public async Task FailureUnitExceptionsAndLogs_CarryNoSubmittedValues()
    {
        using var cancellation = new CancellationTokenSource();
        using var database = new SqliteTestDatabase();
        await database.MigrateAsync();
        var interceptor = new CommitCancellationInterceptor(cancellation, afterCommit: false);
        var logMessages = new List<string>();
        await using var context = new IdentityDbContext(database.BuildOptions(interceptor));
        var recorder = CreateRecorder(context, new ListLogger(logMessages));

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            recorder.RecordFailureAsync(
                new LoginAttemptChange(LoginAttemptChangeKind.RecordFailure, CanaryUsername),
                CanaryUsername,
                FailureReason,
                CanaryAppId,
                CanaryClientIp,
                CanaryUserAgent,
                CanaryCorrelationId,
                cancellation.Token));

        // The exception string plus every captured log message stay free of the submitted values;
        // at the HTTP layer the same guarantee for password, handle, and antiforgery values is
        // scanned by OAuthLoginSensitiveValueScanTests.
        var text = exception.ToString() + string.Join(Environment.NewLine, logMessages);
        Assert.DoesNotContain(CanaryUsername, text, StringComparison.Ordinal);
        Assert.DoesNotContain(FailureReason, text, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryAppId, text, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryClientIp, text, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryUserAgent, text, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryCorrelationId, text, StringComparison.Ordinal);
    }

    private static OidcLoginFailureRecorder CreateRecorder(
        IdentityDbContext context,
        ILogger<OidcLoginFailureRecorder>? logger = null) =>
        new(
            new LoginAttemptRepository(context),
            new AuditService(
                new LoginHistoryRepository(context),
                new AuditLogRepository(context)),
            new EfCoreUnitOfWork(context),
            context,
            logger ?? NullLogger<OidcLoginFailureRecorder>.Instance);

    private static async Task<string> DumpAsync(DbContextOptions<IdentityDbContext> options)
    {
        await using var context = new IdentityDbContext(options);
        var dump = new StringBuilder();
        foreach (var attempt in await context.LoginAttempts.AsNoTracking()
                     .OrderBy(row => row.Id).ToListAsync())
        {
            dump.Append("attempt|").Append(attempt.Id).Append('|').Append(attempt.FailedAttempts)
                .Append('|').Append(attempt.LockoutUntil?.UtcTicks).AppendLine();
        }

        foreach (var history in await context.LoginHistories.AsNoTracking()
                     .OrderBy(row => row.Id).ToListAsync())
        {
            dump.Append("history|").Append(history.Id).Append('|').Append(history.Username)
                .AppendLine();
        }

        foreach (var continuation in await context.AuthorizationRequests.AsNoTracking()
                     .OrderBy(row => row.Id).ToListAsync())
        {
            dump.Append("continuation|").Append(continuation.Id).Append('|')
                .Append(continuation.ConsumedAt?.UtcTicks).AppendLine();
        }

        return dump.ToString();
    }

    private sealed class ListLogger(List<string> messages) : ILogger<OidcLoginFailureRecorder>
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            messages.Add(formatter(state, exception));
    }

    /// <summary>
    /// A file-backed SQLite test database on the production migration chain, onto which a
    /// retrying execution strategy and interceptors are attached as needed.
    /// </summary>
    private sealed class SqliteTestDatabase : IDisposable
    {
        private readonly string _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-login-failure-{Guid.NewGuid():N}.db");

        public DbContextOptions<IdentityDbContext> BuildOptions(IInterceptor? interceptor = null)
        {
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseSqlite(
                $"Data Source={_databasePath};Default Timeout=30",
                providerOptions =>
                {
                    providerOptions.MigrationsAssembly("SignaCore.Database.Migrations.Sqlite");
                    // SQLite has no EnableRetryOnFailure, so a retrying strategy is installed by
                    // hand, equivalent to RetriesOnFailure == true under the production
                    // PostgreSQL configuration.
                    providerOptions.ExecutionStrategy(
                        dependencies => new TestRetryingExecutionStrategy(dependencies));
                });

            if (interceptor != null)
            {
                optionsBuilder.AddInterceptors(interceptor);
            }

            return optionsBuilder.Options;
        }

        public async Task MigrateAsync()
        {
            // The migration runs without interceptors: the commit-cancellation interceptor would
            // otherwise abort the migration transaction itself.
            await using var context = new IdentityDbContext(BuildOptions());
            await context.Database.MigrateAsync();
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

    private sealed class CommitCancellationInterceptor(
        CancellationTokenSource cancellation,
        bool afterCommit) : DbTransactionInterceptor
    {
        public int CommitAttempts { get; private set; }

        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction,
            TransactionEventData eventData,
            InterceptionResult result,
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
            DbTransaction transaction,
            TransactionEndEventData eventData,
            CancellationToken cancellationToken = default)
        {
            cancellation.Cancel();
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Injects transient failures into the first N INSERTs against login_histories, simulating a
    /// connection lost just before the commit of the failure unit.
    /// </summary>
    private sealed class TransientFailureInterceptor(int failuresToInject) : DbCommandInterceptor
    {
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
            if (InjectedFailures >= failuresToInject
                || !command.CommandText.Contains(
                    "INSERT INTO \"login_histories\"",
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            InjectedFailures++;
            throw new InjectedTransientException();
        }
    }
}
