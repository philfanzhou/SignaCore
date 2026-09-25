using System.Data.Common;
using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Host;
using SignaCore.Host.Management;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The management bearer lifecycle service (#383) against real SQLite and PostgreSQL databases:
/// issuance, live validation, first-write-wins revocation, bounded cleanup, caller cancellation
/// at every boundary, single-attempt failure handling, and sensitive-output scanning.
/// Credential and digest comparisons use <see cref="Same"/> so a failure never prints them.
/// </summary>
public sealed class ManagementBearerSessionDatabaseContractTests
{
    private const string AdminUsername = "OpsAdmin";
    private const string OtherUsername = "OrderServiceOperator";
    private const string InactiveUsername = "RetiredOperator";
    private const string PasswordHashCanary = "synthetic-password-hash-canary";
    private const string PostgreSqlPasswordCanary = "bearer-contract-canary-pw";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    // Sub-microsecond ticks prove the service truncates before storing, comparing, and returning.
    private static readonly DateTimeOffset Base = new DateTimeOffset(2026, 9, 25, 8, 0, 0, TimeSpan.Zero).AddTicks(1_234_567);
    private static readonly DateTimeOffset BaseMicros = new DateTimeOffset(2026, 9, 25, 8, 0, 0, TimeSpan.Zero).AddTicks(1_234_560);
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Issue_ProducesIndependentFixedLifetimeCredentialsWithoutPersistingPlaintext(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        var time = new ManualTime(Base);
        var service = fixture.Service(time);

        var first = await service.IssueAsync(fixture.Admin, Ct);
        var second = await service.IssueAsync(fixture.Admin, Ct);

        Assert.Equal(ManagementBearerIssueStatus.Issued, first.Status);
        Assert.Equal(ManagementBearerIssueStatus.Issued, second.Status);
        Assert.False(Same(first.Token, second.Token), "Two issuances returned the same credential.");
        Assert.True(ManagementBearerToken.IsWellFormed(first.Token), "The issued credential is not canonical.");
        Assert.Equal(BaseMicros + Lifetime, first.ExpiresAtUtc);
        Assert.Equal(TimeSpan.Zero, first.ExpiresAtUtc!.Value.Offset);

        var rows = await fixture.SessionsAsync();
        Assert.Equal(2, rows.Count);
        Assert.Equal(2, rows.Select(r => r.TokenDigest).Distinct(StringComparer.Ordinal).Count());
        Assert.Contains(rows, r => Same(r.TokenDigest, ManagementBearerToken.ComputeDigest(first.Token!)));
        Assert.All(rows, row =>
        {
            Assert.Equal(fixture.Admin, row.AccountId);
            Assert.Equal(BaseMicros, row.CreatedAt);
            Assert.Equal(BaseMicros + Lifetime, row.ExpiresAt);
            Assert.Null(row.RevokedAt);
        });

        // No sliding and no refresh: validation up to the last microsecond leaves the row as is.
        time.Now = BaseMicros + Lifetime - TimeSpan.FromTicks(TimeSpan.TicksPerMicrosecond);
        var valid = await service.ValidateAsync(first.Token, Ct);
        Assert.Equal(ManagementBearerValidationStatus.Valid, valid.Status);
        Assert.Equal(fixture.Admin, valid.AccountId);
        Assert.Equal(AdminUsername, valid.OperatorName);
        time.Now = BaseMicros + Lifetime;
        Assert.Equal(ManagementBearerRejectionReason.Expired, (await service.ValidateAsync(first.Token, Ct)).Reason);
        time.Now = BaseMicros + Lifetime + TimeSpan.FromTicks(7);
        Assert.Equal(ManagementBearerRejectionReason.Expired, (await service.ValidateAsync(first.Token, Ct)).Reason);
        Assert.All(await fixture.SessionsAsync(), row => Assert.Equal(BaseMicros + Lifetime, row.ExpiresAt));

        // Every column value of the table is free of either plaintext credential.
        var scanner = new CanaryScanner(first.Token!, first.Token![5..], second.Token!, second.Token![5..]);
        scanner.AssertClean(await fixture.DumpSessionsAsync());
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Validate_ClassifiesEveryRejectionLiveAndStrictly(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        var time = new ManualTime(Base);
        var service = fixture.Service(time);
        var admin = (await service.IssueAsync(fixture.Admin, Ct)).Token!;
        var other = (await service.IssueAsync(fixture.Other, Ct)).Token!;
        var inactive = (await service.IssueAsync(fixture.Inactive, Ct)).Token!;

        foreach (var malformed in new[]
        {
            null, "", admin[..47], admin + "A", "SCM1." + admin[5..], "scm2." + admin[5..], admin[..47] + "=",
            admin[..47] + "+", admin[..47] + "/", ManagementBearerToken.ComputeDigest(admin), " " + admin[..47]
        })
        {
            var result = await service.ValidateAsync(malformed, Ct);
            Assert.Equal(ManagementBearerValidationStatus.Rejected, result.Status);
            Assert.Equal(ManagementBearerRejectionReason.Malformed, result.Reason);
            Assert.Null(result.AccountId);
        }

        Assert.Equal(ManagementBearerRejectionReason.NotFound, (await service.ValidateAsync(ManagementBearerToken.Generate(), Ct)).Reason);
        Assert.Equal(ManagementBearerRejectionReason.NotEligible, (await service.ValidateAsync(other, Ct)).Reason);
        Assert.Equal(ManagementBearerRejectionReason.NotEligible, (await service.ValidateAsync(inactive, Ct)).Reason);
        Assert.Equal(ManagementBearerValidationStatus.Valid, (await service.ValidateAsync(admin, Ct)).Status);

        // Eligibility is re-read on every call: the configured administrator matching another
        // account, no administrator configured, and a deactivated account all reject.
        Assert.Equal(ManagementBearerRejectionReason.NotEligible, (await fixture.Service(time, OtherUsername).ValidateAsync(admin, Ct)).Reason);
        Assert.Equal(ManagementBearerValidationStatus.Valid, (await fixture.Service(time, OtherUsername).ValidateAsync(other, Ct)).Status);
        Assert.Equal(ManagementBearerRejectionReason.NotEligible, (await fixture.Service(time, "").ValidateAsync(admin, Ct)).Reason);
        Assert.Equal(ManagementBearerRejectionReason.NotEligible, (await fixture.Service(time, "  ").ValidateAsync(admin, Ct)).Reason);
        Assert.Equal(ManagementBearerValidationStatus.Valid, (await fixture.Service(time, "opsadmin").ValidateAsync(admin, Ct)).Status);
        await fixture.SetActiveAsync(fixture.Admin, false);
        Assert.Equal(ManagementBearerRejectionReason.NotEligible, (await service.ValidateAsync(admin, Ct)).Reason);
        await fixture.SetActiveAsync(fixture.Admin, true);
        Assert.Equal(ManagementBearerValidationStatus.Valid, (await service.ValidateAsync(admin, Ct)).Status);

        Assert.Equal(ManagementBearerRevocationResult.Revoked, await service.RevokeAsync(admin, Ct));
        Assert.Equal(ManagementBearerRejectionReason.Revoked, (await service.ValidateAsync(admin, Ct)).Reason);

        // Account deletion cascades its sessions away.
        await fixture.DeleteAccountAsync(fixture.Other);
        Assert.Equal(ManagementBearerRejectionReason.NotFound, (await service.ValidateAsync(other, Ct)).Reason);

        foreach (var result in new object[] { await service.ValidateAsync(inactive, Ct), await service.IssueAsync(fixture.Admin, Ct) })
        {
            new CanaryScanner(admin, other, inactive, AdminUsername).AssertClean([result.ToString()!]);
        }
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Revoke_KeepsTheFirstInstantAndRejectsLaterValidationFromAnyConnection(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        var time = new ManualTime(Base);
        var service = fixture.Service(time);
        var token = (await service.IssueAsync(fixture.Admin, Ct)).Token!;

        // A validation completed before the revocation is a finished answer; revocation only
        // affects validations that start after its commit.
        var before = await service.ValidateAsync(token, Ct);
        time.Now = Base.AddMinutes(1).AddTicks(9);
        Assert.Equal(ManagementBearerRevocationResult.Revoked, await service.RevokeAsync(token, Ct));
        Assert.Equal(ManagementBearerValidationStatus.Valid, before.Status);
        // 1_234_567 + 9 ticks truncates to 1_234_570: the stored instant is the microsecond value.
        var firstRevocation = new DateTimeOffset(2026, 9, 25, 8, 1, 0, TimeSpan.Zero).AddTicks(1_234_570);
        Assert.Equal(firstRevocation, (await fixture.SessionsAsync()).Single().RevokedAt);

        time.Now = Base.AddMinutes(2);
        Assert.Equal(ManagementBearerRevocationResult.NotActive, await service.RevokeAsync(token, Ct));
        Assert.Equal(firstRevocation, (await fixture.SessionsAsync()).Single().RevokedAt);

        var otherInstance = fixture.Service(new ManualTime(Base.AddMinutes(3)));
        Assert.Equal(ManagementBearerRejectionReason.Revoked, (await otherInstance.ValidateAsync(token, Ct)).Reason);
        Assert.Equal(ManagementBearerRevocationResult.NotActive, await otherInstance.RevokeAsync(token, Ct));

        // Malformed, unknown, and expired credentials change nothing.
        var expired = (await service.IssueAsync(fixture.Admin, Ct)).Token!;
        Assert.Equal(ManagementBearerRevocationResult.NotActive, await service.RevokeAsync("scm1.not-a-credential", Ct));
        Assert.Equal(ManagementBearerRevocationResult.NotActive, await service.RevokeAsync(ManagementBearerToken.Generate(), Ct));
        Assert.Equal(ManagementBearerRevocationResult.NotActive, await fixture.Service(new ManualTime(Base.AddMinutes(2) + Lifetime)).RevokeAsync(expired, Ct));
        Assert.Single(await fixture.SessionsAsync(), row => row.RevokedAt is not null);

        // Two independent instances racing one revocation: exactly one writes the instant.
        var raced = (await service.IssueAsync(fixture.Admin, Ct)).Token!;
        var results = await Task.WhenAll(
            Task.Run(() => fixture.Service(new ManualTime(Base.AddMinutes(4))).RevokeAsync(raced, Ct), Ct),
            Task.Run(() => fixture.Service(new ManualTime(Base.AddMinutes(5))).RevokeAsync(raced, Ct), Ct));
        Assert.Single(results, r => r == ManagementBearerRevocationResult.Revoked);
        Assert.Single(results, r => r == ManagementBearerRevocationResult.NotActive);
        Assert.Equal(ManagementBearerRejectionReason.Revoked, (await service.ValidateAsync(raced, Ct)).Reason);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task CallerCancellation_WinsAtConnectionQueryCommitAndCleanupBoundaries(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        var time = new ManualTime(Base);
        var token = (await fixture.Service(time).IssueAsync(fixture.Admin, Ct)).Token!;

        // Already canceled: nothing is read or written.
        using (var caller = new CancellationTokenSource())
        {
            caller.Cancel();
            var service = fixture.Service(time);
            await AssertCanceledAsync(caller, () => service.IssueAsync(fixture.Admin, caller.Token));
            await AssertCanceledAsync(caller, () => service.ValidateAsync(token, caller.Token));
            await AssertCanceledAsync(caller, () => service.RevokeAsync(token, caller.Token));
            await AssertCanceledAsync(caller, () => service.CleanupExpiredAsync(Base, caller.Token));
        }

        // While the connection opens.
        using (var caller = new CancellationTokenSource())
        {
            var hook = new Hook { OnOpening = caller.Cancel };
            await AssertCanceledAsync(caller, () => fixture.Service(time, hook: hook).IssueAsync(fixture.Admin, caller.Token));
        }

        // When the lookup query is about to run.
        using (var caller = new CancellationTokenSource())
        {
            var hook = new Hook { OnExecuting = sql => { if (sql.Contains("SELECT", StringComparison.Ordinal)) caller.Cancel(); } };
            await AssertCanceledAsync(caller, () => fixture.Service(time, hook: hook).ValidateAsync(token, caller.Token));
        }

        // After the issuance insert committed: the credential is never returned, the row stays.
        using (var caller = new CancellationTokenSource())
        {
            var hook = new Hook { OnExecuted = sql => { if (sql.Contains("INSERT", StringComparison.Ordinal)) caller.Cancel(); } };
            await AssertCanceledAsync(caller, () => fixture.Service(time, hook: hook).IssueAsync(fixture.Admin, caller.Token));
            Assert.Equal(2, (await fixture.SessionsAsync()).Count);
        }

        // After the revocation update committed: the caller sees cancellation, the revocation holds.
        using (var caller = new CancellationTokenSource())
        {
            var hook = new Hook { OnExecuted = sql => { if (sql.Contains("UPDATE", StringComparison.Ordinal)) caller.Cancel(); } };
            await AssertCanceledAsync(caller, () => fixture.Service(time, hook: hook).RevokeAsync(token, caller.Token));
            Assert.Equal(ManagementBearerRejectionReason.Revoked, (await fixture.Service(time).ValidateAsync(token, Ct)).Reason);
        }

        // At the cleanup delete.
        using (var caller = new CancellationTokenSource())
        {
            var hook = new Hook { OnExecuting = sql => { if (sql.Contains("DELETE", StringComparison.Ordinal)) caller.Cancel(); } };
            await AssertCanceledAsync(caller, () => fixture.Service(time, hook: hook).CleanupExpiredAsync(Base.AddDays(2), caller.Token));
            Assert.Equal(2, (await fixture.SessionsAsync()).Count);
        }
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task UnknownCommitAndStorageFailures_AreUnavailableAfterOneAttempt(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        var time = new ManualTime(Base);
        var logs = new CapturingLogger();

        // The insert really executes, then the provider reports a failure.
        var inserts = 0;
        var failingInsert = new Hook
        {
            OnExecuted = sql =>
            {
                if (!sql.Contains("INSERT", StringComparison.Ordinal)) return;
                Interlocked.Increment(ref inserts);
                throw new InjectedDbException();
            }
        };
        var issued = await fixture.Service(time, hook: failingInsert, logger: logs).IssueAsync(fixture.Admin, Ct);
        Assert.Equal(ManagementBearerIssueStatus.Unavailable, issued.Status);
        Assert.Null(issued.Token);
        Assert.Null(issued.ExpiresAtUtc);
        Assert.Equal(1, inserts);
        Assert.Single(await fixture.SessionsAsync());

        var token = (await fixture.Service(time).IssueAsync(fixture.Admin, Ct)).Token!;
        var failingUpdate = new Hook { OnExecuted = sql => { if (sql.Contains("UPDATE", StringComparison.Ordinal)) throw new InjectedDbException(); } };
        Assert.Equal(ManagementBearerRevocationResult.Unavailable, await fixture.Service(time, hook: failingUpdate, logger: logs).RevokeAsync(token, Ct));
        Assert.Equal(ManagementBearerRejectionReason.Revoked, (await fixture.Service(time).ValidateAsync(token, Ct)).Reason);

        var failingRead = new Hook { OnExecuting = sql => { if (sql.Contains("SELECT", StringComparison.Ordinal)) throw new InjectedDbException(); } };
        Assert.Equal(ManagementBearerValidationStatus.Unavailable, (await fixture.Service(time, hook: failingRead, logger: logs).ValidateAsync(token, Ct)).Status);

        // An unreachable database.
        var unreachable = fixture.UnreachableService(time, logs);
        Assert.Equal(ManagementBearerIssueStatus.Unavailable, (await unreachable.IssueAsync(fixture.Admin, Ct)).Status);
        Assert.Equal(ManagementBearerValidationStatus.Unavailable, (await unreachable.ValidateAsync(token, Ct)).Status);
        Assert.Equal(ManagementBearerRevocationResult.Unavailable, await unreachable.RevokeAsync(token, Ct));
        // Cleanup reports the failure to CleanupWorker, never as a cancellation.
        var cleanupFailure = await Assert.ThrowsAnyAsync<Exception>(() => unreachable.CleanupExpiredAsync(Base, Ct));
        Assert.IsNotAssignableFrom<OperationCanceledException>(cleanupFailure);

        // Logs carry categories and the account id only.
        Assert.NotEmpty(logs.Lines);
        new CanaryScanner(token, token[5..], ManagementBearerToken.ComputeDigest(token), AdminUsername, PasswordHashCanary,
                PostgreSqlPasswordCanary, fixture.ConnectionString, fixture.UnreachableConnectionString, "Injected")
            .AssertClean(logs.Lines);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Issue_NeverSavesUncommittedRequestScopedEntities(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        await using var requestScope = fixture.Context();
        var pending = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = Base, Nickname = "Pending request account" };
        requestScope.Accounts.Add(pending);

        var service = fixture.Service(new ManualTime(Base));
        var token = (await service.IssueAsync(fixture.Admin, Ct)).Token!;
        Assert.Equal(ManagementBearerRevocationResult.Revoked, await service.RevokeAsync(token, Ct));
        await service.CleanupExpiredAsync(Base.AddDays(2), Ct);

        Assert.Equal(EntityState.Added, requestScope.Entry(pending).State);
        await using var read = fixture.Context();
        Assert.False(await read.Accounts.AnyAsync(a => a.Id == pending.Id, Ct));
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Cleanup_DeletesOldestLongExpiredRowsInBoundedBatches(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        var now = BaseMicros;
        var cutoff = now.AddHours(-24);
        await using (var db = fixture.Context())
        {
            for (var i = 0; i < 2500; i++)
            {
                db.ManagementBearerSessions.Add(Row(fixture.Admin, cutoff.AddSeconds(-i)));
            }
            db.ManagementBearerSessions.Add(Row(fixture.Admin, now.AddMinutes(10)));
            db.ManagementBearerSessions.Add(Row(fixture.Admin, now.AddMinutes(-1)));
            db.ManagementBearerSessions.Add(Row(fixture.Admin, cutoff.AddTicks(TimeSpan.TicksPerMicrosecond)));
            await db.SaveChangesAsync(Ct);
        }

        var service = fixture.Service(new ManualTime(now));
        Assert.Equal(1000, await service.CleanupExpiredAsync(Base, Ct));
        var remaining = await fixture.SessionsAsync();
        Assert.Equal(1503, remaining.Count);
        Assert.DoesNotContain(remaining, row => row.ExpiresAt < cutoff.AddSeconds(-1499));
        Assert.Equal(1000, await service.CleanupExpiredAsync(Base, Ct));
        Assert.Equal(500, await service.CleanupExpiredAsync(Base, Ct));
        Assert.Equal(0, await service.CleanupExpiredAsync(Base, Ct));

        remaining = await fixture.SessionsAsync();
        Assert.Equal(3, remaining.Count);
        Assert.All(remaining, row => Assert.True(row.ExpiresAt > cutoff));
    }

    [Fact]
    public void CanaryScanner_FailsOnAPlantedCanary()
    {
        var scanner = new CanaryScanner("planted-canary-value");
        Assert.ThrowsAny<Exception>(() => scanner.AssertClean(["prefix planted-canary-value suffix"]));
        Assert.ThrowsAny<Exception>(() => scanner.AssertClean(["PLANTED-CANARY-VALUE"]));
        scanner.AssertClean(["unrelated"]);
    }

    private static ManagementBearerSessionEntity Row(Guid account, DateTimeOffset expiresAt) => new()
    {
        Id = Guid.NewGuid(),
        TokenDigest = ManagementBearerToken.ComputeDigest(ManagementBearerToken.Generate()),
        AccountId = account,
        CreatedAt = expiresAt - Lifetime,
        ExpiresAt = expiresAt
    };

    private static async Task AssertCanceledAsync(CancellationTokenSource caller, Func<Task> operation)
    {
        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(operation);
        Assert.True(caller.IsCancellationRequested);
        Assert.Equal(caller.Token, exception.CancellationToken);
    }

    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.Ordinal);

    private sealed class ManualTime(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class InjectedDbException() : DbException("Injected failure after the statement executed.");

    /// <summary>Command and connection hooks; the command text never carries parameter values.</summary>
    private sealed class Hook : DbCommandInterceptor, IDbConnectionInterceptor
    {
        public Action? OnOpening { get; init; }
        public Action<string>? OnExecuting { get; init; }
        public Action<string>? OnExecuted { get; init; }

        public ValueTask<InterceptionResult> ConnectionOpeningAsync(DbConnection connection, ConnectionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
        {
            OnOpening?.Invoke();
            return ValueTask.FromResult(result);
        }

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            OnExecuting?.Invoke(command.CommandText);
            return ValueTask.FromResult(result);
        }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            OnExecuting?.Invoke(command.CommandText);
            return ValueTask.FromResult(result);
        }

        public override ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData, DbDataReader result, CancellationToken cancellationToken = default)
        {
            OnExecuted?.Invoke(command.CommandText);
            return ValueTask.FromResult(result);
        }

        public override ValueTask<int> NonQueryExecutedAsync(DbCommand command, CommandExecutedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            OnExecuted?.Invoke(command.CommandText);
            return ValueTask.FromResult(result);
        }
    }

    private sealed class CapturingLogger : ILogger<ManagementBearerSessionService>
    {
        private readonly List<string> _lines = [];

        public IReadOnlyList<string> Lines { get { lock (_lines) return _lines.ToArray(); } }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_lines) _lines.Add($"{logLevel}|{formatter(state, exception)}|{exception}|{state}");
        }
    }

    /// <summary>Fails without printing the matched canary or the scanned text.</summary>
    private sealed class CanaryScanner(params string[] canaries)
    {
        public void AssertClean(IEnumerable<string> values)
        {
            var index = 0;
            foreach (var value in values)
            {
                for (var c = 0; c < canaries.Length; c++)
                {
                    if (value.Contains(canaries[c], StringComparison.OrdinalIgnoreCase))
                    {
                        Assert.Fail($"Scanned value #{index} contains canary #{c}.");
                    }
                }
                index++;
            }
        }
    }

    private sealed class Harness(string provider, DatabaseOptions database, string? path, PostgreSqlContainer? container) : IAsyncDisposable
    {
        public Guid Admin { get; } = Guid.NewGuid();
        public Guid Other { get; } = Guid.NewGuid();
        public Guid Inactive { get; } = Guid.NewGuid();
        public string ConnectionString => database.ConnectionString;

        public string UnreachableConnectionString => provider == "PostgreSQL"
            ? new Npgsql.NpgsqlConnectionStringBuilder(database.ConnectionString) { Port = 1, Timeout = 1 }.ConnectionString
            : $"Data Source={Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}", "bearer.db")};Pooling=false";

        public static async Task<Harness> CreateAsync(string provider)
        {
            PostgreSqlContainer? container = null;
            string? path = null;
            try
            {
                string connection;
                if (provider == "PostgreSQL")
                {
                    Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true", "Enable the PostgreSQL database contract matrix.");
                    container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") ?? "postgres:15-alpine")
                        .WithPassword(PostgreSqlPasswordCanary)
                        .Build();
                    await container.StartAsync(Ct);
                    connection = container.GetConnectionString();
                }
                else
                {
                    path = Path.Combine(Path.GetTempPath(), $"management-bearer-{Guid.NewGuid():N}.db");
                    connection = $"Data Source={path};Pooling=false";
                }
                var harness = new Harness(provider, new DatabaseOptions { Provider = provider, ServerVersion = provider == "PostgreSQL" ? "15" : null, ConnectionString = connection }, path, container);
                await harness.SeedAsync();
                return harness;
            }
            catch { if (container is not null) await container.DisposeAsync(); throw; }
        }

        public ManagementBearerSessionService Service(
            TimeProvider time,
            string adminUsername = AdminUsername,
            Hook? hook = null,
            ILogger<ManagementBearerSessionService>? logger = null) =>
            Create(database, time, adminUsername, hook, logger);

        public ManagementBearerSessionService UnreachableService(TimeProvider time, ILogger<ManagementBearerSessionService> logger) =>
            Create(new DatabaseOptions { Provider = provider, ServerVersion = database.ServerVersion, ConnectionString = UnreachableConnectionString }, time, AdminUsername, null, logger);

        private static ManagementBearerSessionService Create(DatabaseOptions options, TimeProvider time, string adminUsername, Hook? hook, ILogger<ManagementBearerSessionService>? logger) =>
            new(options,
                new AdminIdentityOptions { Username = adminUsername },
                new ManagementBearerSessionRepository(),
                time,
                logger ?? NullLogger<ManagementBearerSessionService>.Instance,
                builder => { if (hook is not null) builder.AddInterceptors(hook); });

        public IdentityDbContext Context()
        {
            var builder = new DbContextOptionsBuilder<IdentityDbContext>();
            builder.UseIdentityDatabase(database, enableRetryOnFailure: false).UseLoggerFactory(NullLoggerFactory.Instance);
            return new IdentityDbContext(builder.Options);
        }

        public async Task<List<ManagementBearerSessionEntity>> SessionsAsync()
        {
            await using var db = Context();
            return await db.ManagementBearerSessions.AsNoTracking().ToListAsync(Ct);
        }

        /// <summary>Every column of every session row, rendered as text.</summary>
        public async Task<List<string>> DumpSessionsAsync()
        {
            await using var db = Context();
            await db.Database.OpenConnectionAsync(Ct);
            await using var command = db.Database.GetDbConnection().CreateCommand();
            command.CommandText = "SELECT * FROM management_bearer_sessions";
            await using var reader = await command.ExecuteReaderAsync(Ct);
            var rows = new List<string>();
            while (await reader.ReadAsync(Ct))
            {
                rows.Add(string.Join('|', Enumerable.Range(0, reader.FieldCount)
                    .Select(i => reader.IsDBNull(i) ? "<null>" : Convert.ToString(reader.GetValue(i), CultureInfo.InvariantCulture))));
            }
            return rows;
        }

        public async Task SetActiveAsync(Guid account, bool active)
        {
            await using var db = Context();
            await db.Accounts.Where(a => a.Id == account).ExecuteUpdateAsync(s => s.SetProperty(a => a.IsActive, active), Ct);
        }

        public async Task DeleteAccountAsync(Guid account)
        {
            await using var db = Context();
            await db.PasswordCredentials.Where(p => p.AccountId == account).ExecuteDeleteAsync(Ct);
            await db.Accounts.Where(a => a.Id == account).ExecuteDeleteAsync(Ct);
        }

        private async Task SeedAsync()
        {
            await using var db = Context();
            await db.Database.MigrateAsync(Ct);
            foreach (var (id, username, active) in new[] { (Admin, AdminUsername, true), (Other, OtherUsername, true), (Inactive, InactiveUsername, false) })
            {
                db.Accounts.Add(new AccountEntity { Id = id, IsActive = active, CreatedAt = Base.AddDays(-1), Nickname = username });
                db.PasswordCredentials.Add(new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = id, Username = username, PasswordHash = PasswordHashCanary, CreatedAt = Base.AddDays(-1) });
            }
            await db.SaveChangesAsync(Ct);
        }

        public async ValueTask DisposeAsync()
        {
            if (container is not null) await container.DisposeAsync();
            if (path is not null) foreach (var file in new[] { path, path + "-wal", path + "-shm" }) File.Delete(file);
        }
    }
}
