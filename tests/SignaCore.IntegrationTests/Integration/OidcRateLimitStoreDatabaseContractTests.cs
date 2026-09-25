using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.RateLimiting;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The PS-24 shared budget store against a real PostgreSQL server: atomic counting across
/// independent connections and store instances, database-clock windows, caller cancellation,
/// single-attempt failure handling, and bounded cleanup. SQLite has no shared store.
/// </summary>
public sealed class OidcRateLimitStoreDatabaseContractTests
{
    private const string Token = "oidc-token";
    private const string Login = "oidc-login";
    private const string RawClient = "client:OrderService-canary";
    private const string RawSource = "ip:203.0.113.77";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly OidcRateLimitPartitioner Partitioner = new(new FixedMasterKeyProvider());
    private static readonly string ClientDigest = Partitioner.Digest(RawClient);
    private static readonly string SourceDigest = Partitioner.Digest(RawSource);

    [Fact]
    public async Task TwoStoreInstances_RacingOneKey_GrantExactlyTheBudgetWithoutCrossTalk()
    {
        await using var fixture = await Harness.CreateAsync();
        await using var first = fixture.Store();
        await using var second = fixture.Store();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var attempts = Enumerable.Range(0, 100).Select(i => Task.Run(async () =>
        {
            await gate.Task.WaitAsync(Ct);
            return await (i % 2 == 0 ? first : second).AcquireAsync(Token, ClientDigest, Ct);
        }, Ct)).ToArray();
        gate.SetResult();
        var results = await Task.WhenAll(attempts);
        Assert.DoesNotContain(OidcRateLimitAcquireResult.Unavailable, results);

        Assert.Equal(90, results.Count(r => r == OidcRateLimitAcquireResult.Granted));
        Assert.Equal(10, results.Count(r => r == OidcRateLimitAcquireResult.Rejected));
        Assert.Equal(90, (await fixture.BucketAsync(Token, ClientDigest))!.PermitCount);

        // Another policy on the same partition and another partition on the same policy each
        // count from their own first permit.
        Assert.Equal(OidcRateLimitAcquireResult.Granted, await first.AcquireAsync(Login, ClientDigest, Ct));
        Assert.Equal(OidcRateLimitAcquireResult.Granted, await second.AcquireAsync(Token, SourceDigest, Ct));
        Assert.Equal(1, (await fixture.BucketAsync(Login, ClientDigest))!.PermitCount);
        Assert.Equal(1, (await fixture.BucketAsync(Token, SourceDigest))!.PermitCount);
        Assert.Equal(90, (await fixture.BucketAsync(Token, ClientDigest))!.PermitCount);
        Assert.Equal(3, await fixture.CountAsync());
    }

    [Fact]
    public async Task Transitions_FollowTheDatabaseClockAndRejectionNeverExtendsTheWindow()
    {
        await using var fixture = await Harness.CreateAsync();
        await using var store = fixture.Store();

        var before = await fixture.DatabaseNowAsync();
        Assert.Equal(OidcRateLimitAcquireResult.Granted, await store.AcquireAsync(Token, ClientDigest, Ct));
        var after = await fixture.DatabaseNowAsync();
        var first = (await fixture.BucketAsync(Token, ClientDigest))!;
        Assert.Equal(1, first.PermitCount);
        Assert.InRange(first.WindowExpiresAt, before.AddSeconds(60), after.AddSeconds(60));

        await fixture.ExecuteAsync($"UPDATE oidc_rate_limit_buckets SET permit_count = 89 WHERE policy = '{Token}'");
        Assert.Equal(OidcRateLimitAcquireResult.Granted, await store.AcquireAsync(Token, ClientDigest, Ct));
        var full = (await fixture.BucketAsync(Token, ClientDigest))!;
        Assert.Equal(90, full.PermitCount);
        Assert.Equal(first.WindowExpiresAt, full.WindowExpiresAt);

        Assert.Equal(OidcRateLimitAcquireResult.Rejected, await store.AcquireAsync(Token, ClientDigest, Ct));
        Assert.Equal(OidcRateLimitAcquireResult.Rejected, await store.AcquireAsync(Token, ClientDigest, Ct));
        var rejected = (await fixture.BucketAsync(Token, ClientDigest))!;
        Assert.Equal(90, rejected.PermitCount);
        Assert.Equal(first.WindowExpiresAt, rejected.WindowExpiresAt);

        // An expired window resets to a fresh one decided by the database clock — the expiry is
        // moved only in the database, the application clock never takes part.
        await fixture.ExecuteAsync("UPDATE oidc_rate_limit_buckets SET window_expires_at = statement_timestamp() - interval '1 millisecond'");
        before = await fixture.DatabaseNowAsync();
        Assert.Equal(OidcRateLimitAcquireResult.Granted, await store.AcquireAsync(Token, ClientDigest, Ct));
        after = await fixture.DatabaseNowAsync();
        var renewed = (await fixture.BucketAsync(Token, ClientDigest))!;
        Assert.Equal(1, renewed.PermitCount);
        Assert.InRange(renewed.WindowExpiresAt, before.AddSeconds(60), after.AddSeconds(60));
    }

    [Fact]
    public async Task InvalidInputs_WriteNothingAndNoRawPartitionIsPersisted()
    {
        await using var fixture = await Harness.CreateAsync();
        await using var store = fixture.Store();
        Assert.Equal(OidcRateLimitAcquireResult.Granted, await store.AcquireAsync(Token, ClientDigest, Ct));
        Assert.Equal(OidcRateLimitAcquireResult.Granted, await store.AcquireAsync(Token, SourceDigest, Ct));

        foreach (var (policy, digest) in new[]
        {
            ("oidc-unknown", ClientDigest), ("OIDC-TOKEN", ClientDigest), (Token, ClientDigest.ToUpperInvariant()),
            (Token, ClientDigest[..63]), (Token, ClientDigest + "0"), (Token, RawClient), (Token, "")
        })
        {
            await Assert.ThrowsAsync<ArgumentException>(() => store.AcquireAsync(policy, digest, Ct));
        }

        var dump = await fixture.DumpAsync();
        Assert.Equal(2, dump.Count);
        Assert.All(dump, row => Assert.True(OidcRateLimitBudgets.IsPartitionDigest(row.Split('|')[1])));
        var scanner = new CanaryScanner(RawClient, "OrderService-canary", RawSource, "203.0.113.77", fixture.Password);
        scanner.AssertClean(dump);
    }

    [Fact]
    public async Task CallerCancellation_WinsBeforeDuringLockWaitAndAfterTheStatement()
    {
        await using var fixture = await Harness.CreateAsync();

        // Before: nothing is written.
        await using (var store = fixture.Store())
        {
            using var caller = new CancellationTokenSource();
            caller.Cancel();
            var canceled = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.AcquireAsync(Token, ClientDigest, caller.Token));
            Assert.Equal(caller.Token, canceled.CancellationToken);
            Assert.Null(await fixture.BucketAsync(Token, ClientDigest));
            Assert.Equal(OidcRateLimitAcquireResult.Granted, await store.AcquireAsync(Token, ClientDigest, Ct));
        }

        // During a row-lock wait: the statement is abandoned and the count is unchanged.
        await using (var store = fixture.Store())
        await using (var holder = await fixture.LockRowAsync(Token, ClientDigest))
        {
            using var caller = new CancellationTokenSource();
            var waiting = store.AcquireAsync(Token, ClientDigest, caller.Token);
            await fixture.WaitForLockWaitAsync();
            caller.Cancel();
            var canceled = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
            Assert.Equal(caller.Token, canceled.CancellationToken);
            await holder.DisposeAsync();
            Assert.Equal(1, (await fixture.BucketAsync(Token, ClientDigest))!.PermitCount);
        }

        // After the statement committed: the caller still sees its cancellation, and the permit
        // stays burned — an unknown outcome never grants, and nothing is refunded.
        using (var caller = new CancellationTokenSource())
        {
            await using var store = fixture.Store(_ => { caller.Cancel(); return ValueTask.CompletedTask; });
            var canceled = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.AcquireAsync(Token, ClientDigest, caller.Token));
            Assert.Equal(caller.Token, canceled.CancellationToken);
            Assert.Equal(2, (await fixture.BucketAsync(Token, ClientDigest))!.PermitCount);
        }
    }

    [Fact]
    public async Task Failures_AreUnavailableAfterOneAttemptAndCarryNothingSensitive()
    {
        await using var fixture = await Harness.CreateAsync();
        await using (var warm = fixture.Store()) Assert.Equal(OidcRateLimitAcquireResult.Granted, await warm.AcquireAsync(Token, ClientDigest, Ct));

        // Lost commit: the statement really executed, then the connection reports a failure.
        var executions = 0;
        await using (var store = fixture.Store(_ =>
        {
            Interlocked.Increment(ref executions);
            throw new NpgsqlException("Injected failure after the budget statement executed.");
        }))
        {
            Assert.Equal(OidcRateLimitAcquireResult.Unavailable, await store.AcquireAsync(Token, ClientDigest, Ct));
            Assert.Equal(1, executions);
            Assert.Equal(2, (await fixture.BucketAsync(Token, ClientDigest))!.PermitCount);
            Assert.Null(await store.DeleteExpiredAsync(Ct));
            Assert.Equal(2, executions);
        }

        // The backend is terminated while the statement waits for the row lock.
        await using (var store = fixture.Store())
        await using (var holder = await fixture.LockRowAsync(Token, ClientDigest))
        {
            var waiting = store.AcquireAsync(Token, ClientDigest, Ct);
            await fixture.WaitForLockWaitAsync();
            await fixture.ExecuteAsync("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()");
            Assert.Equal(OidcRateLimitAcquireResult.Unavailable, await waiting);
            await holder.DisposeAsync();
            Assert.Equal(2, (await fixture.BucketAsync(Token, ClientDigest))!.PermitCount);
        }

        // The internal time budget expires while the row stays locked.
        await using (var store = fixture.Store())
        await using (var holder = await fixture.LockRowAsync(Token, ClientDigest))
        {
            var started = TimeProvider.System.GetTimestamp();
            Assert.Equal(OidcRateLimitAcquireResult.Unavailable, await store.AcquireAsync(Token, ClientDigest, Ct));
            Assert.InRange(TimeProvider.System.GetElapsedTime(started), TimeSpan.FromSeconds(1.5), TimeSpan.FromSeconds(10));
            await holder.DisposeAsync();
            Assert.Equal(2, (await fixture.BucketAsync(Token, ClientDigest))!.PermitCount);
        }

        // An unreachable server.
        await using (var unreachable = new PostgreSqlOidcRateLimitStore(fixture.Unreachable()))
        {
            Assert.Equal(OidcRateLimitAcquireResult.Unavailable, await unreachable.AcquireAsync(Token, ClientDigest, Ct));
            Assert.Null(await unreachable.DeleteExpiredAsync(Ct));
        }

        // The answers are bare enum values: no exception, host, credential or partition travels.
        var scanner = new CanaryScanner(fixture.Password, fixture.Host, "Injected", RawClient, ClientDigest);
        scanner.AssertClean(Enum.GetNames<OidcRateLimitAcquireResult>());
        scanner.AssertClean(await fixture.DumpAsync(), ClientDigest);
    }

    [Fact]
    public async Task Acquisition_NeverSavesUncommittedRequestScopedEntities()
    {
        await using var fixture = await Harness.CreateAsync();
        await using var store = fixture.Store();
        await using var requestScope = fixture.Context();
        var pending = new OidcRateLimitBucketEntity
        {
            Policy = Login, PartitionDigest = SourceDigest, PermitCount = 5,
            WindowExpiresAt = DateTimeOffset.UtcNow.AddMinutes(1)
        };
        requestScope.OidcRateLimitBuckets.Add(pending);
        await requestScope.Database.OpenConnectionAsync(Ct);

        Assert.Equal(OidcRateLimitAcquireResult.Granted, await store.AcquireAsync(Token, ClientDigest, Ct));
        Assert.Equal(OidcRateLimitAcquireResult.Granted, await store.AcquireAsync(Login, ClientDigest, Ct));

        Assert.Equal(EntityState.Added, requestScope.Entry(pending).State);
        Assert.Null(await fixture.BucketAsync(Login, SourceDigest));
        Assert.Equal(2, await fixture.CountAsync());
    }

    [Fact]
    public async Task Cleanup_DeletesBoundedBatchesOfLongExpiredRowsOnly()
    {
        await using var fixture = await Harness.CreateAsync();
        await using var store = fixture.Store();
        await fixture.ExecuteAsync(
            """
            INSERT INTO oidc_rate_limit_buckets (policy, partition_digest, window_expires_at, permit_count)
            SELECT 'oidc-token', lpad(to_hex(n), 64, '0'), statement_timestamp() - interval '25 hours' - n * interval '1 second', 1
            FROM generate_series(1, 2500) AS n
            """);
        await fixture.ExecuteAsync(
            $"""
            INSERT INTO oidc_rate_limit_buckets (policy, partition_digest, window_expires_at, permit_count) VALUES
            ('oidc-login', '{ClientDigest}', statement_timestamp() + interval '30 seconds', 7),
            ('oidc-login', '{SourceDigest}', statement_timestamp() - interval '23 hours 59 minutes', 90)
            """);

        var batches = new List<int?>();
        for (var i = 0; i < 4; i++) batches.Add(await store.DeleteExpiredAsync(Ct));

        Assert.Equal(new int?[] { 1000, 1000, 500, 0 }, batches);
        Assert.Equal(2, await fixture.CountAsync());
        Assert.Equal(7, (await fixture.BucketAsync(Login, ClientDigest))!.PermitCount);
        Assert.Equal(90, (await fixture.BucketAsync(Login, SourceDigest))!.PermitCount);
    }

    [Fact]
    public async Task Cleanup_RacingAWindowRenewal_KeepsTheRenewedRow()
    {
        await using var fixture = await Harness.CreateAsync();
        await using var store = fixture.Store();
        await fixture.ExecuteAsync(
            $"""
            INSERT INTO oidc_rate_limit_buckets (policy, partition_digest, window_expires_at, permit_count)
            VALUES ('oidc-token', '{ClientDigest}', statement_timestamp() - interval '25 hours', 90)
            """);

        // A concurrent acquisition renews the long-expired row and holds its lock while cleanup
        // has already selected it as a victim.
        await using var renewal = await fixture.OpenAsync();
        await using var transaction = await renewal.BeginTransactionAsync(Ct);
        await using (var renew = new NpgsqlCommand(
            "UPDATE oidc_rate_limit_buckets SET permit_count = 1, window_expires_at = statement_timestamp() + interval '60 seconds'",
            renewal, transaction))
        {
            Assert.Equal(1, await renew.ExecuteNonQueryAsync(Ct));
        }

        var cleanup = store.DeleteExpiredAsync(Ct);
        await fixture.WaitForLockWaitAsync();
        await transaction.CommitAsync(Ct);

        Assert.Equal(0, await cleanup);
        var survivor = (await fixture.BucketAsync(Token, ClientDigest))!;
        Assert.Equal(1, survivor.PermitCount);
        Assert.True(survivor.WindowExpiresAt > await fixture.DatabaseNowAsync());
    }

    [Fact]
    public void CanaryScanner_FailsOnAPlantedCanary()
    {
        var scanner = new CanaryScanner("planted-canary-value");
        Assert.ThrowsAny<Exception>(() => scanner.AssertClean(["prefix planted-canary-value suffix"]));
        Assert.ThrowsAny<Exception>(() => scanner.AssertClean(["PLANTED-CANARY-VALUE"]));
        scanner.AssertClean(["unrelated"]);
    }

    private sealed class FixedMasterKeyProvider : IMasterKeyProvider
    {
        public byte[] GetMasterKey() => Enumerable.Repeat((byte)0x5C, 32).ToArray();
    }

    /// <summary>Fails without printing the matched canary or the scanned text.</summary>
    private sealed class CanaryScanner(params string[] canaries)
    {
        public void AssertClean(IEnumerable<string> values, params string[] allowed)
        {
            var index = 0;
            foreach (var value in values)
            {
                for (var c = 0; c < canaries.Length; c++)
                {
                    if (allowed.Contains(canaries[c], StringComparer.Ordinal)) continue;
                    if (value.Contains(canaries[c], StringComparison.OrdinalIgnoreCase))
                    {
                        Assert.Fail($"Scanned value #{index} contains canary #{c}.");
                    }
                }
                index++;
            }
        }
    }

    private sealed class Harness(DatabaseOptions database, PostgreSqlContainer container) : IAsyncDisposable
    {
        public string Password { get; } = new NpgsqlConnectionStringBuilder(database.ConnectionString).Password!;
        public string Host { get; } = new NpgsqlConnectionStringBuilder(database.ConnectionString).Host!;

        public static async Task<Harness> CreateAsync()
        {
            Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true", "Enable the PostgreSQL database contract matrix.");
            var container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") ?? "postgres:15-alpine").Build();
            try
            {
                await container.StartAsync(Ct);
                var harness = new Harness(new DatabaseOptions { Provider = "PostgreSQL", ServerVersion = "15", ConnectionString = container.GetConnectionString() }, container);
                await using var db = harness.Context();
                await db.Database.MigrateAsync(Ct);
                return harness;
            }
            catch { await container.DisposeAsync(); throw; }
        }

        // Each store models one instance with a bounded pool, so a 100-caller race waits for
        // pooled connections instead of exceeding the server's default max_connections of 100.
        public PostgreSqlOidcRateLimitStore Store(Func<CancellationToken, ValueTask>? afterStatement = null) => new(new DatabaseOptions
        {
            Provider = "PostgreSQL", ServerVersion = "15",
            ConnectionString = new NpgsqlConnectionStringBuilder(database.ConnectionString) { MaxPoolSize = 25 }.ConnectionString
        }, afterStatement);

        public DatabaseOptions Unreachable() => new()
        {
            Provider = "PostgreSQL", ServerVersion = "15",
            ConnectionString = new NpgsqlConnectionStringBuilder(database.ConnectionString) { Port = 1, Timeout = 1 }.ConnectionString
        };

        public IdentityDbContext Context()
        {
            var builder = new DbContextOptionsBuilder<IdentityDbContext>();
            builder.UseIdentityDatabase(database, enableRetryOnFailure: false).UseLoggerFactory(NullLoggerFactory.Instance);
            return new IdentityDbContext(builder.Options);
        }

        public async Task<NpgsqlConnection> OpenAsync()
        {
            var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(database.ConnectionString) { Pooling = false }.ConnectionString);
            await connection.OpenAsync(Ct);
            return connection;
        }

        public async Task ExecuteAsync(string sql)
        {
            await using var connection = await OpenAsync();
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(Ct);
        }

        public async Task<DateTimeOffset> DatabaseNowAsync()
        {
            await using var connection = await OpenAsync();
            await using var command = new NpgsqlCommand("SELECT statement_timestamp()", connection);
            return new DateTimeOffset((DateTime)(await command.ExecuteScalarAsync(Ct))!, TimeSpan.Zero);
        }

        public async Task<int> CountAsync()
        {
            await using var connection = await OpenAsync();
            await using var command = new NpgsqlCommand("SELECT count(*) FROM oidc_rate_limit_buckets", connection);
            return Convert.ToInt32(await command.ExecuteScalarAsync(Ct), CultureInfo.InvariantCulture);
        }

        public async Task<OidcRateLimitBucketEntity?> BucketAsync(string policy, string digest)
        {
            await using var db = Context();
            return await db.OidcRateLimitBuckets.AsNoTracking()
                .SingleOrDefaultAsync(x => x.Policy == policy && x.PartitionDigest == digest, Ct);
        }

        public async Task<List<string>> DumpAsync()
        {
            await using var connection = await OpenAsync();
            await using var command = new NpgsqlCommand("SELECT policy, partition_digest, window_expires_at::text, permit_count::text FROM oidc_rate_limit_buckets", connection);
            await using var reader = await command.ExecuteReaderAsync(Ct);
            var rows = new List<string>();
            while (await reader.ReadAsync(Ct)) rows.Add(string.Join('|', reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)));
            return rows;
        }

        /// <summary>Holds the row lock of one bucket in an open transaction until disposed.</summary>
        public async Task<IAsyncDisposable> LockRowAsync(string policy, string digest)
        {
            var connection = await OpenAsync();
            var transaction = await connection.BeginTransactionAsync(Ct);
            await using (var command = new NpgsqlCommand("SELECT 1 FROM oidc_rate_limit_buckets WHERE policy = @p AND partition_digest = @d FOR UPDATE", connection, transaction))
            {
                command.Parameters.AddWithValue("p", policy);
                command.Parameters.AddWithValue("d", digest);
                Assert.NotNull(await command.ExecuteScalarAsync(Ct));
            }
            return new RowLock(connection, transaction);
        }

        /// <summary>Waits until another session is blocked on a row lock.</summary>
        public async Task WaitForLockWaitAsync()
        {
            var deadline = TimeProvider.System.GetTimestamp();
            while (TimeProvider.System.GetElapsedTime(deadline) < TimeSpan.FromSeconds(10))
            {
                await using var connection = await OpenAsync();
                await using var command = new NpgsqlCommand("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()", connection);
                if (Convert.ToInt32(await command.ExecuteScalarAsync(Ct), CultureInfo.InvariantCulture) > 0) return;
                await Task.Delay(20, Ct);
            }
            Assert.Fail("No session started waiting for the row lock.");
        }

        public ValueTask DisposeAsync() => container.DisposeAsync();

        private sealed class RowLock(NpgsqlConnection connection, NpgsqlTransaction transaction) : IAsyncDisposable
        {
            private bool _disposed;

            public async ValueTask DisposeAsync()
            {
                if (_disposed) return;
                _disposed = true;
                await transaction.DisposeAsync();
                await connection.DisposeAsync();
            }
        }
    }
}
