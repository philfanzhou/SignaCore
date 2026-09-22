using System.Collections.Concurrent;
using System.Data.Common;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Npgsql;
using ServiceMantle.Audit;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Host.Services;
using Testcontainers.PostgreSql;
using Xunit;

using SignaCore.Tests.Integration;

namespace SignaCore.IntegrationTests.Integration;

public sealed class LogoutPreparationDatabaseContractTests
{
    private const string Issuer = "https://logout-contract.test";
    private const string Client = "logout-contract";
    private const string Redirect = "https://bff.contract.test/logout-canary";
    private const string State = "logout-state-canary-345";
    private const string Canary = "logout-dependency-canary-345";

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Prepare_EveryBoundaryHonorsOriginalCancellationAndPairsPersistedFacts(string provider)
    {
        await using var harness = await Harness.Create(provider);
        foreach (var boundary in new[] { "refresh", "keys", "uri", "stage", "audit", "save-before", "save", "cleanup" })
        foreach (var cancelled in new[] { false, true })
        foreach (var outcome in new[] { "return", "throw", "internal-cancel" })
        {
            if (!cancelled && outcome == "return") continue;
            await harness.Clear();
            using var caller = new CancellationTokenSource();
            harness.Fault.Configure(boundary, outcome, cancelled ? caller : null);
            var operation = harness.Prepare(caller.Token);
            if (cancelled)
            {
                var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);
                Assert.Equal(caller.Token, error.CancellationToken);
            }
            else Assert.Null(await operation);
            Assert.True(harness.Fault.Observed);
            Assert.DoesNotContain(harness.Log.Entries, entry => entry.Contains("Logout request prepared", StringComparison.Ordinal));
            var committed = boundary is "save" or "cleanup";
            await harness.AssertPairs(committed ? 1 : 0);
            Assert.InRange(harness.Fault.StageCalls, 0, 1);
            Assert.InRange(harness.Fault.SaveCalls, 0, 1);
            Assert.All(harness.Log.Entries, entry => Assert.False(entry.Contains(Canary, StringComparison.Ordinal)));
        }
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Prepare_ActualInsertAndPrecommitFailuresRollbackExecutedSql(string provider)
    {
        await using var harness = await Harness.Create(provider);
        foreach (var target in new[] { "service_audit_logs", "logout_requests", "precommit", "precommit-cancel" })
        {
            await harness.Clear();
            using var caller = new CancellationTokenSource();
            if (target.StartsWith("precommit", StringComparison.Ordinal))
                harness.Fault.Configure("commit-before", target == "precommit" ? "throw" : "return", target == "precommit-cancel" ? caller : null);
            else
            {
                await using var context = harness.Context();
                var sql = provider == "SQLite"
                    ? $"CREATE TRIGGER fail_insert BEFORE INSERT ON {target} BEGIN SELECT RAISE(ABORT, '{Canary}'); END"
                    : $"CREATE OR REPLACE FUNCTION fail_insert_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION '{Canary}'; END $$; CREATE TRIGGER fail_insert BEFORE INSERT ON {target} FOR EACH ROW EXECUTE FUNCTION fail_insert_fn()";
                await context.Database.ExecuteSqlRawAsync(sql, TestContext.Current.CancellationToken);
            }
            if (target == "precommit-cancel")
            {
                var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => harness.Prepare(caller.Token));
                Assert.Equal(caller.Token, error.CancellationToken);
            }
            else Assert.Null(await harness.Prepare(TestContext.Current.CancellationToken));
            Assert.True(harness.Fault.Transactions > 0);
            if (target.StartsWith("precommit", StringComparison.Ordinal))
            {
                Assert.True(harness.Fault.InsertCommands > 0);
                Assert.True(harness.Fault.Observed);
            }
            await harness.AssertPairs(0);
            // A completely new successful operation cannot flush the failed graph from its scope.
            harness.Fault.Configure("", "return", null);
            if (target is "service_audit_logs" or "logout_requests")
            {
                await using var context = harness.Context();
                await context.Database.ExecuteSqlRawAsync(provider == "SQLite" ? "DROP TRIGGER fail_insert" : $"DROP TRIGGER fail_insert ON {target}", TestContext.Current.CancellationToken);
            }
            Assert.NotNull(await harness.Prepare(TestContext.Current.CancellationToken));
            await harness.AssertPairs(1);
            Assert.All(harness.Log.Entries, entry => Assert.False(entry.Contains(Canary, StringComparison.Ordinal)));
        }
    }

    [Fact]
    public async Task Prepare_PostgreSqlTransientRetryAndLostCommitReuseTheSameEntityGraph()
    {
        await using var harness = await Harness.Create("PostgreSQL");
        foreach (var fault in new[] { "transient-insert", "lost-commit" })
        {
            await harness.Clear();
            harness.Fault.Configure(fault, "return", null);
            var result = await harness.Prepare(TestContext.Current.CancellationToken);
            Assert.True(harness.Fault.Observed);
            Assert.True(harness.Fault.Transactions >= 2);
            Assert.Equal(1, harness.Fault.StageCalls);
            Assert.Equal(1, harness.Fault.AuditCalls);
            Assert.Equal(1, harness.Fault.SaveCalls);
            Assert.Single(harness.Fault.RequestIds);
            Assert.Single(harness.Fault.AuditIds);
            if (fault == "transient-insert") Assert.NotNull(result);
            else Assert.Null(result);
            await harness.AssertPairs(1);
        }
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Prepare_ConcurrentCallsHaveIndependentHandlesAndNoRequestScopeWrites(string provider)
    {
        await using var harness = await Harness.Create(provider);
        using var outerScope = harness.Services.CreateScope();
        var unrelated = outerScope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        await new EfCoreManagementAuditWriter<IdentityDbContext>(unrelated).RecordAsync(
            ManagementAuditEvent.Create(
                ManagementAuditOperator.Create(WellKnownManagementAuditOperatorSources.System),
                ManagementAuditAction.Parse("unrelated"),
                ManagementAuditTarget.Create(ManagementAuditTargetType.Parse("other"), "other")));
        foreach (var mixed in new[] { false, true })
        {
            await harness.Clear();
            harness.Fault.Configure(mixed ? "one-stage" : "", "return", null);
            var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => Task.Run(() => harness.Prepare(TestContext.Current.CancellationToken))));
            Assert.Equal(mixed ? 3 : 4, results.Count(result => result is not null));
            Assert.Equal(mixed ? 3 : 4, results.Where(result => result is not null).Select(result => result!.LogoutUri).Distinct(StringComparer.Ordinal).Count());
            await harness.AssertPairs(mixed ? 3 : 4);
            Assert.True(unrelated.ChangeTracker.HasChanges());
            foreach (var result in results.Where(result => result is not null))
            {
                var handle = result!.LogoutUri.Split('=')[1];
                Assert.All(harness.Log.Entries, entry => Assert.False(entry.Contains(handle, StringComparison.Ordinal)));
            }
        }
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly string? path;
        private readonly PostgreSqlContainer? container;
        private readonly DbContextOptions<IdentityDbContext> options;
        public ServiceProvider Services { get; }
        public FaultPlan Fault { get; } = new();
        public CaptureLog Log { get; } = new();
        private readonly Keys keys;
        private readonly OidcLogoutPreparationService service;
        private AppRegistrationEntity app = null!;
        private string hint = "";

        private Harness(string? path, PostgreSqlContainer? container, DatabaseOptions database)
        {
            this.path = path; this.container = container;
            options = new DbContextOptionsBuilder<IdentityDbContext>().UseIdentityDatabase(database)
                .UseLoggerFactory(NullLoggerFactory.Instance).Options as DbContextOptions<IdentityDbContext>
                ?? throw new InvalidOperationException("Typed options required.");
            var services = new ServiceCollection();
            services.AddScoped(_ => new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>(options)
                .AddInterceptors(new SqlProbe(Fault), new TransactionProbe(Fault)).Options));
            services.AddScoped<ILogoutRequestStore>(provider =>
            {
                var context = provider.GetRequiredService<IdentityDbContext>();
                var real = new LogoutRequestStore(new LogoutRequestRepository(context), new EfCoreUnitOfWork(context));
                var mock = new Mock<ILogoutRequestStore>(MockBehavior.Strict);
                mock.Setup(store => store.StageCreateAsync(It.IsAny<LogoutRequestDescriptor>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
                    .Returns(async (LogoutRequestDescriptor descriptor, DateTimeOffset now, CancellationToken token) =>
                    {
                        Interlocked.Increment(ref Fault.StageCalls);
                        var result = await real.StageCreateAsync(descriptor, now, token);
                        Fault.RequestIds.TryAdd(result.Id, 0);
                        Fault.Complete("stage");
                        return result;
                    });
                return mock.Object;
            });
            services.AddScoped<IManagementAuditWriter>(provider =>
            {
                var context = provider.GetRequiredService<IdentityDbContext>();
                var real = new EfCoreManagementAuditWriter<IdentityDbContext>(context);
                return new FaultedAuditWriter(real, Fault);
            });
            services.AddScoped<IUnitOfWork>(provider => new ObservedSave(provider.GetRequiredService<IdentityDbContext>(), Fault));
            Services = services.BuildServiceProvider();
            keys = new Keys(Fault);
            service = new OidcLogoutPreparationService(new ScopeFactory(Services.GetRequiredService<IServiceScopeFactory>(), Fault),
                keys, new JwtOptions { Issuer = Issuer }, Log);
        }

        public static async Task<Harness> Create(string provider)
        {
            PostgreSqlContainer? container = null;
            string? path = null;
            string connection;
            if (provider == "PostgreSQL")
            {
                Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true", "Enable the PostgreSQL database contract matrix.");
                container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") ?? "postgres:15-alpine").Build();
                await container.StartAsync(TestContext.Current.CancellationToken);
                connection = container.GetConnectionString();
            }
            else { path = Path.Combine(Path.GetTempPath(), $"logout-atomic-{Guid.NewGuid():N}.db"); connection = $"Data Source={path};Pooling=false"; }
            var harness = new Harness(path, container, new DatabaseOptions { Provider = provider, ServerVersion = provider == "PostgreSQL" ? "15.0" : null, ConnectionString = connection });
            await using var context = harness.Context();
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
            Assert.False(context.Database.HasPendingModelChanges());
            Assert.Equal(provider == "PostgreSQL", context.Database.CreateExecutionStrategy().RetriesOnFailure);
            harness.app = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = Client, AppName = "Logout contract", AppSecretHash = "synthetic-hash", IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
            context.AppRegistrations.Add(harness.app);
            context.AppRedirectUris.Add(new AppRedirectUriEntity { Id = Guid.NewGuid(), AppRegistrationId = harness.app.Id, Kind = RedirectUriKind.PostLogout, CanonicalUri = Redirect });
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
            harness.hint = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(new JwtHeader(new SigningCredentials(harness.keys.GetCurrentKey(), "RS256")),
                new JwtPayload(Issuer, Client, [new Claim("sub", Guid.NewGuid().ToString("D")), new Claim("sid", Guid.NewGuid().ToString("D"))], null, null, DateTime.UtcNow.AddMinutes(-1))));
            return harness;
        }

        public IdentityDbContext Context() => new(options);
        public Task<OidcLogoutPreparationSuccess?> Prepare(CancellationToken token) => service.PrepareAsync(app,
            new Dictionary<string, string> { ["id_token_hint"] = hint, ["post_logout_redirect_uri"] = Redirect, ["state"] = State }, null, null, token);
        public async Task Clear()
        {
            Fault.Configure("", "return", null); Log.Entries.Clear();
            await using var context = Context();
            await context.LogoutRequests.ExecuteDeleteAsync(TestContext.Current.CancellationToken);
            await context.Database.ExecuteSqlRawAsync("DELETE FROM service_audit_logs", TestContext.Current.CancellationToken);
        }
        public async Task AssertPairs(int count)
        {
            await using var context = Context();
            var requests = await context.LogoutRequests.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken);
            var audits = (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(context, TestContext.Current.CancellationToken))
                .Where(audit => audit.Action == "oidc.logout.prepared")
                .ToList();
            Assert.Equal(count, requests.Count); Assert.Equal(count, audits.Count);
            foreach (var request in requests)
            {
                var audit = Assert.Single(audits, audit => audit.TargetId == request.Id.ToString("D"));
                Assert.Equal("oidc.logout.prepared", audit.Action); Assert.Equal("logoutrequest", audit.TargetType);
            }
            var dump = JsonSerializer.Serialize(audits) + string.Join("\n", Log.Entries);
            foreach (var secret in new[] { hint, Redirect, State, Canary }) Assert.False(dump.Contains(secret, StringComparison.Ordinal));
        }
        public async ValueTask DisposeAsync()
        {
            await Services.DisposeAsync(); keys.Dispose();
            if (container is not null) await container.DisposeAsync();
            if (path is not null) { File.Delete(path); File.Delete(path + "-wal"); File.Delete(path + "-shm"); }
        }
    }

    private sealed class FaultPlan
    {
        public string Boundary = "", Outcome = "return";
        private CancellationTokenSource? caller;
        public bool Observed;
        public int StageCalls, AuditCalls, SaveCalls, Transactions, InsertCommands;
        private int stagedAttempts;
        public ConcurrentDictionary<Guid, byte> RequestIds { get; } = new();
        public ConcurrentDictionary<Guid, byte> AuditIds { get; } = new();
        public void Configure(string boundary, string outcome, CancellationTokenSource? cancellation)
        {
            Boundary = boundary; Outcome = outcome; caller = cancellation; Observed = false;
            StageCalls = AuditCalls = SaveCalls = Transactions = InsertCommands = stagedAttempts = 0;
            RequestIds.Clear(); AuditIds.Clear();
        }
        public void Complete(string boundary)
        {
            if (Boundary == "one-stage" && boundary == "stage")
            {
                if (Interlocked.Increment(ref stagedAttempts) == 1) throw new InvalidOperationException(Canary);
                return;
            }
            if (Boundary != boundary) return;
            Observed = true;
            caller?.Cancel();
            if (Outcome == "throw") throw new InvalidOperationException(Canary, new Exception(Canary));
            if (Outcome == "internal-cancel") throw new OperationCanceledException(Canary, new CancellationToken(true));
        }
    }

    private sealed class SqlProbe(FaultPlan fault) : DbCommandInterceptor
    {
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("INSERT INTO", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref fault.InsertCommands);
                if (fault.Boundary == "transient-insert" && !fault.Observed)
                {
                    fault.Observed = true;
                    throw new NpgsqlException(Canary, new IOException(Canary));
                }
            }
            return ValueTask.FromResult(result);
        }
        public override ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData, DbDataReader result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("app_redirect_uris", StringComparison.Ordinal)) fault.Complete("uri");
            return ValueTask.FromResult(result);
        }
    }

    private sealed class TransactionProbe(FaultPlan fault) : DbTransactionInterceptor
    {
        public override ValueTask<DbTransaction> TransactionStartedAsync(DbConnection connection, TransactionEndEventData eventData, DbTransaction result, CancellationToken cancellationToken = default)
        { Interlocked.Increment(ref fault.Transactions); return ValueTask.FromResult(result); }
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction, TransactionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
        {
            fault.Complete("commit-before");
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(result);
        }
        public override Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
        {
            if (fault.Boundary == "lost-commit" && !fault.Observed)
            {
                fault.Observed = true;
                throw new NpgsqlException(Canary, new IOException(Canary));
            }
            return Task.CompletedTask;
        }
    }

    private sealed class ObservedSave(IdentityDbContext context, FaultPlan fault) : IUnitOfWork
    {
        public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref fault.SaveCalls);
            fault.Complete("save-before");
            cancellationToken.ThrowIfCancellationRequested();
            var result = await context.SaveChangesAsync(cancellationToken);
            fault.Complete("save");
            return result;
        }
    }

    private sealed class ScopeFactory(IServiceScopeFactory inner, FaultPlan fault) : IServiceScopeFactory
    {
        public IServiceScope CreateScope() => new Scope(inner.CreateScope(), fault);
        private sealed class Scope(IServiceScope inner, FaultPlan fault) : IServiceScope, IAsyncDisposable
        {
            public IServiceProvider ServiceProvider => inner.ServiceProvider;
            public void Dispose() => inner.Dispose();
            public async ValueTask DisposeAsync()
            { await ((IAsyncDisposable)inner).DisposeAsync(); fault.Complete("cleanup"); }
        }
    }

    private sealed class Keys(FaultPlan fault) : IKeyManager, IDisposable
    {
        private readonly RSA rsa = RSA.Create(2048);
        private RsaSecurityKey Key => new(rsa) { KeyId = "logout-contract-key" };
        public RsaSecurityKey GetCurrentKey() => Key;
        public IReadOnlyList<SecurityKey> GetValidationKeys() => [Key];
        public Task RefreshKeysAsync(CancellationToken cancellationToken = default) { fault.Complete("refresh"); return Task.CompletedTask; }
        public Task<IReadOnlyList<RsaSecurityKey>> GetLogoutHintValidationKeysAsync(CancellationToken cancellationToken = default) { fault.Complete("keys"); return Task.FromResult<IReadOnlyList<RsaSecurityKey>>([Key]); }
        public Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<RsaSecurityKey>>([Key]);
        public Task<bool> NeedsKeyRotationAsync(CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task RotateKeyAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task InitializationCompleted => Task.CompletedTask;
        public void Dispose() => rsa.Dispose();
    }

    private sealed class CaptureLog : ILogger<OidcLogoutPreparationService>
    {
        public ConcurrentQueue<string> Entries { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => Entries.Enqueue(formatter(state, exception) + exception);
    }

    /// <summary>
    /// Counts each staged shared event, delegates to the real writer, records the staged row's id,
    /// and reports the fault boundary.
    /// </summary>
    private sealed class FaultedAuditWriter(
        EfCoreManagementAuditWriter<IdentityDbContext> inner, FaultPlan fault) : IManagementAuditWriter
    {
        public async ValueTask<ManagementAuditRecord> RecordAsync(
            ManagementAuditEvent auditEvent,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref fault.AuditCalls);
            var record = await inner.RecordAsync(auditEvent, cancellationToken);
            fault.AuditIds.TryAdd(record.Id, 0);
            fault.Complete("audit");
            return record;
        }
    }
}
