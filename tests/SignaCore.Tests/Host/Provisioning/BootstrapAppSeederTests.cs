using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Entity;
using ServiceMantle.Audit;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Host.Provisioning;
using Xunit;

namespace SignaCore.Tests.Host.Provisioning;

/// <summary>
/// Pins the deployment-facing bootstrap-apps.json contract, per-entry failure isolation, summary
/// diagnostics, and the audit/hash boundaries shared with application creation through the API.
/// </summary>
public class BootstrapAppSeederTests : IDisposable
{
    private readonly TestIdentityDbContext _dbContext;
    private readonly RecordingAuditWriter _auditService;
    private readonly TrackingPasswordHasher _passwordHasher = new();
    private readonly TestLogger _logger = new();

    public BootstrapAppSeederTests()
    {
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _dbContext = new TestIdentityDbContext(options);
        _auditService = new RecordingAuditWriter(
            new EfCoreManagementAuditWriter<IdentityDbContext>(_dbContext));
    }

    [Fact]
    public async Task WithoutTheConfigurationKey_TheDefaultPathIsUsedAndAMissingFileIsNotAnError()
    {
        var configuration = new ConfigurationBuilder().Build();

        await BootstrapAppSeeder.SeedBootstrapAppsAsync(
            configuration,
            _dbContext,
            _auditService,
            _passwordHasher,
            _logger,
            isDevelopment: false);

        Assert.Empty(await _dbContext.AppRegistrations.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Contains(
            _logger.Entries,
            entry => entry.Level == LogLevel.Information &&
                entry.Message.Contains(
                    "/app/data/bootstrap-apps.json",
                    StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnUnparsableFile_DoesNotInterruptStartupAndReportsZeroProcessedEntries()
    {
        await SeedAsync("{ this is not json");

        Assert.Empty(await _dbContext.AppRegistrations.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Contains(
            _logger.Entries,
            entry => entry.Level == LogLevel.Warning &&
                entry.Message.Contains(
                    "Zero entries were processed",
                    StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("\"AppId\": \"\", \"AppSecret\": \"unused-input\"")]
    [InlineData("\"AppId\": \"incomplete-app\", \"AppSecret\": \"\"")]
    public async Task AnEntryWithoutBothCredentialHalves_IsSkipped(string credentials)
    {
        await SeedAsync($$"""
            {
              "Apps": [
                { {{credentials}}, "AppName": "Incomplete" },
                {
                  "appId": "complete-app",
                  "appSecret": "complete-input",
                  "appName": "Complete App",
                  "callbackUrl": "https://claims.example.test/permissions"
                }
              ]
            }
            """);

        var app = Assert.Single(await _dbContext.AppRegistrations.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal("complete-app", app.AppId);
        Assert.Single(_auditService.Events);
    }

    [Fact]
    public async Task AValidEntry_UsesTheHasherAndCommitsTheMatchingAuditWithTheApplication()
    {
        await SeedAsync("""
            {
              "Apps": [
                {
                  "appId": "bootstrap-seeded-app",
                  "appSecret": "verification-input",
                  "appName": "Bootstrap Seeded App",
                  "callbackUrl": "https://claims.example.test/permissions"
                }
              ]
            }
            """);

        var app = Assert.Single(await _dbContext.AppRegistrations.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal("bootstrap-seeded-app", app.AppId);
        Assert.Equal("Bootstrap Seeded App", app.AppName);
        Assert.Equal("https://claims.example.test/permissions", app.CallbackUrl);
        Assert.True(app.IsActive);
        Assert.NotEqual(DateTimeOffset.MinValue, app.CreatedAt);
        Assert.Equal(1, _passwordHasher.HashCalls);
        Assert.True(_passwordHasher.VerifyPassword("verification-input", app.AppSecretHash));

        var audit = Assert.Single(_auditService.Events);
        Assert.Equal("app_created", audit.Action.Value);
        Assert.Equal("appregistration", audit.Target.Type.Value);
        Assert.Equal(app.AppId, audit.Target.Id);
        Assert.Null(audit.Operator.OperatorId);
        Assert.Equal("bootstrap", audit.Operator.DisplayName);
        Assert.Equal("system", audit.Operator.Source.Value);
        Assert.Contains("Bootstrap pre-seed", audit.SecurityDescription, StringComparison.Ordinal);
        Assert.Null(audit.ClientIp);
        Assert.Null(audit.CorrelationId);
        Assert.Equal(ManagementAuditOutcome.Success, audit.Outcome);

        Assert.Contains(
            _dbContext.SaveBatches,
            batch => batch.AddedApplications == 1 && batch.AddedAudits == 1);
        Assert.DoesNotContain(
            _dbContext.SaveBatches,
            batch => batch.AddedApplications > 0 && batch.AddedAudits == 0);

        var logText = string.Join("\n", _logger.Entries.Select(entry => entry.Message));
        Assert.False(logText.Contains("verification-input", StringComparison.Ordinal));
        Assert.False(logText.Contains(app.AppSecretHash, StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnEntryForAnExistingApplication_ChangesNothing()
    {
        _dbContext.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "existing-app",
            AppSecretHash = "existing-hash",
            AppName = "Existing App",
            CallbackUrl = "https://claims.example.test/permissions",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        _dbContext.ChangeTracker.Clear();

        await SeedAsync("""
            {
              "Apps": [
                {
                  "appId": "existing-app",
                  "appSecret": "replacement-input",
                  "appName": "Replacement Name",
                  "callbackUrl": "https://replacement.example.test/permissions"
                }
              ]
            }
            """);

        var app = Assert.Single(await _dbContext.AppRegistrations.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal("Existing App", app.AppName);
        Assert.Equal("existing-hash", app.AppSecretHash);
        Assert.Equal("https://claims.example.test/permissions", app.CallbackUrl);
        Assert.Empty(_auditService.Events);
    }

    [Fact]
    public async Task OneEntryFailure_DoesNotStopLaterEntriesAndProducesOneCompleteSummary()
    {
        _dbContext.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "existing-app",
            AppSecretHash = "existing-hash",
            AppName = "Existing App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        _dbContext.ChangeTracker.Clear();
        _dbContext.ResetSaveBatches();

        await SeedAsync(
            """
            {
              "Apps": [
                { "appId": "created-before", "appSecret": "first-input", "appName": "Created Before" },
                { "appId": "existing-app", "appSecret": "existing-input", "appName": "Existing" },
                { "appId": "invalid-app", "appSecret": "", "appName": "Invalid" },
                { "appId": "failing-app", "appSecret": "failing-input", "appName": "Failing" },
                { "appId": "created-after", "appSecret": "last-input", "appName": "Created After" }
              ]
            }
            """,
            new SelectiveFailureAuditService(_auditService, "failing-app"));

        var appIds = await _dbContext.AppRegistrations.AsNoTracking()
            .OrderBy(app => app.AppId)
            .Select(app => app.AppId)
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(["created-after", "created-before", "existing-app"], appIds);

        Assert.Equal(
            ["created-after", "created-before"],
            _auditService.Events.Select(audit => audit.Target.Id).Order().ToList());

        var summary = Assert.Single(
            _logger.Entries,
            entry => entry.Message.StartsWith(
                "Bootstrap app pre-seeding completed:",
                StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, summary.Level);
        Assert.Contains("created=2", summary.Message, StringComparison.Ordinal);
        Assert.Contains("skipped-existing=1", summary.Message, StringComparison.Ordinal);
        Assert.Contains("skipped-invalid=1", summary.Message, StringComparison.Ordinal);
        Assert.Contains("failed=1", summary.Message, StringComparison.Ordinal);
        Assert.Contains("failing-app (InvalidOperationException)", summary.Message, StringComparison.Ordinal);

        var logText = string.Join("\n", _logger.Entries.Select(entry => entry.Message));
        foreach (var input in new[]
                 {
                     "first-input", "existing-input", "failing-input", "last-input"
                 })
        {
            Assert.False(logText.Contains(input, StringComparison.Ordinal));
        }
        foreach (var hash in _passwordHasher.GeneratedHashes)
        {
            Assert.False(logText.Contains(hash, StringComparison.Ordinal));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuditAndSave_ShareCancellationAndCommitBothOrNeither(bool cancel)
    {
        using var cancellationSource = new CancellationTokenSource();
        var audit = new ObservingAuditService(_auditService, cancellationSource, cancel);
        var operation = () => SeedAsync(
            """
            {
              "Apps": [
                { "appId": "cancellation-app", "appSecret": "unused-input", "appName": "Cancellation App" }
              ]
            }
            """,
            audit,
            cancellationSource.Token);

        if (cancel)
        {
            var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(operation);
            Assert.Equal(cancellationSource.Token, exception.CancellationToken);
        }
        else
            await operation();

        Assert.Equal(cancellationSource.Token, audit.ObservedToken);
        Assert.Equal(cancellationSource.Token, _dbContext.LastSaveCancellationToken);
        var batch = Assert.Single(_dbContext.SaveBatches);
        Assert.Equal(1, batch.AddedApplications);
        Assert.Equal(1, batch.AddedAudits);
        _dbContext.ChangeTracker.Clear();
        Assert.Equal(cancel ? 0 : 1, await _dbContext.AppRegistrations.CountAsync(TestContext.Current.CancellationToken));
        // The audit event is staged in both cases; whether its row persists is decided by the same
        // single save as the application row, which the batch assertion above pins.
        var logs = string.Join("\n", _logger.Entries.Select(entry => entry.Message));
        Assert.False(logs.Contains("unused-input", StringComparison.Ordinal));
        foreach (var hash in _passwordHasher.GeneratedHashes)
            Assert.False(logs.Contains(hash, StringComparison.Ordinal));
    }

    public void Dispose()
    {
        _dbContext.Dispose();
        GC.SuppressFinalize(this);
    }

    private async Task SeedAsync(
        string json,
        IManagementAuditWriter? auditWriter = null,
        CancellationToken cancellationToken = default)
    {
        var path = Path.Combine(Path.GetTempPath(), $"bootstrap-apps-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, json, TestContext.Current.CancellationToken);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["BootstrapApps:FilePath"] = path
                })
                .Build();

            await BootstrapAppSeeder.SeedBootstrapAppsAsync(
                configuration,
                _dbContext,
                auditWriter ?? _auditService,
                _passwordHasher,
                _logger,
                isDevelopment: false,
                cancellationToken: cancellationToken);
            _dbContext.ChangeTracker.Clear();
        }
        finally
        {
            File.Delete(path);
        }
    }

    private sealed class TestIdentityDbContext : IdentityDbContext
    {
        public TestIdentityDbContext(DbContextOptions<IdentityDbContext> options)
            : base(options)
        {
        }

        public List<SaveBatch> SaveBatches { get; } = [];
        public CancellationToken LastSaveCancellationToken { get; private set; }

        public override Task<int> SaveChangesAsync(
            bool acceptAllChangesOnSuccess,
            CancellationToken cancellationToken = default)
        {
            LastSaveCancellationToken = cancellationToken;
            SaveBatches.Add(new SaveBatch(
                ChangeTracker.Entries<AppRegistrationEntity>()
                    .Count(entry => entry.State == EntityState.Added),
                ChangeTracker.Entries()
                    .Count(entry => entry.State == EntityState.Added &&
                        entry.Entity.GetType().Name == "ManagementAuditLogEntity")));
            return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
        }

        public void ResetSaveBatches() => SaveBatches.Clear();
    }

    private sealed record SaveBatch(int AddedApplications, int AddedAudits);

    private sealed class TrackingPasswordHasher : IPasswordHasher
    {
        private readonly BCryptPasswordHasher _inner = new(new PasswordHasherOptions
        {
            WorkFactor = 4
        });

        public int HashCalls { get; private set; }
        public List<string> GeneratedHashes { get; } = [];

        public string HashPassword(string password)
        {
            HashCalls++;
            var hash = _inner.HashPassword(password);
            GeneratedHashes.Add(hash);
            return hash;
        }

        public bool VerifyPassword(string password, string hash) =>
            _inner.VerifyPassword(password, hash);
    }

    private sealed class SelectiveFailureAuditService : IManagementAuditWriter
    {
        private readonly IManagementAuditWriter _inner;
        private readonly string _failingTargetId;

        public SelectiveFailureAuditService(IManagementAuditWriter inner, string failingTargetId)
        {
            _inner = inner;
            _failingTargetId = failingTargetId;
        }

        public ValueTask<ManagementAuditRecord> RecordAsync(
            ManagementAuditEvent auditEvent,
            CancellationToken cancellationToken = default)
        {
            if (auditEvent.Target.Id == _failingTargetId)
            {
                throw new InvalidOperationException("Injected audit staging failure.");
            }

            return _inner.RecordAsync(auditEvent, cancellationToken);
        }
    }

    private sealed class ObservingAuditService(
        IManagementAuditWriter inner, CancellationTokenSource cancellationSource, bool cancel)
        : IManagementAuditWriter
    {
        public CancellationToken ObservedToken { get; private set; }

        public async ValueTask<ManagementAuditRecord> RecordAsync(
            ManagementAuditEvent auditEvent,
            CancellationToken cancellationToken = default)
        {
            ObservedToken = cancellationToken;
            var record = await inner.RecordAsync(auditEvent, cancellationToken);
            if (cancel) await cancellationSource.CancelAsync();
            return record;
        }
    }

    /// <summary>Records every staged event so assertions do not need the internal entity type.</summary>
    private sealed class RecordingAuditWriter(IManagementAuditWriter inner) : IManagementAuditWriter
    {
        public List<ManagementAuditEvent> Events { get; } = [];

        public ValueTask<ManagementAuditRecord> RecordAsync(
            ManagementAuditEvent auditEvent,
            CancellationToken cancellationToken = default)
        {
            Events.Add(auditEvent);
            return inner.RecordAsync(auditEvent, cancellationToken);
        }
    }

    private sealed class TestLogger : ILogger
    {
        public List<LogEntry> Entries { get; } = [];

        public IDisposable BeginScope<TState>(TState state) where TState : notnull =>
            NoopScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add(new LogEntry(logLevel, formatter(state, exception)));
        }
    }

    private sealed record LogEntry(LogLevel Level, string Message);

    private sealed class NoopScope : IDisposable
    {
        public static NoopScope Instance { get; } = new();

        public void Dispose()
        {
        }
    }
}
