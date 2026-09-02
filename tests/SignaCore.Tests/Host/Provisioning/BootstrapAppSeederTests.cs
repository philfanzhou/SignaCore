using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Entity;
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
    private readonly IAuditService _auditService;
    private readonly TrackingPasswordHasher _passwordHasher = new();
    private readonly TestLogger _logger = new();

    public BootstrapAppSeederTests()
    {
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _dbContext = new TestIdentityDbContext(options);
        _auditService = new AuditService(
            new LoginHistoryRepository(_dbContext),
            new AuditLogRepository(_dbContext));
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
        Assert.Single(await _dbContext.AuditLogs.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
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

        var audit = Assert.Single(await _dbContext.AuditLogs.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal("app_created", audit.Action);
        Assert.Equal("AppRegistration", audit.TargetType);
        Assert.Equal(app.AppId, audit.TargetId);
        Assert.Null(audit.ActorId);
        Assert.Equal("bootstrap", audit.ActorName);
        Assert.Contains("Bootstrap pre-seed", audit.Description, StringComparison.Ordinal);
        Assert.Null(audit.ClientIp);
        Assert.Null(audit.CorrelationId);
        Assert.Null(audit.BeforeSnapshot);

        using var snapshot = JsonDocument.Parse(Assert.IsType<string>(audit.AfterSnapshot));
        var after = snapshot.RootElement;
        Assert.Equal(5, after.EnumerateObject().Count());
        Assert.Equal(app.AppId, after.GetProperty("appId").GetString());
        Assert.Equal(app.AppName, after.GetProperty("appName").GetString());
        Assert.Equal(app.CallbackUrl, after.GetProperty("callbackUrl").GetString());
        Assert.Equal(JsonValueKind.Null, after.GetProperty("callbackExpiresAt").ValueKind);
        Assert.True(after.GetProperty("isActive").GetBoolean());

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
        Assert.Empty(await _dbContext.AuditLogs.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
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

        var auditTargets = await _dbContext.AuditLogs.AsNoTracking()
            .OrderBy(audit => audit.TargetId)
            .Select(audit => audit.TargetId)
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(["created-after", "created-before"], auditTargets);

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

    [Fact]
    public async Task CancellationBeforeCommit_IsPropagatedAndDoesNotPersistTheEntry()
    {
        using var cancellationSource = new CancellationTokenSource();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => SeedAsync(
            """
            {
              "Apps": [
                { "appId": "canceled-app", "appSecret": "unused-input", "appName": "Canceled App" }
              ]
            }
            """,
            new CancelingAuditService(cancellationSource),
            cancellationSource.Token));

        Assert.Equal(cancellationSource.Token, _dbContext.LastSaveCancellationToken);
        _dbContext.ChangeTracker.Clear();
        Assert.Empty(await _dbContext.AppRegistrations.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    public void Dispose()
    {
        _dbContext.Dispose();
        GC.SuppressFinalize(this);
    }

    private async Task SeedAsync(
        string json,
        IAuditService? auditService = null,
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
                auditService ?? _auditService,
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
                ChangeTracker.Entries<AuditLogEntity>()
                    .Count(entry => entry.State == EntityState.Added)));
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

    private sealed class SelectiveFailureAuditService : IAuditService
    {
        private readonly IAuditService _inner;
        private readonly string _failingTargetId;

        public SelectiveFailureAuditService(IAuditService inner, string failingTargetId)
        {
            _inner = inner;
            _failingTargetId = failingTargetId;
        }

        public Task RecordLoginAsync(
            Guid? accountId,
            string username,
            string authMethod,
            string eventType,
            string? clientIp,
            string? userAgent,
            string? failureReason = null,
            string? appId = null,
            string? correlationId = null,
            CancellationToken cancellationToken = default) =>
            _inner.RecordLoginAsync(
                accountId,
                username,
                authMethod,
                eventType,
                clientIp,
                userAgent,
                failureReason,
                appId,
                correlationId,
                cancellationToken);

        public Task RecordActionAsync(
            string action,
            string targetType,
            string targetId,
            Guid? actorId,
            string? actorName,
            string? description,
            string? clientIp = null,
            string? correlationId = null,
            object? before = null,
            object? after = null,
            CancellationToken cancellationToken = default)
        {
            if (targetId == _failingTargetId)
            {
                throw new InvalidOperationException("Injected audit staging failure.");
            }

            return _inner.RecordActionAsync(
                action,
                targetType,
                targetId,
                actorId,
                actorName,
                description,
                clientIp,
                correlationId,
                before,
                after,
                cancellationToken);
        }
    }

    private sealed class CancelingAuditService : IAuditService
    {
        private readonly CancellationTokenSource _cancellationSource;

        public CancelingAuditService(CancellationTokenSource cancellationSource)
        {
            _cancellationSource = cancellationSource;
        }

        public Task RecordLoginAsync(
            Guid? accountId,
            string username,
            string authMethod,
            string eventType,
            string? clientIp,
            string? userAgent,
            string? failureReason = null,
            string? appId = null,
            string? correlationId = null,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task RecordActionAsync(
            string action,
            string targetType,
            string targetId,
            Guid? actorId,
            string? actorName,
            string? description,
            string? clientIp = null,
            string? correlationId = null,
            object? before = null,
            object? after = null,
            CancellationToken cancellationToken = default)
        {
            _cancellationSource.Cancel();
            return Task.CompletedTask;
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
