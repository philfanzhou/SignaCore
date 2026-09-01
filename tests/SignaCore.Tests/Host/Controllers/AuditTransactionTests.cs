using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Sms;
using SignaCore.Host;
using SignaCore.Host.Controllers;
using SignaCore.Host.Http;
using SignaCore.Host.Models;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

public sealed class AuditTransactionTests
{
    [Fact]
    public async Task CreateApp_WhenAuditInsertFails_RollsBackApplicationAndReturnsFailure()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await database.Context.Database.ExecuteSqlRawAsync(
            """
            CREATE TRIGGER fail_audit_insert
            BEFORE INSERT ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit insert failed');
            END;
            """,
            TestContext.Current.CancellationToken);

        var controller = CreateAdminController();

        await Assert.ThrowsAsync<DbUpdateException>(() => controller.CreateApp(
            new AdminCreateAppRequest("Atomic app", null, 0),
            new AppRegistrationRepository(database.Context),
            new CallbackUrlValidator(),
            new EfCoreUnitOfWork(database.Context),
            CreateAuditService(database.Context),
            TestContext.Current.CancellationToken));

        database.Context.ChangeTracker.Clear();
        Assert.False(await database.Context.AppRegistrations.AnyAsync(TestContext.Current.CancellationToken));
        Assert.False(await database.Context.AuditLogs.AnyAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CreateApp_WhenBusinessInsertFails_RollsBackAuditAndReturnsFailure()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        await database.Context.Database.ExecuteSqlRawAsync(
            """
            CREATE TRIGGER fail_application_insert
            BEFORE INSERT ON app_registrations
            BEGIN
                SELECT RAISE(ABORT, 'application insert failed');
            END;
            """,
            TestContext.Current.CancellationToken);

        var controller = CreateAdminController();

        await Assert.ThrowsAsync<DbUpdateException>(() => controller.CreateApp(
            new AdminCreateAppRequest("Atomic app", null, 0),
            new AppRegistrationRepository(database.Context),
            new CallbackUrlValidator(),
            new EfCoreUnitOfWork(database.Context),
            CreateAuditService(database.Context),
            TestContext.Current.CancellationToken));

        database.Context.ChangeTracker.Clear();
        Assert.False(await database.Context.AppRegistrations.AnyAsync(TestContext.Current.CancellationToken));
        Assert.False(await database.Context.AuditLogs.AnyAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SmsCodeWithoutBusinessState_ExplicitlyPersistsEveryLoginHistoryField()
    {
        await using var database = await SqliteTestDatabase.CreateAsync();
        var otpService = new Mock<IOtpService>();
        otpService.Setup(service => service.GenerateAndSendAsync(
                It.IsAny<Guid>(), "+8613800138000", "primary", It.IsAny<CancellationToken>()))
            .ReturnsAsync(string.Empty);

        var controller = new SmsCodeController(
            otpService.Object,
            new Mock<ISmsAdmissionService>().Object,
            CreateAuditService(database.Context),
            new EfCoreUnitOfWork(database.Context),
            NullLogger<SmsCodeController>.Instance);
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "sms-app",
            AppName = "SMS app",
            AppSecretHash = "not-used",
            IsActive = true,
            SmsLoginMode = SmsLoginMode.AutoProvision,
            SmsProfileKey = "primary",
            CreatedAt = DateTimeOffset.UtcNow
        };
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.10");
        httpContext.Request.Headers.UserAgent = "audit-test-agent";
        httpContext.Items[IdentityHeaders.ValidatedApp] = app;
        httpContext.Items[CorrelationIdMiddleware.HttpContextItemsKey] = "correlation-148";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        var action = await controller.RequestSmsCode(
            new SmsCodeRequest { Phone = "13800138000" },
            TestContext.Current.CancellationToken);

        Assert.True(Assert.IsType<SmsCodeResponse>(Assert.IsType<OkObjectResult>(action.Result).Value).Success);
        database.Context.ChangeTracker.Clear();
        var entry = await database.Context.LoginHistories.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Null(entry.AccountId);
        Assert.Equal("+8613800138000", entry.Username);
        Assert.Equal(IdentityConstants.GrantTypeSms, entry.AuthMethod);
        Assert.Equal("sms_code_sent", entry.EventType);
        Assert.Equal("192.0.2.10", entry.ClientIp);
        Assert.Equal("audit-test-agent", entry.UserAgent);
        Assert.Null(entry.FailureReason);
        Assert.Equal("sms-app", entry.AppId);
        Assert.Equal("correlation-148", entry.CorrelationId);
    }

    [Fact]
    public async Task RemoveExchangeTrust_WhenConcurrentDeleteLoses_ReturnsNotFoundWithoutAudit()
    {
        await using var database = await SharedSqliteTestDatabase.CreateAsync();
        var acceptingApp = CreateApp("accepting-app");
        var sourceApp = CreateApp("source-app");
        await using (var seedContext = database.CreateContext())
        {
            seedContext.AppRegistrations.AddRange(acceptingApp, sourceApp);
            seedContext.AppExchangeTrusts.Add(new AppExchangeTrustEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = acceptingApp.Id,
                SourceAppRegistrationId = sourceApp.Id,
                CreatedAt = DateTimeOffset.UtcNow
            });
            await seedContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await using var firstContext = database.CreateContext();
        await using var secondContext = database.CreateContext();
        var bothDeletesStaged = new AsyncBarrier(participantCount: 2);
        var firstSaveCompleted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var firstTask = CreateAdminController().RemoveExchangeTrust(
            acceptingApp.AppId,
            sourceApp.AppId,
            new AppRegistrationRepository(firstContext),
            new CoordinatedExchangeTrustRepository(firstContext, bothDeletesStaged),
            CreateAuditService(firstContext),
            new OrderedUnitOfWork(firstContext, Task.CompletedTask, firstSaveCompleted),
            firstContext,
            TestContext.Current.CancellationToken);
        var secondTask = CreateAdminController().RemoveExchangeTrust(
            acceptingApp.AppId,
            sourceApp.AppId,
            new AppRegistrationRepository(secondContext),
            new CoordinatedExchangeTrustRepository(secondContext, bothDeletesStaged),
            CreateAuditService(secondContext),
            new OrderedUnitOfWork(secondContext, firstSaveCompleted.Task),
            secondContext,
            TestContext.Current.CancellationToken);

        var results = await Task.WhenAll(firstTask, secondTask);

        Assert.IsType<OkObjectResult>(results[0]);
        Assert.IsType<NotFoundObjectResult>(results[1]);
        Assert.Empty(secondContext.ChangeTracker.Entries());

        await using var verificationContext = database.CreateContext();
        Assert.False(await verificationContext.AppExchangeTrusts
            .AnyAsync(TestContext.Current.CancellationToken));
        var audit = await verificationContext.AuditLogs
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal("app_exchange_trust_removed", audit.Action);
        Assert.Equal(acceptingApp.AppId, audit.TargetId);
        Assert.Contains(sourceApp.AppId, audit.BeforeSnapshot, StringComparison.Ordinal);
    }

    private static AdminController CreateAdminController()
    {
        var controller = new AdminController(NullLogger<AdminController>.Instance);
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.20");
        httpContext.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Name, "admin")
        ], "Test"));
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
        return controller;
    }

    private static AuditService CreateAuditService(IdentityDbContext context) =>
        new(new LoginHistoryRepository(context), new AuditLogRepository(context));

    private static AppRegistrationEntity CreateApp(string appId) => new()
    {
        Id = Guid.NewGuid(),
        AppId = appId,
        AppIdNormalized = IdentityValueNormalizer.Normalize(appId),
        AppName = appId,
        AppSecretHash = "not-used",
        IsActive = true,
        CreatedAt = DateTimeOffset.UtcNow
    };

    private sealed class AsyncBarrier
    {
        private readonly TaskCompletionSource _released = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int _remaining;

        public AsyncBarrier(int participantCount) => _remaining = participantCount;

        public async Task SignalAndWaitAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.Decrement(ref _remaining) == 0)
            {
                _released.TrySetResult();
            }

            await _released.Task.WaitAsync(cancellationToken);
        }
    }

    private sealed class CoordinatedExchangeTrustRepository : IAppExchangeTrustRepository
    {
        private readonly AppExchangeTrustRepository _inner;
        private readonly AsyncBarrier _barrier;

        public CoordinatedExchangeTrustRepository(IdentityDbContext context, AsyncBarrier barrier)
        {
            _inner = new AppExchangeTrustRepository(context);
            _barrier = barrier;
        }

        public Task<bool> IsTrustedSourceAsync(
            Guid appRegistrationId,
            string sourceAppId,
            CancellationToken cancellationToken = default) =>
            _inner.IsTrustedSourceAsync(appRegistrationId, sourceAppId, cancellationToken);

        public Task<IReadOnlyList<AppExchangeTrust>> ListSourcesAsync(
            Guid appRegistrationId,
            CancellationToken cancellationToken = default) =>
            _inner.ListSourcesAsync(appRegistrationId, cancellationToken);

        public Task<AppExchangeTrust> AddAsync(
            AppRegistrationEntity app,
            AppRegistrationEntity sourceApp,
            Guid? approvedBy,
            CancellationToken cancellationToken = default) =>
            _inner.AddAsync(app, sourceApp, approvedBy, cancellationToken);

        public async Task<bool> RemoveAsync(
            Guid appRegistrationId,
            Guid sourceAppRegistrationId,
            CancellationToken cancellationToken = default)
        {
            var removed = await _inner.RemoveAsync(
                appRegistrationId,
                sourceAppRegistrationId,
                cancellationToken);
            await _barrier.SignalAndWaitAsync(cancellationToken);
            return removed;
        }
    }

    private sealed class OrderedUnitOfWork : IUnitOfWork
    {
        private readonly IdentityDbContext _context;
        private readonly Task _waitBeforeSave;
        private readonly TaskCompletionSource? _saveCompleted;

        public OrderedUnitOfWork(
            IdentityDbContext context,
            Task waitBeforeSave,
            TaskCompletionSource? saveCompleted = null)
        {
            _context = context;
            _waitBeforeSave = waitBeforeSave;
            _saveCompleted = saveCompleted;
        }

        public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            await _waitBeforeSave.WaitAsync(cancellationToken);
            try
            {
                return await _context.SaveChangesAsync(cancellationToken);
            }
            finally
            {
                _saveCompleted?.TrySetResult();
            }
        }
    }

    private sealed class SqliteTestDatabase : IAsyncDisposable
    {
        private SqliteTestDatabase(SqliteConnection connection, IdentityDbContext context)
        {
            Connection = connection;
            Context = context;
        }

        private SqliteConnection Connection { get; }

        public IdentityDbContext Context { get; }

        public static async Task<SqliteTestDatabase> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var context = new IdentityDbContext(
                new DbContextOptionsBuilder<IdentityDbContext>().UseSqlite(connection).Options);
            await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            return new SqliteTestDatabase(connection, context);
        }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }

    private sealed class SharedSqliteTestDatabase : IAsyncDisposable
    {
        private readonly string _connectionString;
        private readonly SqliteConnection _keepAliveConnection;

        private SharedSqliteTestDatabase(string connectionString, SqliteConnection keepAliveConnection)
        {
            _connectionString = connectionString;
            _keepAliveConnection = keepAliveConnection;
        }

        public static async Task<SharedSqliteTestDatabase> CreateAsync()
        {
            var connectionString = $"Data Source=audit-{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
            var keepAliveConnection = new SqliteConnection(connectionString);
            await keepAliveConnection.OpenAsync(TestContext.Current.CancellationToken);
            var database = new SharedSqliteTestDatabase(connectionString, keepAliveConnection);
            await using var context = database.CreateContext();
            await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            return database;
        }

        public IdentityDbContext CreateContext() => new(
            new DbContextOptionsBuilder<IdentityDbContext>()
                .UseSqlite(_connectionString)
                .Options);

        public async ValueTask DisposeAsync() => await _keepAliveConnection.DisposeAsync();
    }
}
