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
}
