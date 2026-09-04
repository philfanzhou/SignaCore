using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Host.Controllers;
using SignaCore.Host.Models;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

public sealed class AdminAppCancellationDatabaseContractTests
{
    [Fact]
    public async Task CreateApp_WhenCanceledBeforeCommit_DoesNotPersistOrReturnSecret()
    {
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        using var cancellation = new CancellationTokenSource();
        var controller = CreateController();
        var auditService = new CancelingActionAuditService(
            CreateAuditService(database.Context),
            cancellation);
        IActionResult? response = null;

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            response = await controller.CreateApp(
                new AdminCreateAppRequest("Canceled app", null, 0),
                new AppRegistrationRepository(database.Context),
                new CallbackUrlValidator(),
                new EfCoreUnitOfWork(database.Context),
                auditService,
                cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Null(response);
        database.Context.ChangeTracker.Clear();
        Assert.False(await database.Context.AppRegistrations
            .AsNoTracking()
            .AnyAsync(TestContext.Current.CancellationToken));
        Assert.False(await database.Context.AuditLogs
            .AsNoTracking()
            .AnyAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ResetAppSecret_WhenCanceledBeforeCommit_PreservesHashAndReturnsNoSecret()
    {
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var originalHash = BCrypt.Net.BCrypt.HashPassword("existing-test-secret");
        database.Context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "canceled-reset-app",
            AppName = "Canceled reset app",
            AppSecretHash = originalHash,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        database.Context.ChangeTracker.Clear();

        using var cancellation = new CancellationTokenSource();
        var controller = CreateController();
        var auditService = new CancelingActionAuditService(
            CreateAuditService(database.Context),
            cancellation);
        IActionResult? response = null;

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            response = await controller.ResetAppSecret(
                "canceled-reset-app",
                new AppRegistrationRepository(database.Context),
                new EfCoreUnitOfWork(database.Context),
                auditService,
                cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Null(response);
        database.Context.ChangeTracker.Clear();
        var persistedHash = await database.Context.AppRegistrations
            .AsNoTracking()
            .Select(app => app.AppSecretHash)
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.True(CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(originalHash),
            Encoding.UTF8.GetBytes(persistedHash)));
        Assert.False(await database.Context.AuditLogs
            .AsNoTracking()
            .AnyAsync(TestContext.Current.CancellationToken));
    }

    private static AdminController CreateController()
    {
        var controller = new AdminController(NullLogger<AdminController>.Instance);
        var httpContext = new DefaultHttpContext
        {
            Connection = { RemoteIpAddress = IPAddress.Parse("192.0.2.25") },
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Name, "admin")
            ], "Test"))
        };
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
        return controller;
    }

    private static AuditService CreateAuditService(IdentityDbContext context) =>
        new(new LoginHistoryRepository(context), new AuditLogRepository(context));

    private sealed class CancelingActionAuditService(
        IAuditService inner,
        CancellationTokenSource cancellation) : IAuditService
    {
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
            inner.RecordLoginAsync(
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
            Assert.Equal(cancellation.Token, cancellationToken);
            cancellation.Cancel();
            return inner.RecordActionAsync(
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

    private sealed class MigratedSqliteTestDatabase : IAsyncDisposable
    {
        private MigratedSqliteTestDatabase(SqliteConnection connection, IdentityDbContext context)
        {
            Connection = connection;
            Context = context;
        }

        private SqliteConnection Connection { get; }

        public IdentityDbContext Context { get; }

        public static async Task<MigratedSqliteTestDatabase> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var options = new DbContextOptionsBuilder<IdentityDbContext>()
                .UseSqlite(
                    connection,
                    providerOptions => providerOptions.MigrationsAssembly(
                        "SignaCore.Database.Migrations.Sqlite"))
                .Options;
            var context = new IdentityDbContext(options);
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
            return new MigratedSqliteTestDatabase(connection, context);
        }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }
}
