using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Host.Controllers;
using SignaCore.Host.Models;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

/// <summary>
/// Holds the cancellation contract of the administrative refresh-token revocation and of the login
/// history and audit log queries: every asynchronous boundary of one request observes the exact
/// request token, the revocation flag and its audit entry share one commit boundary, and a paged
/// query canceled between its count and its page returns no partial response.
/// </summary>
public sealed class AdminRevocationAndQueryCancellationTests
{
    private const string TokenValue = "admin-revocation-test-token";

    [Fact]
    public async Task RevokeRefreshToken_PassesTheRequestTokenToEveryBoundary()
    {
        using var cancellation = new CancellationTokenSource();
        var accountId = Guid.NewGuid();
        var token = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            TokenValue = TokenValue,
            IsRevoked = false
        };
        var refreshTokens = new Mock<IRefreshTokenRepository>(MockBehavior.Strict);
        refreshTokens.Setup(repository => repository.GetByTokenValueAsync(TokenValue, cancellation.Token))
            .ReturnsAsync(token);
        var audit = new Mock<IAuditService>(MockBehavior.Strict);
        audit.Setup(service => service.RecordActionAsync(
                "refresh_token_revoked", "RefreshToken", accountId.ToString(), It.IsAny<Guid?>(),
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
                It.IsAny<object?>(), It.IsAny<object?>(), cancellation.Token))
            .Returns(Task.CompletedTask);
        var unitOfWork = new Mock<IUnitOfWork>(MockBehavior.Strict);
        unitOfWork.Setup(unit => unit.SaveChangesAsync(cancellation.Token)).ReturnsAsync(1);

        var result = await CreateController().RevokeRefreshToken(
            new AdminRevokeRefreshTokenRequest(TokenValue),
            refreshTokens.Object,
            unitOfWork.Object,
            audit.Object,
            cancellation.Token);

        Assert.IsType<OkObjectResult>(result);
        Assert.True(token.IsRevoked);
        refreshTokens.VerifyAll();
        audit.VerifyAll();
        unitOfWork.VerifyAll();
    }

    [Fact]
    public async Task GetUserLoginHistory_PassesTheRequestTokenToBothPagingReads()
    {
        using var cancellation = new CancellationTokenSource();
        var userId = Guid.NewGuid();
        var histories = new Mock<ILoginHistoryRepository>(MockBehavior.Strict);
        histories.Setup(repository => repository.CountByAccountIdAsync(userId, cancellation.Token))
            .ReturnsAsync(1);
        histories.Setup(repository => repository.GetByAccountIdAsync(userId, 20, 0, cancellation.Token))
            .ReturnsAsync([new LoginHistoryEntity
            {
                Id = Guid.NewGuid(),
                AccountId = userId,
                AuthMethod = "Password",
                EventType = "login_success"
            }]);

        var result = await CreateController().GetUserLoginHistory(
            userId, null, null, histories.Object, cancellation.Token);

        var response = Assert.IsType<PagedResponse<AdminLoginHistoryItemResponse>>(
            Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(1, response.Total);
        Assert.Single(response.Items);
        histories.VerifyAll();
    }

    [Fact]
    public async Task GetAuditLogs_PassesTheRequestTokenToBothPagingReads()
    {
        using var cancellation = new CancellationTokenSource();
        var logs = new Mock<IAuditLogRepository>(MockBehavior.Strict);
        logs.Setup(repository => repository.CountAsync(
                "login", "Session", "target1", null, cancellation.Token))
            .ReturnsAsync(1);
        logs.Setup(repository => repository.QueryAsync(
                "login", "Session", "target1", null, 20, 0, cancellation.Token))
            .ReturnsAsync([new AuditLogEntity
            {
                Id = Guid.NewGuid(),
                Action = "login",
                TargetType = "Session",
                TargetId = "target1"
            }]);

        var result = await CreateController().GetAuditLogs(
            "login", "Session", "target1", null, null, null, logs.Object, cancellation.Token);

        var response = Assert.IsType<PagedResponse<AdminAuditLogItemResponse>>(
            Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(1, response.Total);
        Assert.Single(response.Items);
        logs.VerifyAll();
    }

    public static TheoryData<string> PagedQueries() => new("login-history", "audit-logs");

    /// <summary>
    /// A paged response is built from a count and a page read: cancellation observed between them
    /// propagates instead of returning half a page.
    /// </summary>
    [Theory]
    [MemberData(nameof(PagedQueries))]
    public async Task PagedQueries_WhenCanceledBetweenCountAndPage_ReturnNoPartialResponse(string query)
    {
        using var cancellation = new CancellationTokenSource();
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var accountId = await SeedHistoryAndAuditAsync(database.Context);
        var controller = CreateController();
        IActionResult? response = null;

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            response = query == "login-history"
                ? await controller.GetUserLoginHistory(
                    accountId,
                    null,
                    null,
                    new CancelAfterCountLoginHistoryRepository(
                        new LoginHistoryRepository(database.Context), cancellation),
                    cancellation.Token)
                : await controller.GetAuditLogs(
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    new CancelAfterCountAuditLogRepository(
                        new AuditLogRepository(database.Context), cancellation),
                    cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Null(response);
    }

    public static TheoryData<string> RevocationBoundaries() => new("before-commit", "after-commit");

    /// <summary>
    /// The revocation flag and its audit entry are one <c>SaveChanges</c> unit: cancellation
    /// observed before that commit persists neither, while cancellation observed afterwards leaves
    /// the committed revocation authoritative.
    /// </summary>
    [Theory]
    [MemberData(nameof(RevocationBoundaries))]
    public async Task RevokeRefreshToken_CancellationPreservesTheCommitBoundary(string boundary)
    {
        using var cancellation = new CancellationTokenSource();
        var interceptor = boundary == "after-commit" ? new CancelAfterSaveInterceptor(cancellation) : null;
        await using var database = await MigratedSqliteTestDatabase.CreateAsync(interceptor);
        var accountId = await SeedRefreshTokenAsync(database.Context);
        IAuditService auditService = boundary == "before-commit"
            ? new CancelingActionAuditService(CreateAuditService(database.Context), cancellation)
            : CreateAuditService(database.Context);
        if (interceptor != null) interceptor.Armed = true;
        IActionResult? response = null;

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            response = await CreateController().RevokeRefreshToken(
                new AdminRevokeRefreshTokenRequest(TokenValue),
                new RefreshTokenRepository(database.Context),
                new EfCoreUnitOfWork(database.Context),
                auditService,
                cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Null(response);
        var committed = boundary == "after-commit";
        database.Context.ChangeTracker.Clear();
        Assert.Equal(committed, await database.Context.RefreshTokens
            .AsNoTracking()
            .Select(token => token.IsRevoked)
            .SingleAsync(TestContext.Current.CancellationToken));
        var audits = await database.Context.AuditLogs
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken);
        if (committed)
        {
            var audited = Assert.Single(audits);
            Assert.Equal("refresh_token_revoked", audited.Action);
            Assert.Equal(accountId.ToString(), audited.TargetId);
            // The token value itself is never part of the audit trail.
            Assert.DoesNotContain(TokenValue, audited.Description ?? string.Empty, StringComparison.Ordinal);
        }
        else
        {
            Assert.Empty(audits);
        }
    }

    private static AdminController CreateController()
    {
        var controller = new AdminController(NullLogger<AdminController>.Instance);
        var httpContext = new DefaultHttpContext
        {
            Connection = { RemoteIpAddress = IPAddress.Parse("192.0.2.45") },
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

    private static async Task<Guid> SeedRefreshTokenAsync(IdentityDbContext context)
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        context.Accounts.Add(account);
        context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            AppId = "revocation-app",
            // Stored refresh tokens are digests; the endpoint looks the presented value up the same way.
            TokenValue = RefreshTokenDigest.Compute(TokenValue),
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            CreatedAt = DateTimeOffset.UtcNow,
            IsRevoked = false
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
        return account.Id;
    }

    private static async Task<Guid> SeedHistoryAndAuditAsync(IdentityDbContext context)
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        context.Accounts.Add(account);
        context.LoginHistories.Add(new LoginHistoryEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            AuthMethod = "Password",
            EventType = "login_success",
            CreatedAt = DateTimeOffset.UtcNow
        });
        context.AuditLogs.Add(new AuditLogEntity
        {
            Id = Guid.NewGuid(),
            Action = "account_created",
            TargetType = "Account",
            TargetId = account.Id.ToString(),
            CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
        return account.Id;
    }

    /// <summary>Cancels once the total is known, i.e. between the two reads of one page.</summary>
    private sealed class CancelAfterCountLoginHistoryRepository(
        ILoginHistoryRepository inner, CancellationTokenSource cancellation) : ILoginHistoryRepository
    {
        public Task AddAsync(LoginHistoryEntity loginHistory, CancellationToken cancellationToken = default) =>
            inner.AddAsync(loginHistory, cancellationToken);

        public Task<List<LoginHistoryEntity>> GetByAccountIdAsync(
            Guid accountId, int pageSize, int skip, CancellationToken cancellationToken = default)
        {
            Assert.Equal(cancellation.Token, cancellationToken);
            return inner.GetByAccountIdAsync(accountId, pageSize, skip, cancellationToken);
        }

        public async Task<int> CountByAccountIdAsync(Guid accountId, CancellationToken cancellationToken = default)
        {
            Assert.Equal(cancellation.Token, cancellationToken);
            var total = await inner.CountByAccountIdAsync(accountId, cancellationToken);
            await cancellation.CancelAsync();
            return total;
        }

        public Task<int> RemoveOlderThanAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default) =>
            inner.RemoveOlderThanAsync(cutoff, cancellationToken);
    }

    /// <summary>Cancels once the total is known, i.e. between the two reads of one page.</summary>
    private sealed class CancelAfterCountAuditLogRepository(
        IAuditLogRepository inner, CancellationTokenSource cancellation) : IAuditLogRepository
    {
        public Task AddAsync(AuditLogEntity auditLog, CancellationToken cancellationToken = default) =>
            inner.AddAsync(auditLog, cancellationToken);

        public Task<List<AuditLogEntity>> QueryAsync(
            string? action,
            string? targetType,
            string? targetId,
            Guid? actorId,
            int pageSize,
            int skip,
            CancellationToken cancellationToken = default)
        {
            Assert.Equal(cancellation.Token, cancellationToken);
            return inner.QueryAsync(action, targetType, targetId, actorId, pageSize, skip, cancellationToken);
        }

        public async Task<int> CountAsync(
            string? action,
            string? targetType,
            string? targetId,
            Guid? actorId,
            CancellationToken cancellationToken = default)
        {
            Assert.Equal(cancellation.Token, cancellationToken);
            var total = await inner.CountAsync(action, targetType, targetId, actorId, cancellationToken);
            await cancellation.CancelAsync();
            return total;
        }

        public Task<int> RemoveOlderThanAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default) =>
            inner.RemoveOlderThanAsync(cutoff, cancellationToken);
    }

    /// <summary>Observes cancellation only once the revocation is already committed.</summary>
    private sealed class CancelAfterSaveInterceptor(CancellationTokenSource cancellation) : SaveChangesInterceptor
    {
        public bool Armed { get; set; }

        public override ValueTask<int> SavedChangesAsync(
            SaveChangesCompletedEventData eventData,
            int result,
            CancellationToken cancellationToken = default)
        {
            if (!Armed) return ValueTask.FromResult(result);
            Assert.Equal(cancellation.Token, cancellationToken);
            cancellation.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(result);
        }
    }

    /// <summary>
    /// Cancels while the audit entry is being staged, which is the last boundary before the single
    /// commit that carries both the revocation flag and the audit entry.
    /// </summary>
    private sealed class CancelingActionAuditService(IAuditService inner, CancellationTokenSource cancellation)
        : IAuditService
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
                accountId, username, authMethod, eventType, clientIp, userAgent, failureReason, appId,
                correlationId, cancellationToken);

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
                action, targetType, targetId, actorId, actorName, description, clientIp, correlationId,
                before, after, cancellationToken);
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

        public static async Task<MigratedSqliteTestDatabase> CreateAsync(IInterceptor? interceptor = null)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var builder = new DbContextOptionsBuilder<IdentityDbContext>()
                .UseSqlite(
                    connection,
                    providerOptions => providerOptions.MigrationsAssembly(
                        "SignaCore.Database.Migrations.Sqlite"));
            if (interceptor != null) builder.AddInterceptors(interceptor);
            var context = new IdentityDbContext(builder.Options);
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
