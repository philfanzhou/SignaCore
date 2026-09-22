using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using ServiceMantle.Audit;
using ServiceMantle.Persistence.EntityFrameworkCore;
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
/// history query: every asynchronous boundary of one request observes the exact request token, the
/// revocation flag and its audit entry share one commit boundary, and a paged query canceled
/// between its count and its page returns no partial response. The audit query itself is the
/// shared restricted endpoint, whose own contract lives in the ServiceMantle suite.
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
        var audit = new Mock<IManagementAuditWriter>(MockBehavior.Strict);
        audit.Setup(writer => writer.RecordAsync(
                It.IsAny<ManagementAuditEvent>(), cancellation.Token))
            .Returns(new ValueTask<ManagementAuditRecord>(default(ManagementAuditRecord)));
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
        audit.Verify(writer => writer.RecordAsync(
            It.Is<ManagementAuditEvent>(auditEvent =>
                auditEvent.Action.Value == "refresh_token_revoked" &&
                auditEvent.Target.Type.Value == "refreshtoken" &&
                auditEvent.Target.Id == accountId.ToString()),
            cancellation.Token));
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

    public static TheoryData<string> PagedQueries() => new("login-history");

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
        var accountId = await SeedLoginHistoryAsync(database.Context);
        var controller = CreateController();
        IActionResult? response = null;

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            response = await controller.GetUserLoginHistory(
                accountId,
                null,
                null,
                new CancelAfterCountLoginHistoryRepository(
                    new LoginHistoryRepository(database.Context), cancellation),
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
        IManagementAuditWriter auditWriter = boundary == "before-commit"
            ? new CancelingActionAuditWriter(CreateAuditWriter(database.Context), cancellation)
            : CreateAuditWriter(database.Context);
        if (interceptor != null) interceptor.Armed = true;
        IActionResult? response = null;

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            response = await CreateController().RevokeRefreshToken(
                new AdminRevokeRefreshTokenRequest(TokenValue),
                new RefreshTokenRepository(database.Context),
                new EfCoreUnitOfWork(database.Context),
                auditWriter,
                cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Null(response);
        var committed = boundary == "after-commit";
        database.Context.ChangeTracker.Clear();
        Assert.Equal(committed, await database.Context.RefreshTokens
            .AsNoTracking()
            .Select(token => token.IsRevoked)
            .SingleAsync(TestContext.Current.CancellationToken));
        var audits = await ReadSharedAuditRowsAsync(database.Context);
        if (committed)
        {
            var audited = Assert.Single(audits);
            Assert.Equal("refresh_token_revoked", audited.Action);
            Assert.Equal("refreshtoken", audited.TargetType);
            Assert.Equal(accountId.ToString(), audited.TargetId);
            // The token value itself is never part of the audit trail.
            Assert.DoesNotContain(TokenValue, audited.SecurityDescription ?? string.Empty, StringComparison.Ordinal);
        }
        else
        {
            Assert.Empty(audits);
        }
    }

    private sealed record SharedAuditRow(
        string Action,
        string TargetType,
        string TargetId,
        string? SecurityDescription);

    /// <summary>
    /// Reads the shared service_audit_logs table, whose entity is internal to the library, through a
    /// portable quoted projection.
    /// </summary>
    private static async Task<List<SharedAuditRow>> ReadSharedAuditRowsAsync(IdentityDbContext context) =>
        await context.Database
            .SqlQuery<SharedAuditRow>($"""
                SELECT "action" AS "Action",
                       "target_type" AS "TargetType",
                       "target_id" AS "TargetId",
                       "security_description" AS "SecurityDescription"
                FROM service_audit_logs
                """)
            .ToListAsync(TestContext.Current.CancellationToken);

    private static AdminController CreateController()
    {
        var controller = AuthTestDoubles.CreateAdminController();
        controller.HttpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.45");
        return controller;
    }

    private static EfCoreManagementAuditWriter<IdentityDbContext> CreateAuditWriter(
        IdentityDbContext context) => new(context);

    private static async Task<Guid> SeedRefreshTokenAsync(IdentityDbContext context)
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        context.Accounts.Add(account);
        var seededTokenId = Guid.NewGuid();
        context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = seededTokenId,
            // PS-07: a directly seeded legacy row is the singleton root of its own family.
            FamilyId = seededTokenId,
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

    private static async Task<Guid> SeedLoginHistoryAsync(IdentityDbContext context)
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
    private sealed class CancelingActionAuditWriter(
        IManagementAuditWriter inner, CancellationTokenSource cancellation) : IManagementAuditWriter
    {
        public ValueTask<ManagementAuditRecord> RecordAsync(
            ManagementAuditEvent auditEvent,
            CancellationToken cancellationToken = default)
        {
            Assert.Equal(cancellation.Token, cancellationToken);
            cancellation.Cancel();
            return inner.RecordAsync(auditEvent, cancellationToken);
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
