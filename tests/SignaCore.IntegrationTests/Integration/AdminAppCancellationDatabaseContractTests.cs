using System.Data.Common;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
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

    public static TheoryData<string, string> AppAccessRevocationCases()
    {
        var cases = new TheoryData<string, string>();
        foreach (var provider in new[] { "sms", "wechat", "ldap" })
        {
            cases.Add(provider, "before-commit");
            cases.Add(provider, "after-commit");
        }

        return cases;
    }

    /// <summary>
    /// The access flag, the conditional refresh-token revocation and the audit entry share one
    /// transaction: cancellation observed before the commit leaves none of them behind and returns
    /// no success payload, while cancellation observed after the commit leaves all of them
    /// authoritative.
    /// </summary>
    [Theory]
    [MemberData(nameof(AppAccessRevocationCases))]
    public async Task RevokeAppAccess_CancellationPreservesTheCommitBoundary(string provider, string boundary)
    {
        using var cancellation = new CancellationTokenSource();
        var interceptor = boundary == "after-commit" ? new CancelAfterCommitInterceptor(cancellation) : null;
        await using var database = await MigratedSqliteTestDatabase.CreateAsync(interceptor);
        var targets = await SeedRevocationTargetsAsync(database.Context);
        IAuditService auditService = boundary == "before-commit"
            ? new CancelingActionAuditService(CreateAuditService(database.Context), cancellation)
            : CreateAuditService(database.Context);
        if (interceptor != null) interceptor.Armed = true;
        IActionResult? response = null;

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            response = await InvokeRevocationAsync(
                provider, database.Context, auditService, targets, cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Null(response);
        var committed = boundary == "after-commit";
        database.Context.ChangeTracker.Clear();
        Assert.Equal(!committed, await ReadAccessIsActiveAsync(provider, database.Context));
        Assert.Equal(committed, await database.Context.RefreshTokens
            .AsNoTracking()
            .Where(token => token.Id == RevokedTokenId(provider, targets))
            .Select(token => token.IsRevoked)
            .SingleAsync(TestContext.Current.CancellationToken));
        var audits = await database.Context.AuditLogs
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken);
        if (committed) Assert.Equal($"app_{provider}_user_revoked", Assert.Single(audits).Action);
        else Assert.Empty(audits);
    }

    private static Task<IActionResult> InvokeRevocationAsync(
        string provider,
        IdentityDbContext context,
        IAuditService auditService,
        RevocationTargets targets,
        CancellationToken cancellationToken) => provider switch
        {
            "sms" => CreateController().RevokeSmsUser(
                targets.AppId, targets.UserLoginId, context, auditService, cancellationToken),
            "wechat" => CreateController().RevokeWechatUser(
                targets.AppId, targets.UserLoginId, context, auditService, cancellationToken),
            "ldap" => CreateController().RevokeLdapUser(
                targets.AppId, targets.LdapCredentialId, context, auditService, cancellationToken),
            _ => throw new ArgumentOutOfRangeException(nameof(provider), provider, "Unknown revocation provider.")
        };

    private static Task<bool> ReadAccessIsActiveAsync(string provider, IdentityDbContext context) => provider switch
    {
        "sms" => context.AppSmsAccesses.AsNoTracking()
            .Select(access => access.IsActive).SingleAsync(TestContext.Current.CancellationToken),
        "wechat" => context.AppWechatAccesses.AsNoTracking()
            .Select(access => access.IsActive).SingleAsync(TestContext.Current.CancellationToken),
        "ldap" => context.AppLdapAccesses.AsNoTracking()
            .Select(access => access.IsActive).SingleAsync(TestContext.Current.CancellationToken),
        _ => throw new ArgumentOutOfRangeException(nameof(provider), provider, "Unknown revocation provider.")
    };

    private static Guid RevokedTokenId(string provider, RevocationTargets targets) => provider switch
    {
        "sms" => targets.SmsTokenId,
        "wechat" => targets.WechatTokenId,
        "ldap" => targets.LdapTokenId,
        _ => throw new ArgumentOutOfRangeException(nameof(provider), provider, "Unknown revocation provider.")
    };

    private static async Task<RevocationTargets> SeedRevocationTargetsAsync(IdentityDbContext context)
    {
        var now = DateTimeOffset.UtcNow;
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = now };
        const string appId = "revoke-cancellation-app";
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppIdNormalized = IdentityValueNormalizer.Normalize(appId),
            AppName = appId,
            AppSecretHash = "unused-test-hash",
            IsActive = true,
            CreatedAt = now
        };
        var userLogin = new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            ProviderName = "Sms",
            ProviderNameNormalized = "sms",
            ProviderUserId = "+8613800000000"
        };
        var ldapCredential = new LdapCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            DirectoryKey = "corp",
            DirectoryKeyNormalized = "corp",
            ObjectGuid = Guid.NewGuid(),
            UserPrincipalName = "member@corp.example",
            UserPrincipalNameNormalized = "member@corp.example",
            SamAccountName = "member",
            SamAccountNameNormalized = "member",
            CreatedAt = now
        };
        var smsToken = CreateRefreshToken(account.Id, appId, "sms-active");
        smsToken.SmsUserLoginId = userLogin.Id;
        var wechatToken = CreateRefreshToken(account.Id, appId, "wechat-active");
        wechatToken.WechatUserLoginId = userLogin.Id;
        var ldapToken = CreateRefreshToken(account.Id, appId, "ldap-active");
        ldapToken.LdapCredentialId = ldapCredential.Id;

        context.Accounts.Add(account);
        context.AppRegistrations.Add(app);
        context.UserLogins.Add(userLogin);
        context.LdapCredentials.Add(ldapCredential);
        context.AppSmsAccesses.Add(new AppSmsAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            UserLoginId = userLogin.Id,
            ApprovalSource = SmsAccessApprovalSource.Admin,
            IsActive = true,
            CreatedAt = now
        });
        context.AppWechatAccesses.Add(new AppWechatAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            UserLoginId = userLogin.Id,
            ApprovalSource = WechatAccessApprovalSource.SelfBind,
            IsActive = true,
            CreatedAt = now
        });
        context.AppLdapAccesses.Add(new AppLdapAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            LdapCredentialId = ldapCredential.Id,
            ApprovalSource = LdapAccessApprovalSource.Admin,
            IsActive = true,
            CreatedAt = now
        });
        context.RefreshTokens.AddRange(smsToken, wechatToken, ldapToken);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();

        return new RevocationTargets(
            appId, userLogin.Id, ldapCredential.Id, smsToken.Id, wechatToken.Id, ldapToken.Id);
    }

    private static RefreshTokenEntity CreateRefreshToken(Guid accountId, string appId, string tokenValue) => new()
    {
        Id = Guid.NewGuid(),
        AccountId = accountId,
        AppId = appId,
        TokenValue = tokenValue,
        ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        CreatedAt = DateTimeOffset.UtcNow,
        IsRevoked = false
    };

    private sealed record RevocationTargets(
        string AppId,
        Guid UserLoginId,
        Guid LdapCredentialId,
        Guid SmsTokenId,
        Guid WechatTokenId,
        Guid LdapTokenId);

    /// <summary>
    /// Observes cancellation only once the revoking transaction is already committed, which is the
    /// boundary after which the revocation stays authoritative.
    /// </summary>
    private sealed class CancelAfterCommitInterceptor(CancellationTokenSource cancellation)
        : DbTransactionInterceptor
    {
        // Migrations and seeding commit on this connection too; only the request under test may be
        // observed.
        public bool Armed { get; set; }

        public override Task TransactionCommittedAsync(
            DbTransaction transaction,
            TransactionEndEventData eventData,
            CancellationToken cancellationToken = default)
        {
            if (!Armed) return Task.CompletedTask;
            Assert.Equal(cancellation.Token, cancellationToken);
            cancellation.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
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
            var options = builder.Options;
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
