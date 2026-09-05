using System.Data.Common;
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
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Ldap;
using SignaCore.Domain.Services.WeChat;
using SignaCore.Host.Controllers;
using SignaCore.Host.Models;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

/// <summary>
/// Holds the cancellation contract of the WeChat and LDAP policy, listing, restore and provisioning
/// endpoints: every asynchronous boundary of one request observes the exact request token, and a
/// policy change plus its audit entry share the same commit boundary.
/// </summary>
public sealed class AdminWechatLdapCancellationTests
{
    private const string AppId = "wechat-ldap-cancellation-app";

    [Fact]
    public async Task UpdateWechatPolicy_PassesTheRequestTokenToEveryBoundary()
    {
        using var cancellation = new CancellationTokenSource();
        var app = CreateApp();
        var appRegistrations = new Mock<IAppRegistrationRepository>(MockBehavior.Strict);
        appRegistrations.Setup(repository => repository.GetByAppIdAsync(AppId, cancellation.Token))
            .ReturnsAsync(app);
        var audit = CreateAuditMock("app_wechat_policy_updated", cancellation.Token);
        var unitOfWork = new Mock<IUnitOfWork>(MockBehavior.Strict);
        unitOfWork.Setup(unit => unit.SaveChangesAsync(cancellation.Token)).ReturnsAsync(1);

        var result = await CreateController().UpdateWechatPolicy(
            AppId,
            new AdminUpdateWechatPolicyRequest("BindRequired"),
            appRegistrations.Object,
            CreateConfiguredWechatOptions(),
            unitOfWork.Object,
            audit.Object,
            cancellation.Token);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(WechatLoginMode.BindRequired, app.WechatLoginMode);
        appRegistrations.VerifyAll();
        audit.VerifyAll();
        unitOfWork.VerifyAll();
    }

    [Fact]
    public async Task UpdateLdapPolicy_PassesTheRequestTokenToEveryBoundary()
    {
        using var cancellation = new CancellationTokenSource();
        var app = CreateApp();
        var appRegistrations = new Mock<IAppRegistrationRepository>(MockBehavior.Strict);
        appRegistrations.Setup(repository => repository.GetByAppIdAsync(AppId, cancellation.Token))
            .ReturnsAsync(app);
        var audit = CreateAuditMock("app_ldap_policy_updated", cancellation.Token);
        var unitOfWork = new Mock<IUnitOfWork>(MockBehavior.Strict);
        unitOfWork.Setup(unit => unit.SaveChangesAsync(cancellation.Token)).ReturnsAsync(1);

        var result = await CreateController().UpdateLdapPolicy(
            AppId,
            new AdminUpdateLdapPolicyRequest("ManualApproval"),
            appRegistrations.Object,
            unitOfWork.Object,
            audit.Object,
            cancellation.Token);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(LdapLoginMode.ManualApproval, app.LdapLoginMode);
        appRegistrations.VerifyAll();
        audit.VerifyAll();
        unitOfWork.VerifyAll();
    }

    [Fact]
    public async Task AddLdapUser_PassesTheRequestTokenToTheAppReadAndTheAudit()
    {
        using var cancellation = new CancellationTokenSource();
        var app = CreateApp();
        var appRegistrations = new Mock<IAppRegistrationRepository>(MockBehavior.Strict);
        appRegistrations.Setup(repository => repository.GetByAppIdAsync(AppId, cancellation.Token))
            .ReturnsAsync(app);
        var audit = CreateAuditMock("app_ldap_user_approved", cancellation.Token);
        var identity = new LdapDirectoryIdentity(
            "corp", Guid.NewGuid(), "member@corp.example", "member", IsEnabled: true);
        var directory = new Mock<ILdapDirectoryClient>(MockBehavior.Strict);
        directory.Setup(client => client.FindUserAsync("corp", "member", cancellation.Token))
            .ReturnsAsync(identity);
        var provisioned = CreateProvisioningResult(app, identity);
        var accounts = new Mock<ILdapAccountService>(MockBehavior.Strict);
        accounts.Setup(service => service.ProvisionAsync(
                identity,
                app,
                LdapAccessApprovalSource.Admin,
                It.IsAny<Guid?>(),
                cancellation.Token,
                It.IsAny<Func<LdapProvisioningResult, Task>?>()))
            .Returns<LdapDirectoryIdentity, AppRegistrationEntity, LdapAccessApprovalSource, Guid?,
                CancellationToken, Func<LdapProvisioningResult, Task>?>(
                async (_, _, _, _, _, beforeCommit) =>
                {
                    // The endpoint stages its audit entry through this callback, inside the account
                    // service's own transaction.
                    if (beforeCommit != null) await beforeCommit(provisioned);
                    return provisioned;
                });

        var result = await CreateController().AddLdapUser(
            AppId,
            new AdminAddLdapUserRequest("corp", "member"),
            appRegistrations.Object,
            directory.Object,
            accounts.Object,
            audit.Object,
            cancellation.Token);

        var response = Assert.IsType<AdminLdapUserResponse>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(provisioned.Credential.Id.ToString(), response.CredentialId);
        appRegistrations.VerifyAll();
        directory.VerifyAll();
        accounts.VerifyAll();
        audit.VerifyAll();
    }

    [Fact]
    public async Task RestoreWechatUser_PassesTheRequestTokenToTheAudit()
    {
        using var cancellation = new CancellationTokenSource();
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var seeded = await SeedAccessAsync(database.Context, wechatActive: false);
        var audit = CreateAuditMock("app_wechat_user_restored", cancellation.Token);

        var result = await CreateController().RestoreWechatUser(
            AppId, seeded.LoginId, database.Context, audit.Object, cancellation.Token);

        Assert.IsType<OkObjectResult>(result);
        audit.VerifyAll();
        database.Context.ChangeTracker.Clear();
        Assert.True(await database.Context.AppWechatAccesses
            .AsNoTracking()
            .Select(access => access.IsActive)
            .SingleAsync(TestContext.Current.CancellationToken));
    }

    public static TheoryData<string> ListingEndpoints() => new("wechat-users", "ldap-users");

    [Theory]
    [MemberData(nameof(ListingEndpoints))]
    public async Task Listings_PassTheRequestTokenToEveryQuery(string endpoint)
    {
        using var cancellation = new CancellationTokenSource();
        var interceptor = new TokenRecordingCommandInterceptor();
        await using var database = await MigratedSqliteTestDatabase.CreateAsync(interceptor);
        var seeded = await SeedAccessAsync(database.Context, wechatActive: true);
        interceptor.Armed = true;

        var result = endpoint == "wechat-users"
            ? await CreateController().GetWechatUsers(AppId, database.Context, cancellation.Token)
            : await CreateController().GetLdapUsers(AppId, database.Context, cancellation.Token);

        var value = Assert.IsType<OkObjectResult>(result).Value;
        if (endpoint == "wechat-users")
        {
            var users = Assert.IsAssignableFrom<IReadOnlyList<AdminWechatUserResponse>>(value);
            Assert.Equal(seeded.LoginId, Guid.Parse(Assert.Single(users).LoginId));
        }
        else
        {
            var users = Assert.IsAssignableFrom<IReadOnlyList<AdminLdapUserResponse>>(value);
            Assert.Equal(seeded.CredentialId, Guid.Parse(Assert.Single(users).CredentialId));
        }

        Assert.Equal(2, interceptor.ObservedTokens.Count);
        Assert.All(interceptor.ObservedTokens, token => Assert.Equal(cancellation.Token, token));
    }

    [Theory]
    [MemberData(nameof(ListingEndpoints))]
    public async Task Listings_WhenCanceledBeforeTheQuery_ReturnNoPartialList(string endpoint)
    {
        using var cancellation = new CancellationTokenSource();
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        await SeedAccessAsync(database.Context, wechatActive: true);
        await cancellation.CancelAsync();
        IActionResult? response = null;

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            response = endpoint == "wechat-users"
                ? await CreateController().GetWechatUsers(AppId, database.Context, cancellation.Token)
                : await CreateController().GetLdapUsers(AppId, database.Context, cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Null(response);
    }

    public static TheoryData<string, string> PolicyCommitCases()
    {
        var cases = new TheoryData<string, string>();
        foreach (var endpoint in new[] { "wechat-policy", "ldap-policy" })
        {
            cases.Add(endpoint, "before-commit");
            cases.Add(endpoint, "after-commit");
        }

        return cases;
    }

    /// <summary>
    /// The policy field and its audit entry are one <c>SaveChanges</c> unit: cancellation observed
    /// before that commit leaves the stored policy untouched and writes no audit entry, while
    /// cancellation observed afterwards leaves the committed policy authoritative.
    /// </summary>
    [Theory]
    [MemberData(nameof(PolicyCommitCases))]
    public async Task PolicyUpdates_CancellationPreservesTheCommitBoundary(string endpoint, string boundary)
    {
        using var cancellation = new CancellationTokenSource();
        var interceptor = boundary == "after-commit" ? new CancelAfterSaveInterceptor(cancellation) : null;
        await using var database = await MigratedSqliteTestDatabase.CreateAsync(interceptor);
        await SeedAppAsync(database.Context);
        IAuditService auditService = boundary == "before-commit"
            ? new CancelingActionAuditService(CreateAuditService(database.Context), cancellation)
            : CreateAuditService(database.Context);
        var appRegistrations = new AppRegistrationRepository(database.Context);
        var unitOfWork = new EfCoreUnitOfWork(database.Context);
        if (interceptor != null) interceptor.Armed = true;
        IActionResult? response = null;

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            response = endpoint == "wechat-policy"
                ? await CreateController().UpdateWechatPolicy(
                    AppId,
                    new AdminUpdateWechatPolicyRequest("BindRequired"),
                    appRegistrations,
                    CreateConfiguredWechatOptions(),
                    unitOfWork,
                    auditService,
                    cancellation.Token)
                : await CreateController().UpdateLdapPolicy(
                    AppId,
                    new AdminUpdateLdapPolicyRequest("ManualApproval"),
                    appRegistrations,
                    unitOfWork,
                    auditService,
                    cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Null(response);
        var committed = boundary == "after-commit";
        database.Context.ChangeTracker.Clear();
        var stored = await database.Context.AppRegistrations
            .AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        if (endpoint == "wechat-policy")
        {
            Assert.Equal(committed ? WechatLoginMode.BindRequired : WechatLoginMode.Disabled, stored.WechatLoginMode);
        }
        else
        {
            Assert.Equal(committed ? LdapLoginMode.ManualApproval : LdapLoginMode.Disabled, stored.LdapLoginMode);
        }

        var audits = await database.Context.AuditLogs
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken);
        if (committed)
        {
            var expected = endpoint == "wechat-policy" ? "app_wechat_policy_updated" : "app_ldap_policy_updated";
            Assert.Equal(expected, Assert.Single(audits).Action);
        }
        else
        {
            Assert.Empty(audits);
        }
    }

    private static Mock<IAuditService> CreateAuditMock(string action, CancellationToken expectedToken)
    {
        var audit = new Mock<IAuditService>(MockBehavior.Strict);
        audit.Setup(service => service.RecordActionAsync(
                action, "AppRegistration", AppId, It.IsAny<Guid?>(), It.IsAny<string?>(), It.IsAny<string?>(),
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<object?>(), It.IsAny<object?>(),
                expectedToken))
            .Returns(Task.CompletedTask);
        return audit;
    }

    private static AdminController CreateController()
    {
        var controller = new AdminController(NullLogger<AdminController>.Instance);
        var httpContext = new DefaultHttpContext
        {
            Connection = { RemoteIpAddress = IPAddress.Parse("192.0.2.35") },
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

    private static WechatOptions CreateConfiguredWechatOptions() => new()
    {
        AppId = "wx-test-app",
        AppSecret = "unused-test-secret"
    };

    private static AppRegistrationEntity CreateApp() => new()
    {
        Id = Guid.NewGuid(),
        AppId = AppId,
        AppIdNormalized = IdentityValueNormalizer.Normalize(AppId),
        AppName = "WeChat and LDAP cancellation app",
        AppSecretHash = "unused-test-hash",
        IsActive = true,
        CreatedAt = DateTimeOffset.UtcNow
    };

    private static LdapProvisioningResult CreateProvisioningResult(
        AppRegistrationEntity app, LdapDirectoryIdentity identity)
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        var credential = new LdapCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            DirectoryKey = identity.DirectoryKey,
            DirectoryKeyNormalized = IdentityValueNormalizer.Normalize(identity.DirectoryKey),
            ObjectGuid = identity.ObjectGuid,
            UserPrincipalName = identity.UserPrincipalName,
            UserPrincipalNameNormalized = IdentityValueNormalizer.Normalize(identity.UserPrincipalName),
            SamAccountName = identity.SamAccountName,
            SamAccountNameNormalized = IdentityValueNormalizer.Normalize(identity.SamAccountName),
            CreatedAt = DateTimeOffset.UtcNow
        };
        var access = new AppLdapAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            LdapCredentialId = credential.Id,
            ApprovalSource = LdapAccessApprovalSource.Admin,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        return new LdapProvisioningResult(account, credential, access, AccountCreated: true, AccessCreated: true);
    }

    private static async Task<AppRegistrationEntity> SeedAppAsync(IdentityDbContext context)
    {
        var app = CreateApp();
        context.AppRegistrations.Add(app);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
        return app;
    }

    private static async Task<SeededAccess> SeedAccessAsync(IdentityDbContext context, bool wechatActive)
    {
        var app = await SeedAppAsync(context);
        var now = DateTimeOffset.UtcNow;
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = now };
        var login = new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            ProviderName = "WeChat",
            ProviderNameNormalized = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodWechat),
            ProviderUserId = "o-test-openid-value"
        };
        var credential = new LdapCredentialEntity
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
        context.Accounts.Add(account);
        context.UserLogins.Add(login);
        context.LdapCredentials.Add(credential);
        context.AppWechatAccesses.Add(new AppWechatAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            UserLoginId = login.Id,
            ApprovalSource = WechatAccessApprovalSource.SelfBind,
            IsActive = wechatActive,
            CreatedAt = now
        });
        context.AppLdapAccesses.Add(new AppLdapAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            LdapCredentialId = credential.Id,
            ApprovalSource = LdapAccessApprovalSource.Admin,
            IsActive = true,
            CreatedAt = now
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
        return new SeededAccess(login.Id, credential.Id);
    }

    private sealed record SeededAccess(Guid LoginId, Guid CredentialId);

    /// <summary>
    /// Records the token every database command of the request under test observes, so a query
    /// falling back to the default token cannot pass unnoticed.
    /// </summary>
    private sealed class TokenRecordingCommandInterceptor : DbCommandInterceptor
    {
        // Migrations and seeding run on this connection too; only the request under test may be
        // observed.
        public bool Armed { get; set; }

        public List<CancellationToken> ObservedTokens { get; } = [];

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            if (Armed) ObservedTokens.Add(cancellationToken);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }
    }

    /// <summary>Observes cancellation only once the policy change is already committed.</summary>
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
    /// commit that carries both the policy change and the audit entry.
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
