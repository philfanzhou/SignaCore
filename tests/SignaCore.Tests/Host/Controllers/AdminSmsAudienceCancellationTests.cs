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
using SignaCore.Domain.Services.Sms;
using SignaCore.Host.Controllers;
using SignaCore.Host.Models;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

/// <summary>
/// Holds the cancellation contract of the SMS policy, SMS user listing, SMS user provisioning and
/// audience-mode endpoints: every asynchronous boundary of one request observes the exact request
/// token, and the policy change plus its audit entry share the same commit boundary.
/// </summary>
public sealed class AdminSmsAudienceCancellationTests
{
    private const string AppId = "sms-cancellation-app";

    [Fact]
    public async Task UpdateSmsPolicy_PassesTheRequestTokenToEveryBoundary()
    {
        using var cancellation = new CancellationTokenSource();
        var app = CreateApp();
        var appRegistrations = new Mock<IAppRegistrationRepository>(MockBehavior.Strict);
        appRegistrations.Setup(repository => repository.GetByAppIdAsync(AppId, cancellation.Token))
            .ReturnsAsync(app);
        var audit = new Mock<IAuditService>(MockBehavior.Strict);
        audit.Setup(service => service.RecordActionAsync(
                "app_sms_policy_updated", "AppRegistration", AppId, It.IsAny<Guid?>(), It.IsAny<string?>(),
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<object?>(),
                It.IsAny<object?>(), cancellation.Token))
            .Returns(Task.CompletedTask);
        var unitOfWork = new Mock<IUnitOfWork>(MockBehavior.Strict);
        unitOfWork.Setup(unit => unit.SaveChangesAsync(cancellation.Token)).ReturnsAsync(1);

        var result = await CreateController().UpdateSmsPolicy(
            AppId,
            new AdminUpdateSmsPolicyRequest("ManualApproval", "primary"),
            appRegistrations.Object,
            CreateSmsOptions("primary"),
            unitOfWork.Object,
            audit.Object,
            cancellation.Token);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(SmsLoginMode.ManualApproval, app.SmsLoginMode);
        appRegistrations.VerifyAll();
        audit.VerifyAll();
        unitOfWork.VerifyAll();
    }

    [Fact]
    public async Task UpdateAudienceMode_PassesTheRequestTokenToEveryBoundary()
    {
        using var cancellation = new CancellationTokenSource();
        var app = CreateApp();
        var appRegistrations = new Mock<IAppRegistrationRepository>(MockBehavior.Strict);
        appRegistrations.Setup(repository => repository.GetByAppIdAsync(AppId, cancellation.Token))
            .ReturnsAsync(app);
        var audit = new Mock<IAuditService>(MockBehavior.Strict);
        audit.Setup(service => service.RecordActionAsync(
                "app_audience_mode_updated", "AppRegistration", AppId, It.IsAny<Guid?>(), It.IsAny<string?>(),
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<object?>(),
                It.IsAny<object?>(), cancellation.Token))
            .Returns(Task.CompletedTask);
        var unitOfWork = new Mock<IUnitOfWork>(MockBehavior.Strict);
        unitOfWork.Setup(unit => unit.SaveChangesAsync(cancellation.Token)).ReturnsAsync(1);

        var result = await CreateController().UpdateAudienceMode(
            AppId,
            new AdminUpdateAudienceModeRequest("PerApplication"),
            appRegistrations.Object,
            new JwtOptions(),
            unitOfWork.Object,
            audit.Object,
            cancellation.Token);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(AudienceMode.PerApplication, app.AudienceMode);
        appRegistrations.VerifyAll();
        audit.VerifyAll();
        unitOfWork.VerifyAll();
    }

    [Fact]
    public async Task AddSmsUser_PassesTheRequestTokenToTheAppReadAndTheAudit()
    {
        using var cancellation = new CancellationTokenSource();
        var app = CreateApp();
        var appRegistrations = new Mock<IAppRegistrationRepository>(MockBehavior.Strict);
        appRegistrations.Setup(repository => repository.GetByAppIdAsync(AppId, cancellation.Token))
            .ReturnsAsync(app);
        var audit = new Mock<IAuditService>(MockBehavior.Strict);
        audit.Setup(service => service.RecordActionAsync(
                "app_sms_user_approved", "AppRegistration", AppId, It.IsAny<Guid?>(), It.IsAny<string?>(),
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<object?>(),
                It.IsAny<object?>(), cancellation.Token))
            .Returns(Task.CompletedTask);
        var admission = CreateAdmission(app);
        var admissionService = new Mock<ISmsAdmissionService>(MockBehavior.Strict);
        admissionService.Setup(service => service.ProvisionAsync(
                app,
                "+8613800138000",
                SmsAccessApprovalSource.Admin,
                It.IsAny<Guid?>(),
                cancellation.Token,
                It.IsAny<Func<SmsAdmission, Task>?>()))
            .Returns<AppRegistrationEntity, string, SmsAccessApprovalSource, Guid?, CancellationToken,
                Func<SmsAdmission, Task>?>(
                async (_, _, _, _, _, beforeCommit) =>
                {
                    // The endpoint stages its audit entry through this callback, inside the
                    // admission service's own transaction.
                    if (beforeCommit != null) await beforeCommit(admission);
                    return admission;
                });

        var result = await CreateController().AddSmsUser(
            AppId,
            new AdminAddSmsUserRequest("13800138000"),
            appRegistrations.Object,
            admissionService.Object,
            audit.Object,
            cancellation.Token);

        var response = Assert.IsType<AdminSmsUserResponse>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(admission.Login.Id.ToString(), response.LoginId);
        appRegistrations.VerifyAll();
        admissionService.VerifyAll();
        audit.VerifyAll();
    }

    [Fact]
    public async Task GetSmsUsers_PassesTheRequestTokenToEveryQuery()
    {
        using var cancellation = new CancellationTokenSource();
        var interceptor = new TokenRecordingCommandInterceptor();
        await using var database = await MigratedSqliteTestDatabase.CreateAsync(interceptor);
        var seeded = await SeedSmsUserAsync(database.Context);
        interceptor.Armed = true;

        var result = await CreateController().GetSmsUsers(AppId, database.Context, cancellation.Token);

        var users = Assert.IsAssignableFrom<IReadOnlyList<AdminSmsUserResponse>>(
            Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(seeded, Guid.Parse(Assert.Single(users).LoginId));
        Assert.Equal(2, interceptor.ObservedTokens.Count);
        Assert.All(interceptor.ObservedTokens, token => Assert.Equal(cancellation.Token, token));
    }

    [Fact]
    public async Task GetSmsUsers_WhenCanceledBeforeTheListing_ReturnsNoPartialList()
    {
        using var cancellation = new CancellationTokenSource();
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        await SeedSmsUserAsync(database.Context);
        await cancellation.CancelAsync();
        IActionResult? response = null;

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            response = await CreateController().GetSmsUsers(AppId, database.Context, cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Null(response);
    }

    public static TheoryData<string, string> PolicyCommitCases()
    {
        var cases = new TheoryData<string, string>();
        foreach (var endpoint in new[] { "sms-policy", "audience-mode" })
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
            response = endpoint == "sms-policy"
                ? await CreateController().UpdateSmsPolicy(
                    AppId,
                    new AdminUpdateSmsPolicyRequest("ManualApproval", "primary"),
                    appRegistrations,
                    CreateSmsOptions("primary"),
                    unitOfWork,
                    auditService,
                    cancellation.Token)
                : await CreateController().UpdateAudienceMode(
                    AppId,
                    new AdminUpdateAudienceModeRequest("PerApplication"),
                    appRegistrations,
                    new JwtOptions(),
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
        if (endpoint == "sms-policy")
        {
            Assert.Equal(committed ? SmsLoginMode.ManualApproval : SmsLoginMode.Disabled, stored.SmsLoginMode);
            Assert.Equal(committed ? "primary" : null, stored.SmsProfileKey);
        }
        else
        {
            Assert.Equal(committed ? AudienceMode.PerApplication : AudienceMode.Shared, stored.AudienceMode);
        }

        var audits = await database.Context.AuditLogs
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken);
        if (committed)
        {
            var expected = endpoint == "sms-policy" ? "app_sms_policy_updated" : "app_audience_mode_updated";
            Assert.Equal(expected, Assert.Single(audits).Action);
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
            Connection = { RemoteIpAddress = IPAddress.Parse("192.0.2.30") },
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

    private static SmsOptions CreateSmsOptions(params string[] profileKeys)
    {
        var options = new SmsOptions();
        foreach (var key in profileKeys)
        {
            options.Profiles[key] = new SmsProviderProfile { Provider = SmsProviderNames.AlibabaCloud };
        }

        return options;
    }

    private static AppRegistrationEntity CreateApp() => new()
    {
        Id = Guid.NewGuid(),
        AppId = AppId,
        AppIdNormalized = IdentityValueNormalizer.Normalize(AppId),
        AppName = "SMS cancellation app",
        AppSecretHash = "unused-test-hash",
        IsActive = true,
        CreatedAt = DateTimeOffset.UtcNow
    };

    private static SmsAdmission CreateAdmission(AppRegistrationEntity app)
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        var login = new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            ProviderName = "Sms",
            ProviderNameNormalized = "sms",
            ProviderUserId = "+8613800138000"
        };
        var access = new AppSmsAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            UserLoginId = login.Id,
            ApprovalSource = SmsAccessApprovalSource.Admin,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        return new SmsAdmission(account, login, access);
    }

    private static async Task<AppRegistrationEntity> SeedAppAsync(IdentityDbContext context)
    {
        var app = CreateApp();
        context.AppRegistrations.Add(app);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
        return app;
    }

    private static async Task<Guid> SeedSmsUserAsync(IdentityDbContext context)
    {
        var app = await SeedAppAsync(context);
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        var login = new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            ProviderName = "Sms",
            ProviderNameNormalized = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodSms),
            ProviderUserId = "+8613800138000"
        };
        context.Accounts.Add(account);
        context.UserLogins.Add(login);
        context.AppSmsAccesses.Add(new AppSmsAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            UserLoginId = login.Id,
            ApprovalSource = SmsAccessApprovalSource.Admin,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
        return login.Id;
    }

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
