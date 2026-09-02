using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.WeChat;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// Almost everything <see cref="WechatAdmissionService"/> does is decided by database constraints and
/// transactions — the provider+provider_user_id unique index and the cascade delete on
/// app_wechat_accesses — so this is pinned against real SQLite on the same migration chain as
/// production rather than the in-memory provider.
/// The <c>DatabaseContractTests</c> suffix in the class name matches CI's filter.
/// </summary>
public sealed class WechatAdmissionDatabaseContractTests : IDisposable
{
    private const string OpenId = "o-contract-openid";
    private readonly string _databasePath = Path.Combine(
        Path.GetTempPath(), $"signacore-wechat-{Guid.NewGuid():N}.db");

    [Fact]
    public async Task Provision_CreatesAccountAndAdmission_AndIsIdempotent()
    {
        var app = await SeedAppAsync(WechatLoginMode.AutoProvision);

        WechatAdmission first;
        await using (var context = CreateContext())
        {
            first = await new WechatAdmissionService(context).ProvisionAsync(app, OpenId, TestContext.Current.CancellationToken);
        }

        Assert.True(first.AccountCreated);
        Assert.True(first.Access.IsActive);

        WechatAdmission second;
        await using (var context = CreateContext())
        {
            second = await new WechatAdmissionService(context).ProvisionAsync(app, OpenId, TestContext.Current.CancellationToken);
        }

        Assert.False(second.AccountCreated);
        Assert.Equal(first.Account.Id, second.Account.Id);

        await using var verify = CreateContext();
        Assert.Single(await verify.UserLogins.AsNoTracking().ToListAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Single(await verify.AppWechatAccesses.AsNoTracking().ToListAsync(cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Bind_AttachesOpenIdToTheAuthenticatedAccount()
    {
        var app = await SeedAppAsync(WechatLoginMode.BindRequired);
        var accountId = await SeedAccountAsync();

        await using (var context = CreateContext())
        {
            var result = await new WechatAdmissionService(context).BindAsync(app, accountId, OpenId, TestContext.Current.CancellationToken);
            Assert.True(result.IsSuccess);
        }

        await using var verify = CreateContext();
        var admission = await new WechatAdmissionService(verify).FindAsync(app.Id, OpenId, TestContext.Current.CancellationToken);
        Assert.NotNull(admission);
        Assert.Equal(accountId, admission!.Account.Id);
        Assert.Equal(WechatAccessApprovalSource.SelfBind, admission.Access.ApprovalSource);
    }

    [Fact]
    public async Task Bind_WhenAuditInsertFails_RollsBackBindingAndAdmission()
    {
        var app = await SeedAppAsync(WechatLoginMode.BindRequired);
        var accountId = await SeedAccountAsync();

        await using (var context = CreateContext())
        {
            await context.Database.ExecuteSqlRawAsync(
                """
                CREATE TRIGGER fail_wechat_bind_audit
                BEFORE INSERT ON audit_logs
                BEGIN
                    SELECT RAISE(ABORT, 'audit insert failed');
                END;
                """,
                TestContext.Current.CancellationToken);
            var auditService = new AuditService(
                new LoginHistoryRepository(context),
                new AuditLogRepository(context));

            await Assert.ThrowsAsync<DbUpdateException>(() =>
                new WechatAdmissionService(context).BindAsync(
                    app,
                    accountId,
                    OpenId,
                    TestContext.Current.CancellationToken,
                    _ => auditService.RecordActionAsync(
                        "wechat_bound",
                        "Account",
                        accountId.ToString(),
                        accountId,
                        null,
                        $"WeChat identity bound for application {app.AppId}",
                        cancellationToken: TestContext.Current.CancellationToken)));
        }

        await using var verify = CreateContext();
        Assert.Empty(await verify.UserLogins.AsNoTracking().ToListAsync(
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Empty(await verify.AppWechatAccesses.AsNoTracking().ToListAsync(
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Empty(await verify.AuditLogs.AsNoTracking().ToListAsync(
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Bind_WhenCanceledAfterAuditStaging_RollsBackBindingAdmissionAndAudit()
    {
        var app = await SeedAppAsync(WechatLoginMode.BindRequired);
        var accountId = await SeedAccountAsync();
        using var cancellation = new CancellationTokenSource();

        await using (var context = CreateContext())
        {
            var auditRepository = new CapturingAuditLogRepository(new AuditLogRepository(context));
            var auditService = new AuditService(
                new LoginHistoryRepository(context),
                auditRepository);

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                new WechatAdmissionService(context).BindAsync(
                    app,
                    accountId,
                    OpenId,
                    cancellation.Token,
                    async _ =>
                    {
                        await auditService.RecordActionAsync(
                            "wechat_bound",
                            "Account",
                            accountId.ToString(),
                            accountId,
                            null,
                            $"WeChat identity bound for application {app.AppId}",
                            cancellationToken: cancellation.Token);
                        cancellation.Cancel();
                    }));

            Assert.Equal(cancellation.Token, auditRepository.ObservedCancellationToken);
        }

        await using var verify = CreateContext();
        Assert.Empty(await verify.UserLogins.AsNoTracking().ToListAsync(
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Empty(await verify.AppWechatAccesses.AsNoTracking().ToListAsync(
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Empty(await verify.AuditLogs.AsNoTracking().ToListAsync(
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Bind_RejectsAnOpenIdThatBelongsToAnotherAccount()
    {
        var app = await SeedAppAsync(WechatLoginMode.BindRequired);
        var firstAccount = await SeedAccountAsync();
        var secondAccount = await SeedAccountAsync();

        await using (var context = CreateContext())
        {
            await new WechatAdmissionService(context).BindAsync(app, firstAccount, OpenId, TestContext.Current.CancellationToken);
        }

        await using (var context = CreateContext())
        {
            var result = await new WechatAdmissionService(context).BindAsync(app, secondAccount, OpenId, TestContext.Current.CancellationToken);
            Assert.Equal(WechatBindOutcome.OpenIdAlreadyBound, result.Outcome);
        }

        await using var verify = CreateContext();
        var login = Assert.Single(await verify.UserLogins.AsNoTracking().ToListAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(firstAccount, login.AccountId);
    }

    [Fact]
    public async Task Bind_RejectsASecondOpenIdForTheSameAccount()
    {
        var app = await SeedAppAsync(WechatLoginMode.BindRequired);
        var accountId = await SeedAccountAsync();

        await using (var context = CreateContext())
        {
            await new WechatAdmissionService(context).BindAsync(app, accountId, OpenId, TestContext.Current.CancellationToken);
        }

        await using (var context = CreateContext())
        {
            var result = await new WechatAdmissionService(context).BindAsync(app, accountId, "o-another-openid",
                TestContext.Current.CancellationToken);
            Assert.Equal(WechatBindOutcome.AccountAlreadyBound, result.Outcome);
        }
    }

    [Fact]
    public async Task Bind_IsRejectedForADisabledAccount()
    {
        var app = await SeedAppAsync(WechatLoginMode.BindRequired);
        var accountId = await SeedAccountAsync(isActive: false);

        await using var context = CreateContext();
        var result = await new WechatAdmissionService(context).BindAsync(app, accountId, OpenId, TestContext.Current.CancellationToken);

        Assert.Equal(WechatBindOutcome.AccountUnavailable, result.Outcome);
    }

    /// <summary>
    /// A revocation is administrator state: neither signing in again (AutoProvision) nor rebinding
    /// as the user restores it. Otherwise
    /// DELETE /api/admin/apps/{appId}/wechat-users/{loginId} would be a mere suggestion — a user
    /// could sign in another way, rebind once, and unblock themselves. Only an administrator can
    /// restore it.
    /// </summary>
    [Fact]
    public async Task RevokedAccess_IsRestoredByNeitherReloginNorRebinding()
    {
        var app = await SeedAppAsync(WechatLoginMode.AutoProvision);
        Guid accountId;
        await using (var context = CreateContext())
        {
            accountId = (await new WechatAdmissionService(context).ProvisionAsync(app, OpenId, TestContext.Current.CancellationToken)).Account.Id;
        }

        await using (var context = CreateContext())
        {
            var access = await context.AppWechatAccesses.SingleAsync(cancellationToken: TestContext.Current.CancellationToken);
            access.IsActive = false;
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await using (var context = CreateContext())
        {
            var admission = await new WechatAdmissionService(context).ProvisionAsync(app, OpenId, TestContext.Current.CancellationToken);
            Assert.False(admission.Access.IsActive);
        }

        await using (var context = CreateContext())
        {
            var result = await new WechatAdmissionService(context).BindAsync(app, accountId, OpenId, TestContext.Current.CancellationToken);
            Assert.Equal(WechatBindOutcome.AccessRevoked, result.Outcome);
        }

        await using var verify = CreateContext();
        Assert.False((await verify.AppWechatAccesses.AsNoTracking().SingleAsync(cancellationToken: TestContext.Current.CancellationToken)).IsActive);
    }

    [Fact]
    public async Task Unbind_RemovesTheBindingAndCascadesApplicationAdmissions()
    {
        var app = await SeedAppAsync(WechatLoginMode.AutoProvision);
        Guid accountId;
        await using (var context = CreateContext())
        {
            accountId = (await new WechatAdmissionService(context).ProvisionAsync(app, OpenId, TestContext.Current.CancellationToken)).Account.Id;
        }

        await using (var context = CreateContext())
        {
            Assert.True(await new WechatAdmissionService(context).UnbindAsync(accountId, TestContext.Current.CancellationToken));
        }

        await using var verify = CreateContext();
        Assert.Empty(await verify.UserLogins.AsNoTracking().ToListAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Empty(await verify.AppWechatAccesses.AsNoTracking().ToListAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.NotNull(await verify.Accounts.AsNoTracking().SingleOrDefaultAsync(item => item.Id == accountId,
            cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Unbind_ReportsFalseWhenNothingIsBound()
    {
        await SeedAppAsync(WechatLoginMode.BindRequired);
        var accountId = await SeedAccountAsync();

        await using var context = CreateContext();
        Assert.False(await new WechatAdmissionService(context).UnbindAsync(accountId, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Unbind_WhenCanceledAfterAuditStaging_RollsBackRemovalAndAudit()
    {
        var app = await SeedAppAsync(WechatLoginMode.AutoProvision);
        Guid accountId;
        await using (var context = CreateContext())
        {
            accountId = (await new WechatAdmissionService(context).ProvisionAsync(
                app, OpenId, TestContext.Current.CancellationToken)).Account.Id;
        }
        using var cancellation = new CancellationTokenSource();

        await using (var context = CreateContext())
        {
            var auditRepository = new CapturingAuditLogRepository(new AuditLogRepository(context));
            var auditService = new AuditService(
                new LoginHistoryRepository(context),
                auditRepository);

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                new WechatAdmissionService(context).UnbindAsync(
                    accountId,
                    cancellation.Token,
                    async () =>
                    {
                        await auditService.RecordActionAsync(
                            "wechat_unbound",
                            "Account",
                            accountId.ToString(),
                            accountId,
                            null,
                            "WeChat identity unbound",
                            cancellationToken: cancellation.Token);
                        cancellation.Cancel();
                    }));

            Assert.Equal(cancellation.Token, auditRepository.ObservedCancellationToken);
        }

        await using var verify = CreateContext();
        Assert.NotNull(await verify.UserLogins.AsNoTracking().SingleOrDefaultAsync(
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.NotNull(await verify.AppWechatAccesses.AsNoTracking().SingleOrDefaultAsync(
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Empty(await verify.AuditLogs.AsNoTracking().ToListAsync(
            cancellationToken: TestContext.Current.CancellationToken));
    }

    private IdentityDbContext CreateContext()
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseSqlite(
            $"Data Source={_databasePath};Default Timeout=30",
            providerOptions => providerOptions.MigrationsAssembly("SignaCore.Database.Migrations.Sqlite"));
        return new IdentityDbContext(optionsBuilder.Options);
    }

    private async Task<AppRegistrationEntity> SeedAppAsync(WechatLoginMode mode)
    {
        await using var context = CreateContext();
        await context.Database.MigrateAsync();
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "wechat-contract-app",
            AppSecretHash = "hash",
            AppName = "WeChat contract app",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            WechatLoginMode = mode
        };
        context.AppRegistrations.Add(app);
        await context.SaveChangesAsync();
        return app;
    }

    private async Task<Guid> SeedAccountAsync(bool isActive = true)
    {
        await using var context = CreateContext();
        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            IsActive = isActive,
            CreatedAt = DateTimeOffset.UtcNow
        };
        context.Accounts.Add(account);
        await context.SaveChangesAsync();
        return account.Id;
    }

    private sealed class CapturingAuditLogRepository(IAuditLogRepository inner) : IAuditLogRepository
    {
        public CancellationToken ObservedCancellationToken { get; private set; }

        public Task AddAsync(AuditLogEntity auditLog, CancellationToken cancellationToken = default)
        {
            ObservedCancellationToken = cancellationToken;
            return inner.AddAsync(auditLog, cancellationToken);
        }

        public Task<List<AuditLogEntity>> QueryAsync(
            string? action,
            string? targetType,
            string? targetId,
            Guid? actorId,
            int pageSize,
            int skip,
            CancellationToken cancellationToken = default) =>
            inner.QueryAsync(action, targetType, targetId, actorId, pageSize, skip, cancellationToken);

        public Task<int> CountAsync(
            string? action,
            string? targetType,
            string? targetId,
            Guid? actorId,
            CancellationToken cancellationToken = default) =>
            inner.CountAsync(action, targetType, targetId, actorId, cancellationToken);

        public Task<int> RemoveOlderThanAsync(
            DateTimeOffset cutoff,
            CancellationToken cancellationToken = default) =>
            inner.RemoveOlderThanAsync(cutoff, cancellationToken);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (File.Exists(_databasePath))
        {
            File.Delete(_databasePath);
        }
    }
}
