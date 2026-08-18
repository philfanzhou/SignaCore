using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services.WeChat;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// <see cref="WechatAdmissionService"/> 的行为几乎全部由数据库约束与事务决定
/// （provider+provider_user_id 唯一索引、app_wechat_accesses 的级联删除），
/// 所以用真实 SQLite + 生产同款迁移链来守，而不是内存 provider。
/// 类名的 <c>DatabaseContractTests</c> 后缀与 CI 的过滤保持一致。
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
    /// 撤销是管理员状态：既不能靠再次登录（AutoProvision）恢复，也不能靠用户重新绑定恢复。
    /// 否则 DELETE /api/admin/apps/{appId}/wechat-users/{loginId} 只是个建议——用户换个方式
    /// 登录进来重绑一次就自己解封了。恢复只能由管理员发起。
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

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (File.Exists(_databasePath))
        {
            File.Delete(_databasePath);
        }
    }
}
