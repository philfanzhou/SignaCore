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
            first = await new WechatAdmissionService(context).ProvisionAsync(app, OpenId);
        }

        Assert.True(first.AccountCreated);
        Assert.True(first.Access.IsActive);

        WechatAdmission second;
        await using (var context = CreateContext())
        {
            second = await new WechatAdmissionService(context).ProvisionAsync(app, OpenId);
        }

        Assert.False(second.AccountCreated);
        Assert.Equal(first.Account.Id, second.Account.Id);

        await using var verify = CreateContext();
        Assert.Single(await verify.UserLogins.AsNoTracking().ToListAsync());
        Assert.Single(await verify.AppWechatAccesses.AsNoTracking().ToListAsync());
    }

    [Fact]
    public async Task Bind_AttachesOpenIdToTheAuthenticatedAccount()
    {
        var app = await SeedAppAsync(WechatLoginMode.BindRequired);
        var accountId = await SeedAccountAsync();

        await using (var context = CreateContext())
        {
            var result = await new WechatAdmissionService(context).BindAsync(app, accountId, OpenId);
            Assert.True(result.IsSuccess);
        }

        await using var verify = CreateContext();
        var admission = await new WechatAdmissionService(verify).FindAsync(app.Id, OpenId);
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
            await new WechatAdmissionService(context).BindAsync(app, firstAccount, OpenId);
        }

        await using (var context = CreateContext())
        {
            var result = await new WechatAdmissionService(context).BindAsync(app, secondAccount, OpenId);
            Assert.Equal(WechatBindOutcome.OpenIdAlreadyBound, result.Outcome);
        }

        await using var verify = CreateContext();
        var login = Assert.Single(await verify.UserLogins.AsNoTracking().ToListAsync());
        Assert.Equal(firstAccount, login.AccountId);
    }

    [Fact]
    public async Task Bind_RejectsASecondOpenIdForTheSameAccount()
    {
        var app = await SeedAppAsync(WechatLoginMode.BindRequired);
        var accountId = await SeedAccountAsync();

        await using (var context = CreateContext())
        {
            await new WechatAdmissionService(context).BindAsync(app, accountId, OpenId);
        }

        await using (var context = CreateContext())
        {
            var result = await new WechatAdmissionService(context).BindAsync(app, accountId, "o-another-openid");
            Assert.Equal(WechatBindOutcome.AccountAlreadyBound, result.Outcome);
        }
    }

    [Fact]
    public async Task Bind_IsRejectedForADisabledAccount()
    {
        var app = await SeedAppAsync(WechatLoginMode.BindRequired);
        var accountId = await SeedAccountAsync(isActive: false);

        await using var context = CreateContext();
        var result = await new WechatAdmissionService(context).BindAsync(app, accountId, OpenId);

        Assert.Equal(WechatBindOutcome.AccountUnavailable, result.Outcome);
    }

    /// <summary>撤销后再登录不得自动恢复；只有用户重新绑定才恢复。</summary>
    [Fact]
    public async Task RevokedAccess_SurvivesAutoProvision_ButIsRestoredByRebinding()
    {
        var app = await SeedAppAsync(WechatLoginMode.AutoProvision);
        Guid accountId;
        await using (var context = CreateContext())
        {
            accountId = (await new WechatAdmissionService(context).ProvisionAsync(app, OpenId)).Account.Id;
        }

        await using (var context = CreateContext())
        {
            var access = await context.AppWechatAccesses.SingleAsync();
            access.IsActive = false;
            await context.SaveChangesAsync();
        }

        await using (var context = CreateContext())
        {
            var admission = await new WechatAdmissionService(context).ProvisionAsync(app, OpenId);
            Assert.False(admission.Access.IsActive);
        }

        await using (var context = CreateContext())
        {
            var result = await new WechatAdmissionService(context).BindAsync(app, accountId, OpenId);
            Assert.True(result.IsSuccess);
        }

        await using var verify = CreateContext();
        Assert.True((await verify.AppWechatAccesses.AsNoTracking().SingleAsync()).IsActive);
    }

    [Fact]
    public async Task Unbind_RemovesTheBindingAndCascadesApplicationAdmissions()
    {
        var app = await SeedAppAsync(WechatLoginMode.AutoProvision);
        Guid accountId;
        await using (var context = CreateContext())
        {
            accountId = (await new WechatAdmissionService(context).ProvisionAsync(app, OpenId)).Account.Id;
        }

        await using (var context = CreateContext())
        {
            Assert.True(await new WechatAdmissionService(context).UnbindAsync(accountId));
        }

        await using var verify = CreateContext();
        Assert.Empty(await verify.UserLogins.AsNoTracking().ToListAsync());
        Assert.Empty(await verify.AppWechatAccesses.AsNoTracking().ToListAsync());
        Assert.NotNull(await verify.Accounts.AsNoTracking().SingleOrDefaultAsync(item => item.Id == accountId));
    }

    [Fact]
    public async Task Unbind_ReportsFalseWhenNothingIsBound()
    {
        await SeedAppAsync(WechatLoginMode.BindRequired);
        var accountId = await SeedAccountAsync();

        await using var context = CreateContext();
        Assert.False(await new WechatAdmissionService(context).UnbindAsync(accountId));
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
