using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services.WeChat;

public interface IWechatAdmissionService
{
    Task<WechatAdmission?> FindAsync(Guid appRegistrationId, string openId, CancellationToken cancellationToken = default);

    Task<WechatAdmission?> FindByLoginIdAsync(Guid appRegistrationId, Guid userLoginId, CancellationToken cancellationToken = default);

    /// <summary>Creates the account, the OpenId binding, and the application admission for a first-time WeChat login.</summary>
    Task<WechatAdmission> ProvisionAsync(
        AppRegistrationEntity app,
        string openId,
        CancellationToken cancellationToken = default);

    /// <summary>Binds an OpenId to an already-authenticated account and admits it for the calling application.</summary>
    Task<WechatBindResult> BindAsync(
        AppRegistrationEntity app,
        Guid accountId,
        string openId,
        CancellationToken cancellationToken = default);

    /// <summary>Removes the account's WeChat binding and every application admission that depends on it.</summary>
    Task<bool> UnbindAsync(Guid accountId, CancellationToken cancellationToken = default);

    Task<UserLoginEntity?> GetBindingAsync(Guid accountId, CancellationToken cancellationToken = default);
}

public sealed record WechatAdmission(
    AccountEntity Account,
    UserLoginEntity Login,
    AppWechatAccessEntity Access,
    bool AccountCreated = false);

public enum WechatBindOutcome
{
    Bound = 0,

    /// <summary>The OpenId is already bound to a different account.</summary>
    OpenIdAlreadyBound = 1,

    /// <summary>The account is already bound to a different OpenId.</summary>
    AccountAlreadyBound = 2,

    /// <summary>The account no longer exists or is disabled.</summary>
    AccountUnavailable = 3
}

public sealed record WechatBindResult(WechatBindOutcome Outcome, UserLoginEntity? Login = null)
{
    public bool IsSuccess => Outcome == WechatBindOutcome.Bound;
}

public sealed class WechatAdmissionService : IWechatAdmissionService
{
    private readonly IdentityDbContext _dbContext;

    public WechatAdmissionService(IdentityDbContext dbContext) => _dbContext = dbContext;

    public async Task<WechatAdmission?> FindAsync(
        Guid appRegistrationId,
        string openId,
        CancellationToken cancellationToken = default)
    {
        var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodWechat);
        var item = await _dbContext.UserLogins
            .Where(login => login.ProviderNameNormalized == provider && login.ProviderUserId == openId)
            .Join(_dbContext.Accounts, login => login.AccountId, account => account.Id, (login, account) => new { login, account })
            .Join(_dbContext.AppWechatAccesses.Where(access => access.AppRegistrationId == appRegistrationId),
                item => item.login.Id, access => access.UserLoginId, (item, access) => new { item.login, item.account, access })
            .FirstOrDefaultAsync(cancellationToken);
        return item == null ? null : new WechatAdmission(item.account, item.login, item.access);
    }

    public async Task<WechatAdmission?> FindByLoginIdAsync(
        Guid appRegistrationId,
        Guid userLoginId,
        CancellationToken cancellationToken = default)
    {
        var item = await _dbContext.UserLogins
            .Where(login => login.Id == userLoginId)
            .Join(_dbContext.Accounts, login => login.AccountId, account => account.Id, (login, account) => new { login, account })
            .Join(_dbContext.AppWechatAccesses.Where(access => access.AppRegistrationId == appRegistrationId),
                value => value.login.Id, access => access.UserLoginId, (value, access) => new { value.login, value.account, access })
            .FirstOrDefaultAsync(cancellationToken);
        return item == null ? null : new WechatAdmission(item.account, item.login, item.access);
    }

    public Task<WechatAdmission> ProvisionAsync(
        AppRegistrationEntity app,
        string openId,
        CancellationToken cancellationToken = default) =>
        ExecuteWithRetryAsync(async () =>
        {
            var login = await FindLoginAsync(openId, cancellationToken);
            AccountEntity account;
            var accountCreated = login == null;
            if (login == null)
            {
                account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
                login = NewLogin(account.Id, openId);
                _dbContext.Accounts.Add(account);
                _dbContext.UserLogins.Add(login);
            }
            else
            {
                account = await _dbContext.Accounts.SingleAsync(item => item.Id == login.AccountId, cancellationToken);
            }

            var access = await EnsureAccessAsync(
                app.Id, login.Id, WechatAccessApprovalSource.AutoProvision, cancellationToken);
            return new WechatAdmission(account, login, access, accountCreated);
        }, cancellationToken);

    public async Task<WechatBindResult> BindAsync(
        AppRegistrationEntity app,
        Guid accountId,
        string openId,
        CancellationToken cancellationToken = default)
    {
        var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodWechat);
        var existing = await FindLoginAsync(openId, cancellationToken);
        if (existing != null && existing.AccountId != accountId)
        {
            return new WechatBindResult(WechatBindOutcome.OpenIdAlreadyBound);
        }

        // A single account keeps at most one OpenId: rebinding has to go through
        // an explicit unbind so the previous binding is never silently orphaned.
        var accountBinding = await _dbContext.UserLogins
            .FirstOrDefaultAsync(
                login => login.AccountId == accountId && login.ProviderNameNormalized == provider,
                cancellationToken);
        if (accountBinding != null && accountBinding.ProviderUserId != openId)
        {
            return new WechatBindResult(WechatBindOutcome.AccountAlreadyBound);
        }

        var account = await _dbContext.Accounts.FirstOrDefaultAsync(item => item.Id == accountId, cancellationToken);
        if (account is not { IsActive: true })
        {
            return new WechatBindResult(WechatBindOutcome.AccountUnavailable);
        }

        return await ExecuteWithRetryAsync(async () =>
        {
            var login = await FindLoginAsync(openId, cancellationToken);
            if (login != null && login.AccountId != accountId)
            {
                // Lost a race against another bind between the pre-check and the transaction.
                return new WechatBindResult(WechatBindOutcome.OpenIdAlreadyBound);
            }

            if (login == null)
            {
                login = NewLogin(accountId, openId);
                _dbContext.UserLogins.Add(login);
            }

            await EnsureAccessAsync(app.Id, login.Id, WechatAccessApprovalSource.SelfBind, cancellationToken);
            return new WechatBindResult(WechatBindOutcome.Bound, login);
        }, cancellationToken);
    }

    public async Task<bool> UnbindAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodWechat);
        var login = await _dbContext.UserLogins.FirstOrDefaultAsync(
            item => item.AccountId == accountId && item.ProviderNameNormalized == provider,
            cancellationToken);
        if (login == null)
        {
            return false;
        }

        // Application admissions cascade with the binding; refresh tokens issued from
        // this identity stop validating because the admission row disappears with it.
        _dbContext.UserLogins.Remove(login);
        await _dbContext.SaveChangesAsync(cancellationToken);
        return true;
    }

    public Task<UserLoginEntity?> GetBindingAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodWechat);
        return _dbContext.UserLogins.FirstOrDefaultAsync(
            login => login.AccountId == accountId && login.ProviderNameNormalized == provider,
            cancellationToken);
    }

    private Task<UserLoginEntity?> FindLoginAsync(string openId, CancellationToken cancellationToken)
    {
        var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodWechat);
        return _dbContext.UserLogins.FirstOrDefaultAsync(
            login => login.ProviderNameNormalized == provider && login.ProviderUserId == openId,
            cancellationToken);
    }

    private static UserLoginEntity NewLogin(Guid accountId, string openId) => new()
    {
        Id = Guid.NewGuid(),
        AccountId = accountId,
        ProviderName = IdentityConstants.AuthMethodWechat,
        ProviderUserId = openId
    };

    private async Task<AppWechatAccessEntity> EnsureAccessAsync(
        Guid appRegistrationId,
        Guid userLoginId,
        WechatAccessApprovalSource source,
        CancellationToken cancellationToken)
    {
        var access = await _dbContext.AppWechatAccesses.FirstOrDefaultAsync(
            item => item.AppRegistrationId == appRegistrationId && item.UserLoginId == userLoginId,
            cancellationToken);
        if (access == null)
        {
            access = new AppWechatAccessEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = appRegistrationId,
                UserLoginId = userLoginId,
                ApprovalSource = source,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            };
            _dbContext.AppWechatAccesses.Add(access);
        }
        else if (access.IsActive)
        {
            return access;
        }
        else
        {
            // A revoked admission is only restored by an explicit user action (self-bind),
            // never by simply logging in again through auto-provisioning.
            if (source != WechatAccessApprovalSource.SelfBind)
            {
                return access;
            }

            access.IsActive = true;
            access.ApprovalSource = source;
        }

        return access;
    }

    /// <summary>
    /// Runs <paramref name="operation"/> inside a transaction, retrying once when a concurrent
    /// writer wins the unique index. Mirrors <see cref="Sms.SmsAdmissionService"/>: the execution
    /// strategy can replay the delegate, so tracked state is cleared before every attempt.
    /// </summary>
    private async Task<T> ExecuteWithRetryAsync<T>(Func<Task<T>> operation, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                var strategy = _dbContext.Database.CreateExecutionStrategy();
                return await strategy.ExecuteAsync(async () =>
                {
                    _dbContext.ChangeTracker.Clear();
                    await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
                    var result = await operation();
                    await _dbContext.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    return result;
                });
            }
            catch (DbUpdateException) when (attempt == 0)
            {
                _dbContext.ChangeTracker.Clear();
            }
        }

        throw new InvalidOperationException("WeChat account provisioning failed after a concurrent update.");
    }
}
