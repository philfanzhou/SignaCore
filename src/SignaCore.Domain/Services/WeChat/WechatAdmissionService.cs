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

    /// <summary>
    /// Binds an OpenId to an already-authenticated account and admits it for the calling application.
    /// A previously revoked admission is not restored — see <see cref="WechatBindOutcome.AccessRevoked"/>.
    /// <paramref name="beforeCommit"/> runs after a successful result is staged and before commit.
    /// </summary>
    Task<WechatBindResult> BindAsync(
        AppRegistrationEntity app,
        Guid accountId,
        string openId,
        CancellationToken cancellationToken = default,
        Func<WechatBindResult, Task>? beforeCommit = null);

    /// <summary>
    /// Admits an existing WeChat login for <paramref name="app"/> without a WeChat authorization, for
    /// an admission derived from one the account already holds elsewhere. Returns null when the login
    /// is not a WeChat login of an existing account. An existing admission row is returned unchanged,
    /// including a revoked one — restoring a revoked admission is an administrator action.
    /// </summary>
    Task<WechatAdmission?> GrantByLoginIdAsync(
        AppRegistrationEntity app,
        Guid userLoginId,
        WechatAccessApprovalSource source,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes the account's WeChat binding and every application admission that depends on it.
    /// <paramref name="beforeCommit"/> runs after removal is staged and before commit.
    /// </summary>
    Task<bool> UnbindAsync(
        Guid accountId,
        CancellationToken cancellationToken = default,
        Func<Task>? beforeCommit = null);

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
    AccountUnavailable = 3,

    /// <summary>An administrator revoked this application's admission; only an administrator restores it.</summary>
    AccessRevoked = 4
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

    public async Task<WechatAdmission?> GrantByLoginIdAsync(
        AppRegistrationEntity app,
        Guid userLoginId,
        WechatAccessApprovalSource source,
        CancellationToken cancellationToken = default)
    {
        var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodWechat);
        var item = await _dbContext.UserLogins
            .Where(login => login.Id == userLoginId && login.ProviderNameNormalized == provider)
            .Join(_dbContext.Accounts, login => login.AccountId, account => account.Id,
                (login, account) => new { login, account })
            .FirstOrDefaultAsync(cancellationToken);
        if (item == null) return null;

        var access = await _dbContext.AppWechatAccesses.FirstOrDefaultAsync(
            row => row.AppRegistrationId == app.Id && row.UserLoginId == userLoginId, cancellationToken);
        if (access == null)
        {
            access = new AppWechatAccessEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = app.Id,
                UserLoginId = userLoginId,
                ApprovalSource = source,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            };
            _dbContext.AppWechatAccesses.Add(access);
            try
            {
                await _dbContext.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException)
            {
                // Two exchanges for the same identity raced. The unique index decided; re-read the
                // winner rather than failing a request that got the outcome it asked for.
                _dbContext.ChangeTracker.Clear();
                access = await _dbContext.AppWechatAccesses.AsNoTracking().FirstOrDefaultAsync(
                    row => row.AppRegistrationId == app.Id && row.UserLoginId == userLoginId,
                    cancellationToken);
                if (access == null) throw;
            }
        }

        return new WechatAdmission(item.account, item.login, access);
    }

    public Task<WechatAdmission> ProvisionAsync(
        AppRegistrationEntity app,
        string openId,
        CancellationToken cancellationToken = default) =>
        ExecuteWithRetryAsync(async operationCancellationToken =>
        {
            var login = await FindLoginAsync(openId, operationCancellationToken);
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
                account = await _dbContext.Accounts.SingleAsync(item => item.Id == login.AccountId, operationCancellationToken);
            }

            var access = await EnsureAccessAsync(
                app.Id, login.Id, WechatAccessApprovalSource.AutoProvision, operationCancellationToken);
            return new WechatAdmission(account, login, access, accountCreated);
        }, cancellationToken);

    public async Task<WechatBindResult> BindAsync(
        AppRegistrationEntity app,
        Guid accountId,
        string openId,
        CancellationToken cancellationToken = default,
        Func<WechatBindResult, Task>? beforeCommit = null)
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

        return await ExecuteWithRetryAsync(async operationCancellationToken =>
        {
            var login = await FindLoginAsync(openId, operationCancellationToken);
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

            var access = await EnsureAccessAsync(
                app.Id, login.Id, WechatAccessApprovalSource.SelfBind, operationCancellationToken);
            return access.IsActive
                ? new WechatBindResult(WechatBindOutcome.Bound, login)
                : new WechatBindResult(WechatBindOutcome.AccessRevoked, login);
        }, cancellationToken, beforeCommit);
    }

    public async Task<bool> UnbindAsync(
        Guid accountId,
        CancellationToken cancellationToken = default,
        Func<Task>? beforeCommit = null)
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
        if (beforeCommit is not null)
        {
            await beforeCommit();
        }
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
        if (access != null)
        {
            // A revoked admission is administrator state and is returned as-is. Neither logging in
            // again nor re-binding may clear it: otherwise the user could undo
            // DELETE /api/admin/apps/{appId}/wechat-users/{loginId} simply by binding once more,
            // and revocation would only ever be a suggestion. Restoring is an administrator action.
            return access;
        }

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
        return access;
    }

    /// <summary>
    /// Runs <paramref name="operation"/> inside a transaction, retrying once when a concurrent
    /// writer wins the unique index. Mirrors <see cref="Sms.SmsAdmissionService"/>: the execution
    /// strategy can replay the delegate, so tracked state is cleared before every attempt.
    /// </summary>
    private async Task<T> ExecuteWithRetryAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken,
        Func<T, Task>? beforeCommit = null)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var strategy = _dbContext.Database.CreateExecutionStrategy();
                return await strategy.ExecuteAsync(async operationCancellationToken =>
                {
                    _dbContext.ChangeTracker.Clear();
                    await using var transaction = await _dbContext.Database.BeginTransactionAsync(operationCancellationToken);
                    var result = await operation(operationCancellationToken);
                    if (beforeCommit is not null)
                    {
                        await beforeCommit(result);
                    }
                    await _dbContext.SaveChangesAsync(operationCancellationToken);
                    await transaction.CommitAsync(operationCancellationToken);
                    return result;
                }, cancellationToken);
            }
            catch (DbUpdateException) when (attempt == 0)
            {
                _dbContext.ChangeTracker.Clear();
            }
        }

        throw new InvalidOperationException("WeChat account provisioning failed after a concurrent update.");
    }
}
