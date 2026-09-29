using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services.Sms;

public interface ISmsAdmissionService
{
    Task<SmsAdmission?> FindAsync(Guid appRegistrationId, string phoneE164, CancellationToken cancellationToken = default);
    Task<SmsAdmission?> FindByLoginIdAsync(Guid appRegistrationId, Guid userLoginId, CancellationToken cancellationToken = default);

    /// <summary>
    /// The read-only browser SMS send eligibility of a normalized phone for one application under
    /// its current, enabled <paramref name="mode"/> (canonical "send eligibility"). The checks run
    /// in one fixed order and the first failing one decides: no SMS identity, a disabled account,
    /// no admission row, an inactive admission, and under <see cref="SmsLoginMode.ManualApproval"/>
    /// an admission that is not Admin-approved. Under <see cref="SmsLoginMode.AutoProvision"/> a
    /// missing identity or admission is eligible; nothing is provisioned here. The caller gates
    /// <see cref="SmsLoginMode.Disabled"/> before asking.
    /// </summary>
    Task<SmsSendEligibilityResult> EvaluateSendEligibilityAsync(
        Guid appRegistrationId,
        SmsLoginMode mode,
        string phoneE164,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The read-only <c>PS-04</c> SMS admission predicate of one <c>Sms</c> identity session for
    /// one application, read live at every application operation (<c>EV-38</c>): the application's
    /// current <paramref name="mode"/> is not <see cref="SmsLoginMode.Disabled"/>, an admission row
    /// for the application and the session's SMS login identity exists and is active, and under
    /// <see cref="SmsLoginMode.ManualApproval"/> it is Admin-approved. The SMS profile is not part
    /// of the predicate. The account-active term is the caller's existing account check and is not
    /// repeated here. The read is untracked and never provisions, approves, or writes.
    /// </summary>
    Task<bool> IsSessionAdmittedAsync(
        Guid appRegistrationId,
        SmsLoginMode mode,
        Guid smsUserLoginId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves the SMS identity of a normalized phone for one browser SMS login inside the
    /// caller's open transaction (<c>EV-36</c>, <c>SC-23</c>), and under
    /// <see cref="SmsLoginMode.AutoProvision"/> stages what is missing: a new active account with
    /// its SMS identity when the phone has none, and an <see cref="SmsAccessApprovalSource.AutoProvision"/>
    /// admission when the identity's active account has no admission row for the application. An
    /// existing admission row is never reactivated, re-sourced, or otherwise changed, and nothing
    /// is staged for a disabled account. Under <see cref="SmsLoginMode.ManualApproval"/> nothing is
    /// ever staged. Returns <c>null</c> when the mode is not enabled or when no identity exists and
    /// none may be created.
    /// <para>
    /// Unlike <see cref="ProvisionAsync"/>, this method opens no transaction and never saves: the
    /// staged rows commit or roll back with the caller's unit, whose flush is where a concurrent
    /// provisioning of the same phone surfaces as a unique-key violation. The caller rechecks the
    /// <c>PS-04</c> predicate and the account after its flush.
    /// </para>
    /// </summary>
    /// <exception cref="InvalidOperationException">No ambient transaction exists.</exception>
    Task<SmsLoginIdentity?> FindOrStageLoginIdentityAsync(
        Guid appRegistrationId,
        SmsLoginMode mode,
        string phoneE164,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Provisions the admission and invokes <paramref name="beforeCommit"/> after state is staged but
    /// before the service's single transactional commit.
    /// </summary>
    Task<SmsAdmission> ProvisionAsync(
        AppRegistrationEntity app,
        string phoneE164,
        SmsAccessApprovalSource source,
        Guid? approvedBy,
        CancellationToken cancellationToken = default,
        Func<SmsAdmission, Task>? beforeCommit = null);

    /// <summary>
    /// Admits an existing SMS login for <paramref name="app"/> without verifying an OTP, for an
    /// admission derived from one the account already holds elsewhere. Returns null when the login
    /// is not an SMS login of an existing account. An existing admission row is returned unchanged,
    /// including a revoked one — restoring a revoked admission is an administrator action.
    /// </summary>
    Task<SmsAdmission?> GrantByLoginIdAsync(
        AppRegistrationEntity app,
        Guid userLoginId,
        SmsAccessApprovalSource source,
        CancellationToken cancellationToken = default);
}

public sealed record SmsAdmission(
    AccountEntity Account,
    UserLoginEntity Login,
    AppSmsAccessEntity Access,
    bool AccountCreated = false);

/// <summary>
/// The SMS identity one browser SMS login resolved or staged: the account, the SMS
/// <c>user_logins</c> row the new <c>Sms</c> session references, and whether the account was
/// staged by this call (for the <c>auto_register_sms</c> account-creation metric after commit).
/// </summary>
public sealed record SmsLoginIdentity(Guid AccountId, Guid UserLoginId, bool AccountCreated);

/// <summary>
/// The closed browser SMS send eligibility decision. Every value except
/// <see cref="Eligible"/> names the first failing check in the fixed evaluation order.
/// </summary>
public enum SmsSendEligibility
{
    Eligible,
    NotRegistered,
    AccountDisabled,
    NotAdmitted,
    AdmissionInactive,
    NotAdminApproved
}

/// <summary>
/// One eligibility decision. <paramref name="AccountId"/> is the account of the phone's SMS
/// identity when one resolved, for the masked audit row; it is never shown to the browser.
/// </summary>
public sealed record SmsSendEligibilityResult(SmsSendEligibility Decision, Guid? AccountId);

public sealed class SmsAdmissionService : ISmsAdmissionService
{
    private readonly IdentityDbContext _dbContext;

    public SmsAdmissionService(IdentityDbContext dbContext) => _dbContext = dbContext;

    public async Task<SmsAdmission?> FindAsync(
        Guid appRegistrationId,
        string phoneE164,
        CancellationToken cancellationToken = default)
    {
        var phone = MainlandChinaPhoneNumber.Normalize(phoneE164);
        var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodSms);
        var item = await _dbContext.UserLogins
            .Where(login => login.ProviderNameNormalized == provider && login.ProviderUserId == phone)
            .Join(_dbContext.Accounts, login => login.AccountId, account => account.Id, (login, account) => new { login, account })
            .Join(_dbContext.AppSmsAccesses.Where(access => access.AppRegistrationId == appRegistrationId),
                item => item.login.Id, access => access.UserLoginId, (item, access) => new { item.login, item.account, access })
            .FirstOrDefaultAsync(cancellationToken);
        return item == null ? null : new SmsAdmission(item.account, item.login, item.access);
    }

    public async Task<SmsAdmission?> FindByLoginIdAsync(
        Guid appRegistrationId,
        Guid userLoginId,
        CancellationToken cancellationToken = default)
    {
        var item = await _dbContext.UserLogins
            .Where(login => login.Id == userLoginId)
            .Join(_dbContext.Accounts, login => login.AccountId, account => account.Id, (login, account) => new { login, account })
            .Join(_dbContext.AppSmsAccesses.Where(access => access.AppRegistrationId == appRegistrationId),
                value => value.login.Id, access => access.UserLoginId, (value, access) => new { value.login, value.account, access })
            .FirstOrDefaultAsync(cancellationToken);
        return item == null ? null : new SmsAdmission(item.account, item.login, item.access);
    }

    public async Task<SmsSendEligibilityResult> EvaluateSendEligibilityAsync(
        Guid appRegistrationId,
        SmsLoginMode mode,
        string phoneE164,
        CancellationToken cancellationToken = default)
    {
        if (mode is not (SmsLoginMode.ManualApproval or SmsLoginMode.AutoProvision))
        {
            throw new ArgumentOutOfRangeException(
                nameof(mode), "Send eligibility is evaluated only for an application whose SMS login is enabled.");
        }

        var manualApproval = mode == SmsLoginMode.ManualApproval;
        var phone = MainlandChinaPhoneNumber.Normalize(phoneE164);
        var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodSms);

        // Reads only, untracked: a send never provisions, approves, or otherwise writes here.
        var identity = await _dbContext.UserLogins
            .AsNoTracking()
            .Where(login => login.ProviderNameNormalized == provider && login.ProviderUserId == phone)
            .Join(_dbContext.Accounts.AsNoTracking(), login => login.AccountId, account => account.Id,
                (login, account) => new { LoginId = login.Id, AccountId = account.Id, account.IsActive })
            .FirstOrDefaultAsync(cancellationToken);
        if (identity is null)
        {
            return new SmsSendEligibilityResult(
                manualApproval ? SmsSendEligibility.NotRegistered : SmsSendEligibility.Eligible,
                AccountId: null);
        }

        if (!identity.IsActive)
        {
            return new SmsSendEligibilityResult(SmsSendEligibility.AccountDisabled, identity.AccountId);
        }

        var access = await _dbContext.AppSmsAccesses
            .AsNoTracking()
            .Where(row => row.AppRegistrationId == appRegistrationId && row.UserLoginId == identity.LoginId)
            .Select(row => new { row.IsActive, row.ApprovalSource })
            .FirstOrDefaultAsync(cancellationToken);
        var decision = access switch
        {
            null => manualApproval ? SmsSendEligibility.NotAdmitted : SmsSendEligibility.Eligible,
            { IsActive: false } => SmsSendEligibility.AdmissionInactive,
            _ when manualApproval && access.ApprovalSource != SmsAccessApprovalSource.Admin =>
                SmsSendEligibility.NotAdminApproved,
            _ => SmsSendEligibility.Eligible
        };
        return new SmsSendEligibilityResult(decision, identity.AccountId);
    }

    public async Task<bool> IsSessionAdmittedAsync(
        Guid appRegistrationId,
        SmsLoginMode mode,
        Guid smsUserLoginId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (mode is not (SmsLoginMode.ManualApproval or SmsLoginMode.AutoProvision))
        {
            return false;
        }

        var requireAdminApproval = mode == SmsLoginMode.ManualApproval;
        return await _dbContext.AppSmsAccesses
            .AsNoTracking()
            .AnyAsync(
                row => row.AppRegistrationId == appRegistrationId
                    && row.UserLoginId == smsUserLoginId
                    && row.IsActive
                    && (!requireAdminApproval || row.ApprovalSource == SmsAccessApprovalSource.Admin),
                cancellationToken);
    }

    public async Task<SmsLoginIdentity?> FindOrStageLoginIdentityAsync(
        Guid appRegistrationId,
        SmsLoginMode mode,
        string phoneE164,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_dbContext.Database.CurrentTransaction is null)
        {
            throw new InvalidOperationException("SMS login provisioning requires the caller's transaction.");
        }

        if (mode is not (SmsLoginMode.ManualApproval or SmsLoginMode.AutoProvision))
        {
            return null;
        }

        var phone = MainlandChinaPhoneNumber.Normalize(phoneE164);
        var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodSms);
        var login = await _dbContext.UserLogins.FirstOrDefaultAsync(
            item => item.ProviderNameNormalized == provider && item.ProviderUserId == phone,
            cancellationToken);
        if (mode != SmsLoginMode.AutoProvision)
        {
            return login is null ? null : new SmsLoginIdentity(login.AccountId, login.Id, AccountCreated: false);
        }

        if (login is null)
        {
            var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = now };
            login = new UserLoginEntity
            {
                Id = Guid.NewGuid(),
                AccountId = account.Id,
                ProviderName = IdentityConstants.AuthMethodSms,
                ProviderUserId = phone
            };
            _dbContext.Accounts.Add(account);
            _dbContext.UserLogins.Add(login);
            StageAutoProvisionAdmission(appRegistrationId, login.Id, now);
            return new SmsLoginIdentity(account.Id, login.Id, AccountCreated: true);
        }

        var accountActive = await _dbContext.Accounts
            .Where(item => item.Id == login.AccountId)
            .Select(item => item.IsActive)
            .FirstOrDefaultAsync(cancellationToken);
        if (accountActive && !await _dbContext.AppSmsAccesses.AnyAsync(
                item => item.AppRegistrationId == appRegistrationId && item.UserLoginId == login.Id,
                cancellationToken))
        {
            StageAutoProvisionAdmission(appRegistrationId, login.Id, now);
        }

        return new SmsLoginIdentity(login.AccountId, login.Id, AccountCreated: false);
    }

    private void StageAutoProvisionAdmission(Guid appRegistrationId, Guid userLoginId, DateTimeOffset now) =>
        _dbContext.AppSmsAccesses.Add(new AppSmsAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = appRegistrationId,
            UserLoginId = userLoginId,
            ApprovalSource = SmsAccessApprovalSource.AutoProvision,
            IsActive = true,
            ApprovedBy = null,
            CreatedAt = now
        });

    public async Task<SmsAdmission> ProvisionAsync(
        AppRegistrationEntity app,
        string phoneE164,
        SmsAccessApprovalSource source,
        Guid? approvedBy,
        CancellationToken cancellationToken = default,
        Func<SmsAdmission, Task>? beforeCommit = null)
    {
        var phone = MainlandChinaPhoneNumber.Normalize(phoneE164);
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
                    var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodSms);
                    var login = await _dbContext.UserLogins.FirstOrDefaultAsync(item =>
                        item.ProviderNameNormalized == provider && item.ProviderUserId == phone, operationCancellationToken);
                    AccountEntity account;
                    var accountCreated = login == null;
                    if (login == null)
                    {
                        account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
                        login = new UserLoginEntity
                        {
                            Id = Guid.NewGuid(),
                            AccountId = account.Id,
                            ProviderName = IdentityConstants.AuthMethodSms,
                            ProviderUserId = phone
                        };
                        _dbContext.Accounts.Add(account);
                        _dbContext.UserLogins.Add(login);
                    }
                    else
                    {
                        account = await _dbContext.Accounts.SingleAsync(item => item.Id == login.AccountId, operationCancellationToken);
                    }

                    var access = await _dbContext.AppSmsAccesses.FirstOrDefaultAsync(item =>
                        item.AppRegistrationId == app.Id && item.UserLoginId == login.Id, operationCancellationToken);
                    if (access == null)
                    {
                        access = new AppSmsAccessEntity
                        {
                            Id = Guid.NewGuid(),
                            AppRegistrationId = app.Id,
                            UserLoginId = login.Id,
                            ApprovalSource = source,
                            IsActive = true,
                            ApprovedBy = approvedBy,
                            CreatedAt = DateTimeOffset.UtcNow
                        };
                        _dbContext.AppSmsAccesses.Add(access);
                    }
                    else if (source == SmsAccessApprovalSource.Admin)
                    {
                        access.ApprovalSource = source;
                        access.IsActive = true;
                        access.ApprovedBy = approvedBy;
                    }

                    var result = new SmsAdmission(account, login, access, accountCreated);
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

        throw new InvalidOperationException("SMS account provisioning failed after a concurrent update.");
    }

    public async Task<SmsAdmission?> GrantByLoginIdAsync(
        AppRegistrationEntity app,
        Guid userLoginId,
        SmsAccessApprovalSource source,
        CancellationToken cancellationToken = default)
    {
        var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodSms);
        var item = await _dbContext.UserLogins
            .Where(login => login.Id == userLoginId && login.ProviderNameNormalized == provider)
            .Join(_dbContext.Accounts, login => login.AccountId, account => account.Id,
                (login, account) => new { login, account })
            .FirstOrDefaultAsync(cancellationToken);
        if (item == null) return null;

        var access = await _dbContext.AppSmsAccesses.FirstOrDefaultAsync(
            row => row.AppRegistrationId == app.Id && row.UserLoginId == userLoginId, cancellationToken);
        if (access == null)
        {
            access = new AppSmsAccessEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = app.Id,
                UserLoginId = userLoginId,
                ApprovalSource = source,
                IsActive = true,
                ApprovedBy = null,
                CreatedAt = DateTimeOffset.UtcNow
            };
            _dbContext.AppSmsAccesses.Add(access);
            try
            {
                await _dbContext.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException)
            {
                // Two exchanges for the same identity raced. The unique index decided; re-read the
                // winner rather than failing a request that got the outcome it asked for.
                _dbContext.ChangeTracker.Clear();
                access = await _dbContext.AppSmsAccesses.AsNoTracking().FirstOrDefaultAsync(
                    row => row.AppRegistrationId == app.Id && row.UserLoginId == userLoginId,
                    cancellationToken);
                if (access == null) throw;
            }
        }

        return new SmsAdmission(item.account, item.login, access);
    }
}
