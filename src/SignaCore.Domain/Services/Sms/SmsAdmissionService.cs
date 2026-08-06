using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services.Sms;

public interface ISmsAdmissionService
{
    Task<SmsAdmission?> FindAsync(Guid appRegistrationId, string phoneE164, CancellationToken cancellationToken = default);
    Task<SmsAdmission?> FindByLoginIdAsync(Guid appRegistrationId, Guid userLoginId, CancellationToken cancellationToken = default);
    Task<SmsAdmission> ProvisionAsync(
        AppRegistrationEntity app,
        string phoneE164,
        SmsAccessApprovalSource source,
        Guid? approvedBy,
        CancellationToken cancellationToken = default);
}

public sealed record SmsAdmission(
    AccountEntity Account,
    UserLoginEntity Login,
    AppSmsAccessEntity Access,
    bool AccountCreated = false);

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

    public async Task<SmsAdmission> ProvisionAsync(
        AppRegistrationEntity app,
        string phoneE164,
        SmsAccessApprovalSource source,
        Guid? approvedBy,
        CancellationToken cancellationToken = default)
    {
        var phone = MainlandChinaPhoneNumber.Normalize(phoneE164);
        for (var attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                var strategy = _dbContext.Database.CreateExecutionStrategy();
                return await strategy.ExecuteAsync(async () =>
                {
                    _dbContext.ChangeTracker.Clear();
                    await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
                    var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodSms);
                    var login = await _dbContext.UserLogins.FirstOrDefaultAsync(item =>
                        item.ProviderNameNormalized == provider && item.ProviderUserId == phone, cancellationToken);
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
                        account = await _dbContext.Accounts.SingleAsync(item => item.Id == login.AccountId, cancellationToken);
                    }

                    var access = await _dbContext.AppSmsAccesses.FirstOrDefaultAsync(item =>
                        item.AppRegistrationId == app.Id && item.UserLoginId == login.Id, cancellationToken);
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

                    await _dbContext.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    return new SmsAdmission(account, login, access, accountCreated);
                });
            }
            catch (DbUpdateException) when (attempt == 0)
            {
                _dbContext.ChangeTracker.Clear();
            }
        }

        throw new InvalidOperationException("SMS account provisioning failed after a concurrent update.");
    }
}
