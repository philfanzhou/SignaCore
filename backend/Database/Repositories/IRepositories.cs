using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public interface IAccountRepository
{
    Task<AccountEntity?> GetByIdAsync(Guid id);
    Task<AccountEntity?> GetByLoginProviderAsync(string providerName, string providerUserId);
    Task<AccountEntity?> GetByPasswordCredentialUsernameAsync(string username);
    Task AddAsync(AccountEntity account);
    Task<AccountEntity> CreateDefaultAccountAsync();
    Task UpdateAsync(AccountEntity account);
}

public interface IPasswordCredentialRepository
{
    Task<PasswordCredentialEntity?> GetByUsernameAsync(string username);
    Task<PasswordCredentialEntity?> GetByAccountIdAsync(Guid accountId);
    Task AddAsync(PasswordCredentialEntity credential);
    Task<bool> ExistsByUsernameAsync(string username);
}

public interface IUserLoginRepository
{
    Task<UserLoginEntity?> GetByProviderAsync(string providerName, string providerUserId);
    Task<UserLoginEntity?> GetBySmsPhoneAsync(string phone);
    Task AddAsync(UserLoginEntity userLogin);
    Task RemoveAsync(UserLoginEntity userLogin);
    Task<List<UserLoginEntity>> GetByAccountIdAsync(Guid accountId);
}

public interface IRefreshTokenRepository
{
    Task<RefreshTokenEntity?> GetByTokenValueAsync(string tokenValue);
    Task AddAsync(RefreshTokenEntity refreshToken);
    Task RemoveRangeAsync(IEnumerable<RefreshTokenEntity> tokens);
    Task<int> RemoveExpiredAndRevokedAsync();
}

public interface IAppRegistrationRepository
{
    Task<AppRegistrationEntity?> GetByAppIdAsync(string appId);
    Task AddAsync(AppRegistrationEntity app);
    Task DeleteAsync(AppRegistrationEntity app);
    Task<int> DeactivateExpiredCallbacksAsync(DateTimeOffset utcNow);
}

public interface ISecurityKeyRepository
{
    Task<SecurityKeyEntity?> GetActiveKeyAsync();
    Task<SecurityKeyEntity?> GetLatestKeyAsync();
    Task<IReadOnlyList<SecurityKeyEntity>> GetValidKeysAsync();
    Task AddAsync(SecurityKeyEntity key);
    Task RemoveRangeAsync(IEnumerable<SecurityKeyEntity> keys);
    Task RemoveExpiredInactiveAsync();
}

public interface IOtpRepository
{
    Task<OtpEntity?> GetByPhoneAsync(string phone);
    Task AddAsync(OtpEntity otp);
    Task RemoveAsync(OtpEntity otp);
}

public interface ILoginAttemptRepository
{
    Task<LoginAttemptEntity?> GetByUsernameAsync(string username);
    Task AddAsync(LoginAttemptEntity loginAttempt);
    Task RemoveAsync(LoginAttemptEntity loginAttempt);
    Task RemoveExpiredAsync(DateTimeOffset cutoff);
}

public interface ILoginHistoryRepository
{
    Task AddAsync(LoginHistoryEntity loginHistory);
    Task<List<LoginHistoryEntity>> GetByAccountIdAsync(Guid accountId, int pageSize, int skip);
    Task<int> RemoveOlderThanAsync(DateTimeOffset cutoff);
}

public interface IAuditLogRepository
{
    Task AddAsync(AuditLogEntity auditLog);
    Task<List<AuditLogEntity>> QueryAsync(string? action, string? targetType, string? targetId, Guid? actorId, int pageSize, int skip);
    Task<int> RemoveOlderThanAsync(DateTimeOffset cutoff);
}

public interface IUnitOfWork
{
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
