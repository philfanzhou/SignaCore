using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public class AccountRepository : IAccountRepository
{
    private readonly IdentityDbContext _dbContext;

    public AccountRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<AccountEntity?> GetByIdAsync(Guid id)
    {
        return await _dbContext.Accounts.FirstOrDefaultAsync(a => a.Id == id);
    }

    public async Task<AccountEntity?> GetByLoginProviderAsync(string providerName, string providerUserId)
    {
        return await _dbContext.UserLogins
            .Where(l => l.ProviderName == providerName && l.ProviderUserId == providerUserId)
            .Join(_dbContext.Accounts, l => l.AccountId, a => a.Id, (_, a) => a)
            .FirstOrDefaultAsync();
    }

    public async Task<AccountEntity?> GetByPasswordCredentialUsernameAsync(string username)
    {
        return await _dbContext.PasswordCredentials
            .Where(c => c.Username == username)
            .Join(_dbContext.Accounts, c => c.AccountId, a => a.Id, (_, a) => a)
            .FirstOrDefaultAsync();
    }

    public Task AddAsync(AccountEntity account)
    {
        _dbContext.Accounts.Add(account);
        return Task.CompletedTask;
    }

    public Task<AccountEntity> CreateDefaultAccountAsync()
    {
        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        _dbContext.Accounts.Add(account);
        return Task.FromResult(account);
    }

    public Task UpdateAsync(AccountEntity account)
    {
        _dbContext.Accounts.Update(account);
        return Task.CompletedTask;
    }
}

public class PasswordCredentialRepository : IPasswordCredentialRepository
{
    private readonly IdentityDbContext _dbContext;

    public PasswordCredentialRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<PasswordCredentialEntity?> GetByUsernameAsync(string username)
    {
        return await _dbContext.PasswordCredentials
            .FirstOrDefaultAsync(c => c.Username == username);
    }

    public async Task<PasswordCredentialEntity?> GetByAccountIdAsync(Guid accountId)
    {
        return await _dbContext.PasswordCredentials
            .FirstOrDefaultAsync(c => c.AccountId == accountId);
    }

    public Task AddAsync(PasswordCredentialEntity credential)
    {
        _dbContext.PasswordCredentials.Add(credential);
        return Task.CompletedTask;
    }

    public async Task<bool> ExistsByUsernameAsync(string username)
    {
        return await _dbContext.PasswordCredentials.AnyAsync(c => c.Username == username);
    }
}

public class UserLoginRepository : IUserLoginRepository
{
    private readonly IdentityDbContext _dbContext;

    public UserLoginRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<UserLoginEntity?> GetByProviderAsync(string providerName, string providerUserId)
    {
        return await _dbContext.UserLogins
            .FirstOrDefaultAsync(l => l.ProviderName == providerName && l.ProviderUserId == providerUserId);
    }

    public async Task<UserLoginEntity?> GetBySmsPhoneAsync(string phone)
    {
        return await _dbContext.UserLogins
            .FirstOrDefaultAsync(l => l.ProviderName == IdentityConstants.AuthMethodSms && l.ProviderUserId == phone);
    }

    public Task AddAsync(UserLoginEntity userLogin)
    {
        _dbContext.UserLogins.Add(userLogin);
        return Task.CompletedTask;
    }

    public Task RemoveAsync(UserLoginEntity userLogin)
    {
        _dbContext.UserLogins.Remove(userLogin);
        return Task.CompletedTask;
    }

    public async Task<List<UserLoginEntity>> GetByAccountIdAsync(Guid accountId)
    {
        return await _dbContext.UserLogins
            .Where(l => l.AccountId == accountId)
            .ToListAsync();
    }
}

public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly IdentityDbContext _dbContext;

    public RefreshTokenRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<RefreshTokenEntity?> GetByTokenValueAsync(string tokenValue)
    {
        return await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(r => r.TokenValue == tokenValue);
    }

    public Task AddAsync(RefreshTokenEntity refreshToken)
    {
        _dbContext.RefreshTokens.Add(refreshToken);
        return Task.CompletedTask;
    }

    public Task RemoveRangeAsync(IEnumerable<RefreshTokenEntity> tokens)
    {
        _dbContext.RefreshTokens.RemoveRange(tokens);
        return Task.CompletedTask;
    }

    public async Task<int> RemoveExpiredAndRevokedAsync()
    {
        var now = DateTimeOffset.UtcNow;
        return await _dbContext.RefreshTokens
            .Where(r => r.IsRevoked || r.ExpiresAt < now)
            .ExecuteDeleteAsync();
    }
}

public class AppRegistrationRepository : IAppRegistrationRepository
{
    private readonly IdentityDbContext _dbContext;

    public AppRegistrationRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<AppRegistrationEntity?> GetByAppIdAsync(string appId)
    {
        return await _dbContext.AppRegistrations.FirstOrDefaultAsync(a => a.AppId == appId);
    }

    public Task AddAsync(AppRegistrationEntity app)
    {
        _dbContext.AppRegistrations.Add(app);
        return Task.CompletedTask;
    }

    public Task DeleteAsync(AppRegistrationEntity app)
    {
        _dbContext.AppRegistrations.Remove(app);
        return Task.CompletedTask;
    }

    public async Task<int> DeactivateExpiredCallbacksAsync(DateTimeOffset utcNow)
    {
        return await _dbContext.AppRegistrations
            .Where(a => a.CallbackExpiresAt.HasValue && a.IsActive && a.CallbackExpiresAt! < utcNow)
            .ExecuteUpdateAsync(setters => setters.SetProperty(a => a.IsActive, false));
    }
}

public class SecurityKeyRepository : ISecurityKeyRepository
{
    private readonly IdentityDbContext _dbContext;

    public SecurityKeyRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<SecurityKeyEntity?> GetActiveKeyAsync()
    {
        // SQLite does not support server-side DateTimeOffset comparison/orderBy in LINQ;
        // security_keys table is tiny (< 10 rows), client evaluation is acceptable.
        var now = DateTimeOffset.UtcNow;
        var keys = await _dbContext.SecurityKeys
            .Where(k => k.IsActive)
            .ToListAsync();
        return keys.OrderByDescending(k => k.CreatedAt).FirstOrDefault(k => k.ExpiresAt > now);
    }

    public async Task<SecurityKeyEntity?> GetLatestKeyAsync()
    {
        // SQLite does not support server-side DateTimeOffset orderBy in LINQ;
        // security_keys table is tiny (< 10 rows), client evaluation is acceptable.
        var keys = await _dbContext.SecurityKeys.ToListAsync();
        return keys.OrderByDescending(k => k.CreatedAt).FirstOrDefault();
    }

    public async Task<IReadOnlyList<SecurityKeyEntity>> GetValidKeysAsync()
    {
        // SQLite does not support server-side DateTimeOffset comparison/orderBy in LINQ;
        // security_keys table is tiny (< 10 rows), client evaluation is acceptable.
        var now = DateTimeOffset.UtcNow;
        var keys = await _dbContext.SecurityKeys.ToListAsync();
        return keys.Where(k => k.ExpiresAt > now)
            .OrderByDescending(k => k.IsActive)
            .ThenByDescending(k => k.CreatedAt)
            .ToList();
    }

    public Task AddAsync(SecurityKeyEntity key)
    {
        _dbContext.SecurityKeys.Add(key);
        return Task.CompletedTask;
    }

    public Task RemoveRangeAsync(IEnumerable<SecurityKeyEntity> keys)
    {
        _dbContext.SecurityKeys.RemoveRange(keys);
        return Task.CompletedTask;
    }

    public async Task RemoveExpiredInactiveAsync()
    {
        var now = DateTimeOffset.UtcNow;
        await _dbContext.SecurityKeys
            .Where(k => !k.IsActive && k.ExpiresAt < now)
            .ExecuteDeleteAsync();
    }
}

public class OtpRepository : IOtpRepository
{
    private readonly IdentityDbContext _dbContext;

    public OtpRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<OtpEntity?> GetByPhoneAsync(string phone)
    {
        return await _dbContext.Otps.FirstOrDefaultAsync(o => o.Phone == phone);
    }

    public Task AddAsync(OtpEntity otp)
    {
        _dbContext.Otps.Add(otp);
        return Task.CompletedTask;
    }

    public Task RemoveAsync(OtpEntity otp)
    {
        _dbContext.Otps.Remove(otp);
        return Task.CompletedTask;
    }
}

public class LoginAttemptRepository : ILoginAttemptRepository
{
    private readonly IdentityDbContext _dbContext;

    public LoginAttemptRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<LoginAttemptEntity?> GetByUsernameAsync(string username)
    {
        return await _dbContext.LoginAttempts
            .FirstOrDefaultAsync(l => l.Username == username);
    }

    public Task AddAsync(LoginAttemptEntity loginAttempt)
    {
        _dbContext.LoginAttempts.Add(loginAttempt);
        return Task.CompletedTask;
    }

    public Task RemoveAsync(LoginAttemptEntity loginAttempt)
    {
        _dbContext.LoginAttempts.Remove(loginAttempt);
        return Task.CompletedTask;
    }

    public async Task RemoveExpiredAsync(DateTimeOffset cutoff)
    {
        await _dbContext.LoginAttempts
            .Where(l => l.LastAttemptAt < cutoff)
            .ExecuteDeleteAsync();
    }
}

public class LoginHistoryRepository : ILoginHistoryRepository
{
    private readonly IdentityDbContext _dbContext;

    public LoginHistoryRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public Task AddAsync(LoginHistoryEntity loginHistory)
    {
        _dbContext.LoginHistories.Add(loginHistory);
        return Task.CompletedTask;
    }

    public async Task<List<LoginHistoryEntity>> GetByAccountIdAsync(Guid accountId, int pageSize, int skip)
    {
        return await _dbContext.LoginHistories
            .Where(h => h.AccountId == accountId)
            .OrderByDescending(h => h.CreatedAt)
            .Skip(skip)
            .Take(pageSize)
            .ToListAsync();
    }

    public async Task<int> RemoveOlderThanAsync(DateTimeOffset cutoff)
    {
        return await _dbContext.LoginHistories
            .Where(h => h.CreatedAt < cutoff)
            .ExecuteDeleteAsync();
    }
}

public class AuditLogRepository : IAuditLogRepository
{
    private readonly IdentityDbContext _dbContext;

    public AuditLogRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public Task AddAsync(AuditLogEntity auditLog)
    {
        _dbContext.AuditLogs.Add(auditLog);
        return Task.CompletedTask;
    }

    public async Task<List<AuditLogEntity>> QueryAsync(string? action, string? targetType, string? targetId, Guid? actorId, int pageSize, int skip)
    {
        var query = _dbContext.AuditLogs.AsQueryable();

        if (!string.IsNullOrEmpty(action))
            query = query.Where(a => a.Action == action);

        if (!string.IsNullOrEmpty(targetType))
            query = query.Where(a => a.TargetType == targetType);

        if (!string.IsNullOrEmpty(targetId))
            query = query.Where(a => a.TargetId == targetId);

        if (actorId.HasValue)
            query = query.Where(a => a.ActorId == actorId.Value);

        return await query
            .OrderByDescending(a => a.CreatedAt)
            .Skip(skip)
            .Take(pageSize)
            .ToListAsync();
    }

    public async Task<int> RemoveOlderThanAsync(DateTimeOffset cutoff)
    {
        return await _dbContext.AuditLogs
            .Where(a => a.CreatedAt < cutoff)
            .ExecuteDeleteAsync();
    }
}

public class EfCoreUnitOfWork : IUnitOfWork
{
    private readonly IdentityDbContext _dbContext;

    public EfCoreUnitOfWork(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return await _dbContext.SaveChangesAsync(cancellationToken);
    }
}
