using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class UserLoginRepository : IUserLoginRepository
{
    private readonly IdentityDbContext _dbContext;

    public UserLoginRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<UserLoginEntity?> GetByProviderAsync(string providerName, string providerUserId)
    {
        var normalizedProviderName = IdentityValueNormalizer.Normalize(providerName);
        return await _dbContext.UserLogins
            .FirstOrDefaultAsync(l =>
                l.ProviderNameNormalized == normalizedProviderName &&
                l.ProviderUserId == providerUserId);
    }

    public async Task<UserLoginEntity?> GetBySmsPhoneAsync(string phone)
    {
        var normalizedProviderName =
            IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodSms);
        return await _dbContext.UserLogins
            .FirstOrDefaultAsync(l =>
                l.ProviderNameNormalized == normalizedProviderName &&
                l.ProviderUserId == phone);
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
