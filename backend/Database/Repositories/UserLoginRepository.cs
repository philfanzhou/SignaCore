using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

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
