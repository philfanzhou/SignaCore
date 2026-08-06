using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

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
        var normalizedProviderName = IdentityValueNormalizer.Normalize(providerName);
        return await _dbContext.UserLogins
            .Where(l =>
                l.ProviderNameNormalized == normalizedProviderName &&
                l.ProviderUserId == providerUserId)
            .Join(_dbContext.Accounts, l => l.AccountId, a => a.Id, (_, a) => a)
            .FirstOrDefaultAsync();
    }

    public async Task<AccountEntity?> GetByPasswordCredentialUsernameAsync(string username)
    {
        var normalizedUsername = IdentityValueNormalizer.Normalize(username);
        return await _dbContext.PasswordCredentials
            .Where(c => c.UsernameNormalized == normalizedUsername)
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
