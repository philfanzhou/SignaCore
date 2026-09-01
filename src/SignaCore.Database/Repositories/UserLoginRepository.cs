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

    public async Task<UserLoginEntity?> GetByProviderAsync(
        string providerName,
        string providerUserId,
        CancellationToken cancellationToken = default)
    {
        var normalizedProviderName = IdentityValueNormalizer.Normalize(providerName);
        return await _dbContext.UserLogins
            .FirstOrDefaultAsync(l =>
                l.ProviderNameNormalized == normalizedProviderName &&
                l.ProviderUserId == providerUserId,
                cancellationToken);
    }

    public async Task<UserLoginEntity?> GetBySmsPhoneAsync(
        string phone,
        CancellationToken cancellationToken = default)
    {
        var normalizedProviderName =
            IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodSms);
        return await _dbContext.UserLogins
            .FirstOrDefaultAsync(l =>
                l.ProviderNameNormalized == normalizedProviderName &&
                l.ProviderUserId == phone,
                cancellationToken);
    }

    public Task AddAsync(
        UserLoginEntity userLogin,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.UserLogins.Add(userLogin);
        return Task.CompletedTask;
    }

    public Task RemoveAsync(
        UserLoginEntity userLogin,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.UserLogins.Remove(userLogin);
        return Task.CompletedTask;
    }

    public async Task<List<UserLoginEntity>> GetByAccountIdAsync(
        Guid accountId,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.UserLogins
            .Where(l => l.AccountId == accountId)
            .ToListAsync(cancellationToken);
    }
}
