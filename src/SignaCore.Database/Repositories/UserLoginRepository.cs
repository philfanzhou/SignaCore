using Microsoft.EntityFrameworkCore;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class UserLoginRepository : IUserLoginRepository
{
    private readonly IdentityDbContext _dbContext;

    public UserLoginRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
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

}
