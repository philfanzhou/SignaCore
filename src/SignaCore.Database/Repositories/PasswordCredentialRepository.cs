using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class PasswordCredentialRepository : IPasswordCredentialRepository
{
    private readonly IdentityDbContext _dbContext;

    public PasswordCredentialRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<PasswordCredentialEntity?> GetByUsernameAsync(
        string username,
        CancellationToken cancellationToken = default)
    {
        var normalizedUsername = IdentityValueNormalizer.Normalize(username);
        return await _dbContext.PasswordCredentials
            .FirstOrDefaultAsync(
                c => c.UsernameNormalized == normalizedUsername,
                cancellationToken);
    }

    public async Task<PasswordCredentialEntity?> GetByAccountIdAsync(
        Guid accountId,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.PasswordCredentials
            .FirstOrDefaultAsync(c => c.AccountId == accountId, cancellationToken);
    }

    public Task AddAsync(
        PasswordCredentialEntity credential,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.PasswordCredentials.Add(credential);
        return Task.CompletedTask;
    }

    public async Task<bool> ExistsByUsernameAsync(
        string username,
        CancellationToken cancellationToken = default)
    {
        var normalizedUsername = IdentityValueNormalizer.Normalize(username);
        return await _dbContext.PasswordCredentials
            .AnyAsync(c => c.UsernameNormalized == normalizedUsername, cancellationToken);
    }
}
