using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

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
