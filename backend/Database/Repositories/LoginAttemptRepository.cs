using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

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
