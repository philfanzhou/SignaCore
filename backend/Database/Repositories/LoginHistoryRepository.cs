using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

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
