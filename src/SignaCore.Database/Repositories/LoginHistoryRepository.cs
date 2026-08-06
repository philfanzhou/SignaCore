using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

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

    public async Task<int> CountByAccountIdAsync(Guid accountId)
    {
        return await _dbContext.LoginHistories
            .Where(h => h.AccountId == accountId)
            .CountAsync();
    }

    public async Task<int> RemoveOlderThanAsync(DateTimeOffset cutoff)
    {
        return await _dbContext.LoginHistories
            .Where(h => h.CreatedAt < cutoff)
            .ExecuteDeleteAsync();
    }
}
