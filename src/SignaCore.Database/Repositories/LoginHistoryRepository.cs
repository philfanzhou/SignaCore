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

    public Task AddAsync(
        LoginHistoryEntity loginHistory,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.LoginHistories.Add(loginHistory);
        return Task.CompletedTask;
    }

    public async Task<List<LoginHistoryEntity>> GetByAccountIdAsync(
        Guid accountId,
        int pageSize,
        int skip,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.LoginHistories
            .Where(h => h.AccountId == accountId)
            .OrderByDescending(h => h.CreatedAt)
            .Skip(skip)
            .Take(pageSize)
            .ToListAsync(cancellationToken);
    }

    public async Task<int> CountByAccountIdAsync(
        Guid accountId,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.LoginHistories
            .Where(h => h.AccountId == accountId)
            .CountAsync(cancellationToken);
    }

    public async Task<int> RemoveOlderThanAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.LoginHistories
            .Where(h => h.CreatedAt < cutoff)
            .ExecuteDeleteAsync(cancellationToken);
    }
}
