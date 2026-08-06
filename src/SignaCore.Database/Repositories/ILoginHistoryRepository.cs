using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface ILoginHistoryRepository
{
    Task AddAsync(LoginHistoryEntity loginHistory);
    Task<List<LoginHistoryEntity>> GetByAccountIdAsync(Guid accountId, int pageSize, int skip);
    Task<int> CountByAccountIdAsync(Guid accountId);
    Task<int> RemoveOlderThanAsync(DateTimeOffset cutoff);
}
