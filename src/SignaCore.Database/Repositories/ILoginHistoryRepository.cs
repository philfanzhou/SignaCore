using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface ILoginHistoryRepository
{
    Task AddAsync(LoginHistoryEntity loginHistory, CancellationToken cancellationToken = default);
    Task<List<LoginHistoryEntity>> GetByAccountIdAsync(
        Guid accountId,
        int pageSize,
        int skip,
        CancellationToken cancellationToken = default);
    Task<int> CountByAccountIdAsync(
        Guid accountId,
        CancellationToken cancellationToken = default);
    Task<int> RemoveOlderThanAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default);
}
