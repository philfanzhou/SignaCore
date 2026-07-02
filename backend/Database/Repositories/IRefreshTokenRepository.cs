using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public interface IRefreshTokenRepository
{
    Task<RefreshTokenEntity?> GetByTokenValueAsync(string tokenValue);
    Task AddAsync(RefreshTokenEntity refreshToken);
    Task RemoveRangeAsync(IEnumerable<RefreshTokenEntity> tokens);
    Task<int> RemoveExpiredAndRevokedAsync();
}
