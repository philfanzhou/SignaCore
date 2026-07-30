using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public interface IRefreshTokenRepository
{
    Task<RefreshTokenEntity?> GetByTokenValueAsync(string tokenValue);
    Task<bool> TryRevokeAsync(string tokenValue);
    Task<bool> TryRotateAsync(string tokenValue, RefreshTokenEntity replacement);
    Task AddAsync(RefreshTokenEntity refreshToken);
    Task RemoveRangeAsync(IEnumerable<RefreshTokenEntity> tokens);
    Task<int> RemoveExpiredAndRevokedAsync();
}
