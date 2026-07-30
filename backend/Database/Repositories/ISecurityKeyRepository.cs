using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public interface ISecurityKeyRepository
{
    Task<SecurityKeyEntity?> GetActiveKeyAsync();
    Task<SecurityKeyEntity?> GetLatestKeyAsync();
    Task<IReadOnlyList<SecurityKeyEntity>> GetValidKeysAsync();
    Task AddAsync(SecurityKeyEntity key);
    Task RemoveRangeAsync(IEnumerable<SecurityKeyEntity> keys);
    Task RemoveExpiredInactiveAsync();
}
