using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public interface ISecurityKeyRepository
{
    Task<SecurityKeyEntity?> GetActiveKeyAsync();
    Task<SecurityKeyEntity?> GetLatestKeyAsync();
    Task<IReadOnlyList<SecurityKeyEntity>> GetValidKeysAsync();
    Task AddAsync(SecurityKeyEntity key);

    /// <summary>
    /// 把所有 <c>IsActive=true</c> 的行标记为非活跃，返回受影响行数。**不** SaveChanges，
    /// 由调用方与新密钥的插入合并成一次提交，中途不出现"零个活跃密钥"的状态。
    /// <para>
    /// 刻意不带 <c>ExpiresAt</c> 过滤：<see cref="GetActiveKeyAsync"/> 带了过期过滤，
    /// 密钥一旦过期就再也返回不了那一行，旧行会永远卡在 <c>IsActive=true</c>，
    /// 而 <see cref="RemoveExpiredInactiveAsync"/> 只删 <c>!IsActive</c> 的行，清不掉。
    /// </para>
    /// </summary>
    Task<int> DeactivateAllActiveAsync();

    Task RemoveRangeAsync(IEnumerable<SecurityKeyEntity> keys);
    Task RemoveExpiredInactiveAsync();
}
