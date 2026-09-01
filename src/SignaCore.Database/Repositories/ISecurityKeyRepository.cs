using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface ISecurityKeyRepository
{
    Task<SecurityKeyEntity?> GetActiveKeyAsync(CancellationToken cancellationToken = default);
    Task<SecurityKeyEntity?> GetLatestKeyAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<SecurityKeyEntity>> GetValidKeysAsync(
        CancellationToken cancellationToken = default);
    Task AddAsync(SecurityKeyEntity key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks every <c>IsActive=true</c> row as inactive and returns the number of rows affected. It
    /// does <b>not</b> SaveChanges: the caller commits it together with the insert of the new key,
    /// so there is never a moment with zero active keys.
    /// <para>
    /// The absence of an <c>ExpiresAt</c> filter is deliberate. <see cref="GetActiveKeyAsync"/> does
    /// filter on expiry, so once a key has expired it can no longer return that row, which would
    /// leave the old row stuck at <c>IsActive=true</c> forever — and
    /// <see cref="RemoveExpiredInactiveAsync"/> only deletes <c>!IsActive</c> rows, so it could
    /// never clean it up.
    /// </para>
    /// </summary>
    Task<int> DeactivateAllActiveAsync(CancellationToken cancellationToken = default);

    Task RemoveRangeAsync(
        IEnumerable<SecurityKeyEntity> keys,
        CancellationToken cancellationToken = default);
    Task RemoveExpiredInactiveAsync(CancellationToken cancellationToken = default);
}
