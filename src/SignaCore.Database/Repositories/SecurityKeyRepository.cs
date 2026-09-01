using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class SecurityKeyRepository : ISecurityKeyRepository
{
    private readonly IdentityDbContext _dbContext;

    public SecurityKeyRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<SecurityKeyEntity?> GetActiveKeyAsync(
        CancellationToken cancellationToken = default)
    {
        // security_keys table is tiny (< 10 rows), client evaluation is acceptable.
        var now = DateTimeOffset.UtcNow;
        var keys = await _dbContext.SecurityKeys
            .Where(k => k.IsActive)
            .ToListAsync(cancellationToken);
        return keys.OrderByDescending(k => k.CreatedAt).FirstOrDefault(k => k.ExpiresAt > now);
    }

    public async Task<SecurityKeyEntity?> GetLatestKeyAsync(
        CancellationToken cancellationToken = default)
    {
        // security_keys table is tiny (< 10 rows), client evaluation is acceptable.
        var keys = await _dbContext.SecurityKeys.ToListAsync(cancellationToken);
        return keys.OrderByDescending(k => k.CreatedAt).FirstOrDefault();
    }

    public async Task<IReadOnlyList<SecurityKeyEntity>> GetValidKeysAsync(
        CancellationToken cancellationToken = default)
    {
        // security_keys table is tiny (< 10 rows), client evaluation is acceptable.
        var now = DateTimeOffset.UtcNow;
        var keys = await _dbContext.SecurityKeys.ToListAsync(cancellationToken);
        return keys.Where(k => k.ExpiresAt > now)
            .OrderByDescending(k => k.IsActive)
            .ThenByDescending(k => k.CreatedAt)
            .ToList();
    }

    public Task AddAsync(
        SecurityKeyEntity key,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.SecurityKeys.Add(key);
        return Task.CompletedTask;
    }

    public async Task<int> DeactivateAllActiveAsync(
        CancellationToken cancellationToken = default)
    {
        // security_keys holds very few rows (< 10), so this goes through change tracking rather
        // than ExecuteUpdateAsync: that lets deactivating the old keys and inserting the new one
        // land in the caller's single SaveChanges.
        var activeKeys = await _dbContext.SecurityKeys
            .Where(k => k.IsActive)
            .ToListAsync(cancellationToken);

        foreach (var key in activeKeys)
        {
            key.IsActive = false;
        }

        return activeKeys.Count;
    }

    public Task RemoveRangeAsync(
        IEnumerable<SecurityKeyEntity> keys,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.SecurityKeys.RemoveRange(keys);
        return Task.CompletedTask;
    }

    public async Task RemoveExpiredInactiveAsync(
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        await _dbContext.SecurityKeys
            .Where(k => !k.IsActive && k.ExpiresAt < now)
            .ExecuteDeleteAsync(cancellationToken);
    }
}
