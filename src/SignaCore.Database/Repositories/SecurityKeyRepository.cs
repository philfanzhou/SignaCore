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

    public async Task<SecurityKeyEntity?> GetActiveKeyAsync()
    {
        // security_keys table is tiny (< 10 rows), client evaluation is acceptable.
        var now = DateTimeOffset.UtcNow;
        var keys = await _dbContext.SecurityKeys
            .Where(k => k.IsActive)
            .ToListAsync();
        return keys.OrderByDescending(k => k.CreatedAt).FirstOrDefault(k => k.ExpiresAt > now);
    }

    public async Task<SecurityKeyEntity?> GetLatestKeyAsync()
    {
        // security_keys table is tiny (< 10 rows), client evaluation is acceptable.
        var keys = await _dbContext.SecurityKeys.ToListAsync();
        return keys.OrderByDescending(k => k.CreatedAt).FirstOrDefault();
    }

    public async Task<IReadOnlyList<SecurityKeyEntity>> GetValidKeysAsync()
    {
        // security_keys table is tiny (< 10 rows), client evaluation is acceptable.
        var now = DateTimeOffset.UtcNow;
        var keys = await _dbContext.SecurityKeys.ToListAsync();
        return keys.Where(k => k.ExpiresAt > now)
            .OrderByDescending(k => k.IsActive)
            .ThenByDescending(k => k.CreatedAt)
            .ToList();
    }

    public Task AddAsync(SecurityKeyEntity key)
    {
        _dbContext.SecurityKeys.Add(key);
        return Task.CompletedTask;
    }

    public async Task<int> DeactivateAllActiveAsync()
    {
        // security_keys 行数极少（< 10），走变更跟踪而不是 ExecuteUpdateAsync：
        // 这样停用旧密钥与插入新密钥能合并进调用方的同一次 SaveChanges。
        var activeKeys = await _dbContext.SecurityKeys
            .Where(k => k.IsActive)
            .ToListAsync();

        foreach (var key in activeKeys)
        {
            key.IsActive = false;
        }

        return activeKeys.Count;
    }

    public Task RemoveRangeAsync(IEnumerable<SecurityKeyEntity> keys)
    {
        _dbContext.SecurityKeys.RemoveRange(keys);
        return Task.CompletedTask;
    }

    public async Task RemoveExpiredInactiveAsync()
    {
        var now = DateTimeOffset.UtcNow;
        await _dbContext.SecurityKeys
            .Where(k => !k.IsActive && k.ExpiresAt < now)
            .ExecuteDeleteAsync();
    }
}
