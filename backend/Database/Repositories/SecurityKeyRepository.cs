using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public class SecurityKeyRepository : ISecurityKeyRepository
{
    private readonly IdentityDbContext _dbContext;

    public SecurityKeyRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<SecurityKeyEntity?> GetActiveKeyAsync()
    {
        // SQLite does not support server-side DateTimeOffset comparison/orderBy in LINQ;
        // security_keys table is tiny (< 10 rows), client evaluation is acceptable.
        var now = DateTimeOffset.UtcNow;
        var keys = await _dbContext.SecurityKeys
            .Where(k => k.IsActive)
            .ToListAsync();
        return keys.OrderByDescending(k => k.CreatedAt).FirstOrDefault(k => k.ExpiresAt > now);
    }

    public async Task<SecurityKeyEntity?> GetLatestKeyAsync()
    {
        // SQLite does not support server-side DateTimeOffset orderBy in LINQ;
        // security_keys table is tiny (< 10 rows), client evaluation is acceptable.
        var keys = await _dbContext.SecurityKeys.ToListAsync();
        return keys.OrderByDescending(k => k.CreatedAt).FirstOrDefault();
    }

    public async Task<IReadOnlyList<SecurityKeyEntity>> GetValidKeysAsync()
    {
        // SQLite does not support server-side DateTimeOffset comparison/orderBy in LINQ;
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
