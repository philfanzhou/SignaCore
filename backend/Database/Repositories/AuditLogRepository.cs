using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public class AuditLogRepository : IAuditLogRepository
{
    private readonly IdentityDbContext _dbContext;

    public AuditLogRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public Task AddAsync(AuditLogEntity auditLog)
    {
        _dbContext.AuditLogs.Add(auditLog);
        return Task.CompletedTask;
    }

    public async Task<List<AuditLogEntity>> QueryAsync(string? action, string? targetType, string? targetId, Guid? actorId, int pageSize, int skip)
    {
        var query = _dbContext.AuditLogs.AsQueryable();

        if (!string.IsNullOrEmpty(action))
            query = query.Where(a => a.Action == action);

        if (!string.IsNullOrEmpty(targetType))
            query = query.Where(a => a.TargetType == targetType);

        if (!string.IsNullOrEmpty(targetId))
            query = query.Where(a => a.TargetId == targetId);

        if (actorId.HasValue)
            query = query.Where(a => a.ActorId == actorId.Value);

        return await query
            .OrderByDescending(a => a.CreatedAt)
            .Skip(skip)
            .Take(pageSize)
            .ToListAsync();
    }

    public async Task<int> RemoveOlderThanAsync(DateTimeOffset cutoff)
    {
        return await _dbContext.AuditLogs
            .Where(a => a.CreatedAt < cutoff)
            .ExecuteDeleteAsync();
    }
}
