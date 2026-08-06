using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

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
        return await Filter(action, targetType, targetId, actorId)
            .OrderByDescending(a => a.CreatedAt)
            .Skip(skip)
            .Take(pageSize)
            .ToListAsync();
    }

    public async Task<int> CountAsync(string? action, string? targetType, string? targetId, Guid? actorId)
    {
        return await Filter(action, targetType, targetId, actorId).CountAsync();
    }

    private IQueryable<AuditLogEntity> Filter(string? action, string? targetType, string? targetId, Guid? actorId)
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

        return query;
    }

    public async Task<int> RemoveOlderThanAsync(DateTimeOffset cutoff)
    {
        return await _dbContext.AuditLogs
            .Where(a => a.CreatedAt < cutoff)
            .ExecuteDeleteAsync();
    }
}
