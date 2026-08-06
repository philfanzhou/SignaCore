using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IAuditLogRepository
{
    Task AddAsync(AuditLogEntity auditLog);
    Task<List<AuditLogEntity>> QueryAsync(string? action, string? targetType, string? targetId, Guid? actorId, int pageSize, int skip);
    Task<int> CountAsync(string? action, string? targetType, string? targetId, Guid? actorId);
    Task<int> RemoveOlderThanAsync(DateTimeOffset cutoff);
}
