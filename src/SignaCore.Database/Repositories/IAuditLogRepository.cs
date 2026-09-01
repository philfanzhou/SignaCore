using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IAuditLogRepository
{
    Task AddAsync(AuditLogEntity auditLog, CancellationToken cancellationToken = default);
    Task<List<AuditLogEntity>> QueryAsync(
        string? action,
        string? targetType,
        string? targetId,
        Guid? actorId,
        int pageSize,
        int skip,
        CancellationToken cancellationToken = default);
    Task<int> CountAsync(
        string? action,
        string? targetType,
        string? targetId,
        Guid? actorId,
        CancellationToken cancellationToken = default);
    Task<int> RemoveOlderThanAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default);
}
