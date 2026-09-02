using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services;

public interface IAuditService
{
    Task RecordLoginAsync(Guid? accountId, string username, string authMethod, string eventType,
        string? clientIp, string? userAgent, string? failureReason = null, string? appId = null,
        string? correlationId = null, CancellationToken cancellationToken = default);

    Task RecordActionAsync(string action, string targetType, string targetId,
        Guid? actorId, string? actorName, string? description, string? clientIp = null,
        string? correlationId = null, object? before = null, object? after = null,
        CancellationToken cancellationToken = default);
}
