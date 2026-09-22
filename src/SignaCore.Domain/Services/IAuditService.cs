namespace SignaCore.Domain.Services;

public interface IAuditService
{
    Task RecordLoginAsync(Guid? accountId, string username, string authMethod, string eventType,
        string? clientIp, string? userAgent, string? failureReason = null, string? appId = null,
        string? correlationId = null, CancellationToken cancellationToken = default);
}
