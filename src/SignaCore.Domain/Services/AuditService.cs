using System.Text.Json;
using Microsoft.Extensions.Logging;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;

namespace SignaCore.Domain.Services;

public class AuditService : IAuditService
{
    private readonly ILoginHistoryRepository _loginHistoryRepository;
    private readonly IAuditLogRepository _auditLogRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<AuditService> _logger;

    private static readonly JsonSerializerOptions SnapshotJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public AuditService(
        ILoginHistoryRepository loginHistoryRepository,
        IAuditLogRepository auditLogRepository,
        IUnitOfWork unitOfWork,
        ILogger<AuditService> logger)
    {
        _loginHistoryRepository = loginHistoryRepository;
        _auditLogRepository = auditLogRepository;
        _unitOfWork = unitOfWork;
        _logger = logger;
    }

    public async Task RecordLoginAsync(Guid? accountId, string username, string authMethod, string eventType,
        string? clientIp, string? userAgent, string? failureReason = null, string? appId = null, string? correlationId = null)
    {
        try
        {
            var entry = new LoginHistoryEntity
            {
                Id = Guid.NewGuid(),
                AccountId = accountId,
                Username = username,
                AuthMethod = authMethod,
                EventType = eventType,
                ClientIp = clientIp,
                UserAgent = userAgent,
                FailureReason = failureReason,
                AppId = appId,
                CorrelationId = correlationId,
                CreatedAt = DateTimeOffset.UtcNow
            };

            await _loginHistoryRepository.AddAsync(entry);
            await _unitOfWork.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to record login history for Username={Username}, EventType={EventType}",
                LogValueSanitizer.Sanitize(username), LogValueSanitizer.Sanitize(eventType));
        }
    }

    public async Task RecordActionAsync(string action, string targetType, string targetId,
        Guid? actorId, string? actorName, string? description, string? clientIp = null,
        string? correlationId = null, object? before = null, object? after = null)
    {
        try
        {
            var entry = new AuditLogEntity
            {
                Id = Guid.NewGuid(),
                Action = action,
                TargetType = targetType,
                TargetId = targetId,
                ActorId = actorId,
                ActorName = actorName,
                BeforeSnapshot = before != null ? JsonSerializer.Serialize(before, SnapshotJsonOptions) : null,
                AfterSnapshot = after != null ? JsonSerializer.Serialize(after, SnapshotJsonOptions) : null,
                Description = description,
                ClientIp = clientIp,
                CorrelationId = correlationId,
                CreatedAt = DateTimeOffset.UtcNow
            };

            await _auditLogRepository.AddAsync(entry);
            await _unitOfWork.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to record audit log: Action={Action}, TargetType={TargetType}, TargetId={TargetId}",
                LogValueSanitizer.Sanitize(action), LogValueSanitizer.Sanitize(targetType),
                LogValueSanitizer.Sanitize(targetId));
        }
    }
}
