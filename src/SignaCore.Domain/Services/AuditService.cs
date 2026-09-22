using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;

namespace SignaCore.Domain.Services;

public class AuditService : IAuditService
{
    private readonly ILoginHistoryRepository _loginHistoryRepository;

    public AuditService(ILoginHistoryRepository loginHistoryRepository)
    {
        _loginHistoryRepository = loginHistoryRepository;
    }

    public async Task RecordLoginAsync(Guid? accountId, string username, string authMethod, string eventType,
        string? clientIp, string? userAgent, string? failureReason = null, string? appId = null,
        string? correlationId = null, CancellationToken cancellationToken = default)
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

        await _loginHistoryRepository.AddAsync(entry, cancellationToken);
    }
}
