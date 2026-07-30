namespace QuantumZhou.Identity.Database.Entity;

public class LoginHistoryEntity
{
    public Guid Id { get; set; }

    public Guid? AccountId { get; set; }

    public string Username { get; set; } = string.Empty;

    public string AuthMethod { get; set; } = string.Empty;

    public string EventType { get; set; } = string.Empty;

    public string? ClientIp { get; set; }

    public string? UserAgent { get; set; }

    public string? FailureReason { get; set; }

    public string? AppId { get; set; }

    public string? CorrelationId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}
