namespace QuantumZhou.Identity.Database.Entity;

public class AuditLogEntity
{
    public Guid Id { get; set; }

    public string Action { get; set; } = string.Empty;

    public string TargetType { get; set; } = string.Empty;

    public string TargetId { get; set; } = string.Empty;

    public Guid? ActorId { get; set; }

    public string? ActorName { get; set; }

    public string? BeforeSnapshot { get; set; }

    public string? AfterSnapshot { get; set; }

    public string? Description { get; set; }

    public string? ClientIp { get; set; }

    public string? CorrelationId { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}
