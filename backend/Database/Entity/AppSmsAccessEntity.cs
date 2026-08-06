namespace QuantumZhou.Identity.Database.Entity;

/// <summary>Application-scoped admission for one SMS login identity.</summary>
public sealed class AppSmsAccessEntity
{
    public Guid Id { get; set; }
    public Guid AppRegistrationId { get; set; }
    public Guid UserLoginId { get; set; }
    public SmsAccessApprovalSource ApprovalSource { get; set; }
    public bool IsActive { get; set; } = true;
    public Guid? ApprovedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
