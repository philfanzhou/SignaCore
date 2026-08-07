namespace SignaCore.Database.Entity;

/// <summary>Application-scoped admission for one WeChat login identity.</summary>
public sealed class AppWechatAccessEntity
{
    public Guid Id { get; set; }
    public Guid AppRegistrationId { get; set; }
    public Guid UserLoginId { get; set; }
    public WechatAccessApprovalSource ApprovalSource { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
}
