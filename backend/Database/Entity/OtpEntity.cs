namespace QuantumZhou.Identity.Database.Entity;

public class OtpEntity
{
    public Guid Id { get; set; }
    public Guid AppRegistrationId { get; set; }
    public string Phone { get; set; } = string.Empty;
    public string CodeMac { get; set; } = string.Empty;
    public OtpStatus Status { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public int Attempts { get; set; }
    public DateTimeOffset LockoutUntil { get; set; }
    public DateTimeOffset HourWindowStartedAt { get; set; }
    public int HourSendCount { get; set; }
    public DateTimeOffset DayWindowStartedAt { get; set; }
    public int DaySendCount { get; set; }
    public string Provider { get; set; } = string.Empty;
    public string ProfileKey { get; set; } = string.Empty;
    public string? ProviderMessageId { get; set; }
    public DateTimeOffset? SentAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public int Version { get; set; }
}
