namespace QuantumZhou.Identity.Database.Entity;

public class OtpEntity
{
    public Guid Id { get; set; }
    public string Phone { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; set; }
    public int Attempts { get; set; }
    public DateTimeOffset LockoutUntil { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
