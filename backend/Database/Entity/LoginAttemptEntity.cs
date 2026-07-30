namespace QuantumZhou.Identity.Database.Entity;

public class LoginAttemptEntity
{
    public Guid Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string UsernameNormalized { get; set; } = string.Empty;
    public DateTimeOffset LastAttemptAt { get; set; }
    public int FailedAttempts { get; set; }
    public DateTimeOffset? LockoutUntil { get; set; }
}
