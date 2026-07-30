namespace QuantumZhou.Identity.Database.Entity;

public class RefreshTokenEntity
{
    public Guid Id { get; set; }

    public Guid AccountId { get; set; }

    public string TokenValue { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public bool IsRevoked { get; set; }

    public string? AppId { get; set; }
}