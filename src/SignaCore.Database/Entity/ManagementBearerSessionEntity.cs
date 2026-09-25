namespace SignaCore.Database.Entity;

/// <summary>
/// Persistence for management-only opaque bearer sessions. The schema does not enable
/// authentication; issuance, validation, expiry policy, and revocation are separate work.
/// Only a digest is persisted, never the bearer credential or cached account permissions.
/// </summary>
public class ManagementBearerSessionEntity
{
    public Guid Id { get; set; }
    public string TokenDigest { get; set; } = string.Empty;
    public Guid AccountId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}
