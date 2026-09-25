namespace SignaCore.Database.Entity;

/// <summary>
/// The temporary budget row defined by PS-24. Schema only: runtime admission is not enabled
/// by this entity. The partition contains a digest, never a raw client id or source address.
/// </summary>
public sealed class OidcRateLimitBucketEntity
{
    public string Policy { get; set; } = string.Empty;
    public string PartitionDigest { get; set; } = string.Empty;
    public DateTimeOffset WindowExpiresAt { get; set; }
    public int PermitCount { get; set; }
}
