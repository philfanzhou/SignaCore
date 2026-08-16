namespace SignaCore.Database.Entity;

/// <summary>
/// Administered, directed statement that one application accepts refresh tokens issued to another.
/// The row means: <see cref="AppRegistrationId"/> accepts refresh tokens issued to
/// <see cref="SourceAppRegistrationId"/>. It does not imply the reverse, and it does not compose
/// with a second edge. See docs/adr/0003-cross-application-refresh-grant.md.
/// </summary>
public sealed class AppExchangeTrustEntity
{
    public Guid Id { get; set; }

    /// <summary>Application that accepts the foreign refresh token — the caller of the refresh grant.</summary>
    public Guid AppRegistrationId { get; set; }

    /// <summary>Application the refresh token was issued to.</summary>
    public Guid SourceAppRegistrationId { get; set; }

    /// <summary>Administrator who added the edge.</summary>
    public Guid? ApprovedBy { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}
