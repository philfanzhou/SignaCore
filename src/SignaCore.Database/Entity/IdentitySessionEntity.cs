namespace SignaCore.Database.Entity;

/// <summary>
/// Server-side identity session row, canonical shape <c>PS-04</c>: the shared authority behind
/// the <c>PS-18</c> browser identity cookie. The cookie carries only the opaque <see cref="Id"/>;
/// the subject, authentication time/method, activity, idle/absolute expiry, and revocation facts
/// live exclusively here and are never copied into the cookie. Any instance reads, updates, and
/// revokes any instance's session through the shared database.
/// </summary>
public class IdentitySessionEntity
{
    /// <summary>
    /// The opaque session id. Every creation generates a fresh id and an id is never reused. It
    /// is a public row id in the database, but it never appears in SignaCore logs, metrics,
    /// traces, or exception messages (<c>DF-06</c>).
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>Restrictive reference to the session's account (<c>PS-23</c>); indexed.</summary>
    public Guid AccountId { get; set; }

    /// <summary>
    /// Restrictive reference to the password credential proven at login; indexed. Creation
    /// verifies the credential exists and belongs to <see cref="AccountId"/>.
    /// </summary>
    public Guid PasswordCredentialId { get; set; }

    /// <summary>
    /// How the browser identity was established. Fixed to
    /// <see cref="IdentityConstants.AuthMethodPassword"/> in this phase.
    /// </summary>
    public string AuthMethod { get; set; } = string.Empty;

    /// <summary>Authentication instant; immutable, and the session's creation time.</summary>
    public DateTimeOffset AuthTime { get; set; }

    /// <summary>Last activity write; equals <see cref="AuthTime"/> at creation.</summary>
    public DateTimeOffset LastSeenAt { get; set; }

    /// <summary>
    /// Idle deadline: creation plus the fixed idle timeout, slid by activity writes and always
    /// capped at <see cref="AbsoluteExpiresAt"/>.
    /// </summary>
    public DateTimeOffset IdleExpiresAt { get; set; }

    /// <summary>Absolute deadline: creation plus the fixed maximum session age; never changed.</summary>
    public DateTimeOffset AbsoluteExpiresAt { get; set; }

    /// <summary>Explicit revocation instant; expiry never writes this column (<c>EV-04</c>).</summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>
    /// Closed-set revocation reason, written exactly together with <see cref="RevokedAt"/> by the
    /// first revocation; a later revocation never overwrites either column. The database enforces
    /// the pairing, not the value set, so later canonical events can add reasons without a schema
    /// change.
    /// </summary>
    public string? RevocationReason { get; set; }
}
