namespace SignaCore.Database.Entity;

/// <summary>
/// One short-lived authorization code row, canonical shape <c>PS-05</c>: created inside the login
/// success transaction from an accepted continuation and consumed at most once by the token
/// endpoint on any instance. The plaintext code is returned exactly once at creation; only its
/// versioned digest is persisted (<c>DF-03</c>). The PKCE verifier is never stored
/// (<c>DF-04</c>); the challenge snapshot is compared at redemption time.
/// </summary>
public class AuthorizationCodeEntity
{
    /// <summary>Public record id. Safe to reference in logs and diagnostics (<c>DF-13</c>).</summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Versioned one-way digest of the 43-character code. Unique; the plaintext code is never
    /// persisted.
    /// </summary>
    public string CodeDigest { get; set; } = string.Empty;

    /// <summary>
    /// Restrictive reference to the client the continuation was validated against. Deleting the
    /// application while a retained code row exists fails; cleanup never nulls this reference.
    /// </summary>
    public Guid AppRegistrationId { get; set; }

    /// <summary>
    /// Restrictive reference to the authenticated account, always equal to the referenced
    /// session's account id (guaranteed by <c>IAuthorizationCodeStore.CreateAsync</c>, which is
    /// the only writer).
    /// </summary>
    public Guid AccountId { get; set; }

    /// <summary>
    /// Restrictive reference to the identity session the code was issued from (<c>PS-23</c>);
    /// indexed. The token endpoint locks the session before the code (<c>EV-20</c>).
    /// </summary>
    public Guid IdentitySessionId { get; set; }

    /// <summary>
    /// Exact registered canonical redirect URI snapshot (<c>EV-12</c>/<c>IN-23</c>), compared
    /// ordinally at redemption.
    /// </summary>
    public string RedirectUri { get; set; } = string.Empty;

    /// <summary>Canonical space-delimited scope snapshot in fixed normal order.</summary>
    public string Scope { get; set; } = string.Empty;

    /// <summary>Byte-for-byte <c>nonce</c> snapshot (<c>IN-06</c>).</summary>
    public string Nonce { get; set; } = string.Empty;

    /// <summary>S256 <c>code_challenge</c> snapshot. The PKCE verifier is never stored (<c>DF-04</c>).</summary>
    public string CodeChallenge { get; set; } = string.Empty;

    /// <summary>Authentication instant copied from the referenced session's <c>auth_time</c>.</summary>
    public DateTimeOffset AuthTime { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Creation plus the fixed 60-second code lifetime (<c>IN-22</c>).</summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// Set at most once by the atomic consumption, using the same captured UTC instant as the
    /// comparison that admitted it (<c>PS-22</c>). Expiry never writes this column.
    /// </summary>
    public DateTimeOffset? ConsumedAt { get; set; }

    /// <summary>
    /// Reserved for the interactive refresh family link (<c>EV-21</c>): written only by the
    /// family slice together with the first redemption, so the database check requires
    /// <see cref="ConsumedAt"/> to be set whenever this column is not null. No reference and no
    /// index in this slice; #97 adds the reference after the backfill.
    /// </summary>
    public Guid? RefreshFamilyId { get; set; }
}
