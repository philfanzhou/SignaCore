namespace SignaCore.Database.Entity;

public class RefreshTokenEntity
{
    public Guid Id { get; set; }

    public Guid AccountId { get; set; }

    /// <summary>
    /// Versioned one-way digest of the bearer token. The raw token is returned to the client once
    /// and must never be persisted.
    /// </summary>
    public string TokenValue { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public bool IsRevoked { get; set; }

    public string AppId { get; set; } = string.Empty;

    /// <summary>LDAP identity that authenticated the original session; null otherwise.</summary>
    public Guid? LdapCredentialId { get; set; }

    /// <summary>SMS login identity that authenticated the original session; null otherwise.</summary>
    public Guid? SmsUserLoginId { get; set; }

    /// <summary>WeChat login identity that authenticated the original session; null otherwise.</summary>
    public Guid? WechatUserLoginId { get; set; }

    /// <summary>
    /// AppId this token was exchanged from; null when the token was issued by authentication. A token
    /// with a value here may not be exchanged again, which is what keeps exchange trust from composing
    /// across hops. See docs/adr/0003-cross-application-refresh-grant.md.
    /// </summary>
    public string? SourceAppId { get; set; }

    /// <summary>
    /// The id of the family root this token belongs to (<c>PS-06</c>). A legacy row is always a
    /// singleton root: <c>FamilyId == Id</c> and every interactive marker stays null. An
    /// interactive root also carries <c>FamilyId == Id</c> plus the full interactive marker; a
    /// child carries the root's id and its immediate <see cref="ParentId"/>. The database check
    /// <c>CK_refresh_tokens_family_shape</c> enforces exactly this row shape and the restrictive
    /// self-reference resolves the root.
    /// </summary>
    public Guid FamilyId { get; set; }

    /// <summary>
    /// The immediate parent of an interactive family child; null on every root and every legacy
    /// row. The unique index on this column gives an interactive parent at most one child, which
    /// is what makes a reused parent detectable (<c>PS-07</c>).
    /// </summary>
    public Guid? ParentId { get; set; }

    /// <summary>
    /// The identity session an interactive family belongs to; null on every legacy row. Part of
    /// the complete interactive marker the database check enforces.
    /// </summary>
    public Guid? IdentitySessionId { get; set; }

    /// <summary>
    /// The canonical granted scope snapshot of an interactive family, byte-for-byte copied from
    /// the authorization code; null on every legacy row. Part of the complete interactive marker.
    /// </summary>
    public string? Scope { get; set; }

    /// <summary>
    /// The session authentication time an interactive family carries; null on every legacy row.
    /// Part of the complete interactive marker.
    /// </summary>
    public DateTimeOffset? AuthTime { get; set; }

    /// <summary>
    /// The consumption fact of an interactive family member (<c>EV-29</c>): set once, by the
    /// rotation that supersedes it. Null on every legacy row — legacy rotation only revokes
    /// (<c>PS-07</c>/<c>EV-33</c>) — and only an interactive row may carry it.
    /// </summary>
    public DateTimeOffset? ConsumedAt { get; set; }
}
