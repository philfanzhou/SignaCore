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
}
