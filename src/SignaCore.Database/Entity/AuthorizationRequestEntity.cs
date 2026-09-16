namespace SignaCore.Database.Entity;

/// <summary>
/// Shared server-side authorization request (login continuation) row, canonical shape
/// <c>PS-03</c>. Created by the authorize orchestration from an already validated request
/// (<c>OidcAuthorizationValidationResult.Accepted</c>) and consumed at most once by the login flow.
/// The plaintext <c>login_handle</c> is returned once at creation; only its versioned digest is
/// persisted (<c>DF-05</c>). Snapshot values (redirect URI, scope, state, nonce, code challenge)
/// are copied from the validated request and are never re-derived from browser input.
/// </summary>
public class AuthorizationRequestEntity
{
    /// <summary>Public record id. Safe to reference in logs and diagnostics (<c>DF-13</c>).</summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Versioned one-way digest of the 43-character <c>login_handle</c>. Unique; the plaintext
    /// handle is never persisted.
    /// </summary>
    public string HandleDigest { get; set; } = string.Empty;

    /// <summary>
    /// Restrictive reference to the client the request was validated against. Deleting the
    /// application while a continuation row exists fails; cleanup never nulls this reference.
    /// </summary>
    public Guid AppRegistrationId { get; set; }

    /// <summary>
    /// Exact registered canonical redirect URI snapshot (the <c>app_redirect_uris.canonical_uri</c>
    /// value itself, not a foreign key), so removing the registration does not reshape the row
    /// during its lifetime. Current policy is revalidated before any redirect (<c>EV-02</c>).
    /// </summary>
    public string RedirectUri { get; set; } = string.Empty;

    /// <summary>Canonical space-delimited scope snapshot in fixed normal order.</summary>
    public string Scope { get; set; } = string.Empty;

    /// <summary>Byte-for-byte <c>state</c> snapshot.</summary>
    public string State { get; set; } = string.Empty;

    /// <summary>Byte-for-byte <c>nonce</c> snapshot.</summary>
    public string Nonce { get; set; } = string.Empty;

    /// <summary>S256 <c>code_challenge</c> snapshot. The PKCE verifier is never stored (<c>DF-04</c>).</summary>
    public string CodeChallenge { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Creation plus the fixed 10-minute handle lifetime (<c>IN-10</c>).</summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// Set exactly once by the atomic consumption, using the same captured UTC instant as the
    /// comparison that admitted it (<c>PS-22</c>). Expiry never writes this column: an expired row
    /// stays unconsumed, and consumption is not revocation.
    /// </summary>
    public DateTimeOffset? ConsumedAt { get; set; }
}
