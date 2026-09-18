namespace SignaCore.Database.Entity;

/// <summary>
/// One prepared-logout continuation row, canonical shape <c>PS-08</c>. Created by the
/// authenticated BFF preparation endpoint from an already validated <c>id_token_hint</c> and
/// consumed at most once by the browser completion endpoint. The plaintext
/// <c>logout_handle</c> is returned once at creation; only its versioned digest is persisted
/// (<c>DF-10</c>). The validated ID token itself is never stored (<c>DF-08</c>).
/// </summary>
public class LogoutRequestEntity
{
    /// <summary>Public record id. Safe to reference in logs and diagnostics (<c>DF-13</c>).</summary>
    public Guid Id { get; set; }

    /// <summary>
    /// Versioned one-way digest of the 43-character <c>logout_handle</c>. Unique; the plaintext
    /// handle is never persisted.
    /// </summary>
    public string HandleDigest { get; set; } = string.Empty;

    /// <summary>
    /// Restrictive reference to the authenticated client the preparation was accepted for.
    /// Deleting the application while a row exists fails; cleanup never nulls this reference.
    /// </summary>
    public Guid AppRegistrationId { get; set; }

    /// <summary>
    /// The <c>sub</c> snapshot of the validated ID token. A snapshot column, not a reference:
    /// completion compares it to the live session's account (<c>IN-36</c>) and treats a missing
    /// account row as the no-cookie path, not as a referential error.
    /// </summary>
    public Guid AccountId { get; set; }

    /// <summary>
    /// The <c>sid</c> snapshot of the validated ID token. A snapshot column, not a reference: a
    /// session row may legitimately be gone by completion time, and <c>EV-07</c> handles that
    /// without any state write, so no referential constraint may forbid it.
    /// </summary>
    public Guid IdentitySessionId { get; set; }

    /// <summary>
    /// The verified registered post-logout URI snapshot (the registered canonical value itself),
    /// or null when the preparation carried no matching registration (<c>IN-32</c>/<c>IN-34</c>).
    /// </summary>
    public string? PostLogoutRedirectUri { get; set; }

    /// <summary>The opaque <c>state</c> snapshot echoed byte-for-byte on redirect, or null.</summary>
    public string? State { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Creation plus the fixed 5-minute handle lifetime (<c>IN-35</c>).</summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// Set exactly once by the atomic consumption of <c>EV-06</c>/<c>EV-07</c>, using the same
    /// captured UTC instant as the comparison that admitted it (<c>PS-22</c>). Expiry never
    /// writes this column: an expired row stays unconsumed.
    /// </summary>
    public DateTimeOffset? ConsumedAt { get; set; }
}
