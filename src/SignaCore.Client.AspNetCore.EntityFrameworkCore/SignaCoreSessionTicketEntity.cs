namespace SignaCore.Client.AspNetCore.EntityFrameworkCore;

/// <summary>
/// One persisted server-side session of the hosted-login integration. The row is keyed by the
/// base64 SHA-256 digest of the opaque session key — the plaintext key, the tokens, and the
/// principal exist only inside the Data Protection-encrypted <see cref="Payload"/>. The plain
/// <see cref="ExpiresUtc"/> column stays outside the payload so expiry sweeps can query it
/// without decrypting anything.
/// </summary>
public sealed class SignaCoreSessionTicketEntity
{
    /// <summary>
    /// The base64 SHA-256 digest of the opaque session key. A digest is stored instead of the key
    /// so a database leak alone cannot be replayed as a session cookie.
    /// </summary>
    public string KeyDigest { get; set; } = string.Empty;

    /// <summary>
    /// The Data Protection-protected ticket payload: the principal, the tokens, and the session's
    /// timestamps, in the framework's authentication-ticket serialization. Only a process holding
    /// the same key ring can turn it back into a ticket.
    /// </summary>
    public byte[] Payload { get; set; } = [];

    /// <summary>The moment the session expires, in UTC; the row is unusable and sweepable afterwards.</summary>
    public DateTimeOffset ExpiresUtc { get; set; }

    /// <summary>The moment the session was issued, in UTC.</summary>
    public DateTimeOffset IssuedUtc { get; set; }
}
