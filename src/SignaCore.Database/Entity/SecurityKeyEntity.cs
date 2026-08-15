namespace SignaCore.Database.Entity;

/// <summary>
/// RSA key pair for signing JWTs.
/// Private key is encrypted with the key derived from the bootstrap master key before storage.
/// Public key is exposed via /.well-known/jwks for downstream services to verify JWTs.
/// </summary>
public class SecurityKeyEntity
{
    public Guid Id { get; set; }

    /// <summary>Unique key identifier (used as kid in JWKS).</summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>RSA public key exponent (Base64). Used in JWKS.</summary>
    public string PublicKeyExponent { get; set; } = string.Empty;

    /// <summary>RSA public key modulus (Base64). Used in JWKS.</summary>
    public string PublicKeyModulus { get; set; } = string.Empty;

    /// <summary>AES-GCM encrypted RSA private key params P, Q combined (Base64).</summary>
    public string EncryptedPrivateKeyParams { get; set; } = string.Empty;

    /// <summary>AES-GCM encryption salt (Base64).</summary>
    public string EncryptionSalt { get; set; } = string.Empty;

    /// <summary>When this key was created.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>When this key expires. New key is generated automatically.</summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Whether this is the currently active key for signing.</summary>
    public bool IsActive { get; set; } = true;
}
