namespace SignaCore.Database.Entity;

/// <summary>
/// Username/password credential linked to an account.
/// One account can have multiple password credentials (e.g., different usernames).
/// </summary>
public class PasswordCredentialEntity
{
    public Guid Id { get; set; }

    /// <summary>The account this credential belongs to.</summary>
    public Guid AccountId { get; set; }

    /// <summary>Unique username for this credential.</summary>
    public string Username { get; set; } = string.Empty;
    public string UsernameNormalized { get; set; } = string.Empty;

    /// <summary>BCrypt/Aargon2 hash of the password.</summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>When this credential was created.</summary>
    public DateTimeOffset CreatedAt { get; set; }
}
