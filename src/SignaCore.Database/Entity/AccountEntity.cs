namespace SignaCore.Database.Entity;

/// <summary>
/// Pure account entity. Represents a user's identity in the system.
/// Contains only universal identity attributes, no credential-specific fields.
/// Credentials (password, WeChat, phone, etc.) are stored in separate tables.
/// </summary>
public class AccountEntity
{
    public Guid Id { get; set; }

    /// <summary>Whether the account is active. Inactive accounts cannot login.</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>When the account was created.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Admin remark for identifying the account purpose or owner.</summary>
    public string? Remark { get; set; }
    public string? RemarkNormalized { get; set; }

    /// <summary>User-defined display name / nickname.</summary>
    public string? Nickname { get; set; }
    public string? NicknameNormalized { get; set; }

    public DateTimeOffset? LastLoginAt { get; set; }

    public string? LastLoginIp { get; set; }

    public string? LastLoginMethod { get; set; }

    public int TotalLoginCount { get; set; }
}
