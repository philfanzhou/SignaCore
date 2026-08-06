namespace SignaCore.Database.Entity;

/// <summary>
/// External login binding. Links an account to an external identity provider (e.g., WeChat, Google).
/// One account can have multiple external login bindings.
/// </summary>
public class UserLoginEntity
{
    public Guid Id { get; set; }

    /// <summary>The account this login is bound to.</summary>
    public Guid AccountId { get; set; }

    /// <summary>External provider name (e.g., "WeChat", "Google").</summary>
    public string ProviderName { get; set; } = string.Empty;
    public string ProviderNameNormalized { get; set; } = string.Empty;

    /// <summary>User's unique ID in the external provider (e.g., WeChat OpenId).</summary>
    public string ProviderUserId { get; set; } = string.Empty;
}
