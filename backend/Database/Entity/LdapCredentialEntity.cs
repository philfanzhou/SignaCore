namespace QuantumZhou.Identity.Database.Entity;

/// <summary>
/// Minimal administrator-controlled binding to an LDAP directory identity.
/// Directory profile data is deliberately not synchronized into Identity.
/// </summary>
public sealed class LdapCredentialEntity
{
    public Guid Id { get; set; }
    public Guid AccountId { get; set; }
    public string DirectoryKey { get; set; } = string.Empty;
    public string DirectoryKeyNormalized { get; set; } = string.Empty;
    public Guid ObjectGuid { get; set; }
    public string UserPrincipalName { get; set; } = string.Empty;
    public string UserPrincipalNameNormalized { get; set; } = string.Empty;
    public string SamAccountName { get; set; } = string.Empty;
    public string SamAccountNameNormalized { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
}
