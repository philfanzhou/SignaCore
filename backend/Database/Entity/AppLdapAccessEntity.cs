namespace QuantumZhou.Identity.Database.Entity;

/// <summary>Application-scoped admission for one LDAP identity.</summary>
public sealed class AppLdapAccessEntity
{
    public Guid Id { get; set; }
    public Guid AppRegistrationId { get; set; }
    public Guid LdapCredentialId { get; set; }
    public LdapAccessApprovalSource ApprovalSource { get; set; }
    public bool IsActive { get; set; } = true;
    public Guid? ApprovedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
