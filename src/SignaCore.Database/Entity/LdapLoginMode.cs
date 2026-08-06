namespace SignaCore.Database.Entity;

public enum LdapLoginMode
{
    Disabled = 0,
    ManualApproval = 1,
    AutoProvision = 2
}

public enum LdapAccessApprovalSource
{
    Admin = 1,
    AutoProvision = 2
}
