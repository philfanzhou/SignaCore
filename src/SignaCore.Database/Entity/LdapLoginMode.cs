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
    AutoProvision = 2,

    /// <summary>
    /// A cross-application refresh grant derived this admission from one the account already held at
    /// another application. No directory bind was performed for this application.
    /// </summary>
    ExchangeGranted = 3
}
