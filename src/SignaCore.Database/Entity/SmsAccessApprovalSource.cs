namespace SignaCore.Database.Entity;

public enum SmsAccessApprovalSource
{
    Admin = 0,
    AutoProvision = 1,

    /// <summary>
    /// A cross-application refresh grant derived this admission from one the account already held at
    /// another application. No OTP was verified for this application.
    /// </summary>
    ExchangeGranted = 2
}
