namespace SignaCore.Database.Entity;

public enum WechatAccessApprovalSource
{
    /// <summary>An authenticated user bound WeChat to their own account.</summary>
    SelfBind = 0,

    /// <summary>The first WeChat login provisioned the account under <see cref="WechatLoginMode.AutoProvision"/>.</summary>
    AutoProvision = 1,

    /// <summary>
    /// A cross-application refresh grant derived this admission from one the account already held at
    /// another application. No WeChat authorization was performed for this application.
    /// </summary>
    ExchangeGranted = 2
}
