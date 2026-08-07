namespace SignaCore.Database.Entity;

public enum WechatAccessApprovalSource
{
    /// <summary>An authenticated user bound WeChat to their own account.</summary>
    SelfBind = 0,

    /// <summary>The first WeChat login provisioned the account under <see cref="WechatLoginMode.AutoProvision"/>.</summary>
    AutoProvision = 1
}
