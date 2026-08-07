namespace SignaCore.Database.Entity;

/// <summary>
/// Application-scoped WeChat admission policy.
/// <para>
/// Unlike a phone number or an Active Directory account, an OpenId is only knowable
/// after the user has completed a WeChat authorization at least once, so there is no
/// administrator-driven pre-approval mode here: the binding is always created by the
/// user (<see cref="BindRequired"/>) or by the first login (<see cref="AutoProvision"/>).
/// Administrators revoke, they do not pre-grant.
/// </para>
/// </summary>
public enum WechatLoginMode
{
    Disabled = 0,

    /// <summary>The OpenId must already be bound to an account and admitted for this application.</summary>
    BindRequired = 1,

    /// <summary>An unknown OpenId provisions a new account and admits it for this application.</summary>
    AutoProvision = 2
}
