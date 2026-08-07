using SignaCore.Database;

namespace SignaCore.Host;

/// <summary>
/// Maps between the wire names used at <c>/oauth2/token</c> and the internal grant identifiers that
/// <see cref="Domain.Validators.ValidatorFactory"/> is keyed by.
/// <para>
/// RFC 6749 §4.5 requires an extension grant to be named by an absolute URI; only <c>password</c> and
/// <c>refresh_token</c> are registered names that can be used bare. The internal identifiers
/// (<c>sms</c>, <c>ldap</c>, <c>wechat_code</c>) stay unchanged because they are the contract of the
/// legacy <c>/api/auth/token</c> endpoint and appear in stored audit rows.
/// </para>
/// </summary>
public static class OAuthGrantTypes
{
    public const string UrnPrefix = "urn:signacore:params:oauth:grant-type:";

    public const string Sms = UrnPrefix + "sms";
    public const string Ldap = UrnPrefix + "ldap";
    public const string WechatCode = UrnPrefix + "wechat-code";

    private static readonly Dictionary<string, string> WireToInternal = new(StringComparer.Ordinal)
    {
        [IdentityConstants.GrantTypePassword] = IdentityConstants.GrantTypePassword,
        [IdentityConstants.GrantTypeRefreshToken] = IdentityConstants.GrantTypeRefreshToken,
        [Sms] = IdentityConstants.GrantTypeSms,
        [Ldap] = IdentityConstants.GrantTypeLdap,
        [WechatCode] = IdentityConstants.GrantTypeWechat
    };

    private static readonly Dictionary<string, string> InternalToWire =
        WireToInternal.ToDictionary(pair => pair.Value, pair => pair.Key, StringComparer.Ordinal);

    /// <summary>Returns the internal grant identifier, or null when the wire name is unknown.</summary>
    public static string? ToInternal(string? wireGrantType) =>
        wireGrantType != null && WireToInternal.TryGetValue(wireGrantType, out var internalName)
            ? internalName
            : null;

    /// <summary>
    /// Returns the name to advertise in discovery metadata for an internal grant identifier. A grant
    /// with no mapping falls back to its internal name, so a newly registered validator shows up in
    /// discovery even before it is given a URN.
    /// </summary>
    public static string ToWire(string internalGrantType) =>
        InternalToWire.TryGetValue(internalGrantType, out var wire) ? wire : internalGrantType;
}
