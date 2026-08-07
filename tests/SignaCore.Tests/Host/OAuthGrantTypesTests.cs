using SignaCore.Database;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host;

public class OAuthGrantTypesTests
{
    [Theory]
    [InlineData("password", IdentityConstants.GrantTypePassword)]
    [InlineData("refresh_token", IdentityConstants.GrantTypeRefreshToken)]
    [InlineData("urn:signacore:params:oauth:grant-type:sms", IdentityConstants.GrantTypeSms)]
    [InlineData("urn:signacore:params:oauth:grant-type:ldap", IdentityConstants.GrantTypeLdap)]
    [InlineData("urn:signacore:params:oauth:grant-type:wechat-code", IdentityConstants.GrantTypeWechat)]
    public void ToInternal_MapsEveryWireName(string wire, string expected)
    {
        Assert.Equal(expected, OAuthGrantTypes.ToInternal(wire));
    }

    /// <summary>
    /// 历史短名不是 /oauth2/token 的合法输入：扩展 grant 必须用 URN（RFC 6749 §4.5）。
    /// 两套名字并存时，这条守住"标准端点只认标准名"。
    /// </summary>
    [Theory]
    [InlineData("sms")]
    [InlineData("ldap")]
    [InlineData("wechat_code")]
    [InlineData("no_such_grant")]
    [InlineData("")]
    [InlineData(null)]
    public void ToInternal_RejectsNonStandardNames(string? wire)
    {
        Assert.Null(OAuthGrantTypes.ToInternal(wire));
    }

    [Theory]
    [InlineData(IdentityConstants.GrantTypeSms, "urn:signacore:params:oauth:grant-type:sms")]
    [InlineData(IdentityConstants.GrantTypePassword, "password")]
    public void ToWire_ProducesTheAdvertisedName(string internalName, string expected)
    {
        Assert.Equal(expected, OAuthGrantTypes.ToWire(internalName));
    }

    /// <summary>
    /// 还没给 URN 的新 grant 也要出现在发现文档里（用内部名兜底），而不是从元数据里消失。
    /// </summary>
    [Fact]
    public void ToWire_FallsBackToTheInternalNameForAnUnmappedGrant()
    {
        Assert.Equal("brand_new_grant", OAuthGrantTypes.ToWire("brand_new_grant"));
    }

    [Fact]
    public void RoundTrip_IsStableForEveryMappedGrant()
    {
        foreach (var internalName in new[]
                 {
                     IdentityConstants.GrantTypePassword,
                     IdentityConstants.GrantTypeRefreshToken,
                     IdentityConstants.GrantTypeSms,
                     IdentityConstants.GrantTypeLdap,
                     IdentityConstants.GrantTypeWechat
                 })
        {
            Assert.Equal(internalName, OAuthGrantTypes.ToInternal(OAuthGrantTypes.ToWire(internalName)));
        }
    }
}
