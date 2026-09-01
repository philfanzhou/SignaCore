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
    /// The historical short names are not valid input to /oauth2/token: an extension grant has to
    /// use a URN (RFC 6749 §4.5). While both sets of names exist, this test holds the line that the
    /// standard endpoint only accepts standard names.
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
    /// A new grant that has not been given a URN yet still has to appear in the discovery document,
    /// falling back to its internal name, rather than vanish from the metadata.
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
