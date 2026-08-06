using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host;

public class JwksMapperTests
{
    [Fact]
    public void ToJwk_MapsRsaKeyToPublicJwk()
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = "test-key-id" };

        var jwk = JwksMapper.ToJwk(key);

        Assert.Equal("RSA", jwk.Kty);
        Assert.Equal("sig", jwk.Use);
        Assert.Equal("test-key-id", jwk.Kid);
        Assert.Equal("RS256", jwk.Alg);

        var parameters = rsa.ExportParameters(false);
        Assert.Equal(Base64UrlEncoder.Encode(parameters.Modulus!), jwk.N);
        Assert.Equal(Base64UrlEncoder.Encode(parameters.Exponent!), jwk.E);
    }

    [Fact]
    public void ToJwk_KeyWithoutRsaInstance_Throws()
    {
        var key = new RsaSecurityKey(new RSAParameters
        {
            Modulus = new byte[] { 1, 2, 3 },
            Exponent = new byte[] { 1, 0, 1 }
        });

        Assert.Throws<InvalidOperationException>(() => JwksMapper.ToJwk(key));
    }
}
