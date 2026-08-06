using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

public class JwtTokenServiceTests
{
    private static JwtOptions CreateJwtOptions() => new() { Issuer = "TestIssuer", Audience = "TestAudience", TokenExpirationHours = 2 };

    private static RsaSecurityKey CreateTestKey()
    {
        return new RsaSecurityKey(System.Security.Cryptography.RSA.Create(2048))
        {
            KeyId = "test-key-id"
        };
    }

    [Fact]
    public void GenerateJwtToken_ReturnsValidToken()
    {
        var service = new JwtTokenService(CreateJwtOptions());
        var key = CreateTestKey();
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(ClaimTypes.Name, "testuser")
        };

        var token = service.GenerateJwtToken(claims, key, 2);

        Assert.NotNull(token);
        Assert.NotEmpty(token);

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);
        Assert.Equal("TestIssuer", jwt.Issuer);
        Assert.Equal("TestAudience", jwt.Audiences.First());
        Assert.Contains(jwt.Claims, c => c.Type == ClaimTypes.Name && c.Value == "testuser");
    }

    [Fact]
    public void GenerateJwtToken_WithExpirationHours_SetsCorrectExpiry()
    {
        var service = new JwtTokenService(CreateJwtOptions());
        var key = CreateTestKey();
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()) };

        var before = DateTime.UtcNow;
        var token = service.GenerateJwtToken(claims, key, 4);
        var after = DateTime.UtcNow;

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);
        var expiresAt = jwt.ValidTo;

        Assert.True(expiresAt >= before.AddHours(4).AddSeconds(-5));
        Assert.True(expiresAt <= after.AddHours(4).AddSeconds(5));
    }

    [Fact]
    public void GenerateJwtToken_WithRoles_IncludesRoleClaims()
    {
        var service = new JwtTokenService(CreateJwtOptions());
        var key = CreateTestKey();
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new(ClaimTypes.Role, "admin"),
            new(ClaimTypes.Role, "user")
        };

        var token = service.GenerateJwtToken(claims, key, 2);

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);
        Assert.Equal(2, jwt.Claims.Count(c => c.Type == ClaimTypes.Role));
    }
}
