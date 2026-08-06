using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;

namespace SignaCore.Domain.Services;

public interface ITokenService
{
    string GenerateJwtToken(List<Claim> claims, RsaSecurityKey key, int expirationHours);
}

public class JwtTokenService : ITokenService
{
    private readonly JwtOptions _jwtOptions;

    public JwtTokenService(JwtOptions jwtOptions)
    {
        _jwtOptions = jwtOptions;
    }

    public string GenerateJwtToken(List<Claim> claims, RsaSecurityKey key, int expirationHours)
    {
        var now = DateTimeOffset.UtcNow;
        var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
        var token = new JwtSecurityToken(
            new JwtHeader(credentials),
            new JwtPayload(
                issuer: _jwtOptions.Issuer,
                audience: _jwtOptions.Audience,
                claims: claims,
                notBefore: now.UtcDateTime,
                expires: now.AddHours(expirationHours).UtcDateTime));
        
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
