using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services;

public interface ITokenService
{
    string GenerateJwtToken(List<Claim> claims, RsaSecurityKey key, int expirationHours, string? audience = null);
}

public class JwtTokenService : ITokenService
{
    /// <summary>
    /// RFC 9068 §2.1: an access token in JWT form carries <c>typ: at+jwt</c> so a resource server can
    /// tell it apart from any other JWT signed by the same issuer.
    /// </summary>
    public const string AccessTokenType = "at+jwt";

    private readonly JwtOptions _jwtOptions;

    public JwtTokenService(JwtOptions jwtOptions)
    {
        _jwtOptions = jwtOptions;
    }

    /// <param name="audience">
    /// Audience for this token, or null to use the deployment-wide <see cref="JwtOptions.Audience"/>.
    /// Callers pass the application's own identifier when the application runs in
    /// <see cref="AudienceMode.PerApplication"/>.
    /// </param>
    public string GenerateJwtToken(
        List<Claim> claims,
        RsaSecurityKey key,
        int expirationHours,
        string? audience = null)
    {
        var now = DateTimeOffset.UtcNow;
        var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
        var header = new JwtHeader(credentials) { [JwtHeaderParameterNames.Typ] = AccessTokenType };
        var token = new JwtSecurityToken(
            header,
            new JwtPayload(
                issuer: _jwtOptions.Issuer,
                audience: string.IsNullOrWhiteSpace(audience) ? _jwtOptions.Audience : audience,
                claims: claims,
                notBefore: now.UtcDateTime,
                expires: now.AddHours(expirationHours).UtcDateTime));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// The audience an application's tokens must carry. Kept next to token creation so the issuing side
    /// and the validating side (JwtBearer audience validation in the host) cannot drift apart.
    /// </summary>
    public static string ResolveAudience(AppRegistrationEntity app, JwtOptions jwtOptions) =>
        app.AudienceMode == AudienceMode.PerApplication ? app.AppId : jwtOptions.Audience;
}
