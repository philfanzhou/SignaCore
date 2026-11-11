using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Domain;
using SignaCore.Domain.Keys;

namespace SignaCore.Host.Services;

/// <summary>
/// The single <c>IN-31</c> judgement shared by the prepared logout and the standard
/// <c>end_session_endpoint</c>: an RS256 signature over the logout-hint key set, the exact
/// issuer, the named audience, exactly one parseable <c>sub</c> and <c>sid</c>, and an
/// <c>iat</c> no older than the freshness bound. <c>exp</c> is ignored here and nowhere else;
/// the 24-hour retired-key window admits a token signed by a just-rotated key.
/// </summary>
internal static class OidcLogoutHintValidator
{
    /// <summary>
    /// Reads the single <c>aud</c> claim of an untrusted token without any other interpretation,
    /// so a caller can resolve the application registration before it knows which audience to
    /// validate against. The value is never trusted on its own: the full validation below must
    /// still succeed for the same audience.
    /// </summary>
    public static bool TryReadAudience(string idTokenHint, out string? audience)
    {
        audience = null;
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        if (!handler.CanReadToken(idTokenHint))
        {
            return false;
        }

        try
        {
            var token = handler.ReadJwtToken(idTokenHint);
            var audiences = token.Claims
                .Where(claim => string.Equals(claim.Type, "aud", StringComparison.Ordinal))
                .ToList();
            if (audiences.Count != 1 || string.IsNullOrWhiteSpace(audiences[0].Value))
            {
                return false;
            }

            audience = audiences[0].Value;
            return true;
        }
        // SecurityTokenMalformedException derives from ArgumentException in this token-handler
        // generation, so the single base catch covers the malformed-token path as well.
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Whether the hint validates for the given audience. The output ids are
    /// <see cref="Guid.Empty"/> on every failure path.
    /// </summary>
    public static bool TryValidate(
        string idTokenHint,
        string clientId,
        string issuer,
        IReadOnlyList<RsaSecurityKey> keys,
        DateTimeOffset now,
        out Guid subject,
        out Guid sessionId)
    {
        subject = Guid.Empty;
        sessionId = Guid.Empty;
        if (keys.Count == 0)
        {
            return false;
        }

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        if (!handler.CanReadToken(idTokenHint))
        {
            return false;
        }

        System.Security.Claims.ClaimsPrincipal principal;
        try
        {
            principal = handler.ValidateToken(
                idTokenHint,
                new TokenValidationParameters
                {
                    ValidIssuer = issuer,
                    ValidAudience = clientId,
                    IssuerSigningKeys = keys.Cast<SecurityKey>().ToList(),
                    ValidAlgorithms = ["RS256"],
                    ValidateLifetime = false
                },
                out var validated);
            _ = validated;
        }
        catch (Exception exception) when (exception
            is SecurityTokenValidationException or SecurityTokenMalformedException or ArgumentException)
        {
            return false;
        }

        // Exactly one sub and one sid, both parseable ids; any other shape is a failure.
        var subjectClaims = principal.FindAll("sub").ToList();
        var sessionClaims = principal.FindAll(JwtRegisteredClaimNames.Sid).ToList();
        if (subjectClaims.Count != 1
            || sessionClaims.Count != 1
            || !Guid.TryParse(subjectClaims[0].Value, out subject)
            || subject == Guid.Empty
            || !Guid.TryParse(sessionClaims[0].Value, out sessionId)
            || sessionId == Guid.Empty)
        {
            subject = Guid.Empty;
            sessionId = Guid.Empty;
            return false;
        }

        // IN-31 freshness: iat exists, is not in the future beyond clock skew, and is at most the
        // bound old. exp is deliberately not checked here.
        var issuedAtClaims = principal.FindAll(JwtRegisteredClaimNames.Iat).ToList();
        if (issuedAtClaims.Count != 1
            || !long.TryParse(issuedAtClaims[0].Value, out var issuedAtSeconds))
        {
            subject = Guid.Empty;
            sessionId = Guid.Empty;
            return false;
        }

        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAtSeconds);
        if (!(issuedAt <= now.AddMinutes(5)
            && issuedAt >= now.AddHours(-IdentityConstants.LogoutHintMaximumAgeHours)))
        {
            subject = Guid.Empty;
            sessionId = Guid.Empty;
            return false;
        }

        return true;
    }
}
