using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Domain;

/// <summary>
/// Resolves JWT claims for an account.
/// Basic claims come from the account itself; additional claims (roles, permissions)
/// are injected via callback to business services.
/// </summary>
public class ClaimsResolver
{
    private readonly ILogger<ClaimsResolver> _logger;

    public ClaimsResolver(ILogger<ClaimsResolver> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Resolves basic identity claims for an account.
    /// </summary>
    /// <param name="account">The account.</param>
    /// <param name="displayName">Display name for the account (from credential tables).</param>
    public List<Claim> ResolveBasicClaims(AccountEntity account, string? displayName = null)
    {
        var claims = new List<Claim>
        {
            new(IdentityConstants.ClaimSubject, account.Id.ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };

        if (!string.IsNullOrEmpty(displayName))
        {
            claims.Add(new Claim(IdentityConstants.ClaimName, displayName));
        }

        if (!string.IsNullOrEmpty(account.Nickname))
        {
            claims.Add(new Claim(IdentityConstants.ClaimNickname, account.Nickname));
        }

        _logger.LogDebug("Resolved {Count} basic claims for account {AccountId}",
            claims.Count, account.Id);

        return claims;
    }
}