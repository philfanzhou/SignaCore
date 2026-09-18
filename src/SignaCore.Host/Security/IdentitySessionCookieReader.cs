using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace SignaCore.Host.Security;

/// <summary>
/// Reads the candidate identity-session id a browser request may carry in the protected
/// <see cref="IdentitySessionDefaults.CookieName"/> cookie — nothing more. The cookie is
/// unprotected only through the identity scheme named explicitly (<c>PS-18</c>), and the result
/// is a candidate id, never a session-usable decision: whether the referenced session is live
/// belongs to the locked database read of the reuse transaction, not to the cookie.
/// </summary>
public interface IIdentitySessionCookieReader
{
    /// <summary>
    /// Returns the single <see cref="IdentitySessionDefaults.SessionIdClaim"/> value that parses
    /// as a non-empty <see cref="Guid"/>, or <c>null</c> when the request carries no cookie, the
    /// payload fails to unprotect, the claim is missing, duplicated, or malformed, or the request
    /// only carries a management cookie.
    /// </summary>
    Task<Guid?> TryReadSessionIdAsync(HttpContext context);
}

/// <inheritdoc cref="IIdentitySessionCookieReader"/>
public sealed class IdentitySessionCookieReader : IIdentitySessionCookieReader
{
    /// <inheritdoc cref="IIdentitySessionCookieReader.TryReadSessionIdAsync"/>
    public async Task<Guid?> TryReadSessionIdAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var result = await context.AuthenticateAsync(IdentitySessionDefaults.AuthenticationScheme);
        if (!result.Succeeded || result.Principal is null)
        {
            return null;
        }

        var sessionIdClaims = result.Principal.FindAll(
            claim => string.Equals(claim.Type, IdentitySessionDefaults.SessionIdClaim, StringComparison.Ordinal))
            .ToList();
        if (sessionIdClaims.Count != 1
            || !Guid.TryParse(sessionIdClaims[0].Value, out var sessionId)
            || sessionId == Guid.Empty)
        {
            return null;
        }

        return sessionId;
    }
}
