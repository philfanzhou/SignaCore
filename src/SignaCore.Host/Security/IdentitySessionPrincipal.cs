using System.Security.Claims;

namespace SignaCore.Host.Security;

/// <summary>
/// Builds the minimal identity principal the <c>PS-18</c> cookie may carry: exactly one identity
/// authenticated under the identity scheme, holding the opaque session id and nothing else.
/// </summary>
/// <remarks>
/// This is the constructive enforcement of the payload rule: the subject, authentication
/// time/method, credential binding, activity, and revocation facts stay in the <c>PS-04</c>
/// session authority and are read from the database, so a successfully unprotected cookie is
/// never a self-contained identity fact. Adding claims here would silently turn the cookie into
/// such a fact.
/// </remarks>
public static class IdentitySessionPrincipal
{
    /// <summary>
    /// Creates the principal for one opaque identity-session id.
    /// </summary>
    /// <exception cref="ArgumentException">The session id is empty.</exception>
    public static ClaimsPrincipal Create(Guid sessionId)
    {
        if (sessionId == Guid.Empty)
        {
            throw new ArgumentException(
                "The identity session id must not be empty.",
                nameof(sessionId));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(IdentitySessionDefaults.SessionIdClaim, sessionId.ToString())],
            IdentitySessionDefaults.AuthenticationScheme));
    }
}
