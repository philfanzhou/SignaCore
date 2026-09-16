using Microsoft.AspNetCore.Authorization;

namespace SignaCore.Host.Security;

/// <summary>
/// The identity-session authorization requirement (canonical <c>PS-18</c>): the principal must
/// carry an identity authenticated through the isolated identity cookie scheme, and that identity
/// must hold the opaque session id claim.
/// </summary>
/// <remarks>
/// This is what keeps the two worlds apart at the policy level: the shared ServiceMantle
/// management principal — like any principal the default scheme populates — authenticates under a
/// different type and never holds a session id claim, so it can never satisfy an identity
/// authorization decision, and an identity principal never resolves to a management operator.
/// Whether the referenced session is currently usable is the <c>PS-04</c> authority's decision at
/// the request-time enforcement point, not this requirement's.
/// </remarks>
public sealed class IdentitySessionRequirement : IAuthorizationRequirement;

/// <summary>
/// Evaluates <see cref="IdentitySessionRequirement"/> against the identity-scheme identity and its
/// session id claim.
/// </summary>
public sealed class IdentitySessionHandler : AuthorizationHandler<IdentitySessionRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        IdentitySessionRequirement requirement)
    {
        foreach (var identity in context.User.Identities)
        {
            if (!string.Equals(
                    identity.AuthenticationType,
                    IdentitySessionDefaults.AuthenticationScheme,
                    StringComparison.Ordinal))
            {
                continue;
            }

            var sessionId = identity.FindFirst(IdentitySessionDefaults.SessionIdClaim)?.Value;
            if (!string.IsNullOrEmpty(sessionId))
            {
                context.Succeed(requirement);
                break;
            }
        }

        return Task.CompletedTask;
    }
}
