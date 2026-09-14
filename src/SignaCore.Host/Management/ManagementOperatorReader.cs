using System.Security.Claims;
using ServiceMantle.Management;

namespace SignaCore.Host.Management;

/// <summary>
/// The single SignaCore read point for the administrator identity behind the shared management
/// session: it resolves the current operator through ServiceMantle and projects the audit actor.
/// </summary>
/// <remarks>
/// The audit actor id is the parsed <see cref="ManagementIdentity.OperatorId"/> and the actor name
/// is the operator display name. Ordinary <c>NameIdentifier</c>/<c>Name</c> claims are never
/// consulted: a principal that does not resolve through the shared claims parser yields
/// <see langword="null"/> for both, and authorization keeps such principals out of the admin API.
/// </remarks>
internal sealed class ManagementOperatorReader(IManagementCurrentOperatorResolver resolver)
{
    /// <summary>Projects the principal onto the audit actor; unresolved principals yield no actor.</summary>
    public (Guid? ActorId, string? ActorName) Read(ClaimsPrincipal? principal)
    {
        var resolution = resolver.Resolve(principal);
        if (resolution.Status != ManagementCurrentOperatorStatus.Resolved)
        {
            return (null, null);
        }

        var identity = resolution.Identity!;
        var actorId = Guid.TryParse(identity.OperatorId, out var id) ? id : (Guid?)null;
        return (actorId, identity.DisplayName);
    }
}
