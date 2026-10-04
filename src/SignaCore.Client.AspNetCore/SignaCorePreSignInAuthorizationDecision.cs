using System.Security.Claims;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// Request-local copies of the verified, issuer/subject-correlated tokens. Contains no raw token.
/// Changes to these principals cannot change the session principal or another callback.
/// </summary>
public sealed class SignaCorePreSignInAuthorizationContext
{
    internal SignaCorePreSignInAuthorizationContext(
        ClaimsPrincipal accessPrincipal, ClaimsPrincipal idPrincipal, string issuer, string subject)
    {
        AccessTokenPrincipal = new ClaimsPrincipal(accessPrincipal.Identities.Select(identity => identity.Clone()));
        IdTokenPrincipal = new ClaimsPrincipal(idPrincipal.Identities.Select(identity => identity.Clone()));
        Issuer = issuer;
        Subject = subject;
    }

    /// <summary>The verified access-token claims on which consumer authorization may depend.</summary>
    public ClaimsPrincipal AccessTokenPrincipal { get; }

    /// <summary>The verified ID-token claims; these are identity, not access permissions.</summary>
    public ClaimsPrincipal IdTokenPrincipal { get; }

    /// <summary>The exact verified issuer shared by both tokens.</summary>
    public string Issuer { get; }

    /// <summary>The exact verified subject shared by both tokens.</summary>
    public string Subject { get; }
}

/// <summary>
/// Optional callback authorization before a new ticket or cookie is written. Only Allowed signs
/// in; denial does not remove an existing session. Return promptly with asynchronous work, honor
/// cancellation, and perform no sign-in or other side effects. Arbitrary synchronous blocking
/// and non-cooperative consumer side effects cannot be sandboxed by the package.
/// </summary>
public interface ISignaCorePreSignInAuthorizationDecision
{
    /// <summary>Decides whether this correlated, verified subject may establish a new session.</summary>
    /// <param name="context">Request-local verified claims, without raw protocol material.</param>
    /// <param name="cancellationToken">Request cancellation or the bounded decision timeout.</param>
    ValueTask<SignaCoreAuthorizationDecisionResult> DecideAsync(
        SignaCorePreSignInAuthorizationContext context, CancellationToken cancellationToken);
}
