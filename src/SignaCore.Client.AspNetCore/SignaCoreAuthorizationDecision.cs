using System.Security.Claims;

namespace SignaCore.Client.AspNetCore;

/// <summary>The outcome of the consumer's authorization decision.</summary>
public enum SignaCoreAuthorizationDecisionResult
{
    /// <summary>The subject is allowed.</summary>
    Allowed,

    /// <summary>The subject is denied. A denial is not a sign-out: the session stays valid.</summary>
    Denied
}

/// <summary>
/// Extension point — administrator and authorization decisions. The input is the principal
/// verified from the ID token (its <c>iss</c> and <c>sub</c> are the SignaCore identity); the
/// consumer decides what that subject may do. The package calls it for the session-status answer
/// and never enforces a business rule of its own.
/// </summary>
public interface ISignaCoreAuthorizationDecision
{
    /// <summary>Decides whether the verified subject is allowed.</summary>
    /// <param name="subject">The principal verified from the ID token.</param>
    /// <param name="cancellationToken">Propagates the caller's cancellation.</param>
    ValueTask<SignaCoreAuthorizationDecisionResult> DecideAsync(
        ClaimsPrincipal subject,
        CancellationToken cancellationToken);
}

/// <summary>
/// The default decision: every verified subject is allowed. The package carries no business rule;
/// a consumer that needs a boundary replaces this through the options.
/// </summary>
public sealed class SignaCoreAllowAllAuthorizationDecision : ISignaCoreAuthorizationDecision
{
    private SignaCoreAllowAllAuthorizationDecision()
    {
    }

    /// <summary>The stateless instance every default configuration shares.</summary>
    public static SignaCoreAllowAllAuthorizationDecision Instance { get; } = new();

    /// <inheritdoc />
    public ValueTask<SignaCoreAuthorizationDecisionResult> DecideAsync(
        ClaimsPrincipal subject,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(SignaCoreAuthorizationDecisionResult.Allowed);
}
