using System.Security.Claims;

namespace SignaCore.Client.AspNetCore;

/// <summary>The outcome of the consumer's authorization decision.</summary>
public enum AuthorizationDecisionResult
{
    /// <summary>The subject is allowed.</summary>
    Allowed,

    /// <summary>The subject is denied. Session-status denial retains the session; pre-sign-in denial prevents a new session.</summary>
    Denied
}

/// <summary>
/// Extension point — administrator and authorization decisions. The input is the principal
/// verified from the ID token (its <c>iss</c> and <c>sub</c> are the SignaCore identity); the
/// consumer decides what that subject may do. The package calls it for the session-status answer
/// and never enforces a business rule of its own.
/// </summary>
public interface IAuthorizationDecision
{
    /// <summary>Decides whether the verified subject is allowed.</summary>
    /// <param name="subject">The principal verified from the ID token.</param>
    /// <param name="cancellationToken">Propagates the caller's cancellation.</param>
    ValueTask<AuthorizationDecisionResult> DecideAsync(
        ClaimsPrincipal subject,
        CancellationToken cancellationToken);
}

/// <summary>
/// The default decision: every verified subject is allowed. The package carries no business rule;
/// a consumer that needs a boundary replaces this through the options.
/// </summary>
public sealed class AllowAllAuthorizationDecision : IAuthorizationDecision
{
    private AllowAllAuthorizationDecision()
    {
    }

    /// <summary>The stateless instance every default configuration shares.</summary>
    public static AllowAllAuthorizationDecision Instance { get; } = new();

    /// <inheritdoc />
    public ValueTask<AuthorizationDecisionResult> DecideAsync(
        ClaimsPrincipal subject,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(AuthorizationDecisionResult.Allowed);
}
