using ServiceMantle.Health;
using SignaCore.Domain.Keys;

namespace SignaCore.Host.HealthChecks;

/// <summary>
/// Business readiness gate for token issuance: an instance whose signing keys are not loaded can
/// serve discovery and JWKS shells but cannot issue a usable token, so it must not receive traffic.
/// </summary>
/// <remarks>
/// This contributor is the readiness authority for token issuance behind <c>/health/ready</c> and
/// the <c>/health</c> alias. Only a stable safe code leaves it: the shared result type structurally
/// cannot carry the initialization exception, so neither its text nor any key material can reach a
/// response, log, or metric.
/// </remarks>
internal sealed class SigningKeyReadinessContributor(IKeyManager keyManager) : IServiceReadinessContributor
{
    /// <summary>The stable safe code reported while signing keys cannot issue a token.</summary>
    internal const string SigningKeysUnavailableErrorCode = "signacore.signing_keys_unavailable";

    /// <summary>
    /// The fixed position this gate occupies in the shared readiness sequence. A duplicate order
    /// fails the host at startup, so a later contributor must pick its own value.
    /// </summary>
    internal const int SigningKeyOrder = 100;

    /// <inheritdoc/>
    public int Order => SigningKeyOrder;

    /// <inheritdoc/>
    public ValueTask<ServiceReadinessContributorResult> EvaluateAsync(
        ServiceHealthSnapshot snapshot,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        cancellationToken.ThrowIfCancellationRequested();

        // A faulted initialization and one that has not finished yet are the same closed decision:
        // the exception travels through the startup await, never through this result.
        return ValueTask.FromResult(keyManager.InitializationCompleted.IsCompletedSuccessfully
            ? ServiceReadinessContributorResult.Ready()
            : ServiceReadinessContributorResult.NotReady(SigningKeysUnavailableErrorCode));
    }
}
