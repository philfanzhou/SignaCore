using Microsoft.Extensions.Diagnostics.HealthChecks;
using SignaCore.Domain.Keys;

namespace SignaCore.Host.HealthChecks;

/// <summary>
/// Readiness gate for token issuance: an instance whose signing keys are not loaded can serve
/// discovery and JWKS shells but cannot issue a usable token, so it must not receive traffic.
/// </summary>
internal sealed class SigningKeysHealthCheck : IHealthCheck
{
    private readonly IKeyManager _keyManager;

    public SigningKeysHealthCheck(IKeyManager keyManager)
    {
        _keyManager = keyManager;
    }

    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var initialization = _keyManager.InitializationCompleted;

        if (initialization.IsCompletedSuccessfully)
        {
            return Task.FromResult(HealthCheckResult.Healthy("Signing keys are loaded."));
        }

        if (initialization.IsFaulted)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(
                "Signing key initialization failed.",
                initialization.Exception));
        }

        return Task.FromResult(HealthCheckResult.Unhealthy(
            "Signing key initialization has not completed."));
    }
}
