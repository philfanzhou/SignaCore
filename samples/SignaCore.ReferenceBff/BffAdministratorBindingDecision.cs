using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SignaCore.Client.AspNetCore;
using SignaCore.ReferenceBff.Database;

namespace SignaCore.ReferenceBff;

/// <summary>
/// The sample's plug into the client package's authorization-decision extension point: it
/// answers whether the identity the package verified from the ID token is the locally bound
/// administrator, and the package reports that answer through its session-status endpoint. The
/// decision is computed fresh on every call from the verified <c>iss</c> plus <c>sub</c> only —
/// no request input, no generic admin claim, and no normalization; anything that cannot be
/// answered is a denial, because the session endpoint must never widen permission. The
/// <c>/bff/admin</c> endpoint keeps its own stronger decision: it re-confirms the identity
/// upstream through UserInfo before the same binding match runs.
/// </summary>
internal sealed class BffAdministratorBindingDecision(IServiceProvider services) : ISignaCoreAuthorizationDecision
{
    public async ValueTask<SignaCoreAuthorizationDecisionResult> DecideAsync(
        ClaimsPrincipal subject,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var issuer = ReadSingleClaim(subject, "iss");
        var identitySubject = ReadSingleClaim(subject, "sub");
        if (issuer is null || identitySubject is null)
        {
            // A principal without exactly one verified issuer and subject can prove nothing.
            return SignaCoreAuthorizationDecisionResult.Denied;
        }

        await using var scope = services.CreateAsyncScope();
        var bindingStore = scope.ServiceProvider.GetService<ManagementRoleBindingStore>();
        if (bindingStore is null)
        {
            // No database configured: no binding can exist, so no subject is an administrator.
            return SignaCoreAuthorizationDecisionResult.Denied;
        }

        try
        {
            var match = await bindingStore.MatchAdministratorAsync(issuer, identitySubject, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return match == ManagementRoleBindingMatchStatus.MatchedActiveAdministrator
                ? SignaCoreAuthorizationDecisionResult.Allowed
                : SignaCoreAuthorizationDecisionResult.Denied;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // A database that cannot answer grants nothing.
            return SignaCoreAuthorizationDecisionResult.Denied;
        }
    }

    /// <summary>Reads exactly one non-empty claim of a type, or null for zero, many, or empty.</summary>
    private static string? ReadSingleClaim(ClaimsPrincipal principal, string claimType)
    {
        var claims = principal.FindAll(claimType).ToList();
        return claims.Count == 1 && !string.IsNullOrEmpty(claims[0].Value)
            ? claims[0].Value
            : null;
    }
}
