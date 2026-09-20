using SignaCore.ReferenceBff.Database;

namespace SignaCore.ReferenceBff;

/// <summary>Outcome of the local administrator authorization decision.</summary>
internal enum BffAdminAuthorizationStatus
{
    /// <summary>The verified identity is exactly the active bound administrator.</summary>
    Authorized,

    /// <summary>The verified identity holds no local administrator permission. Keep the ticket.</summary>
    Forbidden,

    /// <summary>The local session no longer names a valid upstream identity. Tear it down.</summary>
    SessionInvalid,

    /// <summary>A dependency could not answer. Keep the ticket; never widen permission.</summary>
    Unavailable
}

/// <summary>
/// The administrator authorization boundary: an upstream-confirmed identity (via
/// <see cref="BffIdentityCheckService"/>) AND the exact local active binding must both hold before
/// any caller is treated as an administrator. The decision is computed per request — nothing is
/// cached across requests, so a revoked binding or a dead upstream session takes effect on the
/// very next request. Only the verified issuer/subject pair is ever matched; no request input,
/// no generic admin claim, and no normalized identity participates.
/// </summary>
internal sealed class BffAdminAuthorizationService(
    BffIdentityCheckService identityCheck,
    IServiceProvider services)
{
    public async Task<BffAdminAuthorizationStatus> AuthorizeAsync(HttpContext http, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var identity = await identityCheck.CheckAsync(http, cancellationToken);
        if (identity.Status != BffIdentityCheckStatus.Confirmed)
        {
            return identity.Status switch
            {
                BffIdentityCheckStatus.SessionInvalid => BffAdminAuthorizationStatus.SessionInvalid,
                _ => BffAdminAuthorizationStatus.Unavailable
            };
        }

        cancellationToken.ThrowIfCancellationRequested();

        // No database configured: the sample keeps running its login surface, but a management
        // query can never be answered — fixed unavailable, never a default grant.
        var roleStore = services.GetService<ManagementRoleBindingStore>();
        if (roleStore is null)
        {
            return BffAdminAuthorizationStatus.Unavailable;
        }

        try
        {
            var match = await roleStore.MatchAdministratorAsync(
                identity.VerifiedIssuer!, identity.VerifiedSubject!, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return match == ManagementRoleBindingMatchStatus.MatchedActiveAdministrator
                ? BffAdminAuthorizationStatus.Authorized
                : BffAdminAuthorizationStatus.Forbidden;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            // An internal cancellation while the caller still waits: bounded unavailable.
            return BffAdminAuthorizationStatus.Unavailable;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // A database that cannot answer (unreachable, missing schema) grants nothing.
            return BffAdminAuthorizationStatus.Unavailable;
        }
    }
}
