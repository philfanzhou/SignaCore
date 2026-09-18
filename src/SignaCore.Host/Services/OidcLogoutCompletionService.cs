using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;

namespace SignaCore.Host.Services;

/// <summary>
/// The closed external result of the logout completion: either the local 400 every unusable or
/// corrupt handle shares, or the committed success both <c>EV-06</c> and <c>EV-07</c> answer with
/// — carrying the exact verified post-logout URI and state snapshot when a redirect is due. The
/// two success paths are deliberately indistinguishable from this value alone: no session-state
/// oracle (<c>SC-15</c>).
/// </summary>
public sealed record OidcLogoutCompletionResult
{
    public static readonly OidcLogoutCompletionResult Unavailable = new(false, null, null);

    /// <summary>
    /// The committed success: the exact stored post-logout URI (null means the local completion
    /// page) and the byte-for-byte state snapshot appended to the redirect.
    /// </summary>
    public static OidcLogoutCompletionResult Success(string? verifiedPostLogoutUri, string? state) =>
        new(true, verifiedPostLogoutUri, state);

    private OidcLogoutCompletionResult(bool isSuccess, string? verifiedPostLogoutUri, string? state)
    {
        IsSuccess = isSuccess;
        VerifiedPostLogoutUri = verifiedPostLogoutUri;
        State = state;
    }

    public bool IsSuccess { get; }

    public string? VerifiedPostLogoutUri { get; }

    public string? State { get; }
}

/// <summary>
/// Step 2 of the prepared logout: the browser consumes one five-minute single-use handle at
/// <c>GET /oauth2/logout</c> (<c>IN-35</c>/<c>IN-36</c>). A matching usable identity cookie
/// executes <c>EV-06</c> — consume the request, revoke the session with reason <c>logout</c>,
/// and explicitly revoke every interactive family bound to it, all in one transaction; a
/// missing, unusable, or mismatching cookie executes <c>EV-07</c> — consume the request and
/// change nothing. Both commit under the canonical session-then-request lock order
/// (<c>EV-28</c>) and answer with the same external shape.
/// </summary>
public sealed class OidcLogoutCompletionService(
    ILogoutRequestStore logoutRequests,
    IIdentitySessionStore identitySessions,
    IRefreshTokenRepository refreshTokens,
    IAuditService auditService,
    IUnitOfWork unitOfWork,
    IdentityDbContext dbContext,
    ILogger<OidcLogoutCompletionService> logger)
{
    private const string CompletedAuditAction = "oidc.logout.completed";
    private const string LogoutRequestAuditTargetType = "LogoutRequest";
    private const string ResultRevoked = "revoked";
    private const string ResultNoSessionWrite = "no_session_write";

    /// <summary>
    /// Digest-loads the request, then — when a session row may exist for the stored
    /// <c>sid</c> — locks the session before the request row inside the provider execution
    /// strategy, repeats the lifecycle checks under the lock, and conditionally consumes the
    /// request exactly once. Caller cancellation before the commit rolls the whole unit back
    /// (<c>EV-18</c>/<c>SC-20</c>); a cookie mismatch is never an error.
    /// </summary>
    /// <exception cref="OperationCanceledException">The caller's token was cancelled before commit.</exception>
    public async Task<OidcLogoutCompletionResult> CompleteAsync(
        string logoutHandle,
        Guid? cookieSessionId,
        string? clientIp,
        string? correlationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(logoutHandle);

        var now = DateTimeOffset.UtcNow;

        // SC-18/IN-35: a missing, malformed, expired, or consumed handle shares the single
        // local answer, with no invented consumption, revocation, or audit.
        var request = await logoutRequests.GetActiveAsync(logoutHandle, now, cancellationToken);
        if (request is null)
        {
            return OidcLogoutCompletionResult.Unavailable;
        }

        var strategy = dbContext.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async operationToken =>
        {
            dbContext.ChangeTracker.Clear();
            await using var transaction = await dbContext.Database
                .BeginTransactionAsync(operationToken);

            // EV-28 lock order: the session row (of the stored sid — it may be gone) before the
            // logout-request row, so a concurrent code redemption on the same session can never
            // deadlock against this unit.
            var lockedSession = await identitySessions.LockAsync(request.IdentitySessionId, operationToken);
            var lockedRequest = await logoutRequests.LockAsync(request.Id, operationToken);
            if (lockedRequest is null
                || lockedRequest.ConsumedAt is not null
                || lockedRequest.ExpiresAt <= now)
            {
                await transaction.RollbackAsync(operationToken);
                return OidcLogoutCompletionResult.Unavailable;
            }

            // IN-36 corruption: the live session row under the stored sid names a different
            // account than the stored sub — an impossible record. Local 400, zero state writes.
            if (lockedSession is not null && lockedSession.AccountId != lockedRequest.AccountId)
            {
                await transaction.RollbackAsync(operationToken);
                logger.LogWarning(
                    "Logout request bound to a mismatched session account; treated as corruption. RequestId={RequestId}",
                    lockedRequest.Id);
                return OidcLogoutCompletionResult.Unavailable;
            }

            // IN-36: the cookie is authoritative only on exact sid equality with a live, matching
            // session row; anything else is EV-07.
            var cookieMatches = cookieSessionId == lockedRequest.IdentitySessionId
                && lockedSession is not null
                && lockedSession.AccountId == lockedRequest.AccountId;

            if (!await logoutRequests.TryConsumeAsync(logoutHandle, now, operationToken))
            {
                await transaction.RollbackAsync(operationToken);
                return OidcLogoutCompletionResult.Unavailable;
            }

            string result;
            if (cookieMatches)
            {
                // EV-06: the session revocation keeps any first fact (an already-revoked session
                // stays revoked), and every interactive family of the session is revoked
                // explicitly in the same unit.
                await identitySessions.RevokeAsync(
                    lockedSession!.Id, IdentitySessionRevocationReason.Logout, now, operationToken);
                await refreshTokens.RevokeInteractiveBySessionAsync(
                    lockedSession.Id, operationToken);
                result = ResultRevoked;
            }
            else
            {
                // EV-07: consumption only — no session, code, or family state changes.
                result = ResultNoSessionWrite;
            }

            await auditService.RecordActionAsync(
                CompletedAuditAction,
                LogoutRequestAuditTargetType,
                lockedRequest.Id.ToString("D"),
                actorId: lockedRequest.AccountId,
                actorName: null,
                description: $"session:{lockedRequest.IdentitySessionId};result:{result}",
                clientIp: clientIp,
                correlationId: correlationId,
                cancellationToken: operationToken);
            await unitOfWork.SaveChangesAsync(operationToken);
            await transaction.CommitAsync(operationToken);

            logger.LogInformation(
                "Logout completed: RequestId={RequestId}, SessionId={SessionId}, Result={Result}",
                lockedRequest.Id,
                lockedRequest.IdentitySessionId,
                result);
            return OidcLogoutCompletionResult.Success(
                lockedRequest.PostLogoutRedirectUri,
                lockedRequest.State);
        }, cancellationToken);
    }
}
