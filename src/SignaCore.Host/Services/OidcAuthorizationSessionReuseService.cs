using Microsoft.EntityFrameworkCore;
using ServiceMantle.Audit;
using SignaCore.Database;
using SignaCore.Host.Audit;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;

namespace SignaCore.Host.Services;

/// <summary>
/// The authorize-side reuse transaction of the interactive flow (<c>AC-09</c>): a browser whose
/// identity cookie names a still-usable server-side session receives a fresh authorization code
/// without another login. The whole unit — the session row lock, the live-session, account, and
/// application max-age decisions, the bounded activity slide (<c>PS-04</c>), the new code row
/// (<c>PS-05</c>), and the <c>accepted</c> audit row — commits once or not at all, and the
/// plaintext code is returned only after the commit (<c>DF-03</c>).
/// </summary>
/// <remarks>
/// Same shape as <see cref="OidcLoginCompletionService"/>: the explicit transaction runs as a
/// whole inside <c>CreateExecutionStrategy()</c> because PostgreSQL enables
/// <c>EnableRetryOnFailure()</c> (<c>PS-22</c>), and cancellation observed before the commit
/// rolls the whole unit back (<c>EV-18</c>). A <c>null</c> return always means "not reusable"
/// with zero committed writes: the caller falls back to the login continuation path afterwards,
/// so every accepted request still produces exactly one continuation-shaped <c>accepted</c>
/// audit row. Persistence failures propagate: the endpoint fails closed with a 500 and no
/// <c>Location</c>, never a half-open fallback.
/// </remarks>
public sealed class OidcAuthorizationSessionReuseService(
    IIdentitySessionStore identitySessions,
    IAuthorizationCodeStore authorizationCodes,
    IAccountRepository accounts,
    IManagementAuditWriter auditWriter,
    IUnitOfWork unitOfWork,
    IdentityDbContext dbContext)
{
    private const string AuditAction = "oidc.authorize.validated";
    private const string AuditTargetType = "OidcAuthorizationRequest";
    private const string AcceptedOutcome = "accepted";

    /// <summary>
    /// Runs the reuse decision for the session the cookie named, under the caller-captured
    /// instant <paramref name="now"/> (<c>PS-22</c>) and the accepted request's validated
    /// snapshot. Returns the committed plaintext code, or <c>null</c> when the session row is
    /// missing, revoked, idle- or absolutely expired (inclusive boundaries, <c>EV-04</c>), the
    /// account is gone or deactivated (<c>EV-08</c>), or this application's session max-age is
    /// reached (<c>EV-05</c>, never a global revocation) — each with the whole unit rolled back.
    /// The application's active/capability state is not re-decided here; the request's
    /// <c>Accepted</c> validation already proved it.
    /// </summary>
    public async Task<string?> TryIssueAsync(
        OidcAuthorizationValidationResult.Accepted accepted,
        Guid sessionId,
        DateTimeOffset now,
        string? clientIp,
        string? correlationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accepted);

        var strategy = dbContext.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async operationToken =>
        {
            dbContext.ChangeTracker.Clear();
            await using var transaction = await dbContext.Database
                .BeginTransactionAsync(operationToken);

            // EV-06 lock order: the session row first, before any code row exists.
            var session = await identitySessions.LockAsync(sessionId, operationToken);
            if (session is null
                || IdentitySessionStore.Classify(session, now) != IdentitySessionState.Active)
            {
                await transaction.RollbackAsync(operationToken);
                return null;
            }

            var account = await accounts.GetByIdAsync(session.AccountId, operationToken);
            if (account is null || !account.IsActive)
            {
                await transaction.RollbackAsync(operationToken);
                return null;
            }

            var application = await dbContext.AppRegistrations
                .AsNoTracking()
                .SingleOrDefaultAsync(app => app.Id == accepted.ApplicationId, operationToken);
            if (application is null
                || (application.IdentitySessionMaxAgeSeconds is int maxAgeSeconds
                    && now >= session.AuthTime.AddSeconds(maxAgeSeconds)))
            {
                await transaction.RollbackAsync(operationToken);
                return null;
            }

            var touch = await identitySessions.TouchActivityAsync(sessionId, now, operationToken);
            if (touch == IdentitySessionActivityResult.Unavailable)
            {
                // Unreachable while the row is locked; enforced against drift anyway.
                await transaction.RollbackAsync(operationToken);
                return null;
            }

            var creation = await authorizationCodes.CreateAsync(
                session,
                new AuthorizationCodeBinding(
                    accepted.ApplicationId,
                    accepted.RegisteredRedirectUri,
                    accepted.CanonicalScope,
                    accepted.Nonce,
                    accepted.CodeChallenge),
                now,
                operationToken);

            await ManagementActionAudit.RecordAsync(
                auditWriter,
                ManagementActionAudit.SystemSource,
                AuditAction,
                AuditTargetType,
                accepted.ApplicationId.ToString("D"),
                actorId: null,
                actorName: null,
                description: AcceptedOutcome,
                clientIp: clientIp,
                correlationId: correlationId,
                cancellationToken: operationToken);
            await unitOfWork.SaveChangesAsync(operationToken);
            await transaction.CommitAsync(operationToken);
            return creation.Code;
        }, cancellationToken);
    }
}
