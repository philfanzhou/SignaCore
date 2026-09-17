using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;

namespace SignaCore.Host.Services;

/// <summary>
/// The single success outcome of the <c>EV-01</c> completion transaction: the fresh
/// <c>PS-04</c> session id that goes into the identity cookie and the plaintext <c>PS-05</c>
/// authorization code that goes into the redirect. Both are released only after the commit
/// (<c>DF-03</c>/<c>DF-06</c>).
/// </summary>
public sealed record OidcLoginCompletion(Guid SessionId, string Code);

/// <summary>
/// Commits the one <c>EV-01</c> success transaction of the browser OIDC login: the continuation
/// consumption, the new identity session, the new authorization code, the failure-counter clear,
/// the login-info update, and the <c>login_success</c> history row are a single unit of work, so
/// a successful login can never leave half of its promised state behind. The caller revalidates
/// the current client, exact redirect URI, and scope before invoking this service and decides the
/// HTTP outcome only after the commit; the identity cookie and the plaintext code never enter a
/// response before it.
/// </summary>
/// <remarks>
/// Same shape as <see cref="OidcLoginFailureRecorder"/>: the explicit transaction runs as a whole
/// inside <c>CreateExecutionStrategy()</c> because PostgreSQL enables <c>EnableRetryOnFailure()</c>
/// (<c>PS-22</c>), a replayed unit commits exactly once, and cancellation observed before the
/// commit rolls the whole unit back with no residue (<c>EV-18</c>, <c>SC-20</c>). The continuation
/// is consumed first so a concurrent duplicate submission loses on the single conditional update
/// and produces no session row; the account is re-read inside the transaction so an account
/// deactivated after the credential check rolls the consumption back. Both races answer with the
/// single <c>null</c> "unavailable" result and zero committed writes.
/// </remarks>
public sealed class OidcLoginCompletionService(
    IAuthorizationRequestStore continuations,
    IAccountRepository accountRepository,
    IIdentitySessionStore identitySessions,
    IAuthorizationCodeStore authorizationCodes,
    ILoginAttemptRepository loginAttemptRepository,
    IAccountLoginInfoService accountLoginInfo,
    IAuditService auditService,
    IUnitOfWork unitOfWork,
    IdentityDbContext dbContext)
{
    private const string LoginSuccessEventType = "login_success";

    /// <summary>
    /// Runs the success transaction under the caller-captured instant <paramref name="now"/>
    /// (<c>PS-22</c>) and returns the committed session id and plaintext code, or <c>null</c> when
    /// the continuation was already consumed or expired (<c>EV-03</c> race) or the account is no
    /// longer active — both with the whole unit rolled back.
    /// <paramref name="credentialResult"/> must be the passing result of the shared Password
    /// validator carrying its <see cref="ValidationResult.PasswordCredentialId"/>; the session
    /// binds exactly the credential that passed. <paramref name="accepted"/> is the fresh
    /// revalidation output whose snapshot the code binds.
    /// </summary>
    /// <exception cref="ArgumentException">The credential result is not a passing validation.</exception>
    /// <exception cref="InvalidOperationException">
    /// The passing credential result carries no password credential id.
    /// </exception>
    public async Task<OidcLoginCompletion?> CompleteAsync(
        string loginHandle,
        OidcAuthorizationValidationResult.Accepted accepted,
        ValidationResult credentialResult,
        string appId,
        string? clientIp,
        string? userAgent,
        string correlationId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accepted);
        ArgumentNullException.ThrowIfNull(credentialResult);
        if (!credentialResult.IsSuccess)
        {
            throw new ArgumentException(
                "The credential result must be a passing validation.",
                nameof(credentialResult));
        }

        var passwordCredentialId = credentialResult.PasswordCredentialId
            ?? throw new InvalidOperationException(
                "The passing credential result carries no password credential id.");

        // The values the replayed unit writes are read exactly once, outside the retry loop.
        var accountId = credentialResult.Account.Id;
        var displayName = credentialResult.DisplayName;
        var loginAttemptChange = credentialResult.LoginAttemptChange;

        var strategy = dbContext.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async operationCancellationToken =>
        {
            dbContext.ChangeTracker.Clear();
            await using var transaction =
                await dbContext.Database.BeginTransactionAsync(operationCancellationToken);

            // Consume first: the conditional update is the single point a concurrent duplicate
            // submission loses on, before any session or code row exists (EV-03 race).
            if (!await continuations.TryConsumeAsync(loginHandle, now, operationCancellationToken))
            {
                await transaction.RollbackAsync(operationCancellationToken);
                return null;
            }

            // Re-read the account inside the transaction: an account deactivated after the
            // credential check rolls the consumption back and writes no failure count.
            var account = await accountRepository.GetByIdAsync(accountId, operationCancellationToken);
            if (account is null || !account.IsActive)
            {
                await transaction.RollbackAsync(operationCancellationToken);
                return null;
            }

            var session = await identitySessions.CreateAsync(
                account.Id, passwordCredentialId, now, operationCancellationToken);
            var code = await authorizationCodes.CreateAsync(
                session,
                new AuthorizationCodeBinding(
                    accepted.ApplicationId,
                    accepted.RegisteredRedirectUri,
                    accepted.CanonicalScope,
                    accepted.Nonce,
                    accepted.CodeChallenge),
                now,
                operationCancellationToken);
            await LoginAttemptChangeApplier.ApplyAsync(
                loginAttemptChange, loginAttemptRepository, operationCancellationToken);
            await accountLoginInfo.UpdateLoginInfoAsync(
                account, clientIp, IdentityConstants.AuthMethodPassword, operationCancellationToken);
            await auditService.RecordLoginAsync(
                account.Id,
                displayName ?? account.Id.ToString(),
                OidcLoginFailureRecorder.OidcLoginAuthMethod,
                LoginSuccessEventType,
                clientIp,
                userAgent,
                null,
                appId,
                correlationId,
                cancellationToken: operationCancellationToken);
            await unitOfWork.SaveChangesAsync(operationCancellationToken);
            await transaction.CommitAsync(operationCancellationToken);
            return new OidcLoginCompletion(session.Id, code.Code);
        }, cancellationToken);
    }
}
