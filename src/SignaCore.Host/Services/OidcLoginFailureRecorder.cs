using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;

namespace SignaCore.Host.Services;

/// <summary>
/// Commits one browser OIDC login credential failure (<c>EV-17</c>): the login-attempt counter
/// change discovered by the shared <see cref="PasswordValidator"/> and the single
/// <c>login_failure</c> history row are one unit of work, so a failed attempt can never be counted
/// without its audit row or audited without its count.
/// </summary>
/// <remarks>
/// Same shape as the <c>RecordFailure</c> branch of <see cref="AdminLoginStateRecorder"/>: the
/// explicit transaction runs as a whole inside <c>CreateExecutionStrategy()</c> because PostgreSQL
/// enables <c>EnableRetryOnFailure()</c> (<c>PS-22</c>), a replayed unit commits exactly once, and
/// cancellation observed before the commit rolls the whole unit back with no counter or audit
/// residue (<c>EV-18</c>, <c>SC-20</c>). A committed failure stays authoritative. This recorder
/// never clears counters and never writes success audits — the <c>EV-01</c> success transaction
/// owns both — and the caller decides the HTTP outcome only after the state is committed. The
/// <c>oidc_login</c> auth method is a new closed value of the existing
/// <c>login_histories.auth_method</c> column; no second failure standard is established.
/// </remarks>
public sealed class OidcLoginFailureRecorder(
    ILoginAttemptRepository loginAttemptRepository,
    IAuditService auditService,
    IUnitOfWork unitOfWork,
    IdentityDbContext dbContext,
    ILogger<OidcLoginFailureRecorder> logger)
{
    /// <summary>
    /// The closed <c>login_histories.auth_method</c> value of this route. It fits the existing
    /// 50-character column (<see cref="IdentityConstants.MaxAuthMethodLength"/>) and names the
    /// browser identity login without reusing a token grant type or <c>admin_login</c>.
    /// </summary>
    public const string OidcLoginAuthMethod = "oidc_login";

    private const string LoginFailureEventType = "login_failure";

    /// <summary>
    /// Commits the failure unit. <paramref name="failureReason"/> is the validator's internal
    /// message: it is written to the audit row and never returned to the browser.
    /// <paramref name="username"/> is the raw submitted personal identifier recorded under the
    /// existing audit standard; <paramref name="appId"/> is the <c>app_registrations.AppId</c> the
    /// continuation references.
    /// </summary>
    public async Task RecordFailureAsync(
        LoginAttemptChange? loginAttemptChange,
        string username,
        string failureReason,
        string appId,
        string? clientIp,
        string? userAgent,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        var strategy = dbContext.Database.CreateExecutionStrategy();
        await strategy.ExecuteAsync(async operationCancellationToken =>
        {
            dbContext.ChangeTracker.Clear();
            await using var transaction =
                await dbContext.Database.BeginTransactionAsync(operationCancellationToken);

            var loginAttempt = await LoginAttemptChangeApplier.ApplyAsync(
                loginAttemptChange,
                loginAttemptRepository,
                operationCancellationToken);
            if (loginAttempt?.LockoutUntil > DateTimeOffset.UtcNow)
            {
                logger.LogWarning(
                    "Account locked due to too many failed attempts, Username={Username}, LockoutUntil={LockoutUntil}",
                    LogValueSanitizer.Sanitize(loginAttempt.Username),
                    loginAttempt.LockoutUntil);
            }

            await auditService.RecordLoginAsync(
                accountId: null,
                username,
                OidcLoginAuthMethod,
                LoginFailureEventType,
                clientIp,
                userAgent,
                failureReason,
                appId,
                correlationId,
                cancellationToken: operationCancellationToken);
            await unitOfWork.SaveChangesAsync(operationCancellationToken);
            await transaction.CommitAsync(operationCancellationToken);
        }, cancellationToken);
    }
}
