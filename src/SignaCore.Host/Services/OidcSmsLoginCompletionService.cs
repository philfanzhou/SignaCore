using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Sms;

namespace SignaCore.Host.Services;

/// <summary>
/// One browser SMS login that passed the <c>IN-17</c>/<c>IN-18</c> field checks, send eligibility,
/// the read-only OTP verification, and the <c>EV-01</c> revalidation. <paramref name="OtpConsumption"/>
/// is the verifier's <see cref="OtpVerificationChangeKind.Consume"/> change bound to the verified
/// MAC; <paramref name="PhoneE164"/> is the normalized phone, which leaves this request only as the
/// identity lookup key and the masked audit username (<c>DF-16</c>).
/// </summary>
public sealed record OidcSmsLoginRequest(
    string LoginHandle,
    OidcAuthorizationValidationResult.Accepted Accepted,
    string AppId,
    string PhoneE164,
    OtpVerificationChange OtpConsumption,
    string? ClientIp,
    string? UserAgent,
    string CorrelationId,
    DateTimeOffset Now);

/// <summary>The closed result of the <c>EV-36</c> transaction.</summary>
public abstract record OidcSmsLoginResult
{
    private OidcSmsLoginResult()
    {
    }

    /// <summary>
    /// The unit committed: the fresh <c>Sms</c> session id for the identity cookie and the
    /// plaintext code for the redirect, both released only after the commit.
    /// </summary>
    public sealed record Completed(Guid SessionId, string Code) : OidcSmsLoginResult;

    /// <summary>
    /// The continuation was consumed or expired concurrently, or the current authorization policy
    /// no longer allows the stored request: the whole unit rolled back and the caller answers as
    /// <c>EV-03</c>.
    /// </summary>
    public sealed record ContinuationUnavailable : OidcSmsLoginResult;

    /// <summary>
    /// The conditional OTP consumption was lost, the identity or account no longer qualifies, the
    /// <c>PS-04</c> recheck failed, or the provisioning conflicted twice (<c>SC-23</c>): the whole
    /// unit rolled back and the caller answers as <c>EV-37</c> with the <c>otp_race</c> reason.
    /// </summary>
    public sealed record SmsFailure : OidcSmsLoginResult;

    internal static readonly ContinuationUnavailable Unavailable = new();
    internal static readonly SmsFailure Failure = new();
}

/// <summary>
/// Commits the one <c>EV-36</c> success transaction of the browser SMS login: the conditional
/// continuation consumption, the conditional OTP consumption against the verified MAC, the
/// <c>AutoProvision</c> account/SMS identity/admission creation, the <c>PS-04</c> recheck, the new
/// <c>Sms</c> identity session, the new authorization code, the login-info update, and one masked
/// <c>login_success</c> history row are a single unit of work, so a login can never leave an OTP
/// consumed without a session, or an account provisioned without the login that proved the phone.
/// </summary>
/// <remarks>
/// <para>
/// Same shape as <see cref="OidcLoginCompletionService"/>: the explicit transaction runs as a whole
/// inside <c>CreateExecutionStrategy()</c> (<c>PS-22</c>), a replayed unit commits exactly once, and
/// cancellation observed before the commit rolls the whole unit back with no residue
/// (<c>EV-18</c>, <c>SC-20</c>). Provisioning never goes through
/// <see cref="ISmsAdmissionService.ProvisionAsync"/>, which owns its own transaction and commit;
/// the rows are staged in this unit by
/// <see cref="ISmsAdmissionService.FindOrStageLoginIdentityAsync"/> and flushed before the recheck
/// and the session insert, because both read the database rather than the change tracker.
/// </para>
/// <para>
/// A concurrent provisioning of the same phone surfaces at that flush as a unique-key violation
/// (<c>SC-23</c>): the unit rolls back and runs once more from the start, now finding the winner's
/// identity and admission; a second conflict answers <see cref="OidcSmsLoginResult.SmsFailure"/>.
/// Any other persistence failure rolls the unit back and propagates unchanged, exactly as in
/// <c>EV-01</c>.
/// </para>
/// </remarks>
public sealed class OidcSmsLoginCompletionService(
    IAuthorizationRequestStore continuations,
    IOtpRepository otpRepository,
    ISmsAdmissionService admissions,
    IAccountRepository accountRepository,
    IIdentitySessionStore identitySessions,
    IAuthorizationCodeStore authorizationCodes,
    IAccountLoginInfoService accountLoginInfo,
    IAuditService auditService,
    IUnitOfWork unitOfWork,
    IdentityDbContext dbContext,
    AuthMetrics metrics,
    ILogger<OidcSmsLoginCompletionService> logger)
{
    /// <summary>The <c>auth.account.creation</c> source, shared with the SMS token grant.</summary>
    public const string AccountCreationSource = "auto_register_sms";

    private const string LoginSuccessEventType = "login_success";

    /// <summary>
    /// Runs the unit under the caller-captured instant of <paramref name="request"/> (<c>PS-22</c>).
    /// </summary>
    /// <exception cref="ArgumentException">The OTP change is not a consumption.</exception>
    public async Task<OidcSmsLoginResult> CompleteAsync(
        OidcSmsLoginRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Accepted);
        ArgumentNullException.ThrowIfNull(request.OtpConsumption);
        if (request.OtpConsumption.Kind != OtpVerificationChangeKind.Consume)
        {
            throw new ArgumentException(
                "The OTP change must be the verified consumption.", nameof(request));
        }

        for (var attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var (result, accountCreated) = await RunUnitAsync(request, cancellationToken);
                if (accountCreated)
                {
                    metrics.RecordAccountCreation(AccountCreationSource);
                }

                return result;
            }
            catch (ProvisioningConflictException) when (attempt == 0)
            {
                // The unit rolled back; the retry starts from a clean tracker and reads the
                // winner's committed identity and admission.
                dbContext.ChangeTracker.Clear();
                logger.LogInformation(
                    "Browser SMS login provisioning conflicted with a concurrent writer; retrying once. CorrelationId={CorrelationId}",
                    LogValueSanitizer.Sanitize(request.CorrelationId));
            }
            catch (ProvisioningConflictException)
            {
                dbContext.ChangeTracker.Clear();
                logger.LogWarning(
                    "Browser SMS login provisioning conflicted again after one retry. CorrelationId={CorrelationId}",
                    LogValueSanitizer.Sanitize(request.CorrelationId));
                return OidcSmsLoginResult.Failure;
            }
        }
    }

    private async Task<(OidcSmsLoginResult Result, bool AccountCreated)> RunUnitAsync(
        OidcSmsLoginRequest request,
        CancellationToken cancellationToken)
    {
        var accepted = request.Accepted;
        var strategy = dbContext.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async operationCancellationToken =>
        {
            dbContext.ChangeTracker.Clear();
            await using var transaction =
                await dbContext.Database.BeginTransactionAsync(operationCancellationToken);

            // ① Consume first: the single point a concurrent duplicate submission loses on,
            // before any OTP, identity, session, or code write (EV-03 race, SC-26).
            if (!await continuations.TryConsumeAsync(request.LoginHandle, request.Now, operationCancellationToken)
                || !await OidcCurrentAuthorizationPolicy.AllowsAsync(dbContext, accepted, operationCancellationToken))
            {
                await transaction.RollbackAsync(operationCancellationToken);
                return ((OidcSmsLoginResult)OidcSmsLoginResult.Unavailable, false);
            }

            // ② The conditional OTP consumption against the verified MAC: a replaced, consumed,
            // expired, or locked OTP loses here (SC-26).
            if (!await OtpVerificationChangeApplier.ApplyAsync(
                    request.OtpConsumption, otpRepository, operationCancellationToken))
            {
                await transaction.RollbackAsync(operationCancellationToken);
                return (OidcSmsLoginResult.Failure, false);
            }

            // The current mode is read inside the unit, after the policy recheck locked the
            // application row on PostgreSQL: it decides both provisioning and the PS-04 recheck.
            var mode = await dbContext.AppRegistrations
                .AsNoTracking()
                .Where(app => app.Id == accepted.ApplicationId)
                .Select(app => app.SmsLoginMode)
                .FirstOrDefaultAsync(operationCancellationToken);

            // ③ Resolve the identity; under AutoProvision stage what is missing.
            var identity = await admissions.FindOrStageLoginIdentityAsync(
                accepted.ApplicationId, mode, request.PhoneE164, request.Now, operationCancellationToken);
            if (identity is null)
            {
                await transaction.RollbackAsync(operationCancellationToken);
                return (OidcSmsLoginResult.Failure, false);
            }

            // ④ Flush the staged rows: the recheck and the session insert read the database.
            try
            {
                await unitOfWork.SaveChangesAsync(operationCancellationToken);
            }
            catch (DbUpdateException exception) when (DatabaseConstraintViolation.IsUniqueViolation(exception))
            {
                throw new ProvisioningConflictException();
            }

            // ⑤ The account and the PS-04 predicate, both read inside the unit.
            var account = await accountRepository.GetByIdAsync(identity.AccountId, operationCancellationToken);
            if (account is null
                || !account.IsActive
                || !await admissions.IsSessionAdmittedAsync(
                    accepted.ApplicationId, mode, identity.UserLoginId, operationCancellationToken))
            {
                await transaction.RollbackAsync(operationCancellationToken);
                return (OidcSmsLoginResult.Failure, false);
            }

            // ⑥–⑨ Session, code, login info, and the masked success audit.
            var session = await identitySessions.CreateSmsAsync(
                account.Id, identity.UserLoginId, request.Now, operationCancellationToken);
            var code = await authorizationCodes.CreateAsync(
                session,
                new AuthorizationCodeBinding(
                    accepted.ApplicationId,
                    accepted.RegisteredRedirectUri,
                    accepted.CanonicalScope,
                    accepted.Nonce,
                    accepted.CodeChallenge),
                request.Now,
                operationCancellationToken);
            await accountLoginInfo.UpdateLoginInfoAsync(
                account, request.ClientIp, IdentityConstants.AuthMethodSms, operationCancellationToken);
            await auditService.RecordLoginAsync(
                account.Id,
                SensitiveDataMasker.MaskPhone(request.PhoneE164),
                OidcSmsCodeSendService.AuthMethod,
                LoginSuccessEventType,
                request.ClientIp,
                request.UserAgent,
                null,
                request.AppId,
                request.CorrelationId,
                cancellationToken: operationCancellationToken);

            // ⑩ One commit for the whole unit.
            await unitOfWork.SaveChangesAsync(operationCancellationToken);
            await transaction.CommitAsync(operationCancellationToken);
            return ((OidcSmsLoginResult)new OidcSmsLoginResult.Completed(session.Id, code.Code), identity.AccountCreated);
        }, cancellationToken);
    }

    /// <summary>
    /// The provisioning flush hit a unique index: another writer committed the same phone's
    /// identity or the same admission first. It carries no value and never leaves this service.
    /// </summary>
    private sealed class ProvisioningConflictException : Exception
    {
        public ProvisioningConflictException()
            : base("SMS login provisioning conflicted with a concurrent writer.")
        {
        }
    }
}
