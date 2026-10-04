using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Sms;

namespace SignaCore.Host.Services;

/// <summary>
/// The closed <c>login_histories.failure_reason</c> values of a failed browser SMS login besides the
/// send-eligibility values (<see cref="OidcSmsCodeSendService.ReasonFor(SmsSendEligibility)"/>).
/// </summary>
public static class OidcSmsLoginFailureReasons
{
    /// <summary>The read-only OTP verification did not pass: no current sent OTP, or a wrong,
    /// expired, or locked code.</summary>
    public const string OtpRejected = "otp_rejected";

    /// <summary>The <c>EV-36</c> unit rolled back after the OTP verified: the OTP consumption was
    /// lost, the identity, account, or admission recheck failed, or provisioning conflicted twice.</summary>
    public const string OtpRace = "otp_race";
}

/// <summary>The closed outcome of the EV-37 failure transaction.</summary>
public enum OidcSmsLoginFailureResult
{
    Recorded,
    ContinuationUnavailable,
    PersistenceFailed
}

/// <summary>
/// Commits one browser SMS login failure (<c>EV-37</c>): the optional conditional OTP
/// failed-attempt/lockout change of a send-eligible phone with a current sent OTP and one masked
/// <c>login_failure</c> history row are one unit of work. It never writes the Password
/// <c>login_attempts</c> counter and never provisions.
/// </summary>
/// <remarks>
/// Same shape as <see cref="OidcLoginFailureRecorder"/>: the explicit transaction runs inside
/// <c>CreateExecutionStrategy()</c> (<c>PS-22</c>) and cancellation observed before the commit
/// rolls the whole unit back (<c>EV-18</c>). Unlike the Password recorder, a failure of the unit
/// itself does not change the answer: the generic SMS failure page must stay byte-identical, so
/// the failure is reduced to one closed log reason and reported to the caller only as
/// <c>PersistenceFailed</c>. An unavailable continuation instead takes precedence as
/// <c>EV-03</c>, without failure writes. Caller cancellation still propagates.
/// </remarks>
public sealed class OidcSmsLoginFailureRecorder(
    IOtpRepository otpRepository,
    IAuditService auditService,
    IUnitOfWork unitOfWork,
    IdentityDbContext dbContext,
    ILogger<OidcSmsLoginFailureRecorder> logger)
{
    private const string LoginFailureEventType = "login_failure";

    /// <summary>
    /// Guards the active continuation, then commits the failure unit and returns its closed outcome. <paramref name="otpFailure"/> is
    /// the verifier's <see cref="OtpVerificationChangeKind.RecordFailure"/> change, or <c>null</c>
    /// when no OTP state may change. <paramref name="accountId"/> is set only when the phone's SMS
    /// identity resolved; <paramref name="failureReason"/> is one closed value.
    /// </summary>
    /// <exception cref="ArgumentException">The OTP change is not a failure record.</exception>
    public async Task<OidcSmsLoginFailureResult> RecordFailureAsync(
        Guid continuationId,
        DateTimeOffset now,
        OtpVerificationChange? otpFailure,
        string phoneE164,
        Guid? accountId,
        string failureReason,
        string appId,
        string? clientIp,
        string? userAgent,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        if (otpFailure is not null && otpFailure.Kind != OtpVerificationChangeKind.RecordFailure)
        {
            throw new ArgumentException("Only an OTP failure record may ride on a failed login.", nameof(otpFailure));
        }

        var result = OidcSmsLoginFailureResult.Recorded;
        var maskedPhone = SensitiveDataMasker.MaskPhone(phoneE164);
        try
        {
            var strategy = dbContext.Database.CreateExecutionStrategy();
            await strategy.ExecuteAsync(async operationCancellationToken =>
            {
                dbContext.ChangeTracker.Clear();
                await using var transaction =
                    await dbContext.Database.BeginTransactionAsync(operationCancellationToken);
                // Lock in the same continuation -> OTP -> audit order as EV-36. The update
                // changes no value, but makes consumption and this failure mutually exclusive.
                var matched = await dbContext.AuthorizationRequests
                    .Where(request => request.Id == continuationId
                        && request.ConsumedAt == null && request.ExpiresAt > now)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(request => request.ExpiresAt, request => request.ExpiresAt),
                        operationCancellationToken);
                if (matched != 1)
                {
                    await transaction.RollbackAsync(operationCancellationToken);
                    result = OidcSmsLoginFailureResult.ContinuationUnavailable;
                    return;
                }

                if (otpFailure is not null)
                {
                    // Conditional: a replaced, consumed, or already locked OTP is left as it is.
                    await OtpVerificationChangeApplier.ApplyAsync(otpFailure, otpRepository, operationCancellationToken);
                }

                await auditService.RecordLoginAsync(
                    accountId,
                    maskedPhone,
                    OidcSmsCodeSendService.AuthMethod,
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
        catch (Exception exception) when (
            exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            dbContext.ChangeTracker.Clear();

            // Only the closed stage reaches the log: never the phone, the code, the handle, or the
            // exception text, which may carry database detail.
            logger.LogWarning(
                "Browser SMS login failure could not persist its state. Stage={Stage}, CorrelationId={CorrelationId}",
                "failure_unit",
                LogValueSanitizer.Sanitize(correlationId));
            return OidcSmsLoginFailureResult.PersistenceFailed;
        }

        if (result == OidcSmsLoginFailureResult.ContinuationUnavailable) return result;

        logger.LogInformation(
            "Browser SMS login failed generically. Reason={Reason}, CorrelationId={CorrelationId}",
            failureReason,
            LogValueSanitizer.Sanitize(correlationId));
        return result;
    }
}
