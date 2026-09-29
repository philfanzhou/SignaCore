using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Sms;

namespace SignaCore.Host.Services;

/// <summary>
/// The closed outcome values of the browser SMS send route. The suppressed-send reasons are also
/// the closed <c>login_histories.failure_reason</c> values of <c>sms_code_suppressed</c>; every value
/// is a metric outcome of <see cref="AuthMetrics.OidcMetricEndpoints.LoginSmsCode"/>.
/// </summary>
public static class OidcSmsCodeSendOutcomes
{
    public const string Sent = "sent";
    public const string InvalidPhone = "invalid_phone";
    public const string LocalRejected = "local_rejected";
    public const string PersistenceFailed = "persistence_failed";

    public const string NotRegistered = "not_registered";
    public const string NotAdmitted = "not_admitted";
    public const string AdmissionInactive = "admission_inactive";
    public const string NotAdminApproved = "not_admin_approved";
    public const string AccountDisabled = "account_disabled";
    public const string ContinuationBudget = "continuation_budget";
    public const string OtpLocked = "otp_locked";
    public const string ResendInterval = "resend_interval";
    public const string HourlyWindow = "hourly_window";
    public const string DailyWindow = "daily_window";
    public const string ProfileMissing = "profile_missing";
    public const string ProviderFailed = "provider_failed";
}

/// <summary>
/// One counted send request after the route's structure, continuation, antiforgery, capability
/// gate, and phone normalization checks passed. <paramref name="PhoneE164"/> is the normalized
/// phone; it leaves this request only as the provider's delivery target, the OTP row key, and the
/// masked audit username (<c>DF-16</c>).
/// </summary>
public sealed record OidcSmsCodeSendRequest(
    string LoginHandle,
    Guid AppRegistrationId,
    string AppId,
    SmsLoginMode Mode,
    string ProfileKey,
    string PhoneE164,
    string? ClientIp,
    string? UserAgent,
    string CorrelationId,
    DateTimeOffset Now);

/// <summary>
/// Executes the <c>EV-35</c> send unit behind the browser SMS send route: the per-continuation
/// budget, send eligibility, the existing OTP send, and one masked audit row, in that order.
/// </summary>
/// <remarks>
/// <para>
/// The budget is one auto-committed conditional update (<c>PS-03</c>) that runs before any account,
/// admission, or OTP read, so an exhausted budget answers without reading anything about the phone.
/// Eligibility is read-only and never provisions. Only an eligible phone reaches the OTP service,
/// whose limit checks and profile resolution precede its committed pre-delivery write and the
/// provider call; a successful delivery state and the <c>sms_code_sent</c> audit row then commit
/// together through the scoped unit of work. Every other case commits one
/// <c>sms_code_suppressed</c> row with its closed reason.
/// </para>
/// <para>
/// The caller renders the same uniform page for every returned value except the invalid-phone and
/// local outcomes it decides itself, so the returned value is the only place the true case
/// travels: to the audit row, one closed log reason, and the metric. After the count update, a
/// failure outside the closed outcomes — a failed read, OTP write, or audit commit — is
/// <see cref="OidcSmsCodeSendOutcomes.PersistenceFailed"/>: whatever already committed stays, nothing
/// is compensated, and the response stays uniform. Caller cancellation propagates at every step
/// (<c>EV-18</c>): observed before the count update nothing is written; observed after it the slot
/// stays taken and any committed OTP state or audit row stays authoritative.
/// </para>
/// </remarks>
public sealed class OidcSmsCodeSendService(
    IAuthorizationRequestStore continuations,
    ISmsAdmissionService admissions,
    IOtpService otpService,
    IAuditService auditService,
    IUnitOfWork unitOfWork,
    IdentityDbContext dbContext,
    ILogger<OidcSmsCodeSendService> logger)
{
    /// <summary>The closed <c>login_histories.auth_method</c> value of browser SMS rows.</summary>
    public const string AuthMethod = "oidc_sms_login";

    public const string SentEventType = "sms_code_sent";
    public const string SuppressedEventType = "sms_code_suppressed";

    /// <summary>
    /// Runs the send unit and returns its closed outcome: <see cref="OidcSmsCodeSendOutcomes.Sent"/>,
    /// a suppressed-send reason, or <see cref="OidcSmsCodeSendOutcomes.PersistenceFailed"/>.
    /// </summary>
    public async Task<string> SendAsync(OidcSmsCodeSendRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // PS-03: the slot is taken first and never refunded. A failure of this statement itself
        // precedes every phone-dependent read, so it cannot depend on the phone's state.
        if (!await continuations.TryTakeSmsCodeSendSlotAsync(request.LoginHandle, request.Now, cancellationToken))
        {
            return await SuppressAsync(request, OidcSmsCodeSendOutcomes.ContinuationBudget, accountId: null, cancellationToken);
        }

        SmsSendEligibilityResult eligibility;
        OtpSendOutcome delivery;
        try
        {
            eligibility = await admissions.EvaluateSendEligibilityAsync(
                request.AppRegistrationId, request.Mode, request.PhoneE164, cancellationToken);
            if (eligibility.Decision != SmsSendEligibility.Eligible)
            {
                return await SuppressAsync(request, ReasonFor(eligibility.Decision), eligibility.AccountId, cancellationToken);
            }

            delivery = await otpService.TrySendAsync(
                request.AppRegistrationId, request.PhoneE164, request.ProfileKey, cancellationToken);
        }
        catch (Exception exception) when (!IsCallerCancellation(exception, cancellationToken))
        {
            return PersistenceFailed(request, "send_state");
        }

        if (delivery != OtpSendOutcome.Sent)
        {
            return await SuppressAsync(request, ReasonFor(delivery), eligibility.AccountId, cancellationToken);
        }

        try
        {
            // The staged Sent state and this row commit together; if the commit fails, the
            // committed PendingDelivery state stays as the OTP service left it.
            await auditService.RecordLoginAsync(
                eligibility.AccountId,
                SensitiveDataMasker.MaskPhone(request.PhoneE164),
                AuthMethod,
                SentEventType,
                request.ClientIp,
                request.UserAgent,
                failureReason: null,
                request.AppId,
                request.CorrelationId,
                cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (Exception exception) when (!IsCallerCancellation(exception, cancellationToken))
        {
            return PersistenceFailed(request, "sent_audit");
        }

        LogOutcome(request, OidcSmsCodeSendOutcomes.Sent);
        return OidcSmsCodeSendOutcomes.Sent;
    }

    private async Task<string> SuppressAsync(
        OidcSmsCodeSendRequest request,
        string reason,
        Guid? accountId,
        CancellationToken cancellationToken)
    {
        try
        {
            // Nothing staged by an absorbed case may ride along with the audit row: a failed
            // pre-delivery write leaves its entity tracked, and eligibility reads are discarded.
            dbContext.ChangeTracker.Clear();
            await auditService.RecordLoginAsync(
                accountId,
                SensitiveDataMasker.MaskPhone(request.PhoneE164),
                AuthMethod,
                SuppressedEventType,
                request.ClientIp,
                request.UserAgent,
                reason,
                request.AppId,
                request.CorrelationId,
                cancellationToken);
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (Exception exception) when (!IsCallerCancellation(exception, cancellationToken))
        {
            return PersistenceFailed(request, "suppressed_audit");
        }

        LogOutcome(request, reason);
        return reason;
    }

    private string PersistenceFailed(OidcSmsCodeSendRequest request, string stage)
    {
        // Only the closed stage name reaches the log: never the phone, the handle, or the
        // exception text, which may carry provider or database detail.
        logger.LogWarning(
            "Browser SMS code send could not persist its state. Stage={Stage}, CorrelationId={CorrelationId}",
            stage,
            LogValueSanitizer.Sanitize(request.CorrelationId));
        return OidcSmsCodeSendOutcomes.PersistenceFailed;
    }

    private void LogOutcome(OidcSmsCodeSendRequest request, string outcome) =>
        logger.LogInformation(
            "Browser SMS code send answered uniformly. Outcome={Outcome}, CorrelationId={CorrelationId}",
            outcome,
            LogValueSanitizer.Sanitize(request.CorrelationId));

    private static bool IsCallerCancellation(Exception exception, CancellationToken cancellationToken) =>
        exception is OperationCanceledException && cancellationToken.IsCancellationRequested;

    /// <summary>
    /// The closed audit reason of an ineligible phone, shared by the send route's
    /// <c>sms_code_suppressed</c> rows and the SMS login's <c>login_failure</c> rows.
    /// </summary>
    internal static string ReasonFor(SmsSendEligibility decision) => decision switch
    {
        SmsSendEligibility.NotRegistered => OidcSmsCodeSendOutcomes.NotRegistered,
        SmsSendEligibility.AccountDisabled => OidcSmsCodeSendOutcomes.AccountDisabled,
        SmsSendEligibility.NotAdmitted => OidcSmsCodeSendOutcomes.NotAdmitted,
        SmsSendEligibility.AdmissionInactive => OidcSmsCodeSendOutcomes.AdmissionInactive,
        SmsSendEligibility.NotAdminApproved => OidcSmsCodeSendOutcomes.NotAdminApproved,
        _ => throw new ArgumentOutOfRangeException(nameof(decision))
    };

    private static string ReasonFor(OtpSendOutcome outcome) => outcome switch
    {
        OtpSendOutcome.Locked => OidcSmsCodeSendOutcomes.OtpLocked,
        OtpSendOutcome.ResendInterval => OidcSmsCodeSendOutcomes.ResendInterval,
        OtpSendOutcome.HourlyWindow => OidcSmsCodeSendOutcomes.HourlyWindow,
        OtpSendOutcome.DailyWindow => OidcSmsCodeSendOutcomes.DailyWindow,
        OtpSendOutcome.ProfileMissing => OidcSmsCodeSendOutcomes.ProfileMissing,
        OtpSendOutcome.ProviderFailed => OidcSmsCodeSendOutcomes.ProviderFailed,
        _ => throw new ArgumentOutOfRangeException(nameof(outcome))
    };
}
