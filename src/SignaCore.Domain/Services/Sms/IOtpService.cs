namespace SignaCore.Domain.Services.Sms;

public interface IOtpService
{
    /// <summary>
    /// Persists the pre-delivery state before contacting the provider, then stages the successful
    /// delivery state without committing it. The caller must stage the matching audit record and
    /// commit both through the shared scoped unit of work.
    /// </summary>
    Task<string> GenerateAndSendAsync(
        Guid appRegistrationId,
        string phoneE164,
        string profileKey,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The browser send path of <see cref="GenerateAndSendAsync"/>: the same limit checks,
    /// pre-delivery write, provider call, and delivery-state handling, answered as a closed
    /// <see cref="OtpSendOutcome"/> instead of message-bearing exceptions, and without returning
    /// the code. On <see cref="OtpSendOutcome.Sent"/> the successful delivery state is staged but
    /// not committed; the caller stages its audit row and commits both through the shared scoped
    /// unit of work. Caller cancellation propagates. Failures outside the closed outcomes — a
    /// failed read or a pre-delivery write that fails for a reason other than a concurrent
    /// challenge — propagate as exceptions.
    /// </summary>
    Task<OtpSendOutcome> TrySendAsync(
        Guid appRegistrationId,
        string phoneE164,
        string profileKey,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies the supplied code without changing persistent OTP state. The caller must apply the
    /// returned conditional change in the same transaction as the matching login audit record.
    /// </summary>
    Task<OtpVerificationResult> VerifyAsync(
        Guid appRegistrationId,
        string phoneE164,
        string code,
        CancellationToken cancellationToken = default);

    Task InvalidateAsync(
        Guid appRegistrationId, string phoneE164, CancellationToken cancellationToken = default);
}

/// <summary>
/// The closed result of <see cref="IOtpService.TrySendAsync"/>. Every value but
/// <see cref="Sent"/> sent nothing that reached the phone; only <see cref="Sent"/> and
/// <see cref="ProviderFailed"/> contacted the provider.
/// </summary>
public enum OtpSendOutcome
{
    /// <summary>The provider accepted the delivery; the <c>Sent</c> state is staged, not committed.</summary>
    Sent,

    /// <summary>The per-phone OTP lockout is active; nothing was written.</summary>
    Locked,

    /// <summary>
    /// The minimum resend interval has not elapsed (nothing was written), or a concurrent send won
    /// the pre-delivery write (this one's write failed and nothing was sent).
    /// </summary>
    ResendInterval,

    /// <summary>The per-phone hourly window is exhausted; nothing was written.</summary>
    HourlyWindow,

    /// <summary>The per-phone daily window is exhausted; nothing was written.</summary>
    DailyWindow,

    /// <summary>
    /// The profile key names no configured profile, or its provider is not registered; nothing
    /// was written.
    /// </summary>
    ProfileMissing,

    /// <summary>
    /// The provider was called after the committed pre-delivery write and rejected or failed the
    /// delivery. A rejection commits the existing <c>DeliveryFailed</c> state; any other provider
    /// failure leaves the committed <c>PendingDelivery</c> state.
    /// </summary>
    ProviderFailed
}

public sealed record OtpVerificationResult(bool IsVerified, OtpVerificationChange? Change);

public enum OtpVerificationChangeKind
{
    Consume,
    RecordFailure
}

/// <summary>
/// A conditional OTP mutation discovered during validation. The MAC remains process-local and must
/// never be logged, audited, or returned to a client.
/// </summary>
public sealed record OtpVerificationChange(
    OtpVerificationChangeKind Kind,
    Guid AppRegistrationId,
    string Phone,
    string ExpectedCodeMac,
    DateTimeOffset ObservedAt,
    int MaxAttempts,
    DateTimeOffset LockoutUntil);
