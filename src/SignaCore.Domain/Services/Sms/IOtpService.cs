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
