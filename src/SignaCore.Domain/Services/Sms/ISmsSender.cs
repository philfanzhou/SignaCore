namespace SignaCore.Domain.Services.Sms;

public interface ISmsSender
{
    string Provider { get; }
    /// <summary>
    /// Observes cancellation before starting delivery. Once an external request is issued, await
    /// its result or the provider's configured timeout; do not abandon it through a cancellable
    /// wait or discard a successful result because the caller cancelled while it was in flight.
    /// Callers must treat cancellation as potentially delivered and must not resend on that basis.
    /// </summary>
    Task<SmsSendResult> SendAsync(
        SmsProviderProfile profile,
        SmsVerificationMessage message,
        CancellationToken cancellationToken);

}

public sealed record SmsVerificationMessage(string PhoneE164, string Code, string? ReferenceId = null);

public sealed record SmsSendResult(string Provider, string? MessageId);
