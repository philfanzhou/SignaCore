namespace QuantumZhou.Identity.Domain.Services.Sms;

public interface ISmsSender
{
    string Provider { get; }
    Task<SmsSendResult> SendAsync(
        SmsProviderProfile profile,
        SmsVerificationMessage message,
        CancellationToken cancellationToken);

}

public sealed record SmsVerificationMessage(string PhoneE164, string Code, string? ReferenceId = null);

public sealed record SmsSendResult(string Provider, string? MessageId);
