namespace SignaCore.Domain.Services.Sms;

public interface IOtpService
{
    Task<string> GenerateAndSendAsync(
        Guid appRegistrationId,
        string phoneE164,
        string profileKey,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Application-bound OTP generation is not implemented.");
    Task<bool> VerifyAsync(Guid appRegistrationId, string phoneE164, string code) =>
        throw new NotSupportedException("Application-bound OTP verification is not implemented.");
    Task InvalidateAsync(Guid appRegistrationId, string phoneE164) =>
        throw new NotSupportedException("Application-bound OTP invalidation is not implemented.");

}
