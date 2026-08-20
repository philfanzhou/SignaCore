namespace SignaCore.Domain.Services.Sms;

public interface IOtpService
{
    Task<string> GenerateAndSendAsync(
        Guid appRegistrationId,
        string phoneE164,
        string profileKey,
        CancellationToken cancellationToken = default);
    Task<bool> VerifyAsync(Guid appRegistrationId, string phoneE164, string code);
    Task InvalidateAsync(Guid appRegistrationId, string phoneE164);

}
