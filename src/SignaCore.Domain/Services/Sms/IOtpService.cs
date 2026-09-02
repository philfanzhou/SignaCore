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
    Task<bool> VerifyAsync(Guid appRegistrationId, string phoneE164, string code);
    Task InvalidateAsync(Guid appRegistrationId, string phoneE164);

}
