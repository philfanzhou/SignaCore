namespace QuantumZhou.Identity.Domain.Services.Sms;

public interface IOtpService
{
    Task<string> GenerateAndSendAsync(string phone, ISmsSender smsSender);
    Task<bool> VerifyAsync(string phone, string code);
    Task InvalidateAsync(string phone);
}
