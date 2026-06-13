namespace QuantumZhou.Identity.Domain.Services.Sms;

public interface ISmsSender
{
    Task SendAsync(string phone, string code);
}
