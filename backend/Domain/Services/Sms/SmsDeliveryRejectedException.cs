namespace QuantumZhou.Identity.Domain.Services.Sms;

public sealed class SmsDeliveryRejectedException : Exception
{
    public SmsDeliveryRejectedException(string providerCode, string? providerMessage)
        : base($"SMS provider rejected the request ({providerCode}).")
    {
        ProviderCode = providerCode;
        ProviderMessage = providerMessage;
    }

    public string ProviderCode { get; }
    public string? ProviderMessage { get; }
}
