using Microsoft.Extensions.Logging;

namespace QuantumZhou.Identity.Domain.Services.Sms;

public class LoggingSmsSender : ISmsSender
{
    private readonly ILogger<LoggingSmsSender> _logger;

    public LoggingSmsSender(ILogger<LoggingSmsSender> logger) => _logger = logger;

    public string Provider => SmsProviderNames.Logging;

    public Task<SmsSendResult> SendAsync(
        SmsProviderProfile profile,
        SmsVerificationMessage message,
        CancellationToken cancellationToken)
    {
        var maskedCode = new string('*', message.Code.Length);
        _logger.LogInformation(
            "[SMS-DEV] Phone={Phone}, Code={MaskedCode} - SMS sent (logging only in development)",
            SensitiveDataMasker.MaskPhone(message.PhoneE164),
            maskedCode);
        return Task.FromResult(new SmsSendResult(Provider, null));
    }

}
