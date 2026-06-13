using Microsoft.Extensions.Logging;

namespace QuantumZhou.Identity.Domain.Services.Sms;

public class LoggingSmsSender : ISmsSender
{
    private readonly ILogger<LoggingSmsSender> _logger;

    public LoggingSmsSender(ILogger<LoggingSmsSender> logger)
    {
        _logger = logger;
    }

    public Task SendAsync(string phone, string code)
    {
        _logger.LogInformation("[SMS-DEV] Phone={Phone}, Code={Code} — SMS sent (logging only in dev mode)", phone, code);
        return Task.CompletedTask;
    }
}
