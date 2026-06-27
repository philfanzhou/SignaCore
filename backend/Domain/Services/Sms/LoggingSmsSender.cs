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
        var maskedCode = code.Length > 2 ? string.Concat(code.AsSpan(0, 2), new string('*', code.Length - 2)) : new string('*', code.Length);
        _logger.LogInformation("[SMS-DEV] Phone={Phone}, Code={MaskedCode} — SMS sent (logging only in dev mode)", SensitiveDataMasker.MaskPhone(phone), maskedCode);
        return Task.CompletedTask;
    }
}

/// <summary>
/// 生产环境 SMS 发送器占位实现。当没有配置真实 SMS 服务时，
/// 调用会抛出异常，防止验证码被静默丢弃或仅记录到日志。
/// </summary>
public class ThrowingSmsSender : ISmsSender
{
    private readonly ILogger<ThrowingSmsSender> _logger;

    public ThrowingSmsSender(ILogger<ThrowingSmsSender> logger)
    {
        _logger = logger;
    }

    public Task SendAsync(string phone, string code)
    {
        _logger.LogError("SMS sending requested in production but no real SMS provider is configured. Phone={Phone}", SensitiveDataMasker.MaskPhone(phone));
        throw new InvalidOperationException("No SMS provider is configured for production environment. Configure a real SMS sender implementation.");
    }
}
