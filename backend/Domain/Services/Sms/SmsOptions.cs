namespace QuantumZhou.Identity.Domain.Services.Sms;

public class SmsOptions
{
    public int OtpTtlSeconds { get; set; } = 300;
    public int MaxAttempts { get; set; } = 5;
    public int LockoutSeconds { get; set; } = 600;

    /// <summary>
    /// SMS bypass code for development/staging. Empty or null = bypass disabled (production-safe default).
    /// Set via Sms:BypassCode in configuration or SMS_BYPASS_CODE environment variable.
    /// </summary>
    public string? BypassCode { get; set; }
}
