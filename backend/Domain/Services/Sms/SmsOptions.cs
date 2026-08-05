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

    /// <summary>
    /// 允许使用 <see cref="BypassCode"/> 的手机号白名单。
    /// 空列表 = 绕过整体禁用，即使 <see cref="BypassCode"/> 已配置。
    /// 通过 Sms:BypassPhones（JSON 数组或逗号分隔字符串）或 SMS_BYPASS_PHONES 环境变量配置。
    /// 号码大小写不敏感规则不适用，按原样 Ordinal 比对（仅去首尾空白）。
    /// </summary>
    public IReadOnlyList<string> BypassPhones { get; set; } = Array.Empty<string>();
}
