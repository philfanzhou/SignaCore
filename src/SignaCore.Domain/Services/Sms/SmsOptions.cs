namespace SignaCore.Domain.Services.Sms;

public class SmsOptions
{
    public const string SectionName = "Sms";

    public int OtpTtlSeconds { get; set; } = 300;
    public int MaxAttempts { get; set; } = 5;
    public int LockoutSeconds { get; set; } = 600;
    public int MinSendIntervalSeconds { get; set; } = 60;
    public int MaxSendsPerHour { get; set; } = 5;
    public int MaxSendsPerDay { get; set; } = 10;
    public string? OtpHmacKey { get; set; }
    public Dictionary<string, SmsProviderProfile> Profiles { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// SMS bypass code for development/staging. Empty or null = bypass disabled (production-safe default).
    /// Set via Sms:BypassCode in configuration or SMS_BYPASS_CODE environment variable.
    /// </summary>
    public string? BypassCode { get; set; }

    /// <summary>
    /// The allow-list of phone numbers that may use <see cref="BypassCode"/>.
    /// An empty list means the bypass is disabled entirely, even when <see cref="BypassCode"/> is
    /// configured.
    /// Set via Sms:BypassPhones (a JSON array or a comma-separated string) or the SMS_BYPASS_PHONES
    /// environment variable.
    /// Case-insensitive rules do not apply to phone numbers: they are compared as written, using
    /// Ordinal comparison, with leading and trailing whitespace removed.
    /// </summary>
    public IReadOnlyList<string> BypassPhones { get; set; } = Array.Empty<string>();

    public void Validate(bool isDevelopment)
    {
        if (OtpTtlSeconds is < 60 or > 900 || MaxAttempts is < 1 or > 10 ||
            LockoutSeconds is < 60 or > 86400 || MinSendIntervalSeconds is < 30 or > 3600 ||
            MaxSendsPerHour is < 1 or > 100 || MaxSendsPerDay < MaxSendsPerHour)
        {
            throw new InvalidOperationException("SMS verification-code limits are invalid.");
        }

        var hmacKeyLength = DecodeHmacKey().Length;
        if ((!string.IsNullOrWhiteSpace(OtpHmacKey) || Profiles.Count > 0) && hmacKeyLength < 32)
        {
            throw new InvalidOperationException("Sms:OtpHmacKey must be a base64-encoded key of at least 32 bytes.");
        }

        foreach (var (key, profile) in Profiles)
        {
            if (string.IsNullOrWhiteSpace(key) || key.Length > 64)
                throw new InvalidOperationException("SMS profile keys must contain 1 to 64 characters.");
            profile.Validate(key, isDevelopment);
        }
    }

    public byte[] DecodeHmacKey()
    {
        if (string.IsNullOrWhiteSpace(OtpHmacKey)) return [];
        try { return Convert.FromBase64String(OtpHmacKey); }
        catch (FormatException) { throw new InvalidOperationException("Sms:OtpHmacKey must be base64 encoded."); }
    }
}

public sealed class SmsProviderProfile
{
    public string Provider { get; set; } = string.Empty;
    public string AccessKeyId { get; set; } = string.Empty;
    public string AccessKeySecret { get; set; } = string.Empty;
    public string SignName { get; set; } = string.Empty;
    public string TemplateId { get; set; } = string.Empty;
    public string? SmsSdkAppId { get; set; }
    public string? Region { get; set; }

    internal void Validate(string key, bool isDevelopment)
    {
        if (string.Equals(Provider, SmsProviderNames.Logging, StringComparison.OrdinalIgnoreCase))
        {
            if (!isDevelopment) throw new InvalidOperationException($"SMS profile '{key}' uses the development-only logging provider.");
            return;
        }

        if (string.IsNullOrWhiteSpace(AccessKeyId) || string.IsNullOrWhiteSpace(AccessKeySecret) ||
            string.IsNullOrWhiteSpace(SignName) || string.IsNullOrWhiteSpace(TemplateId))
        {
            throw new InvalidOperationException($"SMS profile '{key}' is incomplete.");
        }

        if (string.Equals(Provider, SmsProviderNames.TencentCloud, StringComparison.OrdinalIgnoreCase) &&
            (string.IsNullOrWhiteSpace(SmsSdkAppId) || string.IsNullOrWhiteSpace(Region)))
        {
            throw new InvalidOperationException($"Tencent Cloud SMS profile '{key}' requires SmsSdkAppId and Region.");
        }

        if (!string.Equals(Provider, SmsProviderNames.AlibabaCloud, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(Provider, SmsProviderNames.TencentCloud, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"SMS profile '{key}' has an unsupported provider.");
        }
    }
}

public static class SmsProviderNames
{
    public const string AlibabaCloud = "AlibabaCloud";
    public const string TencentCloud = "TencentCloud";
    public const string Logging = "Logging";
}
