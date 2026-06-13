namespace QuantumZhou.Identity.Domain.Services.Sms;

public class SmsOptions
{
    public int OtpTtlSeconds { get; set; } = 300;
    public int MaxAttempts { get; set; } = 5;
    public int LockoutSeconds { get; set; } = 600;
}
