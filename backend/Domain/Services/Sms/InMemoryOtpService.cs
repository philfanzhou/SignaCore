using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace QuantumZhou.Identity.Domain.Services.Sms;

public class InMemoryOtpService : IOtpService
{
    private readonly SmsOptions _options;
    private readonly ILogger<InMemoryOtpService> _logger;
    private readonly ConcurrentDictionary<string, OtpEntry> _store = new();

    public InMemoryOtpService(SmsOptions options, ILogger<InMemoryOtpService> logger)
    {
        _options = options;
        _logger = logger;
    }

    public async Task<string> GenerateAndSendAsync(string phone, ISmsSender smsSender)
    {
        if (_store.TryGetValue(phone, out var existing) && existing.Attempts >= _options.MaxAttempts)
        {
            var remaining = existing.LockoutUntil - DateTimeOffset.UtcNow;
            if (remaining > TimeSpan.Zero)
            {
                throw new InvalidOperationException($"Too many attempts. Please try again in {(int)remaining.TotalSeconds} seconds.");
            }
            _store.TryRemove(phone, out _);
        }

        var code = RandomNumberGenerator.GetInt32(100000, 999999).ToString();

        _store[phone] = new OtpEntry
        {
            Code = code,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(_options.OtpTtlSeconds),
            Attempts = 0,
            LockoutUntil = DateTimeOffset.MinValue
        };

        await smsSender.SendAsync(phone, code);

        _logger.LogInformation("OTP generated for Phone={Phone}, TTL={Ttl}s", phone, _options.OtpTtlSeconds);

        return code;
    }

    public Task<bool> VerifyAsync(string phone, string code)
    {
        if (!_store.TryGetValue(phone, out var entry))
        {
            _logger.LogWarning("OTP verification failed: Phone={Phone}, Reason=No OTP found", phone);
            return Task.FromResult(false);
        }

        if (entry.ExpiresAt < DateTimeOffset.UtcNow)
        {
            _store.TryRemove(phone, out _);
            _logger.LogWarning("OTP verification failed: Phone={Phone}, Reason=Expired", phone);
            return Task.FromResult(false);
        }

        entry.Attempts++;

        if (entry.Attempts >= _options.MaxAttempts)
        {
            entry.LockoutUntil = DateTimeOffset.UtcNow.AddSeconds(_options.LockoutSeconds);
            _store[phone] = entry;
            _logger.LogWarning("OTP verification failed: Phone={Phone}, Reason=Too many attempts, locked for {Lockout}s", phone, _options.LockoutSeconds);
            return Task.FromResult(false);
        }

        var success = entry.Code == code;

        if (!success)
        {
            _store[phone] = entry;
            _logger.LogWarning("OTP verification failed: Phone={Phone}, Attempts={Attempts}", phone, entry.Attempts);
        }
        else
        {
            _store.TryRemove(phone, out _);
            _logger.LogInformation("OTP verified successfully: Phone={Phone}", phone);
        }

        return Task.FromResult(success);
    }

    public Task InvalidateAsync(string phone)
    {
        _store.TryRemove(phone, out _);
        return Task.CompletedTask;
    }

    private class OtpEntry
    {
        public string Code { get; set; } = string.Empty;
        public DateTimeOffset ExpiresAt { get; set; }
        public int Attempts { get; set; }
        public DateTimeOffset LockoutUntil { get; set; }
    }
}
