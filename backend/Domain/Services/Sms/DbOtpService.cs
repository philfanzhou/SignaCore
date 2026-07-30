using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;

namespace QuantumZhou.Identity.Domain.Services.Sms;

public class DbOtpService : IOtpService
{
    private readonly SmsOptions _options;
    private readonly ILogger<DbOtpService> _logger;
    private readonly IOtpRepository _otpRepository;
    private readonly IUnitOfWork _unitOfWork;

    public DbOtpService(SmsOptions options, ILogger<DbOtpService> logger, IOtpRepository otpRepository, IUnitOfWork unitOfWork)
    {
        _options = options;
        _logger = logger;
        _otpRepository = otpRepository;
        _unitOfWork = unitOfWork;
    }

    public async Task<string> GenerateAndSendAsync(string phone, ISmsSender smsSender)
    {
        var maskedPhone = SensitiveDataMasker.MaskPhone(phone);

        var existing = await _otpRepository.GetByPhoneAsync(phone);
        if (existing != null && existing.Attempts >= _options.MaxAttempts)
        {
            var remaining = existing.LockoutUntil - DateTimeOffset.UtcNow;
            if (remaining > TimeSpan.Zero)
            {
                throw new InvalidOperationException($"Too many attempts. Please try again in {(int)remaining.TotalSeconds} seconds.");
            }
        }

        var code = RandomNumberGenerator.GetInt32(100000, 999999).ToString();

        if (existing != null)
        {
            await _otpRepository.RemoveByPhoneAsync(phone);
        }

        var otp = new OtpEntity
        {
            Id = Guid.NewGuid(),
            Phone = phone,
            Code = code,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(_options.OtpTtlSeconds),
            Attempts = 0,
            LockoutUntil = DateTimeOffset.UnixEpoch,
            CreatedAt = DateTimeOffset.UtcNow
        };
        await _otpRepository.AddAsync(otp);
        await _unitOfWork.SaveChangesAsync();

        await smsSender.SendAsync(phone, code);

        _logger.LogInformation("OTP generated and sent for Phone={Phone}, TTL={Ttl}s", maskedPhone, _options.OtpTtlSeconds);

        return code;
    }

    public async Task<bool> VerifyAsync(string phone, string code)
    {
        var maskedPhone = SensitiveDataMasker.MaskPhone(phone);

        var entry = await _otpRepository.GetByPhoneAsync(phone);
        if (entry == null)
        {
            _logger.LogWarning("OTP verification failed: Phone={Phone}, Reason=No OTP found", maskedPhone);
            return false;
        }

        if (entry.ExpiresAt < DateTimeOffset.UtcNow)
        {
            await _otpRepository.RemoveExpiredAsync(phone, DateTimeOffset.UtcNow);
            _logger.LogWarning("OTP verification failed: Phone={Phone}, Reason=Expired", maskedPhone);
            return false;
        }

        var utcNow = DateTimeOffset.UtcNow;
        if (entry.Code == code &&
            await _otpRepository.TryConsumeAsync(
                phone,
                code,
                utcNow,
                _options.MaxAttempts))
        {
            _logger.LogInformation("OTP verified successfully: Phone={Phone}", maskedPhone);
            return true;
        }

        var affectedRows = await _otpRepository.IncrementFailedAttemptsAsync(
            phone,
            utcNow,
            _options.MaxAttempts,
            utcNow.AddSeconds(_options.LockoutSeconds));
        if (affectedRows == 0)
        {
            _logger.LogWarning(
                "OTP verification failed: Phone={Phone}, Reason=OTP changed or locked",
                maskedPhone);
            return false;
        }

        var updatedEntry = await _otpRepository.GetByPhoneAsync(phone);
        if (updatedEntry?.Attempts >= _options.MaxAttempts)
        {
            _logger.LogWarning(
                "OTP verification failed: Phone={Phone}, Reason=Too many attempts, locked for {Lockout}s",
                maskedPhone,
                _options.LockoutSeconds);
            return false;
        }

        _logger.LogWarning(
            "OTP verification failed: Phone={Phone}, Attempts={Attempts}",
            maskedPhone,
            updatedEntry?.Attempts);
        return false;
    }

    public async Task InvalidateAsync(string phone)
    {
        await _otpRepository.RemoveByPhoneAsync(phone);
    }
}
