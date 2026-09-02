using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;

namespace SignaCore.Domain.Services.Sms;

public class DbOtpService : IOtpService
{
    private readonly SmsOptions _options;
    private readonly ILogger<DbOtpService> _logger;
    private readonly IOtpRepository _otpRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly SmsSenderResolver _senderResolver;
    private readonly byte[] _macKey;

    public DbOtpService(
        SmsOptions options,
        ILogger<DbOtpService> logger,
        IOtpRepository otpRepository,
        IUnitOfWork unitOfWork,
        SmsSenderResolver senderResolver)
    {
        _options = options;
        _logger = logger;
        _otpRepository = otpRepository;
        _unitOfWork = unitOfWork;
        _senderResolver = senderResolver;
        _macKey = options.DecodeHmacKey();
    }

    public async Task<string> GenerateAndSendAsync(
        Guid appRegistrationId,
        string phoneE164,
        string profileKey,
        CancellationToken cancellationToken = default)
    {
        var phone = MainlandChinaPhoneNumber.Normalize(phoneE164);
        var now = DateTimeOffset.UtcNow;
        var existing = await _otpRepository.GetAsync(appRegistrationId, phone);
        EnforceSendLimits(existing, now);

        var (sender, profile) = _senderResolver.Resolve(profileKey);
        var code = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
        var otp = existing ?? new OtpEntity { Id = Guid.NewGuid(), AppRegistrationId = appRegistrationId, Phone = phone };
        if (existing == null) await _otpRepository.AddAsync(otp);

        UpdateSendWindows(otp, now);
        otp.CodeMac = ComputeMac(appRegistrationId, phone, code);
        otp.Status = OtpStatus.PendingDelivery;
        otp.ExpiresAt = now.AddSeconds(_options.OtpTtlSeconds);
        otp.Attempts = 0;
        otp.LockoutUntil = DateTimeOffset.UnixEpoch;
        otp.Provider = sender.Provider;
        otp.ProfileKey = profileKey;
        otp.ProviderMessageId = null;
        otp.SentAt = null;
        otp.CreatedAt = now;
        otp.Version++;
        try
        {
            await _unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (Microsoft.EntityFrameworkCore.DbUpdateException)
        {
            throw new InvalidOperationException("A verification code is already being sent. Please try again later.");
        }

        try
        {
            var result = await sender.SendAsync(
                profile, new SmsVerificationMessage(phone, code, otp.Id.ToString("N")), cancellationToken);
            otp.Status = OtpStatus.Sent;
            otp.ProviderMessageId = result.MessageId;
            otp.SentAt = DateTimeOffset.UtcNow;
        }
        catch (SmsDeliveryRejectedException exception)
        {
            otp.Status = OtpStatus.DeliveryFailed;
            await _unitOfWork.SaveChangesAsync(cancellationToken);
            _logger.LogWarning(
                "SMS provider rejected delivery: Provider={Provider}, Code={ProviderCode}, Phone={Phone}",
                sender.Provider, exception.ProviderCode, SensitiveDataMasker.MaskPhone(phone));
            throw new InvalidOperationException("SMS provider rejected the verification-code request.");
        }

        _logger.LogInformation(
            "OTP generated and sent: AppRegistrationId={AppRegistrationId}, Provider={Provider}, Phone={Phone}, TTL={Ttl}s",
            appRegistrationId, sender.Provider, SensitiveDataMasker.MaskPhone(phone), _options.OtpTtlSeconds);
        return code;
    }

    public async Task<OtpVerificationResult> VerifyAsync(
        Guid appRegistrationId,
        string phoneE164,
        string code,
        CancellationToken cancellationToken = default)
    {
        var phone = MainlandChinaPhoneNumber.Normalize(phoneE164);
        var now = DateTimeOffset.UtcNow;
        var entry = await _otpRepository.GetAsync(appRegistrationId, phone, cancellationToken);
        if (entry == null || entry.Status != OtpStatus.Sent || entry.ExpiresAt < now || entry.LockoutUntil > now)
            return new OtpVerificationResult(false, null);

        var codeMac = ComputeMac(appRegistrationId, phone, code);
        if (CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(entry.CodeMac), Convert.FromHexString(codeMac)))
        {
            _logger.LogInformation(
                "OTP matched and is pending conditional consumption: AppRegistrationId={AppRegistrationId}, Phone={Phone}",
                appRegistrationId,
                SensitiveDataMasker.MaskPhone(phone));
            return new OtpVerificationResult(
                true,
                new OtpVerificationChange(
                    OtpVerificationChangeKind.Consume,
                    appRegistrationId,
                    phone,
                    codeMac,
                    now,
                    _options.MaxAttempts,
                    now.AddSeconds(_options.LockoutSeconds)));
        }

        _logger.LogWarning(
            "OTP verification failed and is pending conditional failure recording: AppRegistrationId={AppRegistrationId}, Phone={Phone}",
            appRegistrationId,
            SensitiveDataMasker.MaskPhone(phone));
        return new OtpVerificationResult(
            false,
            new OtpVerificationChange(
                OtpVerificationChangeKind.RecordFailure,
                appRegistrationId,
                phone,
                entry.CodeMac,
                now,
                _options.MaxAttempts,
                now.AddSeconds(_options.LockoutSeconds)));
    }

    public async Task InvalidateAsync(Guid appRegistrationId, string phoneE164)
    {
        var entry = await _otpRepository.GetAsync(appRegistrationId, MainlandChinaPhoneNumber.Normalize(phoneE164));
        if (entry == null) return;
        entry.Status = OtpStatus.Consumed;
        await _unitOfWork.SaveChangesAsync();
    }

    private string ComputeMac(Guid appRegistrationId, string phone, string code)
    {
        if (_macKey.Length < 32)
            throw new InvalidOperationException("A stable SMS OTP HMAC key is required.");
        using var hmac = new HMACSHA256(_macKey);
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes($"{appRegistrationId:N}|{phone}|{code}")));
    }

    private void EnforceSendLimits(OtpEntity? otp, DateTimeOffset now)
    {
        if (otp == null) return;
        if (otp.LockoutUntil > now) throw new InvalidOperationException("Too many verification attempts. Please try again later.");
        if (now - otp.CreatedAt < TimeSpan.FromSeconds(_options.MinSendIntervalSeconds))
            throw new InvalidOperationException("Verification code requested too frequently.");
        if (now - otp.HourWindowStartedAt < TimeSpan.FromHours(1) && otp.HourSendCount >= _options.MaxSendsPerHour)
            throw new InvalidOperationException("Hourly verification-code limit exceeded.");
        if (now - otp.DayWindowStartedAt < TimeSpan.FromDays(1) && otp.DaySendCount >= _options.MaxSendsPerDay)
            throw new InvalidOperationException("Daily verification-code limit exceeded.");
    }

    private static void UpdateSendWindows(OtpEntity otp, DateTimeOffset now)
    {
        if (otp.HourWindowStartedAt == default || now - otp.HourWindowStartedAt >= TimeSpan.FromHours(1))
        {
            otp.HourWindowStartedAt = now;
            otp.HourSendCount = 1;
        }
        else otp.HourSendCount++;

        if (otp.DayWindowStartedAt == default || now - otp.DayWindowStartedAt >= TimeSpan.FromDays(1))
        {
            otp.DayWindowStartedAt = now;
            otp.DaySendCount = 1;
        }
        else otp.DaySendCount++;
    }
}
