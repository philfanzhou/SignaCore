using System.Runtime.ExceptionServices;
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
        var attempt = await SendCoreAsync(appRegistrationId, phoneE164, profileKey, cancellationToken);
        if (attempt.Outcome == OtpSendOutcome.Sent) return attempt.Code!;

        // The legacy contract: a closed rejection surfaces as its fixed message, and a failure that
        // originated elsewhere (profile resolution, a provider exception) is rethrown unchanged.
        attempt.Failure?.Throw();
        throw new InvalidOperationException(attempt.Message);
    }

    public async Task<OtpSendOutcome> TrySendAsync(
        Guid appRegistrationId,
        string phoneE164,
        string profileKey,
        CancellationToken cancellationToken = default)
    {
        var attempt = await SendCoreAsync(appRegistrationId, phoneE164, profileKey, cancellationToken);
        return attempt.Outcome;
    }

    /// <summary>
    /// The one send implementation behind both entry points. The limit checks and the profile
    /// resolution run before any write; the pre-delivery state commits before the provider is
    /// called; the successful delivery state is staged for the caller's commit. Caller
    /// cancellation and failures outside the closed outcomes propagate unchanged.
    /// </summary>
    private async Task<SendAttempt> SendCoreAsync(
        Guid appRegistrationId,
        string phoneE164,
        string profileKey,
        CancellationToken cancellationToken)
    {
        var phone = MainlandChinaPhoneNumber.Normalize(phoneE164);
        var now = DateTimeOffset.UtcNow;
        var existing = await _otpRepository.GetAsync(appRegistrationId, phone, cancellationToken);
        if (CheckSendLimits(existing, now) is { } limited) return limited;

        ISmsSender sender;
        SmsProviderProfile profile;
        try
        {
            (sender, profile) = _senderResolver.Resolve(profileKey);
        }
        catch (InvalidOperationException exception)
        {
            return SendAttempt.Failed(OtpSendOutcome.ProfileMissing, ExceptionDispatchInfo.Capture(exception));
        }

        var code = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
        var otp = existing ?? new OtpEntity { Id = Guid.NewGuid(), AppRegistrationId = appRegistrationId, Phone = phone };
        if (existing == null) await _otpRepository.AddAsync(otp, cancellationToken);

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
            return SendAttempt.Rejected(
                OtpSendOutcome.ResendInterval,
                "A verification code is already being sent. Please try again later.");
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
            return SendAttempt.Rejected(
                OtpSendOutcome.ProviderFailed,
                "SMS provider rejected the verification-code request.");
        }
        catch (Exception exception) when (
            exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // Any other provider failure leaves the committed PendingDelivery state as it was.
            return SendAttempt.Failed(OtpSendOutcome.ProviderFailed, ExceptionDispatchInfo.Capture(exception));
        }

        _logger.LogInformation(
            "OTP generated and sent: AppRegistrationId={AppRegistrationId}, Provider={Provider}, Phone={Phone}, TTL={Ttl}s",
            appRegistrationId, sender.Provider, SensitiveDataMasker.MaskPhone(phone), _options.OtpTtlSeconds);
        return SendAttempt.Delivered(code);
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

    public async Task InvalidateAsync(
        Guid appRegistrationId, string phoneE164, CancellationToken cancellationToken = default)
    {
        var entry = await _otpRepository.GetAsync(appRegistrationId, MainlandChinaPhoneNumber.Normalize(phoneE164), cancellationToken);
        if (entry == null) return;
        entry.Status = OtpStatus.Consumed;
        await _unitOfWork.SaveChangesAsync(cancellationToken);
    }

    private string ComputeMac(Guid appRegistrationId, string phone, string code)
    {
        if (_macKey.Length < 32)
            throw new InvalidOperationException("A stable SMS OTP HMAC key is required.");
        using var hmac = new HMACSHA256(_macKey);
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes($"{appRegistrationId:N}|{phone}|{code}")));
    }

    private SendAttempt? CheckSendLimits(OtpEntity? otp, DateTimeOffset now)
    {
        if (otp == null) return null;
        if (otp.LockoutUntil > now)
            return SendAttempt.Rejected(OtpSendOutcome.Locked, "Too many verification attempts. Please try again later.");
        if (now - otp.CreatedAt < TimeSpan.FromSeconds(_options.MinSendIntervalSeconds))
            return SendAttempt.Rejected(OtpSendOutcome.ResendInterval, "Verification code requested too frequently.");
        if (now - otp.HourWindowStartedAt < TimeSpan.FromHours(1) && otp.HourSendCount >= _options.MaxSendsPerHour)
            return SendAttempt.Rejected(OtpSendOutcome.HourlyWindow, "Hourly verification-code limit exceeded.");
        if (now - otp.DayWindowStartedAt < TimeSpan.FromDays(1) && otp.DaySendCount >= _options.MaxSendsPerDay)
            return SendAttempt.Rejected(OtpSendOutcome.DailyWindow, "Daily verification-code limit exceeded.");
        return null;
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

    /// <summary>
    /// One send result: the delivered code, or a closed outcome with either the fixed legacy
    /// message or the original failure the legacy entry point rethrows unchanged.
    /// </summary>
    private sealed record SendAttempt(
        OtpSendOutcome Outcome,
        string? Code,
        string? Message,
        ExceptionDispatchInfo? Failure)
    {
        public static SendAttempt Delivered(string code) => new(OtpSendOutcome.Sent, code, null, null);

        public static SendAttempt Rejected(OtpSendOutcome outcome, string message) => new(outcome, null, message, null);

        public static SendAttempt Failed(OtpSendOutcome outcome, ExceptionDispatchInfo failure) =>
            new(outcome, null, null, failure);
    }
}
