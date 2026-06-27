using Microsoft.Extensions.Logging;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain.Services.Sms;

namespace QuantumZhou.Identity.Domain.Validators;

public class SmsValidator : IIdentityValidator
{
    private readonly IAccountRepository _accountRepository;
    private readonly IOtpService _otpService;
    private readonly IUserLoginRepository _userLoginRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<SmsValidator> _logger;
    private readonly AuthMetrics _authMetrics;
    private readonly SmsOptions _smsOptions;

    public SmsValidator(
        IAccountRepository accountRepository,
        IOtpService otpService,
        IUserLoginRepository userLoginRepository,
        IUnitOfWork unitOfWork,
        ILogger<SmsValidator> logger,
        AuthMetrics authMetrics,
        SmsOptions smsOptions)
    {
        _accountRepository = accountRepository;
        _otpService = otpService;
        _userLoginRepository = userLoginRepository;
        _unitOfWork = unitOfWork;
        _logger = logger;
        _authMetrics = authMetrics;
        _smsOptions = smsOptions;
    }

    public string GrantType => IdentityConstants.GrantTypeSms;

    public async Task<ValidationResult> ValidateAsync(ValidationRequest request)
    {
        if (string.IsNullOrEmpty(request.Phone) || string.IsNullOrEmpty(request.Code))
        {
            _logger.LogWarning("SMS validation failed: phone or code is empty");
            return ValidationResult.Failure("Phone or code cannot be empty");
        }

        var maskedPhone = SensitiveDataMasker.MaskPhone(request.Phone);

        var bypassCode = _smsOptions.BypassCode;
        var verified = !string.IsNullOrEmpty(bypassCode) && request.Code == bypassCode;
        if (verified)
        {
            _logger.LogWarning("SMS bypass code used for Phone={Phone} — this should only be enabled in development/staging", maskedPhone);
        }

        if (!verified)
        {
            verified = await _otpService.VerifyAsync(request.Phone, request.Code);
        }

        if (!verified)
        {
            _logger.LogWarning("SMS validation failed: wrong or expired code, Phone={Phone}", maskedPhone);
            return ValidationResult.Failure("Wrong or expired verification code");
        }

        var account = await _accountRepository.GetByLoginProviderAsync(
            IdentityConstants.AuthMethodSms, request.Phone);

        if (account == null)
        {
            account = new AccountEntity
            {
                Id = Guid.NewGuid(),
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            };
            await _accountRepository.AddAsync(account);

            var userLogin = new UserLoginEntity
            {
                Id = Guid.NewGuid(),
                AccountId = account.Id,
                ProviderName = IdentityConstants.AuthMethodSms,
                ProviderUserId = request.Phone
            };
            await _userLoginRepository.AddAsync(userLogin);

            await _unitOfWork.SaveChangesAsync();

            _authMetrics.RecordAccountCreation("auto_register_sms");
            _logger.LogInformation("Auto-registered new SMS user: Phone={Phone}, AccountId={AccountId}", maskedPhone, account.Id);
        }

        if (!account.IsActive)
        {
            _logger.LogWarning("SMS validation failed: account disabled, Phone={Phone}", maskedPhone);
            return ValidationResult.Failure("Account is disabled");
        }

        _logger.LogInformation("SMS validated successfully: Phone={Phone}", maskedPhone);
        return ValidationResult.Success(account, IdentityConstants.AuthMethodSms);
    }
}
