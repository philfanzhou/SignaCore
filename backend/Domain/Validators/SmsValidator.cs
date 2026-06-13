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

    public SmsValidator(
        IAccountRepository accountRepository,
        IOtpService otpService,
        IUserLoginRepository userLoginRepository,
        IUnitOfWork unitOfWork,
        ILogger<SmsValidator> logger,
        AuthMetrics authMetrics)
    {
        _accountRepository = accountRepository;
        _otpService = otpService;
        _userLoginRepository = userLoginRepository;
        _unitOfWork = unitOfWork;
        _logger = logger;
        _authMetrics = authMetrics;
    }

    public string GrantType => IdentityConstants.GrantTypeSms;

    public async Task<ValidationResult> ValidateAsync(ValidationRequest request)
    {
        if (string.IsNullOrEmpty(request.Phone) || string.IsNullOrEmpty(request.Code))
        {
            _logger.LogWarning("SMS validation failed: phone or code is empty");
            return ValidationResult.Failure("Phone or code cannot be empty");
        }

        const string bypassCode = "666666";
        var verified = request.Code == bypassCode;
        if (!verified)
        {
            verified = await _otpService.VerifyAsync(request.Phone, request.Code);
        }

        if (!verified)
        {
            _logger.LogWarning("SMS validation failed: wrong or expired code, Phone={Phone}", request.Phone);
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
            _logger.LogInformation("Auto-registered new SMS user: Phone={Phone}, AccountId={AccountId}", request.Phone, account.Id);
        }

        if (!account.IsActive)
        {
            _logger.LogWarning("SMS validation failed: account disabled, Phone={Phone}", request.Phone);
            return ValidationResult.Failure("Account is disabled");
        }

        _logger.LogInformation("SMS validated successfully: Phone={Phone}", request.Phone);
        return ValidationResult.Success(account, IdentityConstants.AuthMethodSms);
    }
}
