using Microsoft.Extensions.Logging;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain.Services.WeChat;

namespace QuantumZhou.Identity.Domain.Validators;

public class WechatValidator : IIdentityValidator
{
    private readonly IAccountRepository _accountRepository;
    private readonly IWechatApiClient _wechatApiClient;
    private readonly ILogger<WechatValidator> _logger;

    public WechatValidator(IAccountRepository accountRepository, IWechatApiClient wechatApiClient, ILogger<WechatValidator> logger)
    {
        _accountRepository = accountRepository;
        _wechatApiClient = wechatApiClient;
        _logger = logger;
    }

    public string GrantType => IdentityConstants.GrantTypeWechat;

    public async Task<ValidationResult> ValidateAsync(ValidationRequest request)
    {
        if (string.IsNullOrEmpty(request.WechatCode))
        {
            _logger.LogWarning("WeChat validation failed: code is empty");
            return ValidationResult.Failure("WeChat code cannot be empty");
        }

        var openId = await _wechatApiClient.CodeToSessionAsync(request.WechatCode);
        if (string.IsNullOrEmpty(openId))
        {
            _logger.LogWarning("WeChat validation failed: failed to get OpenId");
            return ValidationResult.Failure("WeChat authentication failed");
        }

        var maskedOpenId = SensitiveDataMasker.MaskOpenId(openId);

        var account = await _accountRepository.GetByLoginProviderAsync(
            IdentityConstants.AuthMethodWechat, openId);

        if (account == null)
        {
            _logger.LogWarning("WeChat validation failed: WeChat not bound to any account, OpenId={OpenId}", maskedOpenId);
            return ValidationResult.Failure("WeChat is not bound to any account");
        }

        if (!account.IsActive)
        {
            _logger.LogWarning("WeChat validation failed: account not found or disabled, OpenId={OpenId}", maskedOpenId);
            return ValidationResult.Failure("Account is disabled");
        }

        _logger.LogInformation("WeChat validated successfully: OpenId={OpenId}, AccountId={AccountId}", maskedOpenId, account.Id);
        return ValidationResult.Success(account, IdentityConstants.AuthMethodWechat);
    }
}
