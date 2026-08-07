using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services.WeChat;

namespace SignaCore.Domain.Validators;

public class WechatValidator : IIdentityValidator
{
    private readonly IWechatApiClient _wechatApiClient;
    private readonly IWechatAdmissionService _admissionService;
    private readonly AuthMetrics _authMetrics;
    private readonly ILogger<WechatValidator> _logger;

    public WechatValidator(
        IWechatApiClient wechatApiClient,
        IWechatAdmissionService admissionService,
        AuthMetrics authMetrics,
        ILogger<WechatValidator> logger)
    {
        _wechatApiClient = wechatApiClient;
        _admissionService = admissionService;
        _authMetrics = authMetrics;
        _logger = logger;
    }

    public string GrantType => IdentityConstants.GrantTypeWechat;

    public async Task<ValidationResult> ValidateAsync(ValidationRequest request)
    {
        if (request.App == null || request.App.WechatLoginMode == WechatLoginMode.Disabled)
        {
            return ValidationResult.Failure(
                "WeChat login is disabled for this application", OAuthErrorCodes.UnauthorizedClient);
        }

        if (string.IsNullOrEmpty(request.Code))
        {
            _logger.LogWarning("WeChat validation failed: code is empty");
            return ValidationResult.Failure("WeChat code cannot be empty", OAuthErrorCodes.InvalidRequest);
        }

        var openId = await _wechatApiClient.CodeToSessionAsync(request.Code, request.CancellationToken);
        if (string.IsNullOrEmpty(openId))
        {
            _logger.LogWarning("WeChat validation failed: failed to get OpenId");
            return ValidationResult.Failure("WeChat authentication failed");
        }

        var maskedOpenId = SensitiveDataMasker.MaskOpenId(openId);
        var admission = await _admissionService.FindAsync(request.App.Id, openId, request.CancellationToken);

        if (admission is { Access.IsActive: false })
        {
            _logger.LogWarning("WeChat validation failed: application access revoked, OpenId={OpenId}", maskedOpenId);
            return ValidationResult.Failure("WeChat access has been revoked");
        }

        if (admission == null)
        {
            if (request.App.WechatLoginMode != WechatLoginMode.AutoProvision)
            {
                _logger.LogWarning(
                    "WeChat validation failed: OpenId is not bound for this application, OpenId={OpenId}",
                    maskedOpenId);
                return ValidationResult.Failure("WeChat is not bound to any account");
            }

            admission = await _admissionService.ProvisionAsync(request.App, openId, request.CancellationToken);
            if (!admission.Access.IsActive)
            {
                return ValidationResult.Failure("WeChat access has been revoked");
            }

            if (admission.AccountCreated)
            {
                _authMetrics.RecordAccountCreation("auto_register_wechat");
            }
        }

        if (!admission.Account.IsActive)
        {
            _logger.LogWarning("WeChat validation failed: account is disabled, OpenId={OpenId}", maskedOpenId);
            return ValidationResult.Failure("Account is disabled");
        }

        _logger.LogInformation(
            "WeChat validated successfully: OpenId={OpenId}, AccountId={AccountId}", maskedOpenId, admission.Account.Id);
        return ValidationResult.Success(
            admission.Account,
            IdentityConstants.AuthMethodWechat,
            wechatUserLoginId: admission.Login.Id);
    }
}
