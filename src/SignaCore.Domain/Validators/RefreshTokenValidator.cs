using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services.Ldap;
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Services.WeChat;

namespace SignaCore.Domain.Validators;

public class RefreshTokenValidator : IIdentityValidator
{
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IAccountRepository _accountRepository;
    private readonly ILdapAccountService _ldapAccountService;
    private readonly ILdapDirectoryClient _ldapDirectoryClient;
    private readonly ISmsAdmissionService _smsAdmissionService;
    private readonly IWechatAdmissionService _wechatAdmissionService;
    private readonly ILogger<RefreshTokenValidator> _logger;

    public RefreshTokenValidator(
        IRefreshTokenRepository refreshTokenRepository,
        IAccountRepository accountRepository,
        ILdapAccountService ldapAccountService,
        ILdapDirectoryClient ldapDirectoryClient,
        ISmsAdmissionService smsAdmissionService,
        IWechatAdmissionService wechatAdmissionService,
        ILogger<RefreshTokenValidator> logger)
    {
        _refreshTokenRepository = refreshTokenRepository;
        _accountRepository = accountRepository;
        _ldapAccountService = ldapAccountService;
        _ldapDirectoryClient = ldapDirectoryClient;
        _smsAdmissionService = smsAdmissionService;
        _wechatAdmissionService = wechatAdmissionService;
        _logger = logger;
    }

    public string GrantType => IdentityConstants.GrantTypeRefreshToken;

    public async Task<ValidationResult> ValidateAsync(ValidationRequest request)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            _logger.LogWarning("Refresh token validation failed: token is empty");
            return ValidationResult.Failure("Refresh token cannot be empty", OAuthErrorCodes.InvalidRequest);
        }

        var refreshToken = await _refreshTokenRepository.GetByTokenValueAsync(request.RefreshToken);

        if (refreshToken == null)
        {
            _logger.LogWarning("Refresh token validation failed: invalid token");
            return ValidationResult.Failure("Invalid refresh token");
        }

        if (refreshToken.IsRevoked)
        {
            _logger.LogWarning("Refresh token validation failed: token revoked, AccountId={AccountId}", refreshToken.AccountId);
            return ValidationResult.Failure("Refresh token has been revoked");
        }

        if (refreshToken.ExpiresAt < DateTimeOffset.UtcNow)
        {
            _logger.LogWarning("Refresh token validation failed: token expired, AccountId={AccountId}", refreshToken.AccountId);
            return ValidationResult.Failure("Refresh token has expired");
        }

        if (string.IsNullOrWhiteSpace(refreshToken.AppId)
            || string.IsNullOrWhiteSpace(request.AppId)
            || IdentityValueNormalizer.Normalize(refreshToken.AppId) !=
                IdentityValueNormalizer.Normalize(request.AppId))
        {
            _logger.LogWarning(
                "Refresh token application binding mismatch: TokenAppId={TokenAppId}, RequestAppId={RequestAppId}, AccountId={AccountId}",
                refreshToken.AppId, request.AppId, refreshToken.AccountId);
            return ValidationResult.Failure("Refresh token is not valid for this application");
        }

        var account = await _accountRepository.GetByIdAsync(refreshToken.AccountId);
        if (account == null || !account.IsActive)
        {
            _logger.LogWarning("Refresh token validation failed: account not found or disabled, AccountId={AccountId}", refreshToken.AccountId);
            return ValidationResult.Failure("Account is disabled");
        }

        if (refreshToken.LdapCredentialId.HasValue)
        {
            var ldapResult = await ValidateLdapAdmissionAsync(
                request,
                refreshToken.LdapCredentialId.Value);
            if (!ldapResult.IsSuccess)
            {
                return ValidationResult.Failure(ldapResult.ErrorMessage!, ldapResult.ErrorCode);
            }

            return ValidationResult.Success(
                account,
                IdentityConstants.AuthMethodRefreshToken,
                ldapResult.Credential!.UserPrincipalName,
                refreshToken.LdapCredentialId);
        }

        if (refreshToken.SmsUserLoginId.HasValue)
        {
            if (request.App == null || request.App.SmsLoginMode == SmsLoginMode.Disabled)
                return ValidationResult.Failure(
                    "SMS login is disabled for this application", OAuthErrorCodes.UnauthorizedClient);
            var admission = await _smsAdmissionService.FindByLoginIdAsync(
                request.App.Id, refreshToken.SmsUserLoginId.Value, request.CancellationToken);
            var admitted = admission is { Access.IsActive: true } &&
                admission.Account.Id == account.Id &&
                (request.App.SmsLoginMode == SmsLoginMode.AutoProvision ||
                 admission.Access.ApprovalSource == SmsAccessApprovalSource.Admin);
            if (!admitted) return ValidationResult.Failure("SMS access has been revoked");
            return ValidationResult.Success(
                account, IdentityConstants.AuthMethodRefreshToken, admission!.Login.ProviderUserId,
                smsUserLoginId: refreshToken.SmsUserLoginId);
        }

        if (refreshToken.WechatUserLoginId.HasValue)
        {
            if (request.App == null || request.App.WechatLoginMode == WechatLoginMode.Disabled)
                return ValidationResult.Failure(
                    "WeChat login is disabled for this application", OAuthErrorCodes.UnauthorizedClient);
            var admission = await _wechatAdmissionService.FindByLoginIdAsync(
                request.App.Id, refreshToken.WechatUserLoginId.Value, request.CancellationToken);
            var admitted = admission is { Access.IsActive: true } && admission.Account.Id == account.Id;
            if (!admitted) return ValidationResult.Failure("WeChat access has been revoked");
            return ValidationResult.Success(
                account, IdentityConstants.AuthMethodRefreshToken,
                wechatUserLoginId: refreshToken.WechatUserLoginId);
        }

        _logger.LogInformation("Refresh token validated successfully: AccountId={AccountId}, AppId={AppId}", refreshToken.AccountId, request.AppId ?? "N/A");
        return ValidationResult.Success(account, IdentityConstants.AuthMethodRefreshToken);
    }

    /// <summary>刷新时 LDAP 分支的判定结果，带 OAuth 错误码。</summary>
    private readonly record struct LdapAdmission(
        bool IsSuccess,
        string? ErrorMessage,
        string ErrorCode,
        LdapCredentialEntity? Credential)
    {
        public static LdapAdmission Rejected(string message, string? errorCode = null) =>
            new(false, message, errorCode ?? OAuthErrorCodes.InvalidGrant, null);

        public static LdapAdmission Admitted(LdapCredentialEntity credential) =>
            new(true, null, OAuthErrorCodes.InvalidGrant, credential);
    }

    private async Task<LdapAdmission> ValidateLdapAdmissionAsync(
        ValidationRequest request,
        Guid credentialId)
    {
        if (request.App == null || request.App.LdapLoginMode == LdapLoginMode.Disabled)
        {
            return LdapAdmission.Rejected(
                "LDAP login is disabled for this application", OAuthErrorCodes.UnauthorizedClient);
        }

        var credential = await _ldapAccountService.GetCredentialAsync(credentialId);
        if (credential == null)
        {
            return LdapAdmission.Rejected("LDAP access has been revoked");
        }

        var access = await _ldapAccountService.GetAccessAsync(request.App.Id, credentialId);
        var admitted = access is { IsActive: true } &&
            (request.App.LdapLoginMode == LdapLoginMode.AutoProvision ||
             access.ApprovalSource == LdapAccessApprovalSource.Admin);
        if (!admitted)
        {
            return LdapAdmission.Rejected("LDAP access has been revoked");
        }

        try
        {
            if (!await _ldapDirectoryClient.IsUserEnabledAsync(
                    credential.DirectoryKey,
                    credential.ObjectGuid,
                    request.CancellationToken))
            {
                return LdapAdmission.Rejected("LDAP account is disabled");
            }
        }
        catch (LdapDirectoryUnavailableException exception)
        {
            _logger.LogError(exception, "LDAP directory unavailable during refresh validation");
            return LdapAdmission.Rejected("Directory service unavailable", OAuthErrorCodes.TemporarilyUnavailable);
        }

        return LdapAdmission.Admitted(credential);
    }
}
