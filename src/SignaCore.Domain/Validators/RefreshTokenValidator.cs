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
    private readonly IAppExchangeTrustRepository _exchangeTrustRepository;
    private readonly ILdapAccountService _ldapAccountService;
    private readonly ILdapDirectoryClient _ldapDirectoryClient;
    private readonly ISmsAdmissionService _smsAdmissionService;
    private readonly IWechatAdmissionService _wechatAdmissionService;
    private readonly ILogger<RefreshTokenValidator> _logger;

    public RefreshTokenValidator(
        IRefreshTokenRepository refreshTokenRepository,
        IAccountRepository accountRepository,
        IAppExchangeTrustRepository exchangeTrustRepository,
        ILdapAccountService ldapAccountService,
        ILdapDirectoryClient ldapDirectoryClient,
        ISmsAdmissionService smsAdmissionService,
        IWechatAdmissionService wechatAdmissionService,
        ILogger<RefreshTokenValidator> logger)
    {
        _refreshTokenRepository = refreshTokenRepository;
        _accountRepository = accountRepository;
        _exchangeTrustRepository = exchangeTrustRepository;
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

        var exchange = await ResolveExchangeAsync(request, refreshToken);
        if (exchange.Rejection != null)
        {
            return exchange.Rejection;
        }

        var account = await _accountRepository.GetByIdAsync(refreshToken.AccountId);
        if (account == null || !account.IsActive)
        {
            _logger.LogWarning("Refresh token validation failed: account not found or disabled, AccountId={AccountId}", refreshToken.AccountId);
            return ValidationResult.Failure("Account is disabled");
        }

        // 成功结果统一过这里：跨应用换票要把来源 AppId 带给签发路径，它据此改成只签发不轮换。
        ValidationResult Issue(ValidationResult result) => exchange.IsCrossApplication
            ? result.AsCrossApplicationExchange(refreshToken.AppId)
            : result;

        if (refreshToken.LdapCredentialId.HasValue)
        {
            var ldapResult = await ValidateLdapAdmissionAsync(
                request,
                refreshToken.LdapCredentialId.Value,
                exchange.IsCrossApplication);
            if (!ldapResult.IsSuccess)
            {
                return ValidationResult.Failure(ldapResult.ErrorMessage!, ldapResult.ErrorCode);
            }

            return Issue(ValidationResult.Success(
                account,
                IdentityConstants.AuthMethodRefreshToken,
                ldapResult.Credential!.UserPrincipalName,
                refreshToken.LdapCredentialId));
        }

        if (refreshToken.SmsUserLoginId.HasValue)
        {
            if (request.App == null || request.App.SmsLoginMode == SmsLoginMode.Disabled)
                return ValidationResult.Failure(
                    "SMS login is disabled for this application", OAuthErrorCodes.UnauthorizedClient);
            var loginId = refreshToken.SmsUserLoginId.Value;
            var admission = await _smsAdmissionService.FindByLoginIdAsync(
                request.App.Id, loginId, request.CancellationToken);

            if (admission == null && exchange.IsCrossApplication &&
                request.App.SmsLoginMode == SmsLoginMode.AutoProvision)
            {
                // 来源应用已经验过这个手机号，目标应用又是自动准入，所以把准入派生过来——但记成
                // ExchangeGranted，不是 AutoProvision：这里没有验过任何验证码。ManualApproval 故意
                // 不走这条路，落到下面按"必须已有管理员批准的行"判定。
                admission = await _smsAdmissionService.GrantByLoginIdAsync(
                    request.App, loginId, SmsAccessApprovalSource.ExchangeGranted, request.CancellationToken);
            }

            var admitted = admission is { Access.IsActive: true } &&
                admission.Account.Id == account.Id &&
                (request.App.SmsLoginMode == SmsLoginMode.AutoProvision ||
                 admission.Access.ApprovalSource == SmsAccessApprovalSource.Admin);
            if (!admitted) return ValidationResult.Failure("SMS access has been revoked");
            return Issue(ValidationResult.Success(
                account, IdentityConstants.AuthMethodRefreshToken, admission!.Login.ProviderUserId,
                smsUserLoginId: loginId));
        }

        if (refreshToken.WechatUserLoginId.HasValue)
        {
            if (request.App == null || request.App.WechatLoginMode == WechatLoginMode.Disabled)
                return ValidationResult.Failure(
                    "WeChat login is disabled for this application", OAuthErrorCodes.UnauthorizedClient);
            var loginId = refreshToken.WechatUserLoginId.Value;
            var admission = await _wechatAdmissionService.FindByLoginIdAsync(
                request.App.Id, loginId, request.CancellationToken);

            if (admission == null && exchange.IsCrossApplication &&
                request.App.WechatLoginMode == WechatLoginMode.AutoProvision)
            {
                admission = await _wechatAdmissionService.GrantByLoginIdAsync(
                    request.App, loginId, WechatAccessApprovalSource.ExchangeGranted, request.CancellationToken);
            }

            var admitted = admission is { Access.IsActive: true } && admission.Account.Id == account.Id;
            if (!admitted) return ValidationResult.Failure("WeChat access has been revoked");
            return Issue(ValidationResult.Success(
                account, IdentityConstants.AuthMethodRefreshToken,
                wechatUserLoginId: loginId));
        }

        _logger.LogInformation("Refresh token validated successfully: AccountId={AccountId}, AppId={AppId}", refreshToken.AccountId, request.AppId ?? "N/A");
        return Issue(ValidationResult.Success(account, IdentityConstants.AuthMethodRefreshToken));
    }

    /// <summary>换票判定：同应用刷新、被信任边放行的跨应用换票，或拒绝。</summary>
    private readonly record struct ExchangeDecision(bool IsCrossApplication, ValidationResult? Rejection)
    {
        public static readonly ExchangeDecision SameApplication = new(false, null);
        public static readonly ExchangeDecision CrossApplication = new(true, null);
        public static ExchangeDecision Reject(ValidationResult rejection) => new(false, rejection);
    }

    /// <summary>
    /// presented token 属于别的应用时，判断有没有信任边放行。见
    /// docs/adr/0003-cross-application-refresh-grant.md。
    /// </summary>
    private async Task<ExchangeDecision> ResolveExchangeAsync(
        ValidationRequest request,
        RefreshTokenEntity refreshToken)
    {
        if (!string.IsNullOrWhiteSpace(refreshToken.AppId)
            && !string.IsNullOrWhiteSpace(request.AppId)
            && IdentityValueNormalizer.Normalize(refreshToken.AppId) ==
                IdentityValueNormalizer.Normalize(request.AppId))
        {
            return ExchangeDecision.SameApplication;
        }

        // 三种拒绝共用同一句对外文案：哪个应用信任哪个应用不是调用方可以试探出来的信息。
        // 区分留在日志里。
        var rejection = ValidationResult.Failure("Refresh token is not valid for this application");

        if (string.IsNullOrWhiteSpace(refreshToken.AppId)
            || string.IsNullOrWhiteSpace(request.AppId)
            || request.App == null)
        {
            _logger.LogWarning(
                "Refresh token application binding mismatch: TokenAppId={TokenAppId}, RequestAppId={RequestAppId}, AccountId={AccountId}",
                refreshToken.AppId, request.AppId, refreshToken.AccountId);
            return ExchangeDecision.Reject(rejection);
        }

        if (!string.IsNullOrWhiteSpace(refreshToken.SourceAppId))
        {
            _logger.LogWarning(
                "Cross-application refresh rejected: the presented token was itself minted by an exchange, TokenAppId={TokenAppId}, TokenSourceAppId={TokenSourceAppId}, RequestAppId={RequestAppId}, AccountId={AccountId}",
                refreshToken.AppId, refreshToken.SourceAppId, request.AppId, refreshToken.AccountId);
            return ExchangeDecision.Reject(rejection);
        }

        if (!await _exchangeTrustRepository.IsTrustedSourceAsync(
                request.App.Id, refreshToken.AppId, request.CancellationToken))
        {
            _logger.LogWarning(
                "Cross-application refresh rejected: no exchange trust admits the source application, TokenAppId={TokenAppId}, RequestAppId={RequestAppId}, AccountId={AccountId}",
                refreshToken.AppId, request.AppId, refreshToken.AccountId);
            return ExchangeDecision.Reject(rejection);
        }

        _logger.LogInformation(
            "Cross-application refresh admitted by exchange trust: SourceAppId={SourceAppId}, AppId={AppId}, AccountId={AccountId}",
            refreshToken.AppId, request.AppId, refreshToken.AccountId);
        return ExchangeDecision.CrossApplication;
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
        Guid credentialId,
        bool isCrossApplicationExchange)
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
        if (access == null && isCrossApplicationExchange &&
            request.App.LdapLoginMode == LdapLoginMode.AutoProvision)
        {
            access = await _ldapAccountService.GrantAccessAsync(
                request.App.Id, credentialId, LdapAccessApprovalSource.ExchangeGranted, request.CancellationToken);
        }

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
