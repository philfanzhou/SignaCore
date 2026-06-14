using System.Diagnostics;
using System.Security.Claims;
using System.Security.Cryptography;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using QuantumZhou.Identity.Contract.Protos;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Services.Sms;
using QuantumZhou.Identity.Domain.Validators;

namespace QuantumZhou.Identity.Service;

public class AuthServiceImpl : AuthGrpcService.AuthGrpcServiceBase
{
    private readonly IKeyManager _keyManager;
    private readonly ITokenService _tokenService;
    private readonly JwtOptions _jwtOptions;
    private readonly RefreshTokenOptions _refreshTokenOptions;
    private readonly IAppRegistrationRepository _appRegistrationRepository;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly ClaimsResolver _claimsResolver;
    private readonly ValidatorFactory _validatorFactory;
    private readonly ICallbackService? _callbackService;
    private readonly AuthMetrics _authMetrics;
    private readonly ILogger<AuthServiceImpl> _logger;
    private readonly GatewayValidationService _gatewayValidator;
    private readonly CallbackUrlValidator _callbackUrlValidator;
    private readonly IPasswordPolicy _passwordPolicy;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IAccountRepository _accountRepository;
    private readonly IPasswordCredentialRepository _passwordCredentialRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IAuditService _auditService;
    private readonly IOtpService _otpService;
    private readonly ISmsSender _smsSender;

    public AuthServiceImpl(
        IKeyManager keyManager,
        ITokenService tokenService,
        JwtOptions jwtOptions,
        RefreshTokenOptions refreshTokenOptions,
        IAppRegistrationRepository appRegistrationRepository,
        IRefreshTokenRepository refreshTokenRepository,
        ClaimsResolver claimsResolver,
        ValidatorFactory validatorFactory,
        ICallbackService? callbackService,
        AuthMetrics authMetrics,
        ILogger<AuthServiceImpl> logger,
        GatewayValidationService gatewayValidator,
        CallbackUrlValidator callbackUrlValidator,
        IPasswordPolicy passwordPolicy,
        IPasswordHasher passwordHasher,
        IAccountRepository accountRepository,
        IPasswordCredentialRepository passwordCredentialRepository,
        IUnitOfWork unitOfWork,
        IAuditService auditService,
        IOtpService otpService,
        ISmsSender smsSender)
    {
        _keyManager = keyManager;
        _tokenService = tokenService;
        _jwtOptions = jwtOptions;
        _refreshTokenOptions = refreshTokenOptions;
        _appRegistrationRepository = appRegistrationRepository;
        _refreshTokenRepository = refreshTokenRepository;
        _claimsResolver = claimsResolver;
        _validatorFactory = validatorFactory;
        _callbackService = callbackService;
        _authMetrics = authMetrics;
        _logger = logger;
        _gatewayValidator = gatewayValidator;
        _callbackUrlValidator = callbackUrlValidator;
        _passwordPolicy = passwordPolicy;
        _passwordHasher = passwordHasher;
        _accountRepository = accountRepository;
        _passwordCredentialRepository = passwordCredentialRepository;
        _unitOfWork = unitOfWork;
        _auditService = auditService;
        _otpService = otpService;
        _smsSender = smsSender;
    }

    public override async Task<TokenResponse> GetToken(GetTokenRequest request, ServerCallContext context)
    {
        var stopwatch = Stopwatch.StartNew();

        var gatewayResult = await ValidateGatewayAsync(request, context, stopwatch);
        if (gatewayResult.IsFailed)
            return gatewayResult.Response!;

        if (!_validatorFactory.IsSupportedGrantType(request.GrantType))
            return await CreateFailureResponseAsync(stopwatch, request.GrantType, "unsupported_grant_type",
                $"Unsupported grant_type: {request.GrantType}", "unknown", context);

        var validator = _validatorFactory.GetValidator(request.GrantType);
        var credential = ExtractCredential(request);

        var validationResult = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = request.GrantType,
            Username = credential.Username,
            Password = credential.Password,
            Phone = credential.Phone,
            Code = credential.Code,
            WechatCode = credential.WechatCode,
            RefreshToken = credential.RefreshToken,
            AppId = request.AppId
        });

        if (!validationResult.IsSuccess)
        {
            var failedUsername = credential.Username ?? credential.Phone ?? credential.WechatCode ?? "unknown";
            return await CreateFailureResponseAsync(stopwatch, request.GrantType,
                validationResult.ErrorMessage ?? "authentication_failed", validationResult.ErrorMessage, failedUsername, context, request.AppId);
        }

        var account = validationResult.Account!;
        var displayName = ResolveDisplayName(account, validationResult.DisplayName, request.GrantType);
        var claims = BuildClaims(account, displayName, validationResult.AuthMethod ?? request.GrantType);

        if (gatewayResult.App?.CallbackUrl != null && _callbackService != null)
        {
            await EnrichClaimsFromCallbackAsync(claims, gatewayResult.App, account);
        }

        var rsaKey = _keyManager.GetCurrentKey();
        var accessToken = _tokenService.GenerateJwtToken(claims, rsaKey, _jwtOptions.TokenExpirationHours);
        var expiresAt = DateTimeOffset.UtcNow.AddHours(_jwtOptions.TokenExpirationHours).ToUnixTimeSeconds();

        var newRefreshToken = await HandleRefreshTokenAsync(request.GrantType, credential.RefreshToken, account, request.AppId);

        var roles = claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToList();
        var permissions = claims.Where(c => c.Type == IdentityConstants.ClaimPermission).Select(c => c.Value).ToList();

        stopwatch.Stop();
        _authMetrics.RecordLoginSuccess(request.GrantType);
        _authMetrics.RecordLoginDuration(stopwatch.Elapsed.TotalMilliseconds, request.GrantType);

        _logger.LogInformation(
            "Token issued: AccountId={AccountId}, GrantType={GrantType}, AppId={AppId}",
            account.Id, request.GrantType, request.AppId ?? "N/A");

        var clientIp = context.GetClientIp();
        await _auditService.RecordLoginAsync(account.Id, displayName ?? account.Id.ToString(), request.GrantType, "login_success",
            clientIp, context.GetUserAgent(), null, request.AppId, context.GetCorrelationId());

        await UpdateAccountLoginInfoAsync(account, clientIp, validationResult.AuthMethod ?? request.GrantType);

        return new TokenResponse
        {
            Success = true,
            Message = "Login successful",
            AccessToken = accessToken,
            RefreshToken = newRefreshToken ?? string.Empty,
            ExpiresIn = _jwtOptions.TokenExpirationHours * 3600,
            ExpiresAt = expiresAt,
            UserInfo = new UserInfo
            {
                UserId = account.Id.ToString(),
                Username = displayName ?? string.Empty,
                Phone = string.Empty,
                Email = string.Empty,
                AuthMethod = validationResult.AuthMethod ?? request.GrantType,
                Roles = { roles },
                Permissions = { permissions }
            }
        };
    }

    public override async Task<RegisterCallbackResponse> RegisterCallback(RegisterCallbackRequest request, ServerCallContext context)
    {
        if (string.IsNullOrEmpty(request.AppId) || string.IsNullOrEmpty(request.AppSecret))
        {
            return new RegisterCallbackResponse { Success = false, Message = "AppId and AppSecret are required" };
        }

        if (!string.IsNullOrWhiteSpace(request.CallbackUrl))
        {
            var urlValidation = _callbackUrlValidator.Validate(request.CallbackUrl);
            if (!urlValidation.IsValid)
            {
                return new RegisterCallbackResponse { Success = false, Message = $"Invalid callback URL: {urlValidation.ErrorMessage}" };
            }
        }

        var app = await _appRegistrationRepository.GetByAppIdAsync(request.AppId);
        if (app == null)
        {
            return new RegisterCallbackResponse { Success = false, Message = "AppId not registered" };
        }

        if (!BCrypt.Net.BCrypt.Verify(request.AppSecret, app.AppSecretHash))
        {
            _logger.LogWarning("Callback registration failed: AppId={AppId}, Reason=AppSecret mismatch", request.AppId);
            return new RegisterCallbackResponse { Success = false, Message = "AppSecret mismatch" };
        }

        app.CallbackUrl = request.CallbackUrl;
        app.CallbackExpiresAt = request.TtlSeconds == IdentityConstants.CallbackTtlNeverExpire
            ? null
            : DateTimeOffset.UtcNow.AddSeconds(request.TtlSeconds > 0 ? request.TtlSeconds : IdentityConstants.DefaultCallbackTtlSeconds);
        await _unitOfWork.SaveChangesAsync();

        return new RegisterCallbackResponse
        {
            Success = true,
            Message = "Registered successfully",
            ExpiresAt = app.CallbackExpiresAt.HasValue ? app.CallbackExpiresAt.Value.ToUnixTimeSeconds() : 0
        };
    }

    public override async Task<BoolResponse> RevokeRefreshToken(RevokeRefreshTokenRequest request, ServerCallContext context)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            return new BoolResponse { Success = false };
        }

        var success = await RevokeRefreshTokenInternalAsync(request.RefreshToken);
        return new BoolResponse { Success = success };
    }

    public override async Task<RequestSmsCodeResponse> RequestSmsCode(RequestSmsCodeRequest request, ServerCallContext context)
    {
        if (string.IsNullOrWhiteSpace(request.Phone))
        {
            return new RequestSmsCodeResponse { Success = false, Message = "Phone number is required" };
        }

        // 验证网关凭据（如果提供了 AppId）
        if (!string.IsNullOrEmpty(request.AppId))
        {
            var gatewayResult = await _gatewayValidator.ValidateAsync(request.AppId, request.AppSecret);
            if (!gatewayResult.IsSuccess)
            {
                _logger.LogWarning("SMS code request gateway validation failed: AppId={AppId}, Reason={Reason}", request.AppId, gatewayResult.ErrorMessage);
                return new RequestSmsCodeResponse { Success = false, Message = gatewayResult.ErrorMessage };
            }
        }

        try
        {
            var code = await _otpService.GenerateAndSendAsync(request.Phone.Trim(), _smsSender);
            _logger.LogInformation("SMS verification code sent: Phone={Phone}", request.Phone.Trim());

            await _auditService.RecordLoginAsync(null, request.Phone.Trim(), IdentityConstants.GrantTypeSms, "sms_code_sent",
                context.GetClientIp(), context.GetUserAgent(), null, request.AppId, context.GetCorrelationId());

            return new RequestSmsCodeResponse { Success = true, Message = "Verification code sent" };
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning("SMS code request failed: Phone={Phone}, Reason={Reason}", request.Phone, ex.Message);
            return new RequestSmsCodeResponse { Success = false, Message = ex.Message };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SMS code request exception: Phone={Phone}", request.Phone);
            return new RequestSmsCodeResponse { Success = false, Message = "Failed to send verification code" };
        }
    }

    private async Task<GatewayValidationResult> ValidateGatewayAsync(GetTokenRequest request, ServerCallContext context, Stopwatch stopwatch)
    {
        if (string.IsNullOrEmpty(request.AppId))
        {
            return GatewayValidationResult.Ok(null);
        }

        var appValidation = await _gatewayValidator.ValidateAsync(request.AppId, request.AppSecret);
        if (!appValidation.IsSuccess)
        {
            stopwatch.Stop();
            _authMetrics.RecordLoginFailure(request.GrantType, "gateway_validation_failed");
            _authMetrics.RecordLoginDuration(stopwatch.Elapsed.TotalMilliseconds, request.GrantType);
            _logger.LogWarning("Gateway validation failed: AppId={AppId}, Reason={Reason}", request.AppId, appValidation.ErrorMessage);
            await _auditService.RecordLoginAsync(null, "unknown", request.GrantType, "login_failure",
                context.GetClientIp(), context.GetUserAgent(), appValidation.ErrorMessage, request.AppId, context.GetCorrelationId());
            return GatewayValidationResult.Fail(new TokenResponse { Success = false, Message = appValidation.ErrorMessage });
        }

        return GatewayValidationResult.Ok(appValidation.App);
    }

    private static CredentialInfo ExtractCredential(GetTokenRequest request)
    {
        return request.CredentialCase switch
        {
            GetTokenRequest.CredentialOneofCase.Password => new CredentialInfo { Username = request.Password.Username, Password = request.Password.Password },
            GetTokenRequest.CredentialOneofCase.Sms => new CredentialInfo { Phone = request.Sms.Phone, Code = request.Sms.Code },
            GetTokenRequest.CredentialOneofCase.Wechat => new CredentialInfo { WechatCode = request.Wechat.Code },
            GetTokenRequest.CredentialOneofCase.RefreshToken => new CredentialInfo { RefreshToken = request.RefreshToken.RefreshToken },
            _ => new CredentialInfo()
        };
    }

    private static string? ResolveDisplayName(AccountEntity account, string? validationResultDisplayName, string grantType)
    {
        if (!string.IsNullOrWhiteSpace(account.Nickname))
            return account.Nickname;

        if (!string.IsNullOrEmpty(validationResultDisplayName))
            return validationResultDisplayName;

        if (grantType == IdentityConstants.GrantTypeWechat)
            return $"WeChat_{account.Id.ToString()[..8]}";

        return null;
    }

    private List<Claim> BuildClaims(AccountEntity account, string? displayName, string authMethod)
    {
        var claims = _claimsResolver.ResolveBasicClaims(account, displayName);
        claims.Add(new Claim(IdentityConstants.ClaimAuthMethod, authMethod));
        return claims;
    }

    private async Task EnrichClaimsFromCallbackAsync(List<Claim> claims, AppRegistrationEntity app, AccountEntity account)
    {
        try
        {
            var externalClaims = await _callbackService!.FetchExternalClaimsAsync(
                app.CallbackUrl!, account.Id.ToString());

            if (externalClaims.Count > 0)
            {
                _logger.LogInformation("Fetched {Count} external claims from callback: AppId={AppId}", externalClaims.Count, app.AppId);
                claims.AddRange(externalClaims);
            }
            else
            {
                _logger.LogDebug("Callback returned no external claims, continuing with basic claims: AppId={AppId}", app.AppId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Callback request failed, continuing with basic claims: AppId={AppId}, Url={Url}",
                app.AppId, app.CallbackUrl);
        }
    }

    private async Task<string?> HandleRefreshTokenAsync(string grantType, string? existingRefreshToken, AccountEntity account, string? appId)
    {
        if (grantType is IdentityConstants.GrantTypePassword or IdentityConstants.GrantTypeSms or IdentityConstants.GrantTypeWechat)
        {
            return await GenerateRefreshTokenAsync(account, appId);
        }

        if (grantType == IdentityConstants.GrantTypeRefreshToken && !string.IsNullOrEmpty(existingRefreshToken))
        {
            await RevokeRefreshTokenInternalAsync(existingRefreshToken);
            return await GenerateRefreshTokenAsync(account, appId);
        }

        return null;
    }

    private async Task UpdateAccountLoginInfoAsync(AccountEntity account, string? clientIp, string authMethod)
    {
        account.LastLoginAt = DateTimeOffset.UtcNow;
        account.LastLoginIp = clientIp;
        account.LastLoginMethod = authMethod;
        account.TotalLoginCount++;
        await _accountRepository.UpdateAsync(account);
        await _unitOfWork.SaveChangesAsync();
    }

    private async Task<TokenResponse> CreateFailureResponseAsync(Stopwatch stopwatch, string grantType,
        string failureReason, string? userMessage, string username, ServerCallContext context, string? appId = null)
    {
        stopwatch.Stop();
        _authMetrics.RecordLoginFailure(grantType, failureReason);
        _authMetrics.RecordLoginDuration(stopwatch.Elapsed.TotalMilliseconds, grantType);
        _logger.LogWarning("Authentication failed: GrantType={GrantType}, Reason={Reason}", grantType, failureReason);
        await _auditService.RecordLoginAsync(null, username, grantType, "login_failure",
            context.GetClientIp(), context.GetUserAgent(), failureReason, appId, context.GetCorrelationId());
        return new TokenResponse { Success = false, Message = userMessage ?? failureReason };
    }

    private async Task<string> GenerateRefreshTokenAsync(AccountEntity account, string? appId)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var refreshToken = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            TokenValue = token,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(_refreshTokenOptions.RefreshTokenExpirationDays),
            IsRevoked = false,
            AppId = appId
        };

        await _refreshTokenRepository.AddAsync(refreshToken);
        await _unitOfWork.SaveChangesAsync();
        return token;
    }

    private async Task<bool> RevokeRefreshTokenInternalAsync(string token)
    {
        var refreshToken = await _refreshTokenRepository.GetByTokenValueAsync(token);
        if (refreshToken == null) return false;

        refreshToken.IsRevoked = true;
        await _unitOfWork.SaveChangesAsync();
        return true;
    }

    private sealed record GatewayValidationResult(TokenResponse? Response, AppRegistrationEntity? App, bool IsFailed)
    {
        public static GatewayValidationResult Ok(AppRegistrationEntity? app) => new(null, app, false);
        public static GatewayValidationResult Fail(TokenResponse response) => new(response, null, true);
    }

    private sealed class CredentialInfo
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? Phone { get; set; }
        public string? Code { get; set; }
        public string? WechatCode { get; set; }
        public string? RefreshToken { get; set; }
    }
}
