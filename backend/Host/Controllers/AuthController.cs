using System.Diagnostics;
using System.Security.Claims;
using BCrypt.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Services.Sms;
using QuantumZhou.Identity.Domain.Validators;
using QuantumZhou.Identity.Host.Models;

namespace QuantumZhou.Identity.Host.Controllers;

/// <summary>
/// HTTP REST authentication API — Phase 1 replacement for gRPC AuthGrpcService.
/// Shares the same Domain layer logic as AuthServiceImpl.
/// AppId/AppSecret are passed via X-Admin-AppId / X-Admin-AppSecret headers (same as GatewayController).
/// </summary>
[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IKeyManager _keyManager;
    private readonly ITokenService _tokenService;
    private readonly JwtOptions _jwtOptions;
    private readonly IAppRegistrationRepository _appRegistrationRepository;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly ClaimsResolver _claimsResolver;
    private readonly ValidatorFactory _validatorFactory;
    private readonly ICallbackService? _callbackService;
    private readonly AuthMetrics _authMetrics;
    private readonly ILogger<AuthController> _logger;
    private readonly GatewayValidationService _gatewayValidator;
    private readonly CallbackUrlValidator _callbackUrlValidator;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IAuditService _auditService;
    private readonly IOtpService _otpService;
    private readonly ISmsSender _smsSender;
    private readonly IAccountLoginInfoService _accountLoginInfoService;
    private readonly AdminBootstrapOptions _adminBootstrapOptions;

    public AuthController(
        IKeyManager keyManager,
        ITokenService tokenService,
        JwtOptions jwtOptions,
        IAppRegistrationRepository appRegistrationRepository,
        IRefreshTokenService refreshTokenService,
        ClaimsResolver claimsResolver,
        ValidatorFactory validatorFactory,
        ICallbackService? callbackService,
        AuthMetrics authMetrics,
        ILogger<AuthController> logger,
        GatewayValidationService gatewayValidator,
        CallbackUrlValidator callbackUrlValidator,
        IUnitOfWork unitOfWork,
        IAuditService auditService,
        IOtpService otpService,
        ISmsSender smsSender,
        IAccountLoginInfoService accountLoginInfoService,
        IOptions<AdminBootstrapOptions> adminBootstrapOptions)
    {
        _keyManager = keyManager;
        _tokenService = tokenService;
        _jwtOptions = jwtOptions;
        _appRegistrationRepository = appRegistrationRepository;
        _refreshTokenService = refreshTokenService;
        _claimsResolver = claimsResolver;
        _validatorFactory = validatorFactory;
        _callbackService = callbackService;
        _authMetrics = authMetrics;
        _logger = logger;
        _gatewayValidator = gatewayValidator;
        _callbackUrlValidator = callbackUrlValidator;
        _unitOfWork = unitOfWork;
        _auditService = auditService;
        _otpService = otpService;
        _smsSender = smsSender;
        _accountLoginInfoService = accountLoginInfoService;
        _adminBootstrapOptions = adminBootstrapOptions.Value;
    }

    /// <summary>
    /// POST /api/auth/token — Unified token acquisition (OAuth2 grant_type mode).
    /// Replaces gRPC AuthGrpcService.GetToken.
    /// </summary>
    [HttpPost("token")]
    [AllowAnonymous]
    public async Task<ActionResult<TokenResponse>> GetToken(
        [FromBody] TokenRequest request,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var appId = GetAppIdHeader();
        var appSecret = GetAppSecretHeader();
        var clientIp = GetClientIp();
        var userAgent = GetUserAgent();
        var correlationId = GetCorrelationId();

        // Gateway validation (optional, only if AppId header is present)
        AppRegistrationEntity? app = null;
        if (!string.IsNullOrEmpty(appId))
        {
            var gatewayResult = await _gatewayValidator.ValidateAsync(appId, appSecret);
            if (!gatewayResult.IsSuccess)
            {
                stopwatch.Stop();
                _authMetrics.RecordLoginFailure(request.GrantType, "gateway_validation_failed");
                _authMetrics.RecordLoginDuration(stopwatch.Elapsed.TotalMilliseconds, request.GrantType);
                _logger.LogWarning("Gateway validation failed: AppId={AppId}, Reason={Reason}", appId, gatewayResult.ErrorMessage);
                await _auditService.RecordLoginAsync(null, "unknown", request.GrantType, "login_failure",
                    clientIp, userAgent, gatewayResult.ErrorMessage, appId, correlationId);
                return Ok(new TokenResponse { Success = false, Message = gatewayResult.ErrorMessage });
            }
            app = gatewayResult.App;
        }

        if (!_validatorFactory.IsSupportedGrantType(request.GrantType))
        {
            stopwatch.Stop();
            _authMetrics.RecordLoginFailure(request.GrantType, "unsupported_grant_type");
            _authMetrics.RecordLoginDuration(stopwatch.Elapsed.TotalMilliseconds, request.GrantType);
            _logger.LogWarning("Unsupported grant_type: {GrantType}", request.GrantType);
            await _auditService.RecordLoginAsync(null, "unknown", request.GrantType, "login_failure",
                clientIp, userAgent, $"unsupported_grant_type: {request.GrantType}", appId, correlationId);
            return Ok(new TokenResponse { Success = false, Message = "unsupported_grant_type" });
        }

        var validator = _validatorFactory.GetValidator(request.GrantType);
        var validationResult = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = request.GrantType,
            Username = request.Username,
            Password = request.Password,
            Phone = request.Phone,
            Code = request.Code,
            WechatCode = request.Code,
            RefreshToken = request.RefreshToken,
            AppId = appId
        });

        if (!validationResult.IsSuccess)
        {
            var failedUsername = request.Username ?? request.Phone ?? request.Code ?? "unknown";
            stopwatch.Stop();
            _authMetrics.RecordLoginFailure(request.GrantType, validationResult.ErrorMessage ?? "authentication_failed");
            _authMetrics.RecordLoginDuration(stopwatch.Elapsed.TotalMilliseconds, request.GrantType);
            _logger.LogWarning("Authentication failed: GrantType={GrantType}, Reason={Reason}", request.GrantType, validationResult.ErrorMessage);
            await _auditService.RecordLoginAsync(null, failedUsername, request.GrantType, "login_failure",
                clientIp, userAgent, validationResult.ErrorMessage, appId, correlationId);
            return Ok(new TokenResponse { Success = false, Message = validationResult.ErrorMessage ?? "authentication_failed" });
        }

        var account = validationResult.Account!;
        var displayName = ResolveDisplayName(account, validationResult.DisplayName, request.GrantType);
        var claims = _claimsResolver.ResolveBasicClaims(account, displayName);
        claims.Add(new Claim(IdentityConstants.ClaimAuthMethod, validationResult.AuthMethod ?? request.GrantType));

        if (app?.CallbackUrl != null && _callbackService != null)
        {
            try
            {
                var externalClaims = await _callbackService.FetchExternalClaimsAsync(app.CallbackUrl!, account.Id.ToString());
                if (externalClaims.Count > 0)
                {
                    _logger.LogInformation("Fetched {Count} external claims from callback: AppId={AppId}", externalClaims.Count, appId);
                    claims.AddRange(externalClaims);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Callback request failed, continuing with basic claims: AppId={AppId}", appId);
            }
        }

        // Bootstrap admin super-role: when the login username matches the configured
        // AdminBootstrap:Username, unconditionally inject role:admin regardless of which
        // portal the request comes from (bypasses the callback mechanism). Case-insensitive.
        // Deduplicates: skip if callback already returned role:admin.
        InjectBootstrapAdminRole(request, claims);

        var rsaKey = _keyManager.GetCurrentKey();
        var accessToken = _tokenService.GenerateJwtToken(claims, rsaKey, _jwtOptions.TokenExpirationHours);
        var expiresAt = DateTimeOffset.UtcNow.AddHours(_jwtOptions.TokenExpirationHours).ToUnixTimeSeconds();

        var newRefreshToken = await _refreshTokenService.HandleRefreshTokenAsync(
            request.GrantType, request.RefreshToken, account, appId);

        var roles = claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToList();
        var permissions = claims.Where(c => c.Type == IdentityConstants.ClaimPermission).Select(c => c.Value).ToList();

        stopwatch.Stop();
        _authMetrics.RecordLoginSuccess(request.GrantType);
        _authMetrics.RecordLoginDuration(stopwatch.Elapsed.TotalMilliseconds, request.GrantType);

        _logger.LogInformation(
            "Token issued: AccountId={AccountId}, GrantType={GrantType}, AppId={AppId}",
            account.Id, request.GrantType, appId ?? "N/A");

        await _auditService.RecordLoginAsync(account.Id, displayName ?? account.Id.ToString(), request.GrantType, "login_success",
            clientIp, userAgent, null, appId, correlationId);

        await _accountLoginInfoService.UpdateLoginInfoAsync(account, clientIp, validationResult.AuthMethod ?? request.GrantType);

        return Ok(new TokenResponse
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
                AuthMethod = validationResult.AuthMethod ?? request.GrantType,
                Roles = roles,
                Permissions = permissions
            }
        });
    }

    /// <summary>
    /// POST /api/auth/sms-code — Request SMS verification code.
    /// Replaces gRPC AuthGrpcService.RequestSmsCode.
    /// </summary>
    [HttpPost("sms-code")]
    [AllowAnonymous]
    public async Task<ActionResult<SmsCodeResponse>> RequestSmsCode(
        [FromBody] SmsCodeRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Phone))
        {
            return Ok(new SmsCodeResponse { Success = false, Message = "Phone number is required" });
        }

        var appId = GetAppIdHeader();
        var appSecret = GetAppSecretHeader();

        if (!string.IsNullOrEmpty(appId))
        {
            var gatewayResult = await _gatewayValidator.ValidateAsync(appId, appSecret);
            if (!gatewayResult.IsSuccess)
            {
                _logger.LogWarning("SMS code request gateway validation failed: AppId={AppId}, Reason={Reason}", appId, gatewayResult.ErrorMessage);
                return Ok(new SmsCodeResponse { Success = false, Message = gatewayResult.ErrorMessage });
            }
        }

        try
        {
            var phone = request.Phone.Trim();
            var maskedPhone = SensitiveDataMasker.MaskPhone(phone);
            await _otpService.GenerateAndSendAsync(phone, _smsSender);
            _logger.LogInformation("SMS verification code sent: Phone={Phone}", maskedPhone);

            await _auditService.RecordLoginAsync(null, phone, IdentityConstants.GrantTypeSms, "sms_code_sent",
                GetClientIp(), GetUserAgent(), null, appId, GetCorrelationId());

            return Ok(new SmsCodeResponse { Success = true, Message = "Verification code sent" });
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning("SMS code request failed: Phone={Phone}, Reason={Reason}", SensitiveDataMasker.MaskPhone(request.Phone), ex.Message);
            return Ok(new SmsCodeResponse { Success = false, Message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SMS code request exception: Phone={Phone}", SensitiveDataMasker.MaskPhone(request.Phone));
            return Ok(new SmsCodeResponse { Success = false, Message = "Failed to send verification code" });
        }
    }

    /// <summary>
    /// POST /api/auth/revoke — Revoke a refresh token.
    /// Replaces gRPC AuthGrpcService.RevokeRefreshToken.
    /// </summary>
    [HttpPost("revoke")]
    [AllowAnonymous]
    public async Task<ActionResult<RevokeResponse>> RevokeRefreshToken(
        [FromBody] RevokeRequest request)
    {
        var clientIp = GetClientIp();
        var correlationId = GetCorrelationId();

        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            _logger.LogWarning("Refresh token revocation failed: empty token, ClientIp={ClientIp}, CorrelationId={CorrelationId}", clientIp, correlationId);
            return Ok(new RevokeResponse { Success = false });
        }

        var success = await _refreshTokenService.RevokeAsync(request.RefreshToken);
        _logger.LogInformation("Refresh token revoked: Success={Success}, ClientIp={ClientIp}, CorrelationId={CorrelationId}", success, clientIp, correlationId);
        return Ok(new RevokeResponse { Success = success });
    }

    /// <summary>
    /// POST /api/auth/callback/register — Register a business system's callback URL.
    /// Replaces gRPC AuthGrpcService.RegisterCallback.
    /// </summary>
    [HttpPost("callback/register")]
    [AllowAnonymous]
    public async Task<ActionResult<RegisterCallbackHttpResponse>> RegisterCallback(
        [FromBody] RegisterCallbackHttpRequest request)
    {
        var appId = GetAppIdHeader();
        var appSecret = GetAppSecretHeader();

        if (string.IsNullOrEmpty(appId) || string.IsNullOrEmpty(appSecret))
        {
            return Ok(new RegisterCallbackHttpResponse { Success = false, Message = "AppId and AppSecret are required" });
        }

        if (!string.IsNullOrWhiteSpace(request.CallbackUrl))
        {
            var urlValidation = _callbackUrlValidator.Validate(request.CallbackUrl);
            if (!urlValidation.IsValid)
            {
                return Ok(new RegisterCallbackHttpResponse { Success = false, Message = $"Invalid callback URL: {urlValidation.ErrorMessage}" });
            }
        }

        var app = await _appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null)
        {
            return Ok(new RegisterCallbackHttpResponse { Success = false, Message = "AppId not registered" });
        }

        if (!BCrypt.Net.BCrypt.Verify(appSecret, app.AppSecretHash))
        {
            _logger.LogWarning("Callback registration failed: AppId={AppId}, Reason=AppSecret mismatch", appId);
            return Ok(new RegisterCallbackHttpResponse { Success = false, Message = "AppSecret mismatch" });
        }

        app.CallbackUrl = request.CallbackUrl;
        app.CallbackExpiresAt = request.TtlSeconds == IdentityConstants.CallbackTtlNeverExpire
            ? null
            : DateTimeOffset.UtcNow.AddSeconds(request.TtlSeconds > 0 ? request.TtlSeconds : IdentityConstants.DefaultCallbackTtlSeconds);
        await _unitOfWork.SaveChangesAsync();

        return Ok(new RegisterCallbackHttpResponse
        {
            Success = true,
            Message = "Registered successfully",
            ExpiresAt = app.CallbackExpiresAt.HasValue ? app.CallbackExpiresAt.Value.ToUnixTimeSeconds() : 0
        });
    }

    /// <summary>
    /// If the login username matches <see cref="AdminBootstrapOptions.Username"/> (case-insensitive,
    /// non-empty config), injects <c>role:admin</c> into <paramref name="claims"/> unless already
    /// present. This is the "super admin" shortcut that bypasses the portal callback mechanism,
    /// so the bootstrap admin account always receives the admin role regardless of which portal
    /// it logs in from. Only meaningful for password grant (where <c>request.Username</c> is set).
    /// </summary>
    private void InjectBootstrapAdminRole(TokenRequest request, List<Claim> claims)
    {
        var bootstrapUsername = _adminBootstrapOptions.Username;
        if (string.IsNullOrWhiteSpace(bootstrapUsername))
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(request.Username))
        {
            return;
        }

        if (!string.Equals(request.Username.Trim(), bootstrapUsername.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (claims.Any(c => c.Type == ClaimTypes.Role && string.Equals(c.Value, "admin", StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        claims.Add(new Claim(ClaimTypes.Role, "admin"));
        _logger.LogInformation("Injected bootstrap admin role for user {Username}", request.Username);
    }

    private static string? ResolveDisplayName(AccountEntity account, string? validationResultDisplayName, string grantType)
    {
        if (!string.IsNullOrWhiteSpace(account.Nickname))
            return account.Nickname;

        if (!string.IsNullOrEmpty(validationResultDisplayName))
            return validationResultDisplayName;

        if (grantType == IdentityConstants.GrantTypeWechat)
            return $"WeChat_{account.Id.ToString()[..8]}";

        // Fallback for password/sms grant types: use account ID prefix to avoid empty display name
        return $"User_{account.Id.ToString()[..8]}";
    }

    private string? GetAppIdHeader() =>
        HttpContext.Items[GatewayController.AppIdHeader] as string
        ?? Request.Headers[GatewayController.AppIdHeader].FirstOrDefault();

    private string? GetAppSecretHeader() =>
        HttpContext.Items[GatewayController.AppSecretHeader] as string
        ?? Request.Headers[GatewayController.AppSecretHeader].FirstOrDefault();

    private string? GetClientIp() =>
        Request.Headers["X-Forwarded-For"].FirstOrDefault()?.Split(',')[0].Trim()
        ?? HttpContext.Connection.RemoteIpAddress?.ToString();

    private string? GetUserAgent() => Request.Headers.UserAgent.ToString();

    private string GetCorrelationId() =>
        Request.Headers["x-correlation-id"].FirstOrDefault() ?? Guid.NewGuid().ToString("N");
}
