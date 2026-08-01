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
/// 认证 API。AppId/AppSecret 通过 X-Admin-AppId / X-Admin-AppSecret 请求头传递（与 GatewayController 一致）；
/// 在 /api/auth/token 上这两个头是可选的，带了才做网关校验。
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
    private readonly IAccountRepository _accountRepository;
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
        IAccountRepository accountRepository,
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
        _accountRepository = accountRepository;
        _adminBootstrapOptions = adminBootstrapOptions.Value;
    }

    /// <summary>
    /// POST /api/auth/token — 统一发 token（OAuth2 grant_type 模式）。
    /// 失败时返回 HTTP 200 + Success=false，不是 4xx；错误文案是契约，
    /// 见 docs/modules/Auth/GetToken/06-CONVENTIONS.md。
    /// </summary>
    [HttpPost("token")]
    [AllowAnonymous]
    public async Task<ActionResult<TokenResponse>> GetToken(
        [FromBody] TokenRequest request,
        CancellationToken cancellationToken)
    {
        var appId = GetAppIdHeader();
        var appSecret = GetAppSecretHeader();
        var context = new TokenRequestContext(
            request.GrantType,
            GetClientIp(),
            GetUserAgent(),
            appId,
            GetCorrelationId(),
            Stopwatch.StartNew());

        // Gateway validation (optional, only if AppId header is present)
        AppRegistrationEntity? app = null;
        if (!string.IsNullOrEmpty(appId))
        {
            var gatewayResult = await _gatewayValidator.ValidateAsync(appId, appSecret);
            if (!gatewayResult.IsSuccess)
            {
                _logger.LogWarning("Gateway validation failed: AppId={AppId}, Reason={Reason}", appId, gatewayResult.ErrorMessage);
                return await FailAsync(
                    context,
                    metricReason: "gateway_validation_failed",
                    responseMessage: gatewayResult.ErrorMessage,
                    auditFailureReason: gatewayResult.ErrorMessage);
            }
            app = gatewayResult.App;
        }

        if (!_validatorFactory.IsSupportedGrantType(request.GrantType))
        {
            _logger.LogWarning("Unsupported grant_type: {GrantType}", request.GrantType);
            return await FailAsync(
                context,
                metricReason: "unsupported_grant_type",
                responseMessage: "unsupported_grant_type",
                auditFailureReason: $"unsupported_grant_type: {request.GrantType}");
        }

        var validator = _validatorFactory.GetValidator(request.GrantType);
        var validationResult = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = request.GrantType,
            Username = request.Username,
            Password = request.Password,
            Phone = request.Phone,
            Code = request.Code,
            RefreshToken = request.RefreshToken,
            AppId = appId
        });

        if (!validationResult.IsSuccess)
        {
            _logger.LogWarning("Authentication failed: GrantType={GrantType}, Reason={Reason}", request.GrantType, validationResult.ErrorMessage);
            return await FailAsync(
                context,
                metricReason: validationResult.ErrorMessage ?? "authentication_failed",
                responseMessage: validationResult.ErrorMessage ?? "authentication_failed",
                // 审计里刻意保留原始的 null，与 metric/响应的兜底文案不同
                auditFailureReason: validationResult.ErrorMessage,
                auditUsername: request.Username ?? request.Phone ?? request.Code ?? "unknown");
        }

        var account = validationResult.Account!;
        var displayName = ResolveDisplayName(account, validationResult.DisplayName, request.GrantType);
        var newRefreshToken = await _refreshTokenService.HandleRefreshTokenAsync(
            request.GrantType, request.RefreshToken, account, appId);

        if (request.GrantType == IdentityConstants.GrantTypeRefreshToken && newRefreshToken == null)
        {
            _logger.LogWarning(
                "Refresh token rotation failed because the token was already consumed: AccountId={AccountId}, AppId={AppId}",
                account.Id, appId ?? "N/A");
            return await FailAsync(
                context,
                metricReason: "invalid_grant",
                responseMessage: "invalid_grant",
                auditFailureReason: "invalid_grant",
                auditUsername: displayName ?? account.Id.ToString(),
                accountId: account.Id);
        }

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

        // Bootstrap admin super-role: when the authenticated account is the one configured by
        // AdminBootstrap:Username, unconditionally inject role:admin regardless of which portal the
        // request comes from (bypasses the callback mechanism). For password grant the already-
        // validated request.Username is compared; for refresh_token grant the authenticated
        // AccountEntity.Id is compared against the bootstrap account id (request body username is
        // ignored to prevent escalation). SMS/WeChat grants are not triggered. Deduplicates: skip if
        // callback already returned role:admin.
        await InjectBootstrapAdminRoleAsync(request, account, claims);

        var rsaKey = _keyManager.GetCurrentKey();
        var accessToken = _tokenService.GenerateJwtToken(claims, rsaKey, _jwtOptions.TokenExpirationHours);
        var expiresAt = DateTimeOffset.UtcNow.AddHours(_jwtOptions.TokenExpirationHours).ToUnixTimeSeconds();

        var roles = claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToList();
        var permissions = claims.Where(c => c.Type == IdentityConstants.ClaimPermission).Select(c => c.Value).ToList();

        context.Stopwatch.Stop();
        _authMetrics.RecordLoginSuccess(request.GrantType);
        _authMetrics.RecordLoginDuration(context.Stopwatch.Elapsed.TotalMilliseconds, request.GrantType);

        _logger.LogInformation(
            "Token issued: AccountId={AccountId}, GrantType={GrantType}, AppId={AppId}",
            account.Id, request.GrantType, appId ?? "N/A");

        await _auditService.RecordLoginAsync(account.Id, displayName ?? account.Id.ToString(), request.GrantType, "login_success",
            context.ClientIp, context.UserAgent, null, appId, context.CorrelationId);

        await _accountLoginInfoService.UpdateLoginInfoAsync(account, context.ClientIp, validationResult.AuthMethod ?? request.GrantType);

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
    /// 一次 /api/auth/token 请求里埋点与审计共用的横切数据，入口处算一次往下传。
    /// </summary>
    private sealed record TokenRequestContext(
        string GrantType,
        string? ClientIp,
        string? UserAgent,
        string? AppId,
        string? CorrelationId,
        Stopwatch Stopwatch);

    /// <summary>
    /// /api/auth/token 的统一失败出口：停表 → 记失败指标 → 记耗时 → 写审计 → 返回
    /// HTTP 200 + Success=false。这五步顺序固定且缺一不可，新增失败分支时只调用本方法，
    /// 不要再手写一遍（历史上四个分支各抄了一份）。
    /// <para>
    /// <paramref name="metricReason"/>、<paramref name="auditFailureReason"/>、
    /// <paramref name="responseMessage"/> 是三个**可以互不相同**的值，不要合并：
    /// 例如 unsupported_grant_type 分支的审计原因带具体 grant_type 后缀，而响应文案不带；
    /// 校验失败分支的审计原因允许为 null，而响应文案有兜底。响应文案是对外契约，
    /// 见 docs/modules/Auth/GetToken/06-CONVENTIONS.md。
    /// </para>
    /// </summary>
    private async Task<ActionResult<TokenResponse>> FailAsync(
        TokenRequestContext context,
        string metricReason,
        string? responseMessage,
        string? auditFailureReason,
        string auditUsername = "unknown",
        Guid? accountId = null)
    {
        context.Stopwatch.Stop();
        _authMetrics.RecordLoginFailure(context.GrantType, metricReason);
        _authMetrics.RecordLoginDuration(context.Stopwatch.Elapsed.TotalMilliseconds, context.GrantType);

        await _auditService.RecordLoginAsync(
            accountId, auditUsername, context.GrantType, "login_failure",
            context.ClientIp, context.UserAgent, auditFailureReason, context.AppId, context.CorrelationId);

        // 网关校验失败时 ErrorMessage 可能为 null，此处保持既有行为（序列化为 null），
        // 不擅自兜底成空串——响应体形状是对外契约。
        return Ok(new TokenResponse { Success = false, Message = responseMessage! });
    }

    /// <summary>
    /// POST /api/auth/sms-code — 申请短信验证码。
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
    /// POST /api/auth/revoke — 撤销 refresh token。
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
    /// POST /api/auth/callback/register — 注册业务系统的 claims 回调 URL。
    /// </summary>
    [HttpPost("callback/register")]
    [AllowAnonymous]
    public async Task<ActionResult<RegisterCallbackResponse>> RegisterCallback(
        [FromBody] RegisterCallbackRequest request)
    {
        var appId = GetAppIdHeader();
        var appSecret = GetAppSecretHeader();

        if (string.IsNullOrEmpty(appId) || string.IsNullOrEmpty(appSecret))
        {
            return Ok(new RegisterCallbackResponse { Success = false, Message = "AppId and AppSecret are required" });
        }

        if (!string.IsNullOrWhiteSpace(request.CallbackUrl))
        {
            var urlValidation = _callbackUrlValidator.Validate(request.CallbackUrl);
            if (!urlValidation.IsValid)
            {
                return Ok(new RegisterCallbackResponse { Success = false, Message = $"Invalid callback URL: {urlValidation.ErrorMessage}" });
            }
        }

        var app = await _appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null)
        {
            return Ok(new RegisterCallbackResponse { Success = false, Message = "AppId not registered" });
        }

        if (!BCrypt.Net.BCrypt.Verify(appSecret, app.AppSecretHash))
        {
            _logger.LogWarning("Callback registration failed: AppId={AppId}, Reason=AppSecret mismatch", appId);
            return Ok(new RegisterCallbackResponse { Success = false, Message = "AppSecret mismatch" });
        }

        app.CallbackUrl = request.CallbackUrl;
        app.CallbackExpiresAt = request.TtlSeconds == IdentityConstants.CallbackTtlNeverExpire
            ? null
            : DateTimeOffset.UtcNow.AddSeconds(request.TtlSeconds > 0 ? request.TtlSeconds : IdentityConstants.DefaultCallbackTtlSeconds);
        await _unitOfWork.SaveChangesAsync();

        return Ok(new RegisterCallbackResponse
        {
            Success = true,
            Message = "Registered successfully",
            ExpiresAt = app.CallbackExpiresAt.HasValue ? app.CallbackExpiresAt.Value.ToUnixTimeSeconds() : 0
        });
    }

    /// <summary>
    /// Injects <c>role:admin</c> into <paramref name="claims"/> when the authenticated account is
    /// the bootstrap admin configured by <see cref="AdminBootstrapOptions.Username"/>, unless the
    /// role is already present. This is the "super admin" shortcut that bypasses the portal callback
    /// mechanism, so the bootstrap admin account always receives the admin role regardless of which
    /// portal it logs in from or refreshes through.
    /// <para>
    /// Identity is resolved from the already-validated account, never from client-controlled request
    /// fields:
    /// <list type="bullet">
    /// <item><c>password</c> grant: compares the password-validated <c>request.Username</c> with the
    /// configured bootstrap username (case-insensitive).</item>
    /// <item><c>refresh_token</c> grant: resolves the bootstrap account via
    /// <see cref="IAccountRepository.GetByPasswordCredentialUsernameAsync"/> and compares its id with
    /// the authenticated <paramref name="authenticatedAccount"/> id. The request body username is
    /// intentionally ignored so a regular account cannot escalate by forging <c>username=admin</c>.</item>
    /// <item><c>sms</c>/<c>wechat_code</c> grants: bootstrap admin injection is not triggered.</item>
    /// </list>
    /// </para>
    /// </summary>
    private async Task InjectBootstrapAdminRoleAsync(
        TokenRequest request,
        AccountEntity authenticatedAccount,
        List<Claim> claims)
    {
        var bootstrapUsername = _adminBootstrapOptions.Username;
        if (string.IsNullOrWhiteSpace(bootstrapUsername))
        {
            return;
        }

        var isBootstrapAdmin = false;

        if (request.GrantType == IdentityConstants.GrantTypePassword)
        {
            isBootstrapAdmin =
                !string.IsNullOrWhiteSpace(request.Username)
                && string.Equals(
                    request.Username.Trim(),
                    bootstrapUsername.Trim(),
                    StringComparison.OrdinalIgnoreCase);
        }
        else if (request.GrantType == IdentityConstants.GrantTypeRefreshToken)
        {
            var bootstrapAccount =
                await _accountRepository.GetByPasswordCredentialUsernameAsync(
                    bootstrapUsername.Trim());

            isBootstrapAdmin =
                bootstrapAccount != null
                && bootstrapAccount.Id == authenticatedAccount.Id;
        }

        if (!isBootstrapAdmin)
        {
            return;
        }

        if (claims.Any(claim =>
                claim.Type == ClaimTypes.Role
                && string.Equals(
                    claim.Value,
                    "admin",
                    StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        claims.Add(new Claim(ClaimTypes.Role, "admin"));
        _logger.LogInformation(
            "Injected bootstrap admin role for account {AccountId}",
            authenticatedAccount.Id);
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

    /// <summary>
    /// 取本次请求的 CorrelationId。必须复用 <see cref="CorrelationIdMiddleware"/> 已经生成、
    /// 并写入响应头与日志 scope 的那一个，不能在这里另生成——否则调用方没带 x-correlation-id 时，
    /// 审计表里记的 ID 和日志/响应头里的 ID 不是同一个，事后无法串起来。
    /// </summary>
    private string GetCorrelationId() =>
        HttpContext.Items[CorrelationIdMiddleware.HttpContextItemsKey] as string
        ?? Request.Headers[CorrelationIdMiddleware.CorrelationIdHeader].FirstOrDefault()
        ?? Guid.NewGuid().ToString("N");
}
