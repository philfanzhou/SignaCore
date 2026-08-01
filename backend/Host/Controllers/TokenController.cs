using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Validators;
using QuantumZhou.Identity.Host.Http;
using QuantumZhou.Identity.Host.Models;

namespace QuantumZhou.Identity.Host.Controllers;

/// <summary>
/// POST /api/auth/token —— 签发 access token。
/// AppId/AppSecret 通过 X-Admin-AppId / X-Admin-AppSecret 请求头传递，在本端点上是**可选的**：
/// 带了才做网关校验（DocLibrary 的 refresh 流程依赖这一点）。
/// </summary>
[Route("api/auth")]
[ApiController]
public class TokenController : ControllerBase
{
    private readonly IKeyManager _keyManager;
    private readonly ITokenService _tokenService;
    private readonly JwtOptions _jwtOptions;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly ClaimsResolver _claimsResolver;
    private readonly ValidatorFactory _validatorFactory;
    private readonly ICallbackService? _callbackService;
    private readonly AuthMetrics _authMetrics;
    private readonly GatewayValidationService _gatewayValidator;
    private readonly IAuditService _auditService;
    private readonly IAccountLoginInfoService _accountLoginInfoService;
    private readonly IAccountRepository _accountRepository;
    private readonly AdminBootstrapOptions _adminBootstrapOptions;
    private readonly ILogger<TokenController> _logger;

    public TokenController(
        IKeyManager keyManager,
        ITokenService tokenService,
        JwtOptions jwtOptions,
        IRefreshTokenService refreshTokenService,
        ClaimsResolver claimsResolver,
        ValidatorFactory validatorFactory,
        ICallbackService? callbackService,
        AuthMetrics authMetrics,
        GatewayValidationService gatewayValidator,
        IAuditService auditService,
        IAccountLoginInfoService accountLoginInfoService,
        IAccountRepository accountRepository,
        IOptions<AdminBootstrapOptions> adminBootstrapOptions,
        ILogger<TokenController> logger)
    {
        _keyManager = keyManager;
        _tokenService = tokenService;
        _jwtOptions = jwtOptions;
        _refreshTokenService = refreshTokenService;
        _claimsResolver = claimsResolver;
        _validatorFactory = validatorFactory;
        _callbackService = callbackService;
        _authMetrics = authMetrics;
        _gatewayValidator = gatewayValidator;
        _auditService = auditService;
        _accountLoginInfoService = accountLoginInfoService;
        _accountRepository = accountRepository;
        _adminBootstrapOptions = adminBootstrapOptions.Value;
        _logger = logger;
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
        var appId = HttpContext.GetAppId();
        var appSecret = HttpContext.GetAppSecret();
        var context = new TokenRequestContext(
            request.GrantType,
            HttpContext.GetClientIp(),
            HttpContext.GetUserAgent(),
            appId,
            HttpContext.GetCorrelationId(),
            Stopwatch.StartNew());

        // 网关校验：只有带了 AppId 头才做
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
    /// 当已认证账号就是 <see cref="AdminBootstrapOptions.Username"/> 配置的 bootstrap admin 时，
    /// 无条件注入 <c>role:admin</c>（已存在则跳过）。这是绕过门户回调机制的"超管"捷径，
    /// 使 bootstrap admin 无论从哪个门户登录或刷新都能拿到 admin 角色。
    /// <para>
    /// 身份一律从已校验的账号推导，绝不信任客户端可控的请求字段：
    /// <list type="bullet">
    /// <item><c>password</c>：比对已通过密码校验的 <c>request.Username</c> 与配置的用户名（忽略大小写）。</item>
    /// <item><c>refresh_token</c>：通过
    /// <see cref="IAccountRepository.GetByPasswordCredentialUsernameAsync"/> 解析出 bootstrap 账号，
    /// 与已认证的 <paramref name="authenticatedAccount"/> 比对 Id。请求体里的 username 被刻意忽略，
    /// 防止普通账号伪造 <c>username=admin</c> 提权。</item>
    /// <item><c>sms</c> / <c>wechat_code</c>：不触发注入。</item>
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

        // password/sms 的兜底：用账号 ID 前缀，避免空显示名
        return $"User_{account.Id.ToString()[..8]}";
    }
}
