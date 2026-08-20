using System.Diagnostics;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;

namespace SignaCore.Host.Services;

/// <summary>
/// 一次登录换 token 的完整流程：选校验器 → 校验 → 处理 refresh token → 组 claims →
/// 回调补充 claims → 注入 bootstrap admin 角色 → 签发 → 埋点 → 审计 → 更新登录信息。
/// <para>
/// 两个传输端点共用这里：<c>/api/auth/token</c>（历史 JSON 契约，失败也返回 HTTP 200）与
/// <c>/oauth2/token</c>（RFC 6749 form-encoded，失败返回 4xx + error 码）。流程只能有一份——
/// 两份实现迟早会在"哪个分支记了审计、哪个没记"上分叉。
/// </para>
/// </summary>
public sealed class TokenIssuanceService
{
    private readonly IKeyManager _keyManager;
    private readonly ITokenService _tokenService;
    private readonly JwtOptions _jwtOptions;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly ClaimsResolver _claimsResolver;
    private readonly ValidatorFactory _validatorFactory;
    private readonly ICallbackService? _callbackService;
    private readonly AuthMetrics _authMetrics;
    private readonly IAuditService _auditService;
    private readonly IAccountLoginInfoService _accountLoginInfoService;
    private readonly IAccountRepository _accountRepository;
    private readonly AdminIdentityOptions _adminIdentityOptions;
    private readonly ILogger<TokenIssuanceService> _logger;

    public TokenIssuanceService(
        IKeyManager keyManager,
        ITokenService tokenService,
        JwtOptions jwtOptions,
        IRefreshTokenService refreshTokenService,
        ClaimsResolver claimsResolver,
        ValidatorFactory validatorFactory,
        ICallbackService? callbackService,
        AuthMetrics authMetrics,
        IAuditService auditService,
        IAccountLoginInfoService accountLoginInfoService,
        IAccountRepository accountRepository,
        AdminIdentityOptions adminIdentityOptions,
        ILogger<TokenIssuanceService> logger)
    {
        _keyManager = keyManager;
        _tokenService = tokenService;
        _jwtOptions = jwtOptions;
        _refreshTokenService = refreshTokenService;
        _claimsResolver = claimsResolver;
        _validatorFactory = validatorFactory;
        _callbackService = callbackService;
        _authMetrics = authMetrics;
        _auditService = auditService;
        _accountLoginInfoService = accountLoginInfoService;
        _accountRepository = accountRepository;
        _adminIdentityOptions = adminIdentityOptions;
        _logger = logger;
    }

    public bool IsSupportedGrantType(string grantType) => _validatorFactory.IsSupportedGrantType(grantType);

    public async Task<TokenIssuanceOutcome> IssueAsync(
        TokenIssuanceRequest request,
        CancellationToken cancellationToken)
    {
        var appId = request.App.AppId;
        var stopwatch = Stopwatch.StartNew();

        if (!_validatorFactory.IsSupportedGrantType(request.GrantType))
        {
            _logger.LogWarning("Unsupported grant_type: {GrantType}",
                LogValueSanitizer.SanitizeGrantType(request.GrantType));
            return await FailAsync(
                request,
                stopwatch,
                errorCode: OAuthErrorCodes.UnsupportedGrantType,
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
            AppId = appId,
            App = request.App,
            CancellationToken = cancellationToken
        });

        if (!validationResult.IsSuccess)
        {
            _logger.LogWarning(
                "Authentication failed: GrantType={GrantType}, Reason={Reason}",
                LogValueSanitizer.SanitizeGrantType(request.GrantType),
                LogValueSanitizer.Sanitize(validationResult.ErrorMessage));
            return await FailAsync(
                request,
                stopwatch,
                errorCode: validationResult.ErrorCode,
                metricReason: validationResult.ErrorMessage,
                responseMessage: validationResult.ErrorMessage,
                auditFailureReason: validationResult.ErrorMessage,
                // OTPs and provider authorization codes are credentials, never audit identities.
                auditUsername: request.Username ?? request.Phone ?? "unknown");
        }

        // 在成功分支入口一次性捕获：MemberNotNullWhen 给出的非空流状态在跨越
        // 后面的 await（回调取外部 claims）之后不再保留，捕获成局部变量最省事。
        var account = validationResult.Account;
        var authMethod = validationResult.AuthMethod;
        var displayName = ResolveDisplayName(account, validationResult.DisplayName, request.GrantType);

        var claims = _claimsResolver.ResolveBasicClaims(account, displayName);
        claims.Add(new Claim(IdentityConstants.ClaimAuthMethod, authMethod));
        claims.Add(new Claim(IdentityConstants.ClaimClientId, appId));

        if (request.App.CallbackUrl != null && _callbackService != null)
        {
            try
            {
                var externalClaims = await _callbackService.FetchExternalClaimsAsync(
                    request.App.CallbackUrl!, account.Id.ToString(), cancellationToken);
                if (externalClaims.Count > 0)
                {
                    _logger.LogInformation(
                        "Fetched {Count} external claims from callback: AppId={AppId}", externalClaims.Count, appId);
                    claims.AddRange(externalClaims);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Callback request failed, continuing with basic claims: AppId={AppId}", appId);
            }
        }

        await InjectBootstrapAdminRoleAsync(request, account, claims);

        var rsaKey = _keyManager.GetCurrentKey();
        var audience = JwtTokenService.ResolveAudience(request.App, _jwtOptions);
        var accessToken = _tokenService.GenerateJwtToken(
            claims, rsaKey, _jwtOptions.TokenExpirationHours, audience);
        var expiresAt = DateTimeOffset.UtcNow.AddHours(_jwtOptions.TokenExpirationHours).ToUnixTimeSeconds();

        var roles = claims.Where(c => c.Type == IdentityConstants.ClaimRole).Select(c => c.Value).ToList();
        var permissions = claims.Where(c => c.Type == IdentityConstants.ClaimPermission).Select(c => c.Value).ToList();

        // Keep the presented refresh token usable until every fallible step required to construct
        // the response has succeeded. Once rotation commits, no callback, signing, or account update
        // may strand the client without either the old token or the replacement plaintext.
        await _accountLoginInfoService.UpdateLoginInfoAsync(
            account, request.ClientIp, validationResult.AuthMethod ?? request.GrantType);

        var newRefreshToken = await _refreshTokenService.HandleRefreshTokenAsync(
            request.GrantType, request.RefreshToken, account, appId,
            validationResult.LdapCredentialId, validationResult.SmsUserLoginId,
            validationResult.WechatUserLoginId, validationResult.SourceAppId);

        if (request.GrantType == IdentityConstants.GrantTypeRefreshToken && newRefreshToken == null)
        {
            _logger.LogWarning(
                "Refresh token rotation failed because the token was already consumed: AccountId={AccountId}, AppId={AppId}",
                account.Id, appId);
            return await FailAsync(
                request,
                stopwatch,
                errorCode: OAuthErrorCodes.InvalidGrant,
                metricReason: "invalid_grant",
                responseMessage: "invalid_grant",
                auditFailureReason: "invalid_grant",
                auditUsername: displayName ?? account.Id.ToString(),
                accountId: account.Id);
        }

        stopwatch.Stop();
        _authMetrics.RecordLoginSuccess(request.GrantType);
        _authMetrics.RecordLoginDuration(stopwatch.Elapsed.TotalMilliseconds, request.GrantType);

        _logger.LogInformation(
            "Token issued: AccountId={AccountId}, GrantType={GrantType}, AppId={AppId}",
            account.Id,
            LogValueSanitizer.SanitizeGrantType(request.GrantType),
            LogValueSanitizer.Sanitize(appId));

        await _auditService.RecordLoginAsync(
            account.Id, displayName ?? account.Id.ToString(), request.GrantType, "login_success",
            request.ClientIp, request.UserAgent, null, appId, request.CorrelationId);

        return TokenIssuanceOutcome.Success(
            accessToken,
            newRefreshToken ?? string.Empty,
            _jwtOptions.TokenExpirationHours * 3600,
            expiresAt,
            account,
            displayName,
            authMethod,
            roles,
            permissions);
    }

    /// <summary>
    /// 统一失败出口：停表 → 记失败指标 → 记耗时 → 写审计 → 返回失败结果。这四步顺序固定
    /// 且缺一不可，新增失败分支时只调用本方法，不要再手写一遍（历史上四个分支各抄了一份）。
    /// <para>
    /// <paramref name="metricReason"/>、<paramref name="auditFailureReason"/>、
    /// <paramref name="responseMessage"/>、<paramref name="errorCode"/> 是四个**可以互不相同**的值，
    /// 不要合并：unsupported_grant_type 分支的审计原因带具体 grant_type 后缀而响应文案不带；
    /// 校验失败分支的审计原因允许为 null 而响应文案有兜底。响应文案是 /api/auth/token 的对外契约，
    /// 错误码是 /oauth2/token 的对外契约，见 docs/modules/Auth/GetToken/06-CONVENTIONS.md。
    /// </para>
    /// </summary>
    private async Task<TokenIssuanceOutcome> FailAsync(
        TokenIssuanceRequest request,
        Stopwatch stopwatch,
        string errorCode,
        string metricReason,
        string responseMessage,
        string? auditFailureReason,
        string auditUsername = "unknown",
        Guid? accountId = null)
    {
        stopwatch.Stop();
        _authMetrics.RecordLoginFailure(request.GrantType, metricReason);
        _authMetrics.RecordLoginDuration(stopwatch.Elapsed.TotalMilliseconds, request.GrantType);

        await _auditService.RecordLoginAsync(
            accountId, auditUsername, request.GrantType, "login_failure",
            request.ClientIp, request.UserAgent, auditFailureReason, request.App.AppId, request.CorrelationId);

        return TokenIssuanceOutcome.Failure(errorCode, responseMessage);
    }

    /// <summary>
    /// 当已认证账号就是 <see cref="AdminIdentityOptions.Username"/> 配置的 bootstrap admin 时，
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
    /// <item><c>sms</c> / <c>wechat_code</c> / <c>ldap</c>：不触发注入。</item>
    /// </list>
    /// </para>
    /// </summary>
    private async Task InjectBootstrapAdminRoleAsync(
        TokenIssuanceRequest request,
        AccountEntity authenticatedAccount,
        List<Claim> claims)
    {
        var bootstrapUsername = _adminIdentityOptions.Username;
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
                claim.Type == IdentityConstants.ClaimRole
                && string.Equals(
                    claim.Value,
                    "admin",
                    StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        claims.Add(new Claim(IdentityConstants.ClaimRole, "admin"));
        _logger.LogInformation(
            "Injected bootstrap admin role for account {AccountId}",
            authenticatedAccount.Id);
    }

    private static string? ResolveDisplayName(
        AccountEntity account,
        string? validationResultDisplayName,
        string grantType)
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

/// <summary>传输无关的发 token 输入。两个端点各自把自己的请求形态映射到这里。</summary>
public sealed record TokenIssuanceRequest(
    string GrantType,
    AppRegistrationEntity App,
    string? Username = null,
    string? Password = null,
    string? Phone = null,
    string? Code = null,
    string? RefreshToken = null,
    string? ClientIp = null,
    string? UserAgent = null,
    string? CorrelationId = null);

public sealed class TokenIssuanceOutcome
{
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(true, nameof(AccessToken))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(true, nameof(Account))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(true, nameof(AuthMethod))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(false, nameof(ErrorCode))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(false, nameof(ErrorMessage))]
    public bool IsSuccess { get; private init; }

    public string? ErrorCode { get; private init; }

    public string? ErrorMessage { get; private init; }

    public string? AccessToken { get; private init; }

    public string RefreshToken { get; private init; } = string.Empty;

    public long ExpiresIn { get; private init; }

    public long ExpiresAt { get; private init; }

    public AccountEntity? Account { get; private init; }

    public string? DisplayName { get; private init; }

    public string? AuthMethod { get; private init; }

    public IReadOnlyList<string> Roles { get; private init; } = [];

    public IReadOnlyList<string> Permissions { get; private init; } = [];

    public static TokenIssuanceOutcome Success(
        string accessToken,
        string refreshToken,
        long expiresIn,
        long expiresAt,
        AccountEntity account,
        string? displayName,
        string authMethod,
        IReadOnlyList<string> roles,
        IReadOnlyList<string> permissions) => new()
        {
            IsSuccess = true,
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = expiresIn,
            ExpiresAt = expiresAt,
            Account = account,
            DisplayName = displayName,
            AuthMethod = authMethod,
            Roles = roles,
            Permissions = permissions
        };

    public static TokenIssuanceOutcome Failure(string errorCode, string errorMessage) => new()
    {
        IsSuccess = false,
        ErrorCode = errorCode,
        ErrorMessage = errorMessage
    };
}
