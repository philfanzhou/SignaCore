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
/// The complete flow for exchanging a login for tokens: select a validator, validate, process the
/// refresh token, assemble claims, enrich them through the callback, inject the bootstrap admin role,
/// issue tokens, record metrics and audit data, and update login information.
/// <para>
/// Both transport endpoints share this flow: <c>/api/auth/token</c> uses the legacy JSON contract and
/// returns HTTP 200 even for failures, while <c>/oauth2/token</c> is RFC 6749 form-encoded and returns
/// 4xx responses with error codes. Keeping one flow prevents their audit behavior from diverging.
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

        // Capture these once at the start of the success branch. The non-null flow state supplied by
        // MemberNotNullWhen is not preserved across the later await that fetches external claims.
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

        // The signing key is database-backed and may have been rotated by another replica. Refresh
        // before signing so this instance never continues minting tokens with a stale private key.
        await _keyManager.RefreshKeysAsync();
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
    /// The unified failure exit stops the timer, records the failure and duration metrics, writes the
    /// audit entry, and returns the failure result in that fixed order. New failure branches must call
    /// this method instead of duplicating the sequence.
    /// <para>
    /// <paramref name="metricReason"/>, <paramref name="auditFailureReason"/>,
    /// <paramref name="responseMessage"/>, and <paramref name="errorCode"/> may all differ and must not
    /// be merged. The unsupported_grant_type audit reason includes the concrete grant_type suffix while
    /// the response message does not; a validation failure may have a null audit reason while its response
    /// message has a fallback. The response message is part of the /api/auth/token contract, and the error
    /// code is part of the /oauth2/token contract. See docs/modules/Auth/GetToken/06-CONVENTIONS.md.
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
    /// Unconditionally injects <c>role:admin</c>, unless already present, when the authenticated account
    /// is the bootstrap admin configured by <see cref="AdminIdentityOptions.Username"/>. This super-admin
    /// path bypasses the application callback mechanism so the bootstrap admin receives the admin role
    /// when signing in to or refreshing through any application.
    /// <para>
    /// Identity is always derived from the validated account; client-controlled request fields are never trusted:
    /// <list type="bullet">
    /// <item><c>password</c>: compare the password-validated <c>request.Username</c> with the configured
    /// username, ignoring case.</item>
    /// <item><c>refresh_token</c>: resolve the bootstrap account through
    /// <see cref="IAccountRepository.GetByPasswordCredentialUsernameAsync"/> and compare its Id with the
    /// validated <paramref name="authenticatedAccount"/>. The request body's username is deliberately
    /// ignored so an ordinary account cannot elevate privileges by sending <c>username=admin</c>.</item>
    /// <item><c>sms</c>, <c>wechat_code</c>, and <c>ldap</c>: do not trigger injection.</item>
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

        // Password/SMS fallback: use the account ID prefix to avoid an empty display name.
        return $"User_{account.Id.ToString()[..8]}";
    }
}

/// <summary>Transport-neutral token issuance input; each endpoint maps its request shape here.</summary>
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
