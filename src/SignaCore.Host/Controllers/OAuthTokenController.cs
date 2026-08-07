using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host.Http;
using SignaCore.Host.Security;
using SignaCore.Host.Services;

namespace SignaCore.Host.Controllers;

/// <summary>
/// RFC 6749 §3.2 token endpoint. Same issuance pipeline as <see cref="TokenController"/>, standard
/// wire format: <c>application/x-www-form-urlencoded</c> in, a token response or an error object out,
/// and real HTTP status codes.
/// <para>
/// This endpoint exists alongside <c>/api/auth/token</c> rather than replacing it; the legacy contract
/// has downstream consumers and stays unchanged. See docs/overview/StandardsConformance.md.
/// </para>
/// </summary>
[Route("oauth2")]
[ApiController]
public sealed class OAuthTokenController : ControllerBase
{
    private readonly TokenIssuanceService _tokenIssuanceService;
    private readonly IRefreshTokenService _refreshTokenService;

    public OAuthTokenController(
        TokenIssuanceService tokenIssuanceService,
        IRefreshTokenService refreshTokenService)
    {
        _tokenIssuanceService = tokenIssuanceService;
        _refreshTokenService = refreshTokenService;
    }

    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    [Authorize(Policy = OAuthClientAuthenticationDefaults.Policy)]
    public async Task<IActionResult> Token(CancellationToken cancellationToken)
    {
        var app = HttpContext.GetValidatedApp()
            ?? throw new InvalidOperationException("OAuth client authentication did not provide a validated application.");
        var form = Request.Form;

        var wireGrantType = form["grant_type"].ToString();
        if (string.IsNullOrWhiteSpace(wireGrantType))
        {
            return Error(OAuthErrorCodes.InvalidRequest, "grant_type is required.");
        }

        // 未知的 wire 名字 → unsupported_grant_type，不进入发 token 流程。
        var grantType = OAuthGrantTypes.ToInternal(wireGrantType);
        if (grantType == null || !_tokenIssuanceService.IsSupportedGrantType(grantType))
        {
            return Error(
                OAuthErrorCodes.UnsupportedGrantType,
                $"grant_type '{wireGrantType}' is not supported.");
        }

        // RFC 6749 §3.3：本服务暂不支持 scope，客户端显式要 scope 时如实拒绝，
        // 而不是静默忽略后签出一个权限范围与请求不符的 token。
        var requestedScope = form["scope"].ToString();
        if (!string.IsNullOrWhiteSpace(requestedScope))
        {
            return Error(OAuthErrorCodes.InvalidScope, "This authorization server does not support scopes.");
        }

        var outcome = await _tokenIssuanceService.IssueAsync(
            new TokenIssuanceRequest(
                grantType,
                app,
                Value(form["username"]),
                Value(form["password"]),
                Value(form["phone"]),
                Value(form["code"]),
                Value(form["refresh_token"]),
                HttpContext.GetClientIp(),
                HttpContext.GetUserAgent(),
                HttpContext.GetCorrelationId()),
            cancellationToken);

        if (!outcome.IsSuccess)
        {
            return Error(outcome.ErrorCode, outcome.ErrorMessage);
        }

        // RFC 6749 §5.1: 成功响应必须带 no-store，避免中间层缓存 token。
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";

        var body = new Dictionary<string, object>
        {
            ["access_token"] = outcome.AccessToken,
            ["token_type"] = "Bearer",
            ["expires_in"] = outcome.ExpiresIn
        };
        if (!string.IsNullOrEmpty(outcome.RefreshToken))
        {
            body["refresh_token"] = outcome.RefreshToken;
        }

        return Ok(body);
    }

    /// <summary>
    /// RFC 7009 §2.1 token revocation. Always answers 200 for a syntactically valid request, whether or
    /// not the token existed — unlike <c>/api/auth/revoke</c>, whose <c>success</c> flag tells the
    /// caller whether the token was real.
    /// </summary>
    [HttpPost("revoke")]
    [Consumes("application/x-www-form-urlencoded")]
    [Authorize(Policy = OAuthClientAuthenticationDefaults.Policy)]
    public async Task<IActionResult> Revoke()
    {
        var app = HttpContext.GetValidatedApp()
            ?? throw new InvalidOperationException("OAuth client authentication did not provide a validated application.");
        var token = Request.Form["token"].ToString();
        if (string.IsNullOrWhiteSpace(token))
        {
            return Error(OAuthErrorCodes.InvalidRequest, "token is required.");
        }

        // RFC 7009 §2.2.1: 只支持 refresh_token；access token 是自包含的，无法撤销。
        var hint = Request.Form["token_type_hint"].ToString();
        if (!string.IsNullOrWhiteSpace(hint) &&
            !string.Equals(hint, "refresh_token", StringComparison.Ordinal) &&
            !string.Equals(hint, "access_token", StringComparison.Ordinal))
        {
            return Error("unsupported_token_type", $"token_type_hint '{hint}' is not supported.");
        }

        // RFC 7009 §2.1: 只撤销签发给该客户端的 token。持有别人的 token 不足以终止别人的会话。
        // 不匹配时仍然返回 200——响应不能变成"这张 token 是否存在/属于谁"的探针。
        await _refreshTokenService.RevokeForAppAsync(token, app.AppId);
        return Ok();
    }

    private static string? Value(Microsoft.Extensions.Primitives.StringValues values)
    {
        var value = values.ToString();
        return string.IsNullOrEmpty(value) ? null : value;
    }

    /// <summary>
    /// RFC 6749 §5.2: 除 invalid_client 用 401（由认证处理器发出）外，全部用 400。
    /// </summary>
    private IActionResult Error(string error, string description)
    {
        Response.Headers.CacheControl = "no-store";
        return BadRequest(new Dictionary<string, string>
        {
            ["error"] = error,
            ["error_description"] = description
        });
    }
}
