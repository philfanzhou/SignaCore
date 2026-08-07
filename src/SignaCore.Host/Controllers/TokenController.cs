using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SignaCore.Host.Http;
using SignaCore.Host.Models;
using SignaCore.Host.Security;
using SignaCore.Host.Services;

namespace SignaCore.Host.Controllers;

/// <summary>
/// POST /api/auth/token —— 签发 access token（历史 JSON 契约）。
/// AppId/AppSecret 通过 X-Admin-AppId / X-Admin-AppSecret 请求头传递并强制校验。
/// <para>
/// 这是既有下游依赖的契约端点，形态不动。符合 RFC 6749 的等价能力在
/// <see cref="OAuthTokenController"/>（<c>/oauth2/token</c>）上，两者共用
/// <see cref="TokenIssuanceService"/>。
/// </para>
/// </summary>
[Route("api/auth")]
[ApiController]
public class TokenController : ControllerBase
{
    private readonly TokenIssuanceService _tokenIssuanceService;

    public TokenController(TokenIssuanceService tokenIssuanceService)
    {
        _tokenIssuanceService = tokenIssuanceService;
    }

    /// <summary>
    /// POST /api/auth/token — 统一发 token（OAuth2 grant_type 模式）。
    /// 失败时返回 HTTP 200 + Success=false，不是 4xx；错误文案是契约，
    /// 见 docs/modules/Auth/GetToken/06-CONVENTIONS.md。
    /// </summary>
    [HttpPost("token")]
    [Authorize(Policy = GatewayAppAuthenticationDefaults.Policy)]
    public async Task<ActionResult<TokenResponse>> GetToken(
        [FromBody] TokenRequest request,
        CancellationToken cancellationToken)
    {
        var app = HttpContext.GetValidatedApp()
            ?? throw new InvalidOperationException("GatewayApp authentication did not provide a validated application.");

        var outcome = await _tokenIssuanceService.IssueAsync(
            new TokenIssuanceRequest(
                request.GrantType,
                app,
                request.Username,
                request.Password,
                request.Phone,
                request.Code,
                request.RefreshToken,
                HttpContext.GetClientIp(),
                HttpContext.GetUserAgent(),
                HttpContext.GetCorrelationId()),
            cancellationToken);

        if (!outcome.IsSuccess)
        {
            // 失败也是 HTTP 200：这是对外契约，不要改成 4xx。
            return Ok(new TokenResponse { Success = false, Message = outcome.ErrorMessage });
        }

        return Ok(new TokenResponse
        {
            Success = true,
            Message = "Login successful",
            AccessToken = outcome.AccessToken,
            RefreshToken = outcome.RefreshToken,
            ExpiresIn = outcome.ExpiresIn,
            ExpiresAt = outcome.ExpiresAt,
            UserInfo = new UserInfo
            {
                UserId = outcome.Account.Id.ToString(),
                Username = outcome.DisplayName ?? string.Empty,
                AuthMethod = outcome.AuthMethod,
                Roles = [.. outcome.Roles],
                Permissions = [.. outcome.Permissions]
            }
        });
    }
}
