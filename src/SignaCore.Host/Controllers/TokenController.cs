using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SignaCore.Host.Http;
using SignaCore.Host.Models;
using SignaCore.Host.Security;
using SignaCore.Host.Services;

namespace SignaCore.Host.Controllers;

/// <summary>
/// POST /api/auth/token — issues access tokens under the historical JSON contract.
/// AppId/AppSecret travel in the X-Admin-AppId / X-Admin-AppSecret headers and are enforced.
/// <para>
/// This is the contract endpoint existing downstream consumers depend on, and its shape does not
/// change. The RFC 6749 conformant equivalent lives on <see cref="OAuthTokenController"/>
/// (<c>/oauth2/token</c>); both share <see cref="TokenIssuanceService"/>.
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
    /// POST /api/auth/token — the single token issuance entry point, in the OAuth2 grant_type shape.
    /// A failure returns HTTP 200 with Success=false rather than a 4xx, and the message text is part
    /// of the contract; see docs/modules/Auth/GetToken/06-CONVENTIONS.md.
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
            // A failure is HTTP 200 as well: that is the outward contract, not something to turn
            // into a 4xx.
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
