using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SignaCore.Domain.Services;
using SignaCore.Host.Http;
using SignaCore.Host.Models;

namespace SignaCore.Host.Controllers;

/// <summary>
/// POST /api/auth/revoke —— 撤销 refresh token。
/// </summary>
[Route("api/auth")]
[ApiController]
public class TokenRevocationController : ControllerBase
{
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly ILogger<TokenRevocationController> _logger;

    public TokenRevocationController(
        IRefreshTokenService refreshTokenService,
        ILogger<TokenRevocationController> logger)
    {
        _refreshTokenService = refreshTokenService;
        _logger = logger;
    }

    [HttpPost("revoke")]
    [AllowAnonymous]
    public async Task<ActionResult<RevokeResponse>> RevokeRefreshToken(
        [FromBody] RevokeRequest request)
    {
        var clientIp = HttpContext.GetClientIp();
        var correlationId = HttpContext.GetCorrelationId();

        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            _logger.LogWarning("Refresh token revocation failed: empty token, ClientIp={ClientIp}, CorrelationId={CorrelationId}", clientIp, correlationId);
            return Ok(new RevokeResponse { Success = false });
        }

        var success = await _refreshTokenService.RevokeAsync(request.RefreshToken);
        _logger.LogInformation("Refresh token revoked: Success={Success}, ClientIp={ClientIp}, CorrelationId={CorrelationId}", success, clientIp, correlationId);
        return Ok(new RevokeResponse { Success = success });
    }
}
