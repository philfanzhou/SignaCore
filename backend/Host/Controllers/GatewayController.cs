using Microsoft.AspNetCore.Mvc;
using QuantumZhou.Identity.Domain.Models;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Host.Http;
using QuantumZhou.Identity.Host.Models;

namespace QuantumZhou.Identity.Host.Controllers;

/// <summary>
/// Gateway API — 供内部微服务通过 AppId/AppSecret 凭证调用。
/// 安全模型：
///   - 本接口仅限 Docker 内部网络或受信任的内网环境调用；
///   - AppSecret 通过 HTTP 请求头传递，生产环境必须启用 HTTPS（或 TLS 终结于反向代理层），
///     以防止网络嗅探导致凭证泄露；
///   - 请求日志中间件已对 X-Admin-AppSecret 头做脱敏处理，确保该值不会出现在结构化日志中。
/// </summary>
[Route("api/gateway")]
[ApiController]
public class GatewayController : ControllerBase
{
    private readonly ILogger<GatewayController> _logger;

    public GatewayController(ILogger<GatewayController> logger)
    {
        _logger = logger;
    }

    [HttpGet("users/search")]
    public async Task<IActionResult> SearchUsers(
        [FromQuery] string? username,
        [FromQuery] string? phone,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        [FromServices] IUserQueryService userQueryService,
        [FromServices] GatewayValidationService gatewayValidationService)
    {
        var authError = await ValidateGatewayRequestAsync(gatewayValidationService);
        if (authError != null)
        {
            return authError;
        }

        var paging = PageRequest.Normalize(page, pageSize);

        var (users, total) = await userQueryService.SearchUsersAsync(username, phone, paging.Page, paging.PageSize);

        return Ok(new PagedResponse<UserListItemResponse>(
            users,
            total,
            paging.Page,
            paging.PageSize));
    }

    [HttpPost("users/batch")]
    public async Task<IActionResult> GetUsersByIds(
        [FromBody] List<string>? userIds,
        [FromServices] IUserQueryService userQueryService,
        [FromServices] GatewayValidationService gatewayValidationService)
    {
        var authError = await ValidateGatewayRequestAsync(gatewayValidationService);
        if (authError != null)
        {
            return authError;
        }

        if (userIds == null || userIds.Count == 0)
        {
            return Ok(new List<UserListItemResponse>());
        }

        var orderedUsers = await userQueryService.GetUsersByIdsAsync(userIds);

        return Ok(orderedUsers);
    }

    private async Task<IActionResult?> ValidateGatewayRequestAsync(GatewayValidationService gatewayValidationService)
    {
        if (!HttpContext.Request.IsHttps)
        {
            _logger.LogWarning("Gateway request received over non-HTTPS connection from {RemoteIp}; " +
                "AppSecret transmission over plain HTTP is insecure. " +
                "Ensure HTTPS or TLS termination at the reverse proxy in production.",
                HttpContext.Connection.RemoteIpAddress);
        }

        var appId = HttpContext.GetAppId();
        var appSecret = HttpContext.GetAppSecret();

        if (string.IsNullOrWhiteSpace(appId) || string.IsNullOrWhiteSpace(appSecret))
        {
            return StatusCode(StatusCodes.Status401Unauthorized, new ErrorResponse("Missing gateway credentials."));
        }

        var validation = await gatewayValidationService.ValidateAsync(appId, appSecret);
        if (!validation.IsSuccess)
        {
            return StatusCode(StatusCodes.Status401Unauthorized, new ErrorResponse(validation.ErrorMessage));
        }

        return null;
    }
}
