using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Host.Http;
using SignaCore.Host.Models;
using SignaCore.Host.Security;

namespace SignaCore.Host.Controllers;

/// <summary>
/// Gateway API — called by internal microservices with AppId/AppSecret credentials.
/// Security model:
///   - this API is only for calls from the Docker internal network or a trusted internal network;
///   - the AppSecret travels in an HTTP request header, so production must enable HTTPS (or
///     terminate TLS at the reverse proxy) to keep network sniffing from leaking the credential;
///   - the request logging middleware already redacts the X-Admin-AppSecret header, so that value
///     never appears in the structured logs.
/// </summary>
[Route("api/gateway")]
[ApiController]
[Authorize(Policy = GatewayAppAuthenticationDefaults.Policy)]
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

        if (HttpContext.GetValidatedApp() is not null)
        {
            return null;
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
