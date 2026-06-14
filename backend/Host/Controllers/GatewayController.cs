using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services;
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
    internal const string AppIdHeader = "X-Admin-AppId";
    internal const string AppSecretHeader = "X-Admin-AppSecret";

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
        [FromServices] IdentityDbContext dbContext,
        [FromServices] GatewayValidationService gatewayValidationService)
    {
        var authError = await ValidateGatewayRequestAsync(gatewayValidationService);
        if (authError != null)
        {
            return authError;
        }

        var normalizedPage = page.GetValueOrDefault(1) < 1 ? 1 : page.GetValueOrDefault(1);
        var normalizedPageSize = pageSize.GetValueOrDefault(20);
        if (normalizedPageSize < 1)
        {
            normalizedPageSize = 20;
        }

        normalizedPageSize = Math.Min(normalizedPageSize, 100);

        var searchTerm = username?.Trim();
        var phoneTerm = phone?.Trim();

        var query = dbContext.Accounts
            .AsNoTracking()
            .Where(account =>
                (string.IsNullOrWhiteSpace(searchTerm) ||
                 dbContext.PasswordCredentials.Any(credential =>
                     credential.AccountId == account.Id &&
                     EF.Functions.Like(credential.Username, $"%{searchTerm}%")) ||
                 EF.Functions.Like(account.Remark ?? string.Empty, $"%{searchTerm}%")) &&
                (string.IsNullOrWhiteSpace(phoneTerm) ||
                 dbContext.UserLogins.Any(login =>
                     login.AccountId == account.Id &&
                     login.ProviderName == IdentityConstants.AuthMethodSms &&
                     EF.Functions.Like(login.ProviderUserId, $"%{phoneTerm}%"))));

        var total = await query.CountAsync();
        var users = await ProjectUsersAsync(query, dbContext, normalizedPage, normalizedPageSize);

        return Ok(new AdminPagedResponse<AdminUserListItemResponse>(
            users,
            total,
            normalizedPage,
            normalizedPageSize));
    }

    [HttpPost("users/batch")]
    public async Task<IActionResult> GetUsersByIds(
        [FromBody] List<string>? userIds,
        [FromServices] IdentityDbContext dbContext,
        [FromServices] GatewayValidationService gatewayValidationService)
    {
        var authError = await ValidateGatewayRequestAsync(gatewayValidationService);
        if (authError != null)
        {
            return authError;
        }

        if (userIds == null || userIds.Count == 0)
        {
            return Ok(new List<AdminUserListItemResponse>());
        }

        var orderedUserIds = userIds
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var parsedUserIds = orderedUserIds
            .Select(id => Guid.TryParse(id, out var parsedId) ? parsedId : (Guid?)null)
            .Where(id => id.HasValue)
            .Select(id => id!.Value)
            .ToList();

        if (parsedUserIds.Count == 0)
        {
            return Ok(new List<AdminUserListItemResponse>());
        }

        var query = dbContext.Accounts
            .AsNoTracking()
            .Where(account => parsedUserIds.Contains(account.Id));

        var users = await ProjectUsersAsync(query, dbContext, page: 1, pageSize: parsedUserIds.Count);
        var userMap = users.ToDictionary(item => item.UserId, StringComparer.OrdinalIgnoreCase);

        var orderedUsers = orderedUserIds
            .Where(userMap.ContainsKey)
            .Select(id => userMap[id])
            .ToList();

        return Ok(orderedUsers);
    }

    private async Task<List<AdminUserListItemResponse>> ProjectUsersAsync(
        IQueryable<Database.Entity.AccountEntity> query,
        IdentityDbContext dbContext,
        int page,
        int pageSize)
    {
        var pagedAccounts = await query
            .OrderByDescending(account => account.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        var accountIds = pagedAccounts.Select(a => a.Id).ToList();

        var credentials = await dbContext.PasswordCredentials
            .AsNoTracking()
            .Where(c => accountIds.Contains(c.AccountId))
            .ToDictionaryAsync(c => c.AccountId, c => c.Username);

        var phones = await dbContext.UserLogins
            .AsNoTracking()
            .Where(l => accountIds.Contains(l.AccountId) && l.ProviderName == IdentityConstants.AuthMethodSms)
            .ToDictionaryAsync(l => l.AccountId, l => l.ProviderUserId);

        return pagedAccounts.Select(account =>
        {
            var username = credentials.GetValueOrDefault(account.Id);
            var phone = phones.GetValueOrDefault(account.Id);
            var name = username ?? phone ?? string.Empty;
            var displayName = !string.IsNullOrWhiteSpace(account.Nickname)
                ? account.Nickname
                : (!string.IsNullOrWhiteSpace(username)
                    ? username
                    : (!string.IsNullOrWhiteSpace(phone) ? phone : account.Id.ToString()[..8]));
            return new AdminUserListItemResponse(
                account.Id.ToString(),
                name,
                phone ?? string.Empty,
                account.IsActive,
                account.Remark ?? string.Empty,
                account.Nickname,
                account.CreatedAt.ToUnixTimeSeconds(),
                displayName);
        })
            .ToList();
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

        var appId = HttpContext.Request.Headers[AppIdHeader].FirstOrDefault();
        // AppSecret is moved from headers to HttpContext.Items by the sensitive header redaction middleware
        var appSecret = HttpContext.Items[AppSecretHeader] as string
            ?? HttpContext.Request.Headers[AppSecretHeader].FirstOrDefault();

        if (string.IsNullOrWhiteSpace(appId) || string.IsNullOrWhiteSpace(appSecret))
        {
            return StatusCode(StatusCodes.Status401Unauthorized, new AdminApiErrorResponse("Missing gateway credentials."));
        }

        var validation = await gatewayValidationService.ValidateAsync(appId, appSecret);
        if (!validation.IsSuccess)
        {
            return StatusCode(StatusCodes.Status401Unauthorized, new AdminApiErrorResponse(validation.ErrorMessage ?? "Gateway authentication failed."));
        }

        return null;
    }
}
