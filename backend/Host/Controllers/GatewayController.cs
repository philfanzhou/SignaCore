using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Host.Models;

namespace QuantumZhou.Identity.Host.Controllers;

[Route("api/gateway")]
[ApiController]
public class GatewayController : ControllerBase
{
    private const string AppIdHeader = "X-Admin-AppId";
    private const string AppSecretHeader = "X-Admin-AppSecret";

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
        var allFiltered = await query.ToListAsync();
        var paged = allFiltered
            .OrderByDescending(account => account.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();

        var users = paged
            .Select(account =>
            {
                var username = dbContext.PasswordCredentials
                    .Where(credential => credential.AccountId == account.Id)
                    .Select(credential => credential.Username)
                    .FirstOrDefault();
                var phone = dbContext.UserLogins
                    .Where(login => login.AccountId == account.Id && login.ProviderName == IdentityConstants.AuthMethodSms)
                    .Select(login => login.ProviderUserId)
                    .FirstOrDefault();
                return new
                {
                    account.Id,
                    account.IsActive,
                    account.Remark,
                    account.Nickname,
                    account.CreatedAt,
                    Username = username,
                    Phone = phone
                };
            })
            .ToList();

        return users
            .Select(user =>
            {
                var name = user.Username ?? user.Phone ?? string.Empty;
                var displayName = !string.IsNullOrWhiteSpace(user.Nickname)
                    ? user.Nickname
                    : (!string.IsNullOrWhiteSpace(user.Username)
                        ? user.Username
                        : (!string.IsNullOrWhiteSpace(user.Phone) ? user.Phone : user.Id.ToString()[..8]));
                return new AdminUserListItemResponse(
                    user.Id.ToString(),
                    name,
                    user.Phone ?? string.Empty,
                    user.IsActive,
                    user.Remark ?? string.Empty,
                    user.Nickname,
                    user.CreatedAt.ToUnixTimeSeconds(),
                    displayName);
            })
            .ToList();
    }

    private async Task<IActionResult?> ValidateGatewayRequestAsync(GatewayValidationService gatewayValidationService)
    {
        var appId = HttpContext.Request.Headers[AppIdHeader].FirstOrDefault();
        var appSecret = HttpContext.Request.Headers[AppSecretHeader].FirstOrDefault();

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
