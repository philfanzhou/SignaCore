using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Validators;
using QuantumZhou.Identity.Host.Models;

namespace QuantumZhou.Identity.Host.Controllers;

[Route("api/admin")]
[ApiController]
public class AdminController : ControllerBase
{
    private readonly ILogger<AdminController> _logger;

    public AdminController(ILogger<AdminController> logger)
    {
        _logger = logger;
    }

    [HttpPost("session/login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login(
        [FromBody] AdminLoginRequest request,
        [FromServices] ValidatorFactory validatorFactory,
        [FromServices] IOptions<AdminWebOptions> adminWebOptions,
        [FromServices] IAuditService auditService)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new AdminApiErrorResponse("Username and password cannot be empty."));
        }

        var validator = validatorFactory.GetValidator(IdentityConstants.GrantTypePassword);
        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypePassword,
            Username = request.Username.Trim(),
            Password = request.Password
        });

        if (!result.IsSuccess || result.Account == null)
        {
            await auditService.RecordLoginAsync(null, request.Username.Trim(), "admin_login", "login_failure",
                GetClientIp(), HttpContext.Request.Headers.UserAgent, result.ErrorMessage);
            return StatusCode(StatusCodes.Status401Unauthorized, new { message = result.ErrorMessage ?? "Login failed." });
        }

        var username = result.DisplayName ?? request.Username.Trim();
        if (!IsAdminUsernameAllowed(username, adminWebOptions.Value))
        {
            await auditService.RecordLoginAsync(result.Account.Id, username, "admin_login", "login_failure",
                GetClientIp(), HttpContext.Request.Headers.UserAgent, "admin_access_denied");
            return StatusCode(StatusCodes.Status403Forbidden, new { message = "This account is not authorized for admin access." });
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, result.Account.Id.ToString()),
            new(ClaimTypes.Name, username),
            new("admin_access", "true")
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = request.RememberMe,
                AllowRefresh = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(request.RememberMe ? 7 * 24 : 12)
            });

        await auditService.RecordLoginAsync(result.Account.Id, username, "admin_login", "login_success",
            GetClientIp(), HttpContext.Request.Headers.UserAgent);

        return Ok(new AdminSessionResponse(
            result.Account.Id.ToString(),
            username,
            true,
            AdminUsernamesConfigured: adminWebOptions.Value.AdminUsernames.Length > 0));
    }

    [HttpGet("session/me")]
    [Authorize(Policy = "AdminSession")]
    public IActionResult GetCurrentSession([FromServices] IOptions<AdminWebOptions> adminWebOptions)
    {
        var accountId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        var username = User.Identity?.Name ?? string.Empty;
        return Ok(new AdminSessionResponse(
            accountId,
            username,
            true,
            adminWebOptions.Value.AdminUsernames.Length > 0));
    }

    [HttpPost("session/logout")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> Logout([FromServices] IAuditService auditService)
    {
        var (actorId, actorName) = GetAdminIdentity();
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await auditService.RecordActionAsync("admin_logout", "Session", actorId?.ToString() ?? "unknown",
            actorId, actorName, "Admin logged out", GetClientIp());
        return Ok(new AdminOperationResponse(true, "Logged out successfully."));
    }

    [HttpGet("users")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> GetUsers(
        [FromQuery] string? username,
        [FromQuery] string? phone,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        [FromServices] IdentityDbContext dbContext)
    {
        var normalizedPage = page.GetValueOrDefault(1) < 1 ? 1 : page.GetValueOrDefault(1);
        var normalizedPageSize = pageSize.GetValueOrDefault(20);
        if (normalizedPageSize < 1)
        {
            normalizedPageSize = 20;
        }

        normalizedPageSize = Math.Min(normalizedPageSize, 100);

        var searchTerm = username?.Trim();

        var query = dbContext.Accounts
            .AsNoTracking()
            .Where(account =>
                (string.IsNullOrWhiteSpace(searchTerm) ||
                 dbContext.PasswordCredentials.Any(credential =>
                     credential.AccountId == account.Id &&
                     EF.Functions.Like(credential.Username, $"%{searchTerm}%")) ||
                 EF.Functions.Like(account.Remark, $"%{searchTerm}%")) &&
                (string.IsNullOrWhiteSpace(phone) ||
                 dbContext.UserLogins.Any(login =>
                     login.AccountId == account.Id &&
                     login.ProviderName == IdentityConstants.AuthMethodSms &&
                     EF.Functions.Like(login.ProviderUserId, $"%{phone}%"))));

        var total = await query.CountAsync();

        var allFiltered = await query.ToListAsync();
        var users = allFiltered
            .OrderByDescending(account => account.CreatedAt)
            .Skip((normalizedPage - 1) * normalizedPageSize)
            .Take(normalizedPageSize)
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

        var items = users.Select(user =>
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

        return Ok(new AdminPagedResponse<AdminUserListItemResponse>(items, total, normalizedPage, normalizedPageSize));
    }

    [HttpPost("users")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> CreateUser(
        [FromBody] AdminCreateUserRequest request,
        [FromServices] IPasswordPolicy passwordPolicy,
        [FromServices] IPasswordHasher passwordHasher,
        [FromServices] IAccountRepository accountRepository,
        [FromServices] IPasswordCredentialRepository passwordCredentialRepository,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IAuditService auditService)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new AdminApiErrorResponse("Username and password cannot be empty."));
        }

        if (!passwordPolicy.Validate(request.Password, out var policyError))
        {
            return BadRequest(new AdminApiErrorResponse(policyError));
        }

        if (await passwordCredentialRepository.ExistsByUsernameAsync(request.Username))
        {
            return BadRequest(new AdminApiErrorResponse("Username already exists."));
        }

        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            Remark = request.Remark?.Trim(),
            Nickname = request.Nickname?.Trim()
        };
        await accountRepository.AddAsync(account);

        var credential = new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            Username = request.Username.Trim(),
            PasswordHash = passwordHasher.HashPassword(request.Password),
            CreatedAt = DateTimeOffset.UtcNow
        };
        await passwordCredentialRepository.AddAsync(credential);
        await unitOfWork.SaveChangesAsync();

        _logger.LogInformation(
            "User created from Admin API: UserId={UserId}, Username={Username}",
            account.Id,
            credential.Username);

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync("account_created", "Account", account.Id.ToString(),
            actorId, actorName, $"Admin created user: {credential.Username}", GetClientIp(),
            after: new { account.Id, account.IsActive, account.Remark, Username = credential.Username });

        return Ok(new AdminCreateUserResponse(
            account.Id.ToString(),
            credential.Username,
            request.DisplayName?.Trim() ?? credential.Username,
            account.IsActive,
            account.Remark ?? string.Empty,
            account.Nickname,
            account.CreatedAt.ToUnixTimeSeconds()));
    }

    [HttpPost("users/phone")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> CreatePhoneUser(
        [FromBody] AdminCreatePhoneUserRequest request,
        [FromServices] IAccountRepository accountRepository,
        [FromServices] IUserLoginRepository userLoginRepository,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IAuditService auditService)
    {
        if (string.IsNullOrWhiteSpace(request.Phone))
            return BadRequest(new AdminApiErrorResponse("Phone number is required."));

        var phone = request.Phone.Trim();
        var existingLogin = await userLoginRepository.GetBySmsPhoneAsync(phone);
        if (existingLogin != null)
            return BadRequest(new AdminApiErrorResponse("Phone number already registered."));

        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            Remark = request.Remark?.Trim(),
            Nickname = request.Nickname?.Trim()
        };
        await accountRepository.AddAsync(account);

        var userLogin = new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            ProviderName = IdentityConstants.AuthMethodSms,
            ProviderUserId = phone
        };
        await userLoginRepository.AddAsync(userLogin);
        await unitOfWork.SaveChangesAsync();

        _logger.LogInformation(
            "Phone user created from Admin API: AccountId={AccountId}, Phone={Phone}",
            account.Id,
            phone);

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync("account_created", "Account", account.Id.ToString(),
            actorId, actorName, $"Admin created phone user: {phone}", GetClientIp(),
            after: new { account.Id, account.IsActive, Phone = phone });

        return Ok(new AdminCreateUserResponse(
            account.Id.ToString(),
            phone,
            request.DisplayName?.Trim() ?? phone,
            account.IsActive,
            account.Remark ?? string.Empty,
            account.Nickname,
            account.CreatedAt.ToUnixTimeSeconds()));
    }

    [HttpPatch("users/{userId:guid}/remark")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> UpdateUserRemark(
        Guid userId,
        [FromBody] AdminUpdateRemarkRequest request,
        [FromServices] IAccountRepository accountRepository,
        [FromServices] IUnitOfWork unitOfWork)
    {
        var account = await accountRepository.GetByIdAsync(userId);
        if (account == null)
        {
            return NotFound(new AdminApiErrorResponse("User not found."));
        }

        account.Remark = request.Remark?.Trim();
        await accountRepository.UpdateAsync(account);
        await unitOfWork.SaveChangesAsync();

        return Ok(new AdminOperationResponse(true, "Remark updated."));
    }

    [HttpPatch("users/{userId:guid}/nickname")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> UpdateUserNickname(
        Guid userId,
        [FromBody] AdminUpdateNicknameRequest request,
        [FromServices] IAccountRepository accountRepository,
        [FromServices] IUnitOfWork unitOfWork)
    {
        var account = await accountRepository.GetByIdAsync(userId);
        if (account == null)
        {
            return NotFound(new AdminApiErrorResponse("User not found."));
        }

        account.Nickname = string.IsNullOrWhiteSpace(request.Nickname) ? null : request.Nickname.Trim();
        await accountRepository.UpdateAsync(account);
        await unitOfWork.SaveChangesAsync();

        return Ok(new AdminOperationResponse(true, "Nickname updated."));
    }

    [HttpPatch("users/{userId:guid}/status")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> UpdateUserStatus(
        Guid userId,
        [FromBody] AdminUpdateStatusRequest request,
        [FromServices] IAccountRepository accountRepository,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IAuditService auditService)
    {
        var account = await accountRepository.GetByIdAsync(userId);
        if (account == null)
        {
            return NotFound(new AdminApiErrorResponse("User not found."));
        }

        var beforeStatus = account.IsActive;
        account.IsActive = request.IsActive;
        await accountRepository.UpdateAsync(account);
        await unitOfWork.SaveChangesAsync();

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            request.IsActive ? "account_enabled" : "account_disabled",
            "Account", account.Id.ToString(),
            actorId, actorName,
            request.IsActive ? $"Admin enabled user: {userId}" : $"Admin disabled user: {userId}",
            GetClientIp(),
            before: new { IsActive = beforeStatus },
            after: new { IsActive = request.IsActive });

        return Ok(new AdminOperationResponse(true, request.IsActive ? "User enabled." : "User disabled."));
    }

    [HttpGet("apps")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> GetApps([FromServices] IdentityDbContext dbContext)
    {
        var allApps = await dbContext.AppRegistrations
            .AsNoTracking()
            .ToListAsync();

        var apps = allApps
            .OrderByDescending(app => app.CreatedAt)
            .Select(app => new
            {
                app.AppId,
                app.AppName,
                app.CallbackUrl,
                app.CallbackExpiresAt,
                app.IsActive,
                app.CreatedAt
            })
            .ToList();

        var items = apps.Select(app => new AdminAppListItemResponse(
            app.AppId,
            app.AppName,
            app.CallbackUrl ?? string.Empty,
            app.CallbackExpiresAt.HasValue ? app.CallbackExpiresAt.Value.ToUnixTimeSeconds() : null,
            app.IsActive,
            app.CreatedAt.ToUnixTimeSeconds()))
            .ToList();

        return Ok((IReadOnlyList<AdminAppListItemResponse>)items);
    }

    [HttpPost("apps")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> CreateApp(
        [FromBody] AdminCreateAppRequest request,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] IUnitOfWork unitOfWork)
    {
        if (string.IsNullOrWhiteSpace(request.AppName))
        {
            return BadRequest(new AdminApiErrorResponse("App name cannot be empty."));
        }

        var newAppId = Guid.NewGuid().ToString("N");
        var newAppSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = newAppId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(newAppSecret),
            AppName = request.AppName.Trim(),
            CallbackUrl = string.IsNullOrWhiteSpace(request.CallbackUrl) ? null : request.CallbackUrl.Trim(),
            CallbackExpiresAt = string.IsNullOrWhiteSpace(request.CallbackUrl)
                ? null
                : (request.TtlSeconds == IdentityConstants.CallbackTtlNeverExpire
                    ? null
                    : DateTimeOffset.UtcNow.AddSeconds(request.TtlSeconds > 0 ? request.TtlSeconds : IdentityConstants.DefaultCallbackTtlSeconds)),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        await appRegistrationRepository.AddAsync(app);
        await unitOfWork.SaveChangesAsync();

        return Ok(new AdminCreateAppResponse(
            app.AppId,
            newAppSecret,
            app.AppName,
            app.CallbackUrl ?? string.Empty,
            app.CallbackExpiresAt.HasValue ? app.CallbackExpiresAt.Value.ToUnixTimeSeconds() : null));
    }

    [HttpPut("apps/{appId}/callback")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> UpdateCallback(
        string appId,
        [FromBody] AdminUpdateCallbackRequest request,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] IUnitOfWork unitOfWork)
    {
        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null)
        {
            return NotFound(new AdminApiErrorResponse("App not found."));
        }

        if (string.IsNullOrWhiteSpace(request.CallbackUrl))
        {
            app.CallbackUrl = null;
            app.CallbackExpiresAt = null;
        }
        else
        {
            app.CallbackUrl = request.CallbackUrl.Trim();
            app.CallbackExpiresAt = request.TtlSeconds == IdentityConstants.CallbackTtlNeverExpire
                ? null
                : DateTimeOffset.UtcNow.AddSeconds(request.TtlSeconds > 0 ? request.TtlSeconds : IdentityConstants.DefaultCallbackTtlSeconds);
        }

        app.IsActive = request.IsActive;
        await unitOfWork.SaveChangesAsync();

        return Ok(new AdminOperationResponse(true, "Callback configuration updated."));
    }

    [HttpDelete("apps/{appId}")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> DeleteApp(
        string appId,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IAuditService auditService)
    {
        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null)
        {
            return NotFound(new AdminApiErrorResponse("App not found."));
        }

        await appRegistrationRepository.DeleteAsync(app);
        await unitOfWork.SaveChangesAsync();

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync("app_deleted", "AppRegistration", appId,
            actorId, actorName, $"Admin deleted app: {app.AppName}", GetClientIp());

        return Ok(new AdminOperationResponse(true, "App deleted."));
    }

    [HttpPost("apps/{appId}/reset-secret")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> ResetAppSecret(
        string appId,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IAuditService auditService)
    {
        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null)
        {
            return NotFound(new AdminApiErrorResponse("App not found."));
        }

        var newAppSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        app.AppSecretHash = BCrypt.Net.BCrypt.HashPassword(newAppSecret);
        await unitOfWork.SaveChangesAsync();

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync("app_secret_reset", "AppRegistration", appId,
            actorId, actorName, $"Admin reset app secret: {app.AppName}", GetClientIp());

        return Ok(new AdminCreateAppResponse(
            app.AppId,
            newAppSecret,
            app.AppName,
            app.CallbackUrl ?? string.Empty,
            app.CallbackExpiresAt.HasValue ? app.CallbackExpiresAt.Value.ToUnixTimeSeconds() : null));
    }

    [HttpPost("tokens/revoke")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> RevokeRefreshToken(
        [FromBody] AdminRevokeRefreshTokenRequest request,
        [FromServices] IRefreshTokenRepository refreshTokenRepository,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IAuditService auditService)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return BadRequest(new AdminApiErrorResponse("Refresh token cannot be empty."));
        }

        var refreshToken = await refreshTokenRepository.GetByTokenValueAsync(request.RefreshToken.Trim());
        if (refreshToken == null)
        {
            return BadRequest(new AdminApiErrorResponse("Refresh token not found."));
        }

        refreshToken.IsRevoked = true;
        await unitOfWork.SaveChangesAsync();

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync("refresh_token_revoked", "RefreshToken", refreshToken.AccountId.ToString(),
            actorId, actorName, "Admin revoked refresh token", GetClientIp());

        return Ok(new AdminOperationResponse(true, "Refresh token revoked."));
    }

    [HttpGet("users/{userId:guid}/login-history")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> GetUserLoginHistory(
        Guid userId,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        [FromServices] ILoginHistoryRepository loginHistoryRepository)
    {
        var normalizedPage = page.GetValueOrDefault(1) < 1 ? 1 : page.GetValueOrDefault(1);
        var normalizedPageSize = Math.Min(Math.Max(pageSize.GetValueOrDefault(20), 1), 100);
        var skip = (normalizedPage - 1) * normalizedPageSize;

        var histories = await loginHistoryRepository.GetByAccountIdAsync(userId, normalizedPageSize, skip);

        var items = histories.Select(h => new AdminLoginHistoryItemResponse(
            h.AuthMethod,
            h.EventType,
            h.ClientIp ?? string.Empty,
            h.UserAgent ?? string.Empty,
            h.FailureReason,
            h.AppId,
            h.CreatedAt.ToUnixTimeSeconds())).ToList();

        return Ok(new AdminPagedResponse<AdminLoginHistoryItemResponse>(items, items.Count, normalizedPage, normalizedPageSize));
    }

    [HttpGet("audit-logs")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> GetAuditLogs(
        [FromQuery] string? action,
        [FromQuery] string? targetType,
        [FromQuery] string? targetId,
        [FromQuery] Guid? actorId,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        [FromServices] IAuditLogRepository auditLogRepository)
    {
        var normalizedPage = page.GetValueOrDefault(1) < 1 ? 1 : page.GetValueOrDefault(1);
        var normalizedPageSize = Math.Min(Math.Max(pageSize.GetValueOrDefault(20), 1), 100);
        var skip = (normalizedPage - 1) * normalizedPageSize;

        var logs = await auditLogRepository.QueryAsync(action, targetType, targetId, actorId, normalizedPageSize, skip);

        var items = logs.Select(l => new AdminAuditLogItemResponse(
            l.Action,
            l.TargetType,
            l.TargetId,
            l.ActorId?.ToString(),
            l.ActorName,
            l.Description,
            l.ClientIp,
            l.CorrelationId,
            l.CreatedAt.ToUnixTimeSeconds())).ToList();

        return Ok(new AdminPagedResponse<AdminAuditLogItemResponse>(items, items.Count, normalizedPage, normalizedPageSize));
    }

    private (Guid? ActorId, string? ActorName) GetAdminIdentity()
    {
        var idClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var nameClaim = User.Identity?.Name;
        var actorId = Guid.TryParse(idClaim, out var id) ? id : (Guid?)null;
        return (actorId, nameClaim);
    }

    private string? GetClientIp()
    {
        var forwarded = HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwarded))
            return forwarded.Split(',')[0].Trim();
        return HttpContext.Connection.RemoteIpAddress?.ToString();
    }

    private static bool IsAdminUsernameAllowed(string username, AdminWebOptions options)
    {
        if (options.AdminUsernames.Length == 0)
        {
            return true;
        }

        return options.AdminUsernames.Any(item =>
            string.Equals(item?.Trim(), username, StringComparison.OrdinalIgnoreCase));
    }
}
