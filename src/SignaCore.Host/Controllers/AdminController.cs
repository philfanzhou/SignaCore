using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Ldap;
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Services.WeChat;
using SignaCore.Domain.Validators;
using SignaCore.Host.Http;
using SignaCore.Host.Models;

namespace SignaCore.Host.Controllers;

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
        [FromServices] AdminIdentityOptions adminIdentity,
        [FromServices] IAuditService auditService)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new ErrorResponse("Username and password cannot be empty."));
        }

        var validator = validatorFactory.GetValidator(IdentityConstants.GrantTypePassword);
        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypePassword,
            Username = request.Username.Trim(),
            Password = request.Password
        });

        // result.Account == null 这个额外判断已由 ValidationResult 上的 MemberNotNullWhen 承担：
        // Success(account, ...) 的 account 是非空参数，成功分支不可能没有账号。
        if (!result.IsSuccess)
        {
            await auditService.RecordLoginAsync(null, request.Username.Trim(), "admin_login", "login_failure",
                GetClientIp(), HttpContext.Request.Headers.UserAgent, result.ErrorMessage);
            return StatusCode(StatusCodes.Status401Unauthorized, new { message = result.ErrorMessage });
        }

        var username = result.DisplayName ?? request.Username.Trim();
        var configuredAdmin = adminIdentity.Username.Trim();
        if (string.IsNullOrWhiteSpace(configuredAdmin)
            || !string.Equals(username, configuredAdmin, StringComparison.OrdinalIgnoreCase))
        {
            await auditService.RecordLoginAsync(result.Account.Id, username, "admin_login", "login_failure",
                GetClientIp(), HttpContext.Request.Headers.UserAgent, "bootstrap_admin_required");
            return StatusCode(StatusCodes.Status403Forbidden, new { message = "Only the bootstrap administrator can sign in to admin web." });
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
            true));
    }

    [HttpGet("session/me")]
    [Authorize(Policy = "AdminSession")]
    public IActionResult GetCurrentSession()
    {
        var accountId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        var username = User.Identity?.Name ?? string.Empty;
        return Ok(new AdminSessionResponse(
            accountId,
            username,
            true));
    }

    [HttpPost("session/logout")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> Logout([FromServices] IAuditService auditService)
    {
        var (actorId, actorName) = GetAdminIdentity();
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await auditService.RecordActionAsync("admin_logout", "Session", actorId?.ToString() ?? "unknown",
            actorId, actorName, "Admin logged out", GetClientIp());
        return Ok(new OperationResponse(true, "Logged out successfully."));
    }

    [HttpGet("users")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> GetUsers(
        [FromQuery] string? username,
        [FromQuery] string? phone,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        [FromServices] IUserQueryService userQueryService)
    {
        var paging = PageRequest.Normalize(page, pageSize);

        var (users, total) = await userQueryService.SearchUsersAsync(username, phone, paging.Page, paging.PageSize);

        return Ok(new PagedResponse<UserListItemResponse>(users, total, paging.Page, paging.PageSize));
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
            return BadRequest(new ErrorResponse("Username and password cannot be empty."));
        }

        if (!passwordPolicy.Validate(request.Password, out var policyError))
        {
            return BadRequest(new ErrorResponse(policyError));
        }

        if (await passwordCredentialRepository.ExistsByUsernameAsync(request.Username))
        {
            return BadRequest(new ErrorResponse("Username already exists."));
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
            return BadRequest(new ErrorResponse("Phone number is required."));

        if (!MainlandChinaPhoneNumber.TryNormalize(request.Phone, out var phone))
            return BadRequest(new ErrorResponse("A valid mainland China mobile number is required."));
        var existingLogin = await userLoginRepository.GetBySmsPhoneAsync(phone);
        if (existingLogin != null)
            return BadRequest(new ErrorResponse("Phone number already registered."));

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
            SensitiveDataMasker.MaskPhone(phone));

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync("account_created", "Account", account.Id.ToString(),
            actorId, actorName, "Admin created phone user", GetClientIp(),
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
            return NotFound(new ErrorResponse("User not found."));
        }

        account.Remark = request.Remark?.Trim();
        await accountRepository.UpdateAsync(account);
        await unitOfWork.SaveChangesAsync();

        return Ok(new OperationResponse(true, "Remark updated."));
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
            return NotFound(new ErrorResponse("User not found."));
        }

        account.Nickname = string.IsNullOrWhiteSpace(request.Nickname) ? null : request.Nickname.Trim();
        await accountRepository.UpdateAsync(account);
        await unitOfWork.SaveChangesAsync();

        return Ok(new OperationResponse(true, "Nickname updated."));
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
            return NotFound(new ErrorResponse("User not found."));
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

        return Ok(new OperationResponse(true, request.IsActive ? "User enabled." : "User disabled."));
    }

    [HttpGet("apps")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> GetApps(
        [FromServices] IdentityDbContext dbContext,
        [FromServices] JwtOptions jwtOptions)
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
                app.CreatedAt,
                app.LdapLoginMode,
                app.SmsLoginMode,
                app.SmsProfileKey,
                app.WechatLoginMode,
                app.AudienceMode,
                // 直接把生效的 aud 值算出来给管理台，省得前端复制一份解析规则。
                Audience = JwtTokenService.ResolveAudience(app, jwtOptions)
            })
            .ToList();

        var items = apps.Select(app => new AdminAppListItemResponse(
            app.AppId,
            app.AppName,
            app.CallbackUrl ?? string.Empty,
            app.CallbackExpiresAt.HasValue ? app.CallbackExpiresAt.Value.ToUnixTimeSeconds() : null,
            app.IsActive,
            app.CreatedAt.ToUnixTimeSeconds(),
            app.LdapLoginMode.ToString(),
            app.SmsLoginMode.ToString(),
            app.SmsProfileKey,
            app.WechatLoginMode.ToString(),
            app.AudienceMode.ToString(),
            app.Audience))
            .ToList();

        return Ok((IReadOnlyList<AdminAppListItemResponse>)items);
    }

    [HttpPost("apps")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> CreateApp(
        [FromBody] AdminCreateAppRequest request,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] CallbackUrlValidator callbackUrlValidator,
        [FromServices] IUnitOfWork unitOfWork,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.AppName))
        {
            return BadRequest(new ErrorResponse("App name cannot be empty."));
        }

        var callbackUrl = string.IsNullOrWhiteSpace(request.CallbackUrl)
            ? null
            : request.CallbackUrl.Trim();
        if (callbackUrl != null)
        {
            var validation = await callbackUrlValidator.ValidateAsync(
                callbackUrl,
                cancellationToken);
            if (!validation.IsValid)
            {
                return BadRequest(new ErrorResponse(
                    $"Invalid callback URL: {validation.ErrorMessage}"));
            }
        }

        var newAppId = Guid.NewGuid().ToString("N");
        var newAppSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = newAppId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(newAppSecret),
            AppName = request.AppName.Trim(),
            CallbackUrl = callbackUrl,
            CallbackExpiresAt = callbackUrl == null
                ? null
                : (request.TtlSeconds == IdentityConstants.CallbackTtlNeverExpire
                    ? null
                    : DateTimeOffset.UtcNow.AddSeconds(request.TtlSeconds > 0 ? request.TtlSeconds : IdentityConstants.DefaultCallbackTtlSeconds)),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        await appRegistrationRepository.AddAsync(app);
        await unitOfWork.SaveChangesAsync(cancellationToken);

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
        [FromServices] CallbackUrlValidator callbackUrlValidator,
        [FromServices] IUnitOfWork unitOfWork,
        CancellationToken cancellationToken = default)
    {
        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null)
        {
            return NotFound(new ErrorResponse("App not found."));
        }

        if (string.IsNullOrWhiteSpace(request.CallbackUrl))
        {
            app.CallbackUrl = null;
            app.CallbackExpiresAt = null;
        }
        else
        {
            var callbackUrl = request.CallbackUrl.Trim();
            var validation = await callbackUrlValidator.ValidateAsync(
                callbackUrl,
                cancellationToken);
            if (!validation.IsValid)
            {
                return BadRequest(new ErrorResponse(
                    $"Invalid callback URL: {validation.ErrorMessage}"));
            }

            app.CallbackUrl = callbackUrl;
            app.CallbackExpiresAt = request.TtlSeconds == IdentityConstants.CallbackTtlNeverExpire
                ? null
                : DateTimeOffset.UtcNow.AddSeconds(request.TtlSeconds > 0 ? request.TtlSeconds : IdentityConstants.DefaultCallbackTtlSeconds);
        }

        app.IsActive = request.IsActive;
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return Ok(new OperationResponse(true, "Callback configuration updated."));
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
            return NotFound(new ErrorResponse("App not found."));
        }

        await appRegistrationRepository.DeleteAsync(app);
        await unitOfWork.SaveChangesAsync();

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync("app_deleted", "AppRegistration", appId,
            actorId, actorName, $"Admin deleted app: {app.AppName}", GetClientIp());

        return Ok(new OperationResponse(true, "App deleted."));
    }

    [HttpGet("sms/profiles")]
    [Authorize(Policy = "AdminSession")]
    public IActionResult GetSmsProfiles([FromServices] SmsOptions options) =>
        Ok(options.Profiles.OrderBy(item => item.Key).Select(item => new
        {
            Key = item.Key,
            item.Value.Provider
        }));

    [HttpPut("apps/{appId}/sms-policy")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> UpdateSmsPolicy(
        string appId,
        [FromBody] AdminUpdateSmsPolicyRequest request,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] SmsOptions options,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IAuditService auditService)
    {
        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null) return NotFound(new ErrorResponse("App not found."));
        if (!Enum.TryParse<SmsLoginMode>(request.Mode, true, out var mode) || !Enum.IsDefined(mode))
            return BadRequest(new ErrorResponse("Invalid SMS login mode."));

        // A provider profile is only needed to *send* codes. A deployment may enable SMS login without
        // one and admit the phones on the bypass allow-list, so only an unknown key is rejected here;
        // POST /api/auth/sms-code reports the missing provider when a code is actually requested.
        var profileKey = string.IsNullOrWhiteSpace(request.ProfileKey) ? null : request.ProfileKey.Trim();
        if (profileKey != null && !options.Profiles.ContainsKey(profileKey))
            return BadRequest(new ErrorResponse("Unknown SMS provider profile."));

        var before = new { Mode = app.SmsLoginMode.ToString(), app.SmsProfileKey };
        app.SmsLoginMode = mode;
        app.SmsProfileKey = profileKey;
        await unitOfWork.SaveChangesAsync();

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_sms_policy_updated", "AppRegistration", appId, actorId, actorName,
            $"SMS login mode changed to {mode}", GetClientIp(), before: before,
            after: new { Mode = mode.ToString(), SmsProfileKey = profileKey });
        return Ok(new OperationResponse(true, "SMS login policy updated."));
    }

    [HttpGet("apps/{appId}/sms-users")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> GetSmsUsers(string appId, [FromServices] IdentityDbContext dbContext)
    {
        var app = await dbContext.AppRegistrations.AsNoTracking().FirstOrDefaultAsync(
            item => item.AppIdNormalized == IdentityValueNormalizer.Normalize(appId));
        if (app == null) return NotFound(new ErrorResponse("App not found."));

        var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodSms);
        var users = await dbContext.AppSmsAccesses.AsNoTracking()
            .Where(access => access.AppRegistrationId == app.Id)
            .Join(dbContext.UserLogins.AsNoTracking().Where(login => login.ProviderNameNormalized == provider),
                access => access.UserLoginId, login => login.Id, (access, login) => new { access, login })
            .OrderByDescending(item => item.access.CreatedAt)
            .Select(item => new AdminSmsUserResponse(
                item.login.Id.ToString(), item.login.AccountId.ToString(), item.login.ProviderUserId,
                item.access.ApprovalSource.ToString(), item.access.IsActive,
                item.access.CreatedAt.ToUnixTimeSeconds()))
            .ToListAsync();
        return Ok((IReadOnlyList<AdminSmsUserResponse>)users);
    }

    [HttpPost("apps/{appId}/sms-users")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> AddSmsUser(
        string appId,
        [FromBody] AdminAddSmsUserRequest request,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] ISmsAdmissionService admissionService,
        [FromServices] IAuditService auditService,
        CancellationToken cancellationToken)
    {
        if (!MainlandChinaPhoneNumber.TryNormalize(request.Phone, out var phone))
            return BadRequest(new ErrorResponse("A valid mainland China mobile number is required."));
        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null) return NotFound(new ErrorResponse("App not found."));

        var (actorId, actorName) = GetAdminIdentity();
        var admission = await admissionService.ProvisionAsync(
            app, phone, SmsAccessApprovalSource.Admin, actorId, cancellationToken);
        await auditService.RecordActionAsync(
            "app_sms_user_approved", "AppRegistration", appId, actorId, actorName,
            "Administrator approved an SMS identity for the application", GetClientIp(),
            after: new { admission.Account.Id, LoginId = admission.Login.Id });
        return Ok(new AdminSmsUserResponse(
            admission.Login.Id.ToString(), admission.Account.Id.ToString(), admission.Login.ProviderUserId,
            admission.Access.ApprovalSource.ToString(), admission.Access.IsActive,
            admission.Access.CreatedAt.ToUnixTimeSeconds()));
    }

    [HttpDelete("apps/{appId}/sms-users/{loginId:guid}")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> RevokeSmsUser(
        string appId,
        Guid loginId,
        [FromServices] IdentityDbContext dbContext,
        [FromServices] IAuditService auditService,
        CancellationToken cancellationToken)
    {
        var app = await dbContext.AppRegistrations.FirstOrDefaultAsync(
            item => item.AppIdNormalized == IdentityValueNormalizer.Normalize(appId), cancellationToken);
        if (app == null) return NotFound(new ErrorResponse("App not found."));
        var access = await dbContext.AppSmsAccesses.FirstOrDefaultAsync(
            item => item.AppRegistrationId == app.Id && item.UserLoginId == loginId, cancellationToken);
        if (access == null) return NotFound(new ErrorResponse("SMS application access not found."));

        access.IsActive = false;
        await dbContext.RefreshTokens
            .Where(token => token.AppId == app.AppId && token.SmsUserLoginId == loginId && !token.IsRevoked)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.IsRevoked, true), cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_sms_user_revoked", "AppRegistration", appId, actorId, actorName,
            "Administrator revoked an SMS identity for the application", GetClientIp(),
            after: new { LoginId = loginId, IsActive = false });
        return Ok(new OperationResponse(true, "SMS application access revoked."));
    }

    [HttpPut("apps/{appId}/wechat-policy")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> UpdateWechatPolicy(
        string appId,
        [FromBody] AdminUpdateWechatPolicyRequest request,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] WechatOptions wechatOptions,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IAuditService auditService)
    {
        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null) return NotFound(new ErrorResponse("App not found."));
        if (!Enum.TryParse<WechatLoginMode>(request.Mode, true, out var mode) || !Enum.IsDefined(mode))
            return BadRequest(new ErrorResponse("Invalid WeChat login mode."));
        if (mode != WechatLoginMode.Disabled && !wechatOptions.IsConfigured)
            return BadRequest(new ErrorResponse("WeChat credentials are not configured for this deployment."));

        var before = new { Mode = app.WechatLoginMode.ToString() };
        app.WechatLoginMode = mode;
        await unitOfWork.SaveChangesAsync();

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_wechat_policy_updated", "AppRegistration", appId, actorId, actorName,
            $"WeChat login mode changed to {mode}", GetClientIp(), before: before,
            after: new { Mode = mode.ToString() });
        return Ok(new OperationResponse(true, "WeChat login policy updated."));
    }

    /// <summary>
    /// PUT /api/admin/apps/{appId}/audience-mode — 切换该应用 access token 的 aud。
    /// 切到 PerApplication 前，下游必须已经能同时接受共享 audience 与本应用 AppId，
    /// 否则正在使用的 token 会在下游校验失败。见 docs/overview/StandardsConformance.md。
    /// </summary>
    [HttpPut("apps/{appId}/audience-mode")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> UpdateAudienceMode(
        string appId,
        [FromBody] AdminUpdateAudienceModeRequest request,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] JwtOptions jwtOptions,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IAuditService auditService)
    {
        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null) return NotFound(new ErrorResponse("App not found."));
        if (!Enum.TryParse<AudienceMode>(request.Mode, true, out var mode) || !Enum.IsDefined(mode))
            return BadRequest(new ErrorResponse("Invalid audience mode."));

        var before = new { Mode = app.AudienceMode.ToString(), Audience = JwtTokenService.ResolveAudience(app, jwtOptions) };
        app.AudienceMode = mode;
        await unitOfWork.SaveChangesAsync();
        var audience = JwtTokenService.ResolveAudience(app, jwtOptions);

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_audience_mode_updated", "AppRegistration", appId, actorId, actorName,
            $"Access-token audience mode changed to {mode}", GetClientIp(), before: before,
            after: new { Mode = mode.ToString(), Audience = audience });
        return Ok(new OperationResponse(true, $"Access tokens for this application now carry aud={audience}."));
    }

    [HttpGet("apps/{appId}/wechat-users")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> GetWechatUsers(string appId, [FromServices] IdentityDbContext dbContext)
    {
        var app = await dbContext.AppRegistrations.AsNoTracking().FirstOrDefaultAsync(
            item => item.AppIdNormalized == IdentityValueNormalizer.Normalize(appId));
        if (app == null) return NotFound(new ErrorResponse("App not found."));

        var provider = IdentityValueNormalizer.Normalize(IdentityConstants.AuthMethodWechat);
        var rows = await dbContext.AppWechatAccesses.AsNoTracking()
            .Where(access => access.AppRegistrationId == app.Id)
            .Join(dbContext.UserLogins.AsNoTracking().Where(login => login.ProviderNameNormalized == provider),
                access => access.UserLoginId, login => login.Id, (access, login) => new { access, login })
            .OrderByDescending(item => item.access.CreatedAt)
            .ToListAsync();

        // 掩码在内存里做：SensitiveDataMasker 不能翻译成 SQL。
        var users = rows.Select(item => new AdminWechatUserResponse(
            item.login.Id.ToString(), item.login.AccountId.ToString(),
            SensitiveDataMasker.MaskOpenId(item.login.ProviderUserId),
            item.access.ApprovalSource.ToString(), item.access.IsActive,
            item.access.CreatedAt.ToUnixTimeSeconds())).ToList();
        return Ok((IReadOnlyList<AdminWechatUserResponse>)users);
    }

    /// <summary>
    /// POST /api/admin/apps/{appId}/wechat-users/{loginId}/restore — 恢复被撤销的微信准入。
    /// 用户自助重新绑定**不会**清除撤销状态（见 WechatAdmissionService.EnsureAccessAsync），
    /// 所以恢复只能从这里走。
    /// </summary>
    [HttpPost("apps/{appId}/wechat-users/{loginId:guid}/restore")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> RestoreWechatUser(
        string appId,
        Guid loginId,
        [FromServices] IdentityDbContext dbContext,
        [FromServices] IAuditService auditService,
        CancellationToken cancellationToken)
    {
        var app = await dbContext.AppRegistrations.FirstOrDefaultAsync(
            item => item.AppIdNormalized == IdentityValueNormalizer.Normalize(appId), cancellationToken);
        if (app == null) return NotFound(new ErrorResponse("App not found."));
        var access = await dbContext.AppWechatAccesses.FirstOrDefaultAsync(
            item => item.AppRegistrationId == app.Id && item.UserLoginId == loginId, cancellationToken);
        if (access == null) return NotFound(new ErrorResponse("WeChat application access not found."));

        access.IsActive = true;
        await dbContext.SaveChangesAsync(cancellationToken);
        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_wechat_user_restored", "AppRegistration", appId, actorId, actorName,
            "Administrator restored a WeChat identity for the application", GetClientIp(),
            after: new { LoginId = loginId, IsActive = true });
        return Ok(new OperationResponse(true, "WeChat application access restored."));
    }

    [HttpDelete("apps/{appId}/wechat-users/{loginId:guid}")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> RevokeWechatUser(
        string appId,
        Guid loginId,
        [FromServices] IdentityDbContext dbContext,
        [FromServices] IAuditService auditService,
        CancellationToken cancellationToken)
    {
        var app = await dbContext.AppRegistrations.FirstOrDefaultAsync(
            item => item.AppIdNormalized == IdentityValueNormalizer.Normalize(appId), cancellationToken);
        if (app == null) return NotFound(new ErrorResponse("App not found."));
        var access = await dbContext.AppWechatAccesses.FirstOrDefaultAsync(
            item => item.AppRegistrationId == app.Id && item.UserLoginId == loginId, cancellationToken);
        if (access == null) return NotFound(new ErrorResponse("WeChat application access not found."));

        access.IsActive = false;
        await dbContext.RefreshTokens
            .Where(token => token.AppId == app.AppId && token.WechatUserLoginId == loginId && !token.IsRevoked)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.IsRevoked, true), cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_wechat_user_revoked", "AppRegistration", appId, actorId, actorName,
            "Administrator revoked a WeChat identity for the application", GetClientIp(),
            after: new { LoginId = loginId, IsActive = false });
        return Ok(new OperationResponse(true, "WeChat application access revoked."));
    }

    [HttpPut("apps/{appId}/ldap-policy")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> UpdateLdapPolicy(
        string appId,
        [FromBody] AdminUpdateLdapPolicyRequest request,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IAuditService auditService)
    {
        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null)
        {
            return NotFound(new ErrorResponse("App not found."));
        }

        if (!Enum.TryParse<LdapLoginMode>(request.Mode, true, out var mode) ||
            !Enum.IsDefined(mode))
        {
            return BadRequest(new ErrorResponse("Invalid LDAP login mode."));
        }

        var before = app.LdapLoginMode;
        app.LdapLoginMode = mode;
        await unitOfWork.SaveChangesAsync();

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_ldap_policy_updated",
            "AppRegistration",
            appId,
            actorId,
            actorName,
            $"LDAP login mode changed from {before} to {mode}",
            GetClientIp(),
            before: new { Mode = before.ToString() },
            after: new { Mode = mode.ToString() });

        return Ok(new OperationResponse(true, "LDAP login policy updated."));
    }

    [HttpGet("apps/{appId}/ldap-users")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> GetLdapUsers(
        string appId,
        [FromServices] IdentityDbContext dbContext)
    {
        var app = await dbContext.AppRegistrations.AsNoTracking()
            .FirstOrDefaultAsync(item => item.AppIdNormalized == IdentityValueNormalizer.Normalize(appId));
        if (app == null)
        {
            return NotFound(new ErrorResponse("App not found."));
        }

        var users = await dbContext.AppLdapAccesses.AsNoTracking()
            .Where(access => access.AppRegistrationId == app.Id)
            .Join(dbContext.LdapCredentials.AsNoTracking(),
                access => access.LdapCredentialId,
                credential => credential.Id,
                (access, credential) => new { access, credential })
            .OrderByDescending(item => item.access.CreatedAt)
            .Select(item => new AdminLdapUserResponse(
                item.credential.Id.ToString(),
                item.credential.AccountId.ToString(),
                item.credential.UserPrincipalName,
                item.credential.SamAccountName,
                item.credential.DirectoryKey,
                item.access.ApprovalSource.ToString(),
                item.access.IsActive,
                item.access.CreatedAt.ToUnixTimeSeconds()))
            .ToListAsync();

        return Ok((IReadOnlyList<AdminLdapUserResponse>)users);
    }

    [HttpGet("ldap/directories")]
    [Authorize(Policy = "AdminSession")]
    public IActionResult GetLdapDirectories([FromServices] LdapOptions options)
    {
        return Ok(options.Directories.Select(directory => new
        {
            directory.Key,
            IsDefault = string.Equals(
                directory.Key,
                options.DefaultDirectoryKey,
                StringComparison.OrdinalIgnoreCase)
        }));
    }

    [HttpPost("apps/{appId}/ldap-users")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> AddLdapUser(
        string appId,
        [FromBody] AdminAddLdapUserRequest request,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] ILdapDirectoryClient directoryClient,
        [FromServices] ILdapAccountService ldapAccountService,
        [FromServices] IAuditService auditService,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.DirectoryKey) ||
            string.IsNullOrWhiteSpace(request.Username))
        {
            return BadRequest(new ErrorResponse("Directory key and username are required."));
        }

        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null)
        {
            return NotFound(new ErrorResponse("App not found."));
        }

        LdapDirectoryIdentity? identity;
        try
        {
            identity = await directoryClient.FindUserAsync(
                request.DirectoryKey.Trim(),
                request.Username.Trim(),
                cancellationToken);
        }
        catch (KeyNotFoundException)
        {
            return BadRequest(new ErrorResponse("LDAP directory is not configured."));
        }
        catch (LdapDirectoryUnavailableException exception)
        {
            _logger.LogError(exception, "LDAP directory unavailable while adding an application user");
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                new ErrorResponse("Directory service unavailable."));
        }

        if (identity == null)
        {
            return NotFound(new ErrorResponse("LDAP user not found."));
        }
        if (!identity.IsEnabled)
        {
            return BadRequest(new ErrorResponse("LDAP user is disabled."));
        }

        var (actorId, actorName) = GetAdminIdentity();
        var result = await ldapAccountService.ProvisionAsync(
            identity,
            app,
            LdapAccessApprovalSource.Admin,
            actorId,
            cancellationToken);

        await auditService.RecordActionAsync(
            "app_ldap_user_approved",
            "AppRegistration",
            appId,
            actorId,
            actorName,
            $"Administrator approved LDAP identity {identity.ObjectGuid} for the application",
            GetClientIp(),
            after: new
            {
                AccountId = result.Account.Id,
                CredentialId = result.Credential.Id,
                identity.DirectoryKey
            });

        return Ok(new AdminLdapUserResponse(
            result.Credential.Id.ToString(),
            result.Account.Id.ToString(),
            result.Credential.UserPrincipalName,
            result.Credential.SamAccountName,
            result.Credential.DirectoryKey,
            result.Access.ApprovalSource.ToString(),
            result.Access.IsActive,
            result.Access.CreatedAt.ToUnixTimeSeconds()));
    }

    [HttpDelete("apps/{appId}/ldap-users/{credentialId:guid}")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> RevokeLdapUser(
        string appId,
        Guid credentialId,
        [FromServices] IdentityDbContext dbContext,
        [FromServices] IAuditService auditService,
        CancellationToken cancellationToken)
    {
        var app = await dbContext.AppRegistrations.FirstOrDefaultAsync(
            item => item.AppIdNormalized == IdentityValueNormalizer.Normalize(appId),
            cancellationToken);
        if (app == null)
        {
            return NotFound(new ErrorResponse("App not found."));
        }

        var access = await dbContext.AppLdapAccesses.FirstOrDefaultAsync(item =>
            item.AppRegistrationId == app.Id && item.LdapCredentialId == credentialId,
            cancellationToken);
        if (access == null)
        {
            return NotFound(new ErrorResponse("LDAP application access not found."));
        }

        access.IsActive = false;
        await dbContext.RefreshTokens
            .Where(token => token.AppId == app.AppId && token.LdapCredentialId == credentialId && !token.IsRevoked)
            .ExecuteUpdateAsync(setters => setters.SetProperty(token => token.IsRevoked, true), cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_ldap_user_revoked",
            "AppRegistration",
            appId,
            actorId,
            actorName,
            $"Administrator revoked LDAP credential {credentialId} from the application",
            GetClientIp());

        return Ok(new OperationResponse(true, "LDAP application access revoked."));
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
            return NotFound(new ErrorResponse("App not found."));
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
            return BadRequest(new ErrorResponse("Refresh token cannot be empty."));
        }

        var refreshToken = await refreshTokenRepository.GetByTokenValueAsync(request.RefreshToken.Trim());
        if (refreshToken == null)
        {
            return BadRequest(new ErrorResponse("Refresh token not found."));
        }

        refreshToken.IsRevoked = true;
        await unitOfWork.SaveChangesAsync();

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync("refresh_token_revoked", "RefreshToken", refreshToken.AccountId.ToString(),
            actorId, actorName, "Admin revoked refresh token", GetClientIp());

        return Ok(new OperationResponse(true, "Refresh token revoked."));
    }

    [HttpGet("users/{userId:guid}/login-history")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> GetUserLoginHistory(
        Guid userId,
        [FromQuery] int? page,
        [FromQuery] int? pageSize,
        [FromServices] ILoginHistoryRepository loginHistoryRepository)
    {
        var paging = PageRequest.Normalize(page, pageSize);

        var total = await loginHistoryRepository.CountByAccountIdAsync(userId);
        var histories = await loginHistoryRepository.GetByAccountIdAsync(userId, paging.PageSize, paging.Skip);

        var items = histories.Select(h => new AdminLoginHistoryItemResponse(
            h.AuthMethod,
            h.EventType,
            h.ClientIp ?? string.Empty,
            h.UserAgent ?? string.Empty,
            h.FailureReason,
            h.AppId,
            h.CreatedAt.ToUnixTimeSeconds())).ToList();

        return Ok(new PagedResponse<AdminLoginHistoryItemResponse>(items, total, paging.Page, paging.PageSize));
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
        var paging = PageRequest.Normalize(page, pageSize);

        var total = await auditLogRepository.CountAsync(action, targetType, targetId, actorId);
        var logs = await auditLogRepository.QueryAsync(action, targetType, targetId, actorId, paging.PageSize, paging.Skip);

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

        return Ok(new PagedResponse<AdminAuditLogItemResponse>(items, total, paging.Page, paging.PageSize));
    }

    private (Guid? ActorId, string? ActorName) GetAdminIdentity()
    {
        var idClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var nameClaim = User.Identity?.Name;
        var actorId = Guid.TryParse(idClaim, out var id) ? id : (Guid?)null;
        return (actorId, nameClaim);
    }

    private string? GetClientIp() => HttpContext.GetClientIp();
}
