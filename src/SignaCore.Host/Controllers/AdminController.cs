using System.Linq.Expressions;
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
using SignaCore.Host.Services;

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
        [FromServices] IAuditService auditService,
        [FromServices] ILoginAttemptRepository loginAttemptRepository,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IdentityDbContext dbContext)
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
            await CommitAdminLoginStateAsync(
                result,
                null,
                request.Username.Trim(),
                "login_failure",
                result.ErrorMessage,
                loginAttemptRepository,
                auditService,
                unitOfWork,
                dbContext);
            return StatusCode(StatusCodes.Status401Unauthorized, new { message = result.ErrorMessage });
        }

        var username = result.DisplayName ?? request.Username.Trim();
        var configuredAdmin = adminIdentity.Username.Trim();
        if (string.IsNullOrWhiteSpace(configuredAdmin)
            || !string.Equals(username, configuredAdmin, StringComparison.OrdinalIgnoreCase))
        {
            await CommitAdminLoginStateAsync(
                result,
                result.Account.Id,
                username,
                "login_failure",
                "bootstrap_admin_required",
                loginAttemptRepository,
                auditService,
                unitOfWork,
                dbContext);
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

        await CommitAdminLoginStateAsync(
            result,
            result.Account.Id,
            username,
            "login_success",
            null,
            loginAttemptRepository,
            auditService,
            unitOfWork,
            dbContext);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = request.RememberMe,
                AllowRefresh = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(request.RememberMe ? 7 * 24 : 12)
            });

        return Ok(new AdminSessionResponse(
            result.Account.Id.ToString(),
            username,
            true));
    }

    private async Task CommitAdminLoginStateAsync(
        ValidationResult validationResult,
        Guid? accountId,
        string username,
        string eventType,
        string? failureReason,
        ILoginAttemptRepository loginAttemptRepository,
        IAuditService auditService,
        IUnitOfWork unitOfWork,
        IdentityDbContext dbContext)
    {
        async Task StageAndSaveAsync()
        {
            var loginAttempt = await LoginAttemptChangeApplier.ApplyAsync(
                validationResult.LoginAttemptChange,
                loginAttemptRepository);
            if (loginAttempt?.LockoutUntil > DateTimeOffset.UtcNow)
            {
                _logger.LogWarning(
                    "Account locked due to too many failed attempts, Username={Username}, LockoutUntil={LockoutUntil}",
                    LogValueSanitizer.Sanitize(loginAttempt.Username),
                    loginAttempt.LockoutUntil);
            }
            await auditService.RecordLoginAsync(
                accountId,
                username,
                "admin_login",
                eventType,
                GetClientIp(),
                HttpContext.Request.Headers.UserAgent,
                failureReason);
            await unitOfWork.SaveChangesAsync();
        }

        if (validationResult.LoginAttemptChange?.Kind != LoginAttemptChangeKind.RecordFailure)
        {
            await StageAndSaveAsync();
            return;
        }

        // The failed-attempt repository performs an immediate atomic update. Enclose it and the
        // login-history insert in one retryable transaction, while cookie I/O remains outside.
        var strategy = dbContext.Database.CreateExecutionStrategy();
        await strategy.ExecuteAsync(async () =>
        {
            dbContext.ChangeTracker.Clear();
            await using var transaction = await dbContext.Database.BeginTransactionAsync();
            await StageAndSaveAsync();
            await transaction.CommitAsync();
        });
    }

    /// <summary>
    /// Deactivates one application access row and revokes the refresh tokens it issued inside a
    /// single retryable transaction, so the access flag, the revocations and the audit entry commit
    /// or roll back together.
    /// </summary>
    /// <remarks>
    /// The tokens are revoked with a conditional set-based update instead of tracked per-row
    /// updates: <c>CleanupWorker</c> concurrently deletes expired-or-revoked rows, so a row loaded
    /// here can be gone by the time the change is saved, which would fail the whole request with a
    /// concurrency exception instead of skipping the row. The access row is reloaded inside the
    /// transaction because a retry restarts from a cleared change tracker.
    /// </remarks>
    /// <returns><c>false</c> when the access row no longer exists; the caller reports that as 404.</returns>
    private static async Task<bool> RevokeAppAccessAsync<TAccess>(
        IdentityDbContext dbContext,
        Guid accessId,
        Action<TAccess> deactivate,
        Expression<Func<RefreshTokenEntity, bool>> issuedTokens,
        Func<Task> stageAuditAsync,
        CancellationToken cancellationToken)
        where TAccess : class
    {
        var strategy = dbContext.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async () =>
        {
            dbContext.ChangeTracker.Clear();
            await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);
            var access = await dbContext.Set<TAccess>().FirstOrDefaultAsync(
                item => EF.Property<Guid>(item, "Id") == accessId, cancellationToken);
            if (access == null)
            {
                await transaction.RollbackAsync(cancellationToken);
                dbContext.ChangeTracker.Clear();
                return false;
            }

            deactivate(access);
            await dbContext.RefreshTokens
                .Where(issuedTokens)
                .ExecuteUpdateAsync(
                    setters => setters.SetProperty(token => token.IsRevoked, true), cancellationToken);
            await stageAuditAsync();
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return true;
        });
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
    public async Task<IActionResult> Logout(
        [FromServices] IAuditService auditService,
        [FromServices] IUnitOfWork unitOfWork)
    {
        var (actorId, actorName) = GetAdminIdentity();
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await auditService.RecordActionAsync("admin_logout", "Session", actorId?.ToString() ?? "unknown",
            actorId, actorName, "Admin logged out", GetClientIp());
        await unitOfWork.SaveChangesAsync();
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

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync("account_created", "Account", account.Id.ToString(),
            actorId, actorName, $"Admin created user: {credential.Username}", GetClientIp(),
            after: new { account.Id, account.IsActive, account.Remark, Username = credential.Username });
        await unitOfWork.SaveChangesAsync();

        _logger.LogInformation(
            "User created from Admin API: UserId={UserId}, Username={Username}",
            account.Id,
            LogValueSanitizer.Sanitize(credential.Username));

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

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync("account_created", "Account", account.Id.ToString(),
            actorId, actorName, "Admin created phone user", GetClientIp(),
            after: new { account.Id, account.IsActive, Phone = phone });
        await unitOfWork.SaveChangesAsync();

        _logger.LogInformation(
            "Phone user created from Admin API: AccountId={AccountId}, Phone={Phone}",
            account.Id,
            SensitiveDataMasker.MaskPhone(phone));

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

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            request.IsActive ? "account_enabled" : "account_disabled",
            "Account", account.Id.ToString(),
            actorId, actorName,
            request.IsActive ? $"Admin enabled user: {userId}" : $"Admin disabled user: {userId}",
            GetClientIp(),
            before: new { IsActive = beforeStatus },
            after: new { IsActive = request.IsActive });
        await unitOfWork.SaveChangesAsync();

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
            .Include(app => app.RedirectUris)
            .ToListAsync();

        var items = allApps
            .OrderByDescending(app => app.CreatedAt)
            .Select(app => new AdminAppListItemResponse(
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
                // 直接把生效的 aud 值算出来给管理台，省得前端复制一份解析规则。
                JwtTokenService.ResolveAudience(app, jwtOptions),
                app.ClientType.ToString(),
                app.AllowAuthorizationCode,
                SplitCanonicalScopes(app.AllowedScopes),
                app.AllowRefreshToken,
                app.IdentitySessionMaxAgeSeconds,
                RegisteredUris(app, RedirectUriKind.Redirect),
                RegisteredUris(app, RedirectUriKind.PostLogout)))
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
        [FromServices] IAuditService auditService,
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

        // The application did not exist before, so there is no before snapshot. The generated
        // secret and its hash stay out of the record: only the fields an operator needs to read the
        // registration back are captured.
        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_created", "AppRegistration", app.AppId, actorId, actorName,
            $"Admin created app: {app.AppName}", GetClientIp(),
            after: new
            {
                app.AppId,
                app.AppName,
                app.CallbackUrl,
                CallbackExpiresAt = app.CallbackExpiresAt?.ToUnixTimeSeconds(),
                app.IsActive
            });
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
        [FromServices] IAuditService auditService,
        CancellationToken cancellationToken = default)
    {
        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null)
        {
            return NotFound(new ErrorResponse("App not found."));
        }

        // Captured before the entity is mutated. IsActive is part of the snapshot because
        // deactivating an application is a security-relevant state change.
        var before = new
        {
            app.CallbackUrl,
            CallbackExpiresAt = app.CallbackExpiresAt?.ToUnixTimeSeconds(),
            app.IsActive
        };

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

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_callback_updated", "AppRegistration", app.AppId, actorId, actorName,
            $"Admin updated callback configuration for app: {app.AppName}", GetClientIp(),
            before: before,
            after: new
            {
                app.CallbackUrl,
                CallbackExpiresAt = app.CallbackExpiresAt?.ToUnixTimeSeconds(),
                app.IsActive
            });
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

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync("app_deleted", "AppRegistration", appId,
            actorId, actorName, $"Admin deleted app: {app.AppName}", GetClientIp());
        await unitOfWork.SaveChangesAsync();

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

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_sms_policy_updated", "AppRegistration", appId, actorId, actorName,
            $"SMS login mode changed to {mode}", GetClientIp(), before: before,
            after: new { Mode = mode.ToString(), SmsProfileKey = profileKey });
        await unitOfWork.SaveChangesAsync();
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
            app,
            phone,
            SmsAccessApprovalSource.Admin,
            actorId,
            cancellationToken,
            result => auditService.RecordActionAsync(
                "app_sms_user_approved", "AppRegistration", appId, actorId, actorName,
                "Administrator approved an SMS identity for the application", GetClientIp(),
                after: new { result.Account.Id, LoginId = result.Login.Id }));
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

        var (actorId, actorName) = GetAdminIdentity();
        var revoked = await RevokeAppAccessAsync<AppSmsAccessEntity>(
            dbContext,
            access.Id,
            item => item.IsActive = false,
            token => token.AppId == app.AppId && token.SmsUserLoginId == loginId && !token.IsRevoked,
            () => auditService.RecordActionAsync(
                "app_sms_user_revoked", "AppRegistration", appId, actorId, actorName,
                "Administrator revoked an SMS identity for the application", GetClientIp(),
                after: new { LoginId = loginId, IsActive = false }),
            cancellationToken);
        if (!revoked) return NotFound(new ErrorResponse("SMS application access not found."));
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

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_wechat_policy_updated", "AppRegistration", appId, actorId, actorName,
            $"WeChat login mode changed to {mode}", GetClientIp(), before: before,
            after: new { Mode = mode.ToString() });
        await unitOfWork.SaveChangesAsync();
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
        var audience = JwtTokenService.ResolveAudience(app, jwtOptions);

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_audience_mode_updated", "AppRegistration", appId, actorId, actorName,
            $"Access-token audience mode changed to {mode}", GetClientIp(), before: before,
            after: new { Mode = mode.ToString(), Audience = audience });
        await unitOfWork.SaveChangesAsync();
        return Ok(new OperationResponse(true, $"Access tokens for this application now carry aud={audience}."));
    }

    /// <summary>
    /// GET /api/admin/apps/{appId}/oidc — the interactive OIDC configuration of one application.
    /// <para>
    /// The two URI sets are separate registrations and are returned separately. Neither is the
    /// claims callback, which stays on its own endpoint and is never mixed in here.
    /// </para>
    /// </summary>
    [HttpGet("apps/{appId}/oidc")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> GetOidcConfiguration(
        string appId,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        CancellationToken cancellationToken)
    {
        var app = await appRegistrationRepository.GetByAppIdWithOidcConfigurationAsync(
            appId,
            cancellationToken);
        if (app == null) return NotFound(new ErrorResponse("App not found."));

        return Ok(Describe(app));
    }

    /// <summary>
    /// PUT /api/admin/apps/{appId}/oidc-policy — replaces the interactive policy fields.
    /// <para>
    /// The whole resulting configuration, including the URI registrations the request does not
    /// mention, is revalidated together. That is what makes a request such as "enable the code flow"
    /// fail when the application has no redirect URI, instead of committing a policy the
    /// authorization endpoint could never honour.
    /// </para>
    /// </summary>
    [HttpPut("apps/{appId}/oidc-policy")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> UpdateOidcPolicy(
        string appId,
        [FromBody] AdminUpdateOidcPolicyRequest request,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IAuditService auditService,
        [FromServices] IWebHostEnvironment environment,
        CancellationToken cancellationToken)
    {
        var app = await appRegistrationRepository.GetByAppIdWithOidcConfigurationAsync(
            appId,
            cancellationToken);
        if (app == null) return NotFound(new ErrorResponse("App not found."));

        var before = Snapshot(app);
        return await ApplyOidcConfigurationAsync(
            app,
            new OidcClientConfigurationInput
            {
                ClientType = request.ClientType,
                AllowAuthorizationCode = request.AllowAuthorizationCode,
                AllowedScopes = request.AllowedScopes,
                AllowRefreshToken = request.AllowRefreshToken,
                IdentitySessionMaxAgeSeconds = request.IdentitySessionMaxAgeSeconds,
                RedirectUris = RegisteredUris(app, RedirectUriKind.Redirect),
                PostLogoutRedirectUris = RegisteredUris(app, RedirectUriKind.PostLogout)
            },
            before,
            "app_oidc_policy_updated",
            "Interactive OIDC policy updated.",
            appRegistrationRepository,
            unitOfWork,
            auditService,
            environment,
            cancellationToken);
    }

    /// <summary>
    /// POST /api/admin/apps/{appId}/oidc/redirect-uris — registers one or more URIs of one kind.
    /// <para>
    /// The request is one unit: if any submitted value fails registration policy, or the resulting
    /// set would break a cross-field rule, nothing is registered.
    /// </para>
    /// </summary>
    [HttpPost("apps/{appId}/oidc/redirect-uris")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> AddOidcRedirectUris(
        string appId,
        [FromBody] AdminAddRedirectUrisRequest request,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IAuditService auditService,
        [FromServices] IWebHostEnvironment environment,
        CancellationToken cancellationToken)
    {
        var app = await appRegistrationRepository.GetByAppIdWithOidcConfigurationAsync(
            appId,
            cancellationToken);
        if (app == null) return NotFound(new ErrorResponse("App not found."));
        if (!Enum.TryParse<RedirectUriKind>(request.Kind, true, out var kind) || !Enum.IsDefined(kind))
            return BadRequest(new ErrorResponse("Invalid redirect URI kind."));
        if (request.Uris == null || request.Uris.Count == 0)
            return BadRequest(new ErrorResponse("At least one redirect URI is required."));

        var before = Snapshot(app);
        var redirect = RegisteredUris(app, RedirectUriKind.Redirect).ToList();
        var postLogout = RegisteredUris(app, RedirectUriKind.PostLogout).ToList();
        (kind == RedirectUriKind.Redirect ? redirect : postLogout).AddRange(request.Uris);

        return await ApplyOidcConfigurationAsync(
            app,
            CurrentPolicyWith(app, redirect, postLogout),
            before,
            "app_oidc_redirect_uris_added",
            "Redirect URI registrations updated.",
            appRegistrationRepository,
            unitOfWork,
            auditService,
            environment,
            cancellationToken);
    }

    /// <summary>
    /// DELETE /api/admin/apps/{appId}/oidc/redirect-uris/{registrationId} — removes one registration.
    /// <para>
    /// Removing the last redirect URI of an application that still has the code flow enabled is
    /// rejected: an interactive client with no destination is not a configuration the authorization
    /// endpoint can act on.
    /// </para>
    /// </summary>
    [HttpDelete("apps/{appId}/oidc/redirect-uris/{registrationId:guid}")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> RemoveOidcRedirectUri(
        string appId,
        Guid registrationId,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IAuditService auditService,
        [FromServices] IWebHostEnvironment environment,
        CancellationToken cancellationToken)
    {
        var app = await appRegistrationRepository.GetByAppIdWithOidcConfigurationAsync(
            appId,
            cancellationToken);
        if (app == null) return NotFound(new ErrorResponse("App not found."));

        var registration = app.RedirectUris.FirstOrDefault(uri => uri.Id == registrationId);
        if (registration == null) return NotFound(new ErrorResponse("Redirect URI registration not found."));

        var before = Snapshot(app);
        var redirect = RegisteredUris(app, RedirectUriKind.Redirect).ToList();
        var postLogout = RegisteredUris(app, RedirectUriKind.PostLogout).ToList();
        (registration.Kind == RedirectUriKind.Redirect ? redirect : postLogout)
            .Remove(registration.CanonicalUri);

        return await ApplyOidcConfigurationAsync(
            app,
            CurrentPolicyWith(app, redirect, postLogout),
            before,
            "app_oidc_redirect_uris_removed",
            "Redirect URI registrations updated.",
            appRegistrationRepository,
            unitOfWork,
            auditService,
            environment,
            cancellationToken);
    }

    /// <summary>
    /// Validates and commits one interactive configuration change with its audit row.
    /// <para>
    /// Validation runs before anything is staged, so a rejected request leaves the row exactly as it
    /// was and one <c>SaveChanges</c> makes an accepted one and its audit row effective as a unit.
    /// </para>
    /// </summary>
    private async Task<IActionResult> ApplyOidcConfigurationAsync(
        AppRegistrationEntity app,
        OidcClientConfigurationInput input,
        object before,
        string auditAction,
        string successMessage,
        IAppRegistrationRepository appRegistrationRepository,
        IUnitOfWork unitOfWork,
        IAuditService auditService,
        IWebHostEnvironment environment,
        CancellationToken cancellationToken)
    {
        OidcClientConfigurationChange change;
        try
        {
            change = OidcClientConfigurationApplier.Apply(app, input, environment.IsDevelopment());
        }
        catch (OidcClientConfigurationException exception)
        {
            return BadRequest(new ErrorResponse(exception.Message));
        }

        await appRegistrationRepository.AddRedirectUrisAsync(change.AddedRegistrations);
        await appRegistrationRepository.RemoveRedirectUrisAsync(change.RemovedRegistrations);

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            auditAction, "AppRegistration", app.AppId, actorId, actorName,
            successMessage, GetClientIp(), before: before, after: Snapshot(app));
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return Ok(Describe(app));
    }

    /// <summary>The current policy fields with a different pair of URI sets.</summary>
    private static OidcClientConfigurationInput CurrentPolicyWith(
        AppRegistrationEntity app,
        IReadOnlyList<string> redirectUris,
        IReadOnlyList<string> postLogoutRedirectUris) => new()
        {
            ClientType = app.ClientType.ToString(),
            AllowAuthorizationCode = app.AllowAuthorizationCode,
            AllowedScopes = SplitCanonicalScopes(app.AllowedScopes),
            AllowRefreshToken = app.AllowRefreshToken,
            IdentitySessionMaxAgeSeconds = app.IdentitySessionMaxAgeSeconds,
            RedirectUris = redirectUris,
            PostLogoutRedirectUris = postLogoutRedirectUris
        };

    private static AdminAppOidcResponse Describe(AppRegistrationEntity app) => new(
        app.AppId,
        app.ClientType.ToString(),
        app.AllowAuthorizationCode,
        SplitCanonicalScopes(app.AllowedScopes),
        app.AllowRefreshToken,
        app.IdentitySessionMaxAgeSeconds,
        app.AudienceMode.ToString(),
        Registrations(app, RedirectUriKind.Redirect),
        Registrations(app, RedirectUriKind.PostLogout));

    /// <summary>
    /// The audit snapshot. It carries policy and registered URIs only: no secret, no hash, and no
    /// untrusted value, because every URI here has already passed registration policy.
    /// </summary>
    private static object Snapshot(AppRegistrationEntity app) => new
    {
        ClientType = app.ClientType.ToString(),
        app.AllowAuthorizationCode,
        AllowedScopes = app.AllowedScopes,
        app.AllowRefreshToken,
        app.IdentitySessionMaxAgeSeconds,
        AudienceMode = app.AudienceMode.ToString(),
        RedirectUris = RegisteredUris(app, RedirectUriKind.Redirect),
        PostLogoutRedirectUris = RegisteredUris(app, RedirectUriKind.PostLogout)
    };

    private static IReadOnlyList<AdminAppRedirectUriResponse> Registrations(
        AppRegistrationEntity app,
        RedirectUriKind kind) =>
        app.RedirectUris
            .Where(uri => uri.Kind == kind)
            .OrderBy(uri => uri.CanonicalUri, StringComparer.Ordinal)
            .Select(uri => new AdminAppRedirectUriResponse(uri.Id, uri.Kind.ToString(), uri.CanonicalUri))
            .ToList();

    private static IReadOnlyList<string> RegisteredUris(AppRegistrationEntity app, RedirectUriKind kind) =>
        app.RedirectUris
            .Where(uri => uri.Kind == kind)
            .Select(uri => uri.CanonicalUri)
            .OrderBy(uri => uri, StringComparer.Ordinal)
            .ToList();

    private static IReadOnlyList<string> SplitCanonicalScopes(string canonicalScopes) =>
        canonicalScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);

    /// <summary>
    /// GET /api/admin/apps/{appId}/exchange-trusts — 本应用愿意接受哪些应用签发的 refresh token。
    /// 边是有向的：这里列出的是来源，反向不成立。见 docs/adr/0003-cross-application-refresh-grant.md。
    /// </summary>
    [HttpGet("apps/{appId}/exchange-trusts")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> GetExchangeTrusts(
        string appId,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] IAppExchangeTrustRepository exchangeTrustRepository,
        CancellationToken cancellationToken)
    {
        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null) return NotFound(new ErrorResponse("App not found."));

        var trusts = await exchangeTrustRepository.ListSourcesAsync(app.Id, cancellationToken);
        var items = trusts
            .Select(trust => new AdminExchangeTrustResponse(
                trust.SourceAppId, trust.SourceAppName, trust.SourceIsActive,
                trust.CreatedAt.ToUnixTimeSeconds()))
            .ToList();
        return Ok((IReadOnlyList<AdminExchangeTrustResponse>)items);
    }

    /// <summary>
    /// POST /api/admin/apps/{appId}/exchange-trusts — 允许本应用接受来源应用签发的 refresh token。
    /// 加这条边等于：任何持有来源应用 refresh token 的人都能为同一账号换到本应用的会话。本应用比来源
    /// 应用权限更高时，差异必须由本应用的回调和授权规则守住，不能指望这条边不存在。
    /// </summary>
    [HttpPost("apps/{appId}/exchange-trusts")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> AddExchangeTrust(
        string appId,
        [FromBody] AdminAddExchangeTrustRequest request,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] IAppExchangeTrustRepository exchangeTrustRepository,
        [FromServices] IAuditService auditService,
        [FromServices] IUnitOfWork unitOfWork,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.SourceAppId))
            return BadRequest(new ErrorResponse("A source AppId is required."));

        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null) return NotFound(new ErrorResponse("App not found."));

        var sourceApp = await appRegistrationRepository.GetByAppIdAsync(request.SourceAppId.Trim());
        if (sourceApp == null) return NotFound(new ErrorResponse("Source app not found."));
        if (sourceApp.Id == app.Id)
            return BadRequest(new ErrorResponse("An application cannot trust itself."));

        var (actorId, actorName) = GetAdminIdentity();
        var trust = await exchangeTrustRepository.AddAsync(app, sourceApp, actorId, cancellationToken);
        await auditService.RecordActionAsync(
            "app_exchange_trust_added", "AppRegistration", appId, actorId, actorName,
            $"Application now accepts refresh tokens issued to {sourceApp.AppId}", GetClientIp(),
            after: new { SourceAppId = sourceApp.AppId });
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return Ok(new AdminExchangeTrustResponse(
            trust.SourceAppId, trust.SourceAppName, trust.SourceIsActive,
            trust.CreatedAt.ToUnixTimeSeconds()));
    }

    /// <summary>
    /// DELETE /api/admin/apps/{appId}/exchange-trusts/{sourceAppId} — 撤销信任边。
    /// 已经换出去的会话不会因此结束：它们绑定在本应用和本应用的准入记录上，要终止得按应用撤销。
    /// </summary>
    [HttpDelete("apps/{appId}/exchange-trusts/{sourceAppId}")]
    [Authorize(Policy = "AdminSession")]
    public async Task<IActionResult> RemoveExchangeTrust(
        string appId,
        string sourceAppId,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] IAppExchangeTrustRepository exchangeTrustRepository,
        [FromServices] IAuditService auditService,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IdentityDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var app = await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app == null) return NotFound(new ErrorResponse("App not found."));

        var sourceApp = await appRegistrationRepository.GetByAppIdAsync(sourceAppId);
        if (sourceApp == null) return NotFound(new ErrorResponse("Source app not found."));

        if (!await exchangeTrustRepository.RemoveAsync(app.Id, sourceApp.Id, cancellationToken))
            return NotFound(new ErrorResponse("Exchange trust not found."));

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_exchange_trust_removed", "AppRegistration", appId, actorId, actorName,
            $"Application no longer accepts refresh tokens issued to {sourceApp.AppId}", GetClientIp(),
            before: new { SourceAppId = sourceApp.AppId });
        try
        {
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException exception) when (
            exception.Entries.Count == 1 &&
            exception.Entries[0].Entity is AppExchangeTrustEntity)
        {
            // Another request deleted the edge after this request loaded it. SaveChanges rolled its
            // audit insert back with the failed delete; clear both staged entries so this scoped
            // context cannot persist the losing audit in a later save.
            dbContext.ChangeTracker.Clear();
            return NotFound(new ErrorResponse("Exchange trust not found."));
        }

        return Ok(new OperationResponse(true, "Exchange trust removed."));
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
        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync(
            "app_wechat_user_restored", "AppRegistration", appId, actorId, actorName,
            "Administrator restored a WeChat identity for the application", GetClientIp(),
            after: new { LoginId = loginId, IsActive = true });
        await dbContext.SaveChangesAsync(cancellationToken);
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

        var (actorId, actorName) = GetAdminIdentity();
        var revoked = await RevokeAppAccessAsync<AppWechatAccessEntity>(
            dbContext,
            access.Id,
            item => item.IsActive = false,
            token => token.AppId == app.AppId && token.WechatUserLoginId == loginId && !token.IsRevoked,
            () => auditService.RecordActionAsync(
                "app_wechat_user_revoked", "AppRegistration", appId, actorId, actorName,
                "Administrator revoked a WeChat identity for the application", GetClientIp(),
                after: new { LoginId = loginId, IsActive = false }),
            cancellationToken);
        if (!revoked) return NotFound(new ErrorResponse("WeChat application access not found."));
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
        await unitOfWork.SaveChangesAsync();

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
            cancellationToken,
            provisioned => auditService.RecordActionAsync(
                "app_ldap_user_approved",
                "AppRegistration",
                appId,
                actorId,
                actorName,
                $"Administrator approved LDAP identity {identity.ObjectGuid} for the application",
                GetClientIp(),
                after: new
                {
                    AccountId = provisioned.Account.Id,
                    CredentialId = provisioned.Credential.Id,
                    identity.DirectoryKey
                }));

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

        var (actorId, actorName) = GetAdminIdentity();
        var revoked = await RevokeAppAccessAsync<AppLdapAccessEntity>(
            dbContext,
            access.Id,
            item => item.IsActive = false,
            token => token.AppId == app.AppId && token.LdapCredentialId == credentialId && !token.IsRevoked,
            () => auditService.RecordActionAsync(
                "app_ldap_user_revoked",
                "AppRegistration",
                appId,
                actorId,
                actorName,
                $"Administrator revoked LDAP credential {credentialId} from the application",
                GetClientIp()),
            cancellationToken);
        if (!revoked)
        {
            return NotFound(new ErrorResponse("LDAP application access not found."));
        }

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

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync("app_secret_reset", "AppRegistration", appId,
            actorId, actorName, $"Admin reset app secret: {app.AppName}", GetClientIp());
        await unitOfWork.SaveChangesAsync();

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

        var (actorId, actorName) = GetAdminIdentity();
        await auditService.RecordActionAsync("refresh_token_revoked", "RefreshToken", refreshToken.AccountId.ToString(),
            actorId, actorName, "Admin revoked refresh token", GetClientIp());
        await unitOfWork.SaveChangesAsync();

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
