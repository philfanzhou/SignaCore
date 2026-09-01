using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.WeChat;
using SignaCore.Host.Http;
using SignaCore.Host.Models;

namespace SignaCore.Host.Controllers;

[Route("api/profile")]
[ApiController]
[Authorize(Policy = "UserProfile")]
public class ProfileController : ControllerBase
{
    [HttpGet("me")]
    public async Task<IActionResult> GetProfile([FromServices] IAccountRepository accountRepository)
    {
        var accountId = GetAccountId();
        if (accountId == null)
        {
            return Unauthorized();
        }

        var account = await accountRepository.GetByIdAsync(accountId.Value);
        if (account == null)
        {
            return Unauthorized();
        }

        return Ok(new ProfileResponse(
            account.Id.ToString(),
            account.Nickname,
            account.IsActive,
            account.CreatedAt.ToUnixTimeSeconds()));
    }

    [HttpPatch("nickname")]
    public async Task<IActionResult> UpdateNickname(
        [FromBody] UpdateProfileNicknameRequest request,
        [FromServices] IAccountRepository accountRepository,
        [FromServices] IUnitOfWork unitOfWork)
    {
        var accountId = GetAccountId();
        if (accountId == null)
        {
            return Unauthorized();
        }

        var account = await accountRepository.GetByIdAsync(accountId.Value);
        if (account == null)
        {
            return Unauthorized();
        }

        if (request.Nickname is not null && request.Nickname.Trim().Length > IdentityConstants.MaxNicknameLength)
        {
            return BadRequest(new ErrorResponse($"Nickname cannot exceed {IdentityConstants.MaxNicknameLength} characters."));
        }

        account.Nickname = string.IsNullOrWhiteSpace(request.Nickname) ? null : request.Nickname.Trim();
        await accountRepository.UpdateAsync(account);
        await unitOfWork.SaveChangesAsync();

        return Ok(new OperationResponse(true, "Nickname updated."));
    }

    /// <summary>
    /// GET /api/profile/wechat — the WeChat binding state of the current account.
    /// </summary>
    [HttpGet("wechat")]
    public async Task<IActionResult> GetWechatBinding(
        [FromServices] IWechatAdmissionService admissionService,
        CancellationToken cancellationToken)
    {
        var accountId = GetAccountId();
        if (accountId == null)
        {
            return Unauthorized();
        }

        var binding = await admissionService.GetBindingAsync(accountId.Value, cancellationToken);
        return Ok(new WechatBindingResponse(
            binding != null,
            binding == null ? null : SensitiveDataMasker.MaskOpenId(binding.ProviderUserId)));
    }

    /// <summary>
    /// POST /api/profile/wechat — binds the OpenId obtained from a WeChat code to the currently
    /// authenticated account and admits WeChat login for the calling application. It is the only
    /// binding entry point for the <c>wechat_code</c> grant in
    /// <see cref="WechatLoginMode.BindRequired"/> mode.
    /// </summary>
    [HttpPost("wechat")]
    public async Task<IActionResult> BindWechat(
        [FromBody] BindWechatRequest request,
        [FromServices] IWechatApiClient wechatApiClient,
        [FromServices] IWechatAdmissionService admissionService,
        [FromServices] IAppRegistrationRepository appRegistrationRepository,
        [FromServices] IAuditService auditService,
        CancellationToken cancellationToken)
    {
        var accountId = GetAccountId();
        if (accountId == null)
        {
            return Unauthorized();
        }

        if (string.IsNullOrWhiteSpace(request.Code))
        {
            return BadRequest(new ErrorResponse("WeChat code cannot be empty."));
        }

        // The admission granted by a binding is scoped to the application that issued this token,
        // not global: the same App scope that applies at sign-in.
        var appId = User.FindFirstValue(IdentityConstants.ClaimClientId);
        var app = string.IsNullOrWhiteSpace(appId)
            ? null
            : await appRegistrationRepository.GetByAppIdAsync(appId);
        if (app is not { IsActive: true })
        {
            return BadRequest(new ErrorResponse("The calling application is not registered."));
        }

        if (app.WechatLoginMode == WechatLoginMode.Disabled)
        {
            return BadRequest(new ErrorResponse("WeChat login is disabled for this application."));
        }

        var openId = await wechatApiClient.CodeToSessionAsync(request.Code, cancellationToken);
        if (string.IsNullOrEmpty(openId))
        {
            return BadRequest(new ErrorResponse("WeChat authentication failed."));
        }

        var result = await admissionService.BindAsync(app, accountId.Value, openId, cancellationToken);
        if (!result.IsSuccess)
        {
            return result.Outcome switch
            {
                WechatBindOutcome.OpenIdAlreadyBound =>
                    Conflict(new ErrorResponse("This WeChat identity is already bound to another account.")),
                WechatBindOutcome.AccountAlreadyBound =>
                    Conflict(new ErrorResponse("This account is already bound to a different WeChat identity.")),
                // A revocation is administrator state; a user rebinding must not clear it.
                WechatBindOutcome.AccessRevoked =>
                    StatusCode(StatusCodes.Status403Forbidden,
                        new ErrorResponse("WeChat access for this application has been revoked by an administrator.")),
                _ => Unauthorized()
            };
        }

        await auditService.RecordActionAsync(
            "wechat_bound", "Account", accountId.Value.ToString(), accountId, null,
            $"WeChat identity bound for application {app.AppId}", HttpContext.GetClientIp(),
            correlationId: HttpContext.GetCorrelationId());

        return Ok(new WechatBindingResponse(true, SensitiveDataMasker.MaskOpenId(openId)));
    }

    /// <summary>
    /// DELETE /api/profile/wechat — unbinds. Once the binding row is deleted, the application
    /// admissions that depend on it cascade away with it, and refresh tokens issued for that
    /// identity stop working at their next refresh.
    /// </summary>
    [HttpDelete("wechat")]
    public async Task<IActionResult> UnbindWechat(
        [FromServices] IWechatAdmissionService admissionService,
        [FromServices] IAuditService auditService,
        CancellationToken cancellationToken)
    {
        var accountId = GetAccountId();
        if (accountId == null)
        {
            return Unauthorized();
        }

        var removed = await admissionService.UnbindAsync(accountId.Value, cancellationToken);
        if (removed)
        {
            await auditService.RecordActionAsync(
                "wechat_unbound", "Account", accountId.Value.ToString(), accountId, null,
                "WeChat identity unbound", HttpContext.GetClientIp(),
                correlationId: HttpContext.GetCorrelationId());
        }

        return Ok(new OperationResponse(removed, removed ? "WeChat unbound." : "No WeChat binding to remove."));
    }

    private Guid? GetAccountId()
    {
        var idClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(idClaim, out var id) ? id : null;
    }
}
