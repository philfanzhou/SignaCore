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
    /// GET /api/profile/wechat — 当前账号的微信绑定状态。
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
    /// POST /api/profile/wechat — 把微信 code 换到的 OpenId 绑定到当前已认证账号，
    /// 并为调用方应用开通微信登录准入。这是 <c>wechat_code</c> 授权在
    /// <see cref="WechatLoginMode.BindRequired"/> 模式下唯一的绑定入口。
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

        // 绑定的准入范围是"签发这张 token 的应用"，不是全局：与登录时的 App 作用域保持一致。
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
    /// DELETE /api/profile/wechat — 解绑。绑定行被删除后，依赖它的应用准入随之级联删除，
    /// 由该身份签发的 refresh token 在下一次刷新时失效。
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
