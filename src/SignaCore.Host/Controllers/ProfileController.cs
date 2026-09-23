using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using ServiceMantle.Audit;
using SignaCore.Domain.Services.WeChat;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host.Audit;
using SignaCore.Host.Http;
using SignaCore.Host.Models;

namespace SignaCore.Host.Controllers;

[Route("api/profile")]
[ApiController]
[Authorize(Policy = "UserProfile")]
public class ProfileController : ControllerBase
{
    [HttpGet("me")]
    public async Task<IActionResult> GetProfile(
        [FromServices] IAccountRepository accountRepository,
        CancellationToken cancellationToken)
    {
        var accountId = GetAccountId();
        if (accountId == null)
        {
            return Unauthorized();
        }

        var account = await accountRepository.GetByIdAsync(accountId.Value, cancellationToken);
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
        [FromServices] IUnitOfWork unitOfWork,
        CancellationToken cancellationToken)
    {
        var accountId = GetAccountId();
        if (accountId == null)
        {
            return Unauthorized();
        }

        var account = await accountRepository.GetByIdAsync(accountId.Value, cancellationToken);
        if (account == null)
        {
            return Unauthorized();
        }

        if (request.Nickname is not null && request.Nickname.Trim().Length > IdentityConstants.MaxNicknameLength)
        {
            return BadRequest(new ErrorResponse($"Nickname cannot exceed {IdentityConstants.MaxNicknameLength} characters."));
        }

        account.Nickname = string.IsNullOrWhiteSpace(request.Nickname) ? null : request.Nickname.Trim();
        await accountRepository.UpdateAsync(account, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        return Ok(new OperationResponse(true, "Nickname updated."));
    }

    /// <summary>
    /// POST /api/profile/password — the self-service password change. Re-proves the current
    /// password, then writes the new hash and revokes every identity session of the account
    /// (reason <c>password_changed</c>, the caller's own session included), every interactive
    /// refresh family, and every legacy refresh token in one transaction with the audit row.
    /// Already-issued self-contained access/ID tokens are not remotely revoked and stay valid to
    /// <c>exp</c>, matching the existing <c>EV-08</c>/<c>EV-09</c>/<c>EV-11</c> non-guarantee.
    /// A wrong current password is indistinguishable from an account without a password
    /// credential and enters the shared failed-attempt/lockout path.
    /// </summary>
    [HttpPost("password")]
    public async Task<IActionResult> ChangePassword(
        [FromBody] ChangePasswordRequest request,
        [FromServices] IPasswordCredentialRepository passwordCredentialRepository,
        [FromServices] IPasswordHasher passwordHasher,
        [FromServices] IPasswordPolicy passwordPolicy,
        [FromServices] PasswordDecoyHash decoyHash,
        [FromServices] ILoginAttemptRepository loginAttemptRepository,
        [FromServices] IIdentitySessionRepository identitySessionRepository,
        [FromServices] IRefreshTokenFamilyStore refreshTokenFamilyStore,
        [FromServices] IRefreshTokenRepository refreshTokenRepository,
        [FromServices] IdentityDbContext dbContext,
        [FromServices] IUnitOfWork unitOfWork,
        [FromServices] IManagementAuditWriter auditWriter,
        CancellationToken cancellationToken = default)
    {
        var accountId = GetAccountId();
        if (accountId == null)
        {
            return Unauthorized();
        }

        if (string.IsNullOrEmpty(request.CurrentPassword) || string.IsNullOrEmpty(request.NewPassword))
        {
            return BadRequest(new ErrorResponse("Current password and new password cannot be empty."));
        }

        const string genericFailure = "Wrong current password.";
        var credential = await passwordCredentialRepository.GetByAccountIdAsync(accountId.Value, cancellationToken);
        if (credential == null)
        {
            // The decoy verification keeps this branch on the same BCrypt workload as the
            // wrong-password branch, and the generic failure never reveals that this account
            // carries no password credential.
            _ = passwordHasher.VerifyPassword(request.CurrentPassword, decoyHash.Value);
            return BadRequest(new ErrorResponse(genericFailure));
        }

        if (!passwordHasher.VerifyPassword(request.CurrentPassword, credential.PasswordHash))
        {
            // The shared failed-attempt/lockout path: a wrong current password counts exactly
            // like a wrong login password, with the same generic response.
            await loginAttemptRepository.RecordFailureAsync(
                credential.Username, DateTimeOffset.UtcNow, cancellationToken);
            return BadRequest(new ErrorResponse(genericFailure));
        }

        if (!passwordPolicy.Validate(request.NewPassword, out var policyError))
        {
            return BadRequest(new ErrorResponse(policyError));
        }

        var newPasswordHash = passwordHasher.HashPassword(request.NewPassword);
        var strategy = dbContext.Database.CreateExecutionStrategy();
        var committed = await strategy.ExecuteAsync(async operationToken =>
        {
            dbContext.ChangeTracker.Clear();
            await using var transaction = await dbContext.Database
                .BeginTransactionAsync(operationToken);

            var now = DateTimeOffset.UtcNow;

            // One commit boundary owns the hash write, every promised revocation, and the audit
            // row. The session writes run in the canonical lock order (sessions before families)
            // so a concurrent code redemption or refresh rotation of the same account serializes
            // on the same session-row lock as every other account-state transaction.
            var updatedCredentials = await passwordCredentialRepository.UpdatePasswordHashAsync(
                credential.Id, newPasswordHash, operationToken);
            if (updatedCredentials == 0)
            {
                await transaction.RollbackAsync(operationToken);
                return false;
            }

            var revokedSessions = await identitySessionRepository.MarkRevokedByAccountAsync(
                accountId.Value, "password_changed", now, operationToken);
            var revokedFamilyMembers = await refreshTokenFamilyStore.RevokeByAccountAsync(
                accountId.Value, RefreshFamilyRevocationReason.PasswordChanged, operationToken);
            var revokedLegacyTokens = await refreshTokenRepository.RevokeLegacyByAccountAsync(
                accountId.Value, operationToken);

            await ManagementActionAudit.RecordAsync(
                auditWriter, ManagementActionAudit.AccountSource,
                "password_changed", "Account", accountId.Value.ToString(),
                accountId, null,
                $"User changed password; revoked sessions: {revokedSessions}; " +
                $"revoked family members: {revokedFamilyMembers}; " +
                $"revoked legacy tokens: {revokedLegacyTokens}",
                HttpContext.GetClientIp(),
                HttpContext.GetCorrelationId(),
                cancellationToken: operationToken);
            await unitOfWork.SaveChangesAsync(operationToken);
            await transaction.CommitAsync(operationToken);
            return true;
        }, cancellationToken);

        if (!committed)
        {
            return BadRequest(new ErrorResponse(genericFailure));
        }

        return Ok(new OperationResponse(true, "Password changed; every session of this account was signed out."));
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
        [FromServices] IManagementAuditWriter auditWriter,
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
            : await appRegistrationRepository.GetByAppIdAsync(appId, cancellationToken);
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

        var result = await admissionService.BindAsync(
            app,
            accountId.Value,
            openId,
            cancellationToken,
            async bindResult =>
            {
                if (bindResult.IsSuccess)
                {
                    await ManagementActionAudit.RecordAsync(
                        auditWriter, ManagementActionAudit.AccountSource,
                        "wechat_bound", "Account", accountId.Value.ToString(), accountId, null,
                        $"WeChat identity bound for application {app.AppId}", HttpContext.GetClientIp(),
                        HttpContext.GetCorrelationId(),
                        cancellationToken: cancellationToken);
                }
            });
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
        [FromServices] IManagementAuditWriter auditWriter,
        CancellationToken cancellationToken)
    {
        var accountId = GetAccountId();
        if (accountId == null)
        {
            return Unauthorized();
        }

        var removed = await admissionService.UnbindAsync(
            accountId.Value,
            cancellationToken,
            () => ManagementActionAudit.RecordAsync(
                auditWriter, ManagementActionAudit.AccountSource,
                "wechat_unbound", "Account", accountId.Value.ToString(), accountId, null,
                "WeChat identity unbound", HttpContext.GetClientIp(),
                HttpContext.GetCorrelationId(),
                cancellationToken: cancellationToken).AsTask());

        return Ok(new OperationResponse(removed, removed ? "WeChat unbound." : "No WeChat binding to remove."));
    }

    private Guid? GetAccountId()
    {
        var idClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(idClaim, out var id) ? id : null;
    }
}
