using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Host.Models;

namespace QuantumZhou.Identity.Host.Controllers;

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
            return BadRequest(new AdminApiErrorResponse($"Nickname cannot exceed {IdentityConstants.MaxNicknameLength} characters."));
        }

        account.Nickname = string.IsNullOrWhiteSpace(request.Nickname) ? null : request.Nickname.Trim();
        await accountRepository.UpdateAsync(account);
        await unitOfWork.SaveChangesAsync();

        return Ok(new AdminOperationResponse(true, "Nickname updated."));
    }

    private Guid? GetAccountId()
    {
        var idClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(idClaim, out var id) ? id : null;
    }
}
