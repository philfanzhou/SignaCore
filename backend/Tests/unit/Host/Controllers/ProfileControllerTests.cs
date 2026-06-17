using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Host.Controllers;
using QuantumZhou.Identity.Host.Models;
using Xunit;

namespace QuantumZhou.Identity.Tests.Host.Controllers;

public class ProfileControllerTests
{
    private static readonly Guid AccountId = Guid.NewGuid();

    private static ProfileController CreateController(ClaimsPrincipal? user = null)
    {
        var controller = new ProfileController();
        var httpContext = new DefaultHttpContext();
        if (user != null)
        {
            httpContext.User = user;
        }

        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
        return controller;
    }

    private static ClaimsPrincipal CreateAuthenticatedUser(Guid accountId)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, accountId.ToString()),
            new(ClaimTypes.Name, "tester")
        };
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));
    }

    private static AccountEntity CreateAccount(Guid id, string? nickname = "nick", bool isActive = true)
    {
        return new AccountEntity
        {
            Id = id,
            Nickname = nickname,
            IsActive = isActive,
            CreatedAt = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero)
        };
    }

    [Fact]
    public async Task GetProfile_WithoutAuthenticatedUser_ReturnsUnauthorized()
    {
        var accountRepo = new Mock<IAccountRepository>();
        var controller = CreateController(user: null);

        var result = await controller.GetProfile(accountRepo.Object);

        Assert.IsType<UnauthorizedResult>(result);
        accountRepo.Verify(r => r.GetByIdAsync(It.IsAny<Guid>()), Times.Never);
    }

    [Fact]
    public async Task GetProfile_WithInvalidNameIdentifierClaim_ReturnsUnauthorized()
    {
        var accountRepo = new Mock<IAccountRepository>();
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, "not-a-guid") };
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));
        var controller = CreateController(user);

        var result = await controller.GetProfile(accountRepo.Object);

        Assert.IsType<UnauthorizedResult>(result);
        accountRepo.Verify(r => r.GetByIdAsync(It.IsAny<Guid>()), Times.Never);
    }

    [Fact]
    public async Task GetProfile_WhenAccountNotFound_ReturnsUnauthorized()
    {
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo.Setup(r => r.GetByIdAsync(AccountId)).ReturnsAsync((AccountEntity?)null);
        var controller = CreateController(CreateAuthenticatedUser(AccountId));

        var result = await controller.GetProfile(accountRepo.Object);

        Assert.IsType<UnauthorizedResult>(result);
    }

    [Fact]
    public async Task GetProfile_WhenAccountExists_ReturnsProfileResponse()
    {
        var account = CreateAccount(AccountId, nickname: "Alice", isActive: true);
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo.Setup(r => r.GetByIdAsync(AccountId)).ReturnsAsync(account);
        var controller = CreateController(CreateAuthenticatedUser(AccountId));

        var result = await controller.GetProfile(accountRepo.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<ProfileResponse>(ok.Value);
        Assert.Equal(AccountId.ToString(), response.UserId);
        Assert.Equal("Alice", response.Nickname);
        Assert.True(response.IsActive);
        Assert.Equal(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds(), response.CreatedAt);
    }

    [Fact]
    public async Task UpdateNickname_WithoutAuthenticatedUser_ReturnsUnauthorized()
    {
        var accountRepo = new Mock<IAccountRepository>();
        var unitOfWork = new Mock<IUnitOfWork>();
        var controller = CreateController(user: null);

        var result = await controller.UpdateNickname(new UpdateProfileNicknameRequest("new"), accountRepo.Object, unitOfWork.Object);

        Assert.IsType<UnauthorizedResult>(result);
        accountRepo.Verify(r => r.GetByIdAsync(It.IsAny<Guid>()), Times.Never);
        unitOfWork.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task UpdateNickname_WhenAccountNotFound_ReturnsUnauthorized()
    {
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo.Setup(r => r.GetByIdAsync(AccountId)).ReturnsAsync((AccountEntity?)null);
        var unitOfWork = new Mock<IUnitOfWork>();
        var controller = CreateController(CreateAuthenticatedUser(AccountId));

        var result = await controller.UpdateNickname(new UpdateProfileNicknameRequest("new"), accountRepo.Object, unitOfWork.Object);

        Assert.IsType<UnauthorizedResult>(result);
        unitOfWork.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task UpdateNickname_WhenNicknameExceedsLimit_ReturnsBadRequest()
    {
        var account = CreateAccount(AccountId);
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo.Setup(r => r.GetByIdAsync(AccountId)).ReturnsAsync(account);
        var unitOfWork = new Mock<IUnitOfWork>();
        var controller = CreateController(CreateAuthenticatedUser(AccountId));
        var longNickname = new string('a', IdentityConstants.MaxNicknameLength + 1);

        var result = await controller.UpdateNickname(new UpdateProfileNicknameRequest(longNickname), accountRepo.Object, unitOfWork.Object);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        var err = Assert.IsType<AdminApiErrorResponse>(bad.Value);
        Assert.Contains("Nickname cannot exceed", err.Message);
        unitOfWork.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task UpdateNickname_WithValidNickname_UpdatesAndSaves()
    {
        var account = CreateAccount(AccountId, nickname: "old");
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo.Setup(r => r.GetByIdAsync(AccountId)).ReturnsAsync(account);
        accountRepo.Setup(r => r.UpdateAsync(account)).Returns(Task.CompletedTask).Verifiable();
        var unitOfWork = new Mock<IUnitOfWork>();
        unitOfWork.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1).Verifiable();
        var controller = CreateController(CreateAuthenticatedUser(AccountId));

        var result = await controller.UpdateNickname(new UpdateProfileNicknameRequest("NewName"), accountRepo.Object, unitOfWork.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminOperationResponse>(ok.Value);
        Assert.True(response.Success);
        Assert.Equal("NewName", account.Nickname);
        accountRepo.Verify();
        unitOfWork.Verify();
    }

    [Fact]
    public async Task UpdateNickname_WithWhitespaceNickname_SetsNullAndSaves()
    {
        var account = CreateAccount(AccountId, nickname: "old");
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo.Setup(r => r.GetByIdAsync(AccountId)).ReturnsAsync(account);
        var unitOfWork = new Mock<IUnitOfWork>();
        unitOfWork.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1).Verifiable();
        var controller = CreateController(CreateAuthenticatedUser(AccountId));

        var result = await controller.UpdateNickname(new UpdateProfileNicknameRequest("   "), accountRepo.Object, unitOfWork.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.True(Assert.IsType<AdminOperationResponse>(ok.Value).Success);
        Assert.Null(account.Nickname);
        unitOfWork.Verify();
    }

    [Fact]
    public async Task UpdateNickname_WithNullNickname_SetsNullAndSaves()
    {
        var account = CreateAccount(AccountId, nickname: "old");
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo.Setup(r => r.GetByIdAsync(AccountId)).ReturnsAsync(account);
        var unitOfWork = new Mock<IUnitOfWork>();
        unitOfWork.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1).Verifiable();
        var controller = CreateController(CreateAuthenticatedUser(AccountId));

        var result = await controller.UpdateNickname(new UpdateProfileNicknameRequest(null), accountRepo.Object, unitOfWork.Object);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.True(Assert.IsType<AdminOperationResponse>(ok.Value).Success);
        Assert.Null(account.Nickname);
        unitOfWork.Verify();
    }

    [Fact]
    public async Task UpdateNickname_WithExactlyMaxLengthNickname_Succeeds()
    {
        var account = CreateAccount(AccountId);
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo.Setup(r => r.GetByIdAsync(AccountId)).ReturnsAsync(account);
        var unitOfWork = new Mock<IUnitOfWork>();
        unitOfWork.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1).Verifiable();
        var controller = CreateController(CreateAuthenticatedUser(AccountId));
        var maxNickname = new string('a', IdentityConstants.MaxNicknameLength);

        var result = await controller.UpdateNickname(new UpdateProfileNicknameRequest(maxNickname), accountRepo.Object, unitOfWork.Object);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(maxNickname, account.Nickname);
        unitOfWork.Verify();
    }
}
