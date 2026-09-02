using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.WeChat;
using SignaCore.Host.Controllers;
using SignaCore.Host.Models;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

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

    private static ClaimsPrincipal CreateAuthenticatedUser(Guid accountId, string? appId = null)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, accountId.ToString()),
            new(ClaimTypes.Name, "tester")
        };
        if (appId is not null)
        {
            claims.Add(new Claim(IdentityConstants.ClaimClientId, appId));
        }
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

        var result = await controller.GetProfile(accountRepo.Object, CancellationToken.None);

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

        var result = await controller.GetProfile(accountRepo.Object, CancellationToken.None);

        Assert.IsType<UnauthorizedResult>(result);
        accountRepo.Verify(r => r.GetByIdAsync(It.IsAny<Guid>()), Times.Never);
    }

    [Fact]
    public async Task GetProfile_WhenAccountNotFound_ReturnsUnauthorized()
    {
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo.Setup(r => r.GetByIdAsync(AccountId)).ReturnsAsync((AccountEntity?)null);
        var controller = CreateController(CreateAuthenticatedUser(AccountId));

        var result = await controller.GetProfile(accountRepo.Object, CancellationToken.None);

        Assert.IsType<UnauthorizedResult>(result);
    }

    [Fact]
    public async Task GetProfile_WhenAccountExists_ReturnsProfileResponse()
    {
        var account = CreateAccount(AccountId, nickname: "Alice", isActive: true);
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo.Setup(r => r.GetByIdAsync(AccountId)).ReturnsAsync(account);
        var controller = CreateController(CreateAuthenticatedUser(AccountId));

        var result = await controller.GetProfile(accountRepo.Object, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<ProfileResponse>(ok.Value);
        Assert.Equal(AccountId.ToString(), response.UserId);
        Assert.Equal("Alice", response.Nickname);
        Assert.True(response.IsActive);
        Assert.Equal(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds(), response.CreatedAt);
    }

    [Fact]
    public async Task GetProfile_WhenAccountExists_PropagatesActionToken()
    {
        using var cancellation = new CancellationTokenSource();
        var account = CreateAccount(AccountId);
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo.Setup(r => r.GetByIdAsync(AccountId, cancellation.Token)).ReturnsAsync(account);
        var controller = CreateController(CreateAuthenticatedUser(AccountId));

        var result = await controller.GetProfile(accountRepo.Object, cancellation.Token);

        Assert.IsType<OkObjectResult>(result);
        accountRepo.Verify(r => r.GetByIdAsync(AccountId, cancellation.Token), Times.Once);
    }

    [Fact]
    public async Task GetProfile_WhenAccountQueryIsCanceled_DoesNotReturnProfile()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo
            .Setup(r => r.GetByIdAsync(AccountId, cancellation.Token))
            .Returns(Task.FromCanceled<AccountEntity?>(cancellation.Token));
        var controller = CreateController(CreateAuthenticatedUser(AccountId));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            controller.GetProfile(accountRepo.Object, cancellation.Token));

        accountRepo.Verify(r => r.GetByIdAsync(AccountId, cancellation.Token), Times.Once);
    }

    [Fact]
    public async Task UpdateNickname_WithoutAuthenticatedUser_ReturnsUnauthorized()
    {
        var accountRepo = new Mock<IAccountRepository>();
        var unitOfWork = new Mock<IUnitOfWork>();
        var controller = CreateController(user: null);

        var result = await controller.UpdateNickname(
            new UpdateProfileNicknameRequest("new"), accountRepo.Object, unitOfWork.Object, CancellationToken.None);

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

        var result = await controller.UpdateNickname(
            new UpdateProfileNicknameRequest("new"), accountRepo.Object, unitOfWork.Object, CancellationToken.None);

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

        var result = await controller.UpdateNickname(
            new UpdateProfileNicknameRequest(longNickname), accountRepo.Object, unitOfWork.Object, CancellationToken.None);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        var err = Assert.IsType<ErrorResponse>(bad.Value);
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

        var result = await controller.UpdateNickname(
            new UpdateProfileNicknameRequest("NewName"), accountRepo.Object, unitOfWork.Object, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<OperationResponse>(ok.Value);
        Assert.True(response.Success);
        Assert.Equal("NewName", account.Nickname);
        accountRepo.Verify();
        unitOfWork.Verify();
    }

    [Fact]
    public async Task UpdateNickname_WithValidNickname_PropagatesSameActionToken()
    {
        using var cancellation = new CancellationTokenSource();
        var account = CreateAccount(AccountId, nickname: "old");
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo.Setup(r => r.GetByIdAsync(AccountId, cancellation.Token)).ReturnsAsync(account);
        accountRepo.Setup(r => r.UpdateAsync(account, cancellation.Token)).Returns(Task.CompletedTask);
        var unitOfWork = new Mock<IUnitOfWork>();
        unitOfWork.Setup(u => u.SaveChangesAsync(cancellation.Token)).ReturnsAsync(1);
        var controller = CreateController(CreateAuthenticatedUser(AccountId));

        var result = await controller.UpdateNickname(
            new UpdateProfileNicknameRequest("NewName"),
            accountRepo.Object,
            unitOfWork.Object,
            cancellation.Token);

        Assert.IsType<OkObjectResult>(result);
        accountRepo.Verify(r => r.GetByIdAsync(AccountId, cancellation.Token), Times.Once);
        accountRepo.Verify(r => r.UpdateAsync(account, cancellation.Token), Times.Once);
        unitOfWork.Verify(u => u.SaveChangesAsync(cancellation.Token), Times.Once);
    }

    [Fact]
    public async Task UpdateNickname_WhenCanceledBeforeCommit_DoesNotPersistOrReturnSuccess()
    {
        using var cancellation = new CancellationTokenSource();
        var account = CreateAccount(AccountId, nickname: "old");
        var persistedNickname = account.Nickname;
        var accountRepo = new Mock<IAccountRepository>();
        accountRepo.Setup(r => r.GetByIdAsync(AccountId, cancellation.Token)).ReturnsAsync(account);
        accountRepo
            .Setup(r => r.UpdateAsync(account, cancellation.Token))
            .Callback(cancellation.Cancel)
            .Returns(Task.CompletedTask);
        var unitOfWork = new Mock<IUnitOfWork>();
        unitOfWork
            .Setup(u => u.SaveChangesAsync(cancellation.Token))
            .Returns((CancellationToken token) =>
            {
                token.ThrowIfCancellationRequested();
                persistedNickname = account.Nickname;
                return Task.FromResult(1);
            });
        var controller = CreateController(CreateAuthenticatedUser(AccountId));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => controller.UpdateNickname(
            new UpdateProfileNicknameRequest("NewName"),
            accountRepo.Object,
            unitOfWork.Object,
            cancellation.Token));

        Assert.Equal("old", persistedNickname);
        unitOfWork.Verify(u => u.SaveChangesAsync(cancellation.Token), Times.Once);
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

        var result = await controller.UpdateNickname(
            new UpdateProfileNicknameRequest("   "), accountRepo.Object, unitOfWork.Object, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.True(Assert.IsType<OperationResponse>(ok.Value).Success);
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

        var result = await controller.UpdateNickname(
            new UpdateProfileNicknameRequest(null), accountRepo.Object, unitOfWork.Object, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.True(Assert.IsType<OperationResponse>(ok.Value).Success);
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

        var result = await controller.UpdateNickname(
            new UpdateProfileNicknameRequest(maxNickname), accountRepo.Object, unitOfWork.Object, CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
        Assert.Equal(maxNickname, account.Nickname);
        unitOfWork.Verify();
    }

    [Fact]
    public async Task BindWechat_PropagatesSameActionTokenThroughQueryExternalCallAdmissionAndAudit()
    {
        using var cancellation = new CancellationTokenSource();
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "app-1",
            AppName = "App",
            AppSecretHash = "hash",
            IsActive = true,
            WechatLoginMode = WechatLoginMode.BindRequired
        };
        var appRepository = new Mock<IAppRegistrationRepository>();
        appRepository.Setup(r => r.GetByAppIdAsync(app.AppId, cancellation.Token)).ReturnsAsync(app);
        var apiClient = new Mock<IWechatApiClient>();
        apiClient.Setup(client => client.CodeToSessionAsync("code", cancellation.Token)).ReturnsAsync("open-id");
        var auditService = new Mock<IAuditService>();
        auditService
            .Setup(service => service.RecordActionAsync(
                "wechat_bound", "Account", AccountId.ToString(), AccountId, null,
                It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<string?>(), null, null,
                cancellation.Token))
            .Returns(Task.CompletedTask);
        var admissionService = new Mock<IWechatAdmissionService>();
        admissionService
            .Setup(service => service.BindAsync(
                app, AccountId, "open-id", cancellation.Token,
                It.IsAny<Func<WechatBindResult, Task>>()))
            .Returns(async (AppRegistrationEntity _, Guid _, string _, CancellationToken _,
                Func<WechatBindResult, Task>? beforeCommit) =>
            {
                var result = new WechatBindResult(WechatBindOutcome.Bound);
                await beforeCommit!(result);
                return result;
            });
        var controller = CreateController(CreateAuthenticatedUser(AccountId, app.AppId));

        var result = await controller.BindWechat(
            new BindWechatRequest("code"),
            apiClient.Object,
            admissionService.Object,
            appRepository.Object,
            auditService.Object,
            cancellation.Token);

        Assert.IsType<OkObjectResult>(result);
        appRepository.Verify(r => r.GetByAppIdAsync(app.AppId, cancellation.Token), Times.Once);
        apiClient.Verify(client => client.CodeToSessionAsync("code", cancellation.Token), Times.Once);
        admissionService.Verify(service => service.BindAsync(
            app, AccountId, "open-id", cancellation.Token,
            It.IsAny<Func<WechatBindResult, Task>>()), Times.Once);
        auditService.Verify(service => service.RecordActionAsync(
            "wechat_bound", "Account", AccountId.ToString(), AccountId, null,
            It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<string?>(), null, null,
            cancellation.Token), Times.Once);
    }

    [Fact]
    public async Task UnbindWechat_PropagatesSameActionTokenThroughAdmissionAndAudit()
    {
        using var cancellation = new CancellationTokenSource();
        var auditService = new Mock<IAuditService>();
        auditService
            .Setup(service => service.RecordActionAsync(
                "wechat_unbound", "Account", AccountId.ToString(), AccountId, null,
                It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<string?>(), null, null,
                cancellation.Token))
            .Returns(Task.CompletedTask);
        var admissionService = new Mock<IWechatAdmissionService>();
        admissionService
            .Setup(service => service.UnbindAsync(
                AccountId, cancellation.Token, It.IsAny<Func<Task>>()))
            .Returns(async (Guid _, CancellationToken _, Func<Task>? beforeCommit) =>
            {
                await beforeCommit!();
                return true;
            });
        var controller = CreateController(CreateAuthenticatedUser(AccountId));

        var result = await controller.UnbindWechat(
            admissionService.Object,
            auditService.Object,
            cancellation.Token);

        Assert.IsType<OkObjectResult>(result);
        admissionService.Verify(service => service.UnbindAsync(
            AccountId, cancellation.Token, It.IsAny<Func<Task>>()), Times.Once);
        auditService.Verify(service => service.RecordActionAsync(
            "wechat_unbound", "Account", AccountId.ToString(), AccountId, null,
            It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<string?>(), null, null,
            cancellation.Token), Times.Once);
    }
}
