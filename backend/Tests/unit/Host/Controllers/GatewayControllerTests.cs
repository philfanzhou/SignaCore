using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain.Models;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Host.Controllers;
using QuantumZhou.Identity.Host.Models;
using Xunit;

namespace QuantumZhou.Identity.Tests.Host.Controllers;

public class GatewayControllerTests : IDisposable
{
    private readonly IdentityDbContext _dbContext;
    private readonly UserQueryService _userQueryService;
    private readonly GatewayController _controller;
    private readonly Mock<IAppRegistrationRepository> _appRepoMock;

    public GatewayControllerTests()
    {
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        _dbContext = new IdentityDbContext(options);
        _userQueryService = new UserQueryService(_dbContext);

        _appRepoMock = new Mock<IAppRegistrationRepository>();
        var validationService = new GatewayValidationService(_appRepoMock.Object, NullLogger<GatewayValidationService>.Instance);

        _controller = new GatewayController(NullLogger<GatewayController>.Instance);
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        httpContext.Request.IsHttps = true;
        _controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    private void SetGatewayHeaders(string? appId, string? appSecret)
    {
        _controller.HttpContext.Request.Headers.Remove(GatewayController.AppIdHeader);
        _controller.HttpContext.Request.Headers.Remove(GatewayController.AppSecretHeader);
        if (appId != null)
        {
            _controller.HttpContext.Request.Headers[GatewayController.AppIdHeader] = appId;
        }
        if (appSecret != null)
        {
            _controller.HttpContext.Request.Headers[GatewayController.AppSecretHeader] = appSecret;
        }
    }

    private void RegisterValidApp(string appId = "testapp", string appSecret = "testsecret")
    {
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(appSecret),
            AppName = "Test App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        _appRepoMock.Setup(r => r.GetByAppIdAsync(appId)).ReturnsAsync(app);
    }

    private AccountEntity SeedAccount(string? nickname = null, string? remark = null, bool isActive = true)
    {
        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            Nickname = nickname,
            Remark = remark,
            IsActive = isActive,
            CreatedAt = DateTimeOffset.UtcNow
        };
        _dbContext.Accounts.Add(account);
        _dbContext.SaveChanges();
        return account;
    }

    private void SeedPasswordCredential(Guid accountId, string username)
    {
        _dbContext.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = username,
            PasswordHash = "hash",
            CreatedAt = DateTimeOffset.UtcNow
        });
        _dbContext.SaveChanges();
    }

    private void SeedSmsLogin(Guid accountId, string phone)
    {
        _dbContext.UserLogins.Add(new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            ProviderName = IdentityConstants.AuthMethodSms,
            ProviderUserId = phone
        });
        _dbContext.SaveChanges();
    }

    [Fact]
    public async Task SearchUsers_WithoutAppIdHeader_Returns401()
    {
        SetGatewayHeaders(null, "secret");

        var result = await _controller.SearchUsers(null, null, null, null, _userQueryService, CreateValidationService());

        var status = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, status.StatusCode);
        var err = Assert.IsType<AdminApiErrorResponse>(status.Value);
        Assert.Contains("Missing gateway credentials", err.Message);
    }

    [Fact]
    public async Task SearchUsers_WithoutAppSecretHeader_Returns401()
    {
        SetGatewayHeaders("app", null);

        var result = await _controller.SearchUsers(null, null, null, null, _userQueryService, CreateValidationService());

        var status = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, status.StatusCode);
    }

    [Fact]
    public async Task SearchUsers_WithInvalidCredentials_Returns401()
    {
        SetGatewayHeaders("wrongapp", "wrongsecret");
        // No app registered, so validation will fail

        var result = await _controller.SearchUsers(null, null, null, null, _userQueryService, CreateValidationService());

        var status = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, status.StatusCode);
    }

    [Fact]
    public async Task SearchUsers_WithValidCredentials_ReturnsPagedResults()
    {
        SetGatewayHeaders("testapp", "testsecret");
        RegisterValidApp();
        var acc1 = SeedAccount(nickname: "Alice");
        var acc2 = SeedAccount(nickname: "Bob");
        SeedPasswordCredential(acc1.Id, "alice123");

        var result = await _controller.SearchUsers(null, null, null, null, _userQueryService, CreateValidationService());

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminPagedResponse<AdminUserListItemResponse>>(ok.Value);
        Assert.Equal(2, response.Total);
        Assert.Equal(2, response.Items.Count);
        Assert.Equal(1, response.Page);
        Assert.Equal(20, response.PageSize);
    }

    [Fact]
    public async Task SearchUsers_WithUsernameFilter_ReturnsMatchingAccounts()
    {
        SetGatewayHeaders("testapp", "testsecret");
        RegisterValidApp();
        var acc1 = SeedAccount(nickname: "Alice");
        var acc2 = SeedAccount(nickname: "Bob");
        SeedPasswordCredential(acc1.Id, "alice123");
        SeedPasswordCredential(acc2.Id, "bob456");

        var result = await _controller.SearchUsers("alice", null, null, null, _userQueryService, CreateValidationService());

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminPagedResponse<AdminUserListItemResponse>>(ok.Value);
        Assert.Equal(1, response.Total);
        Assert.Equal("alice123", response.Items[0].Username);
    }

    [Fact]
    public async Task SearchUsers_WithPhoneFilter_ReturnsMatchingAccounts()
    {
        SetGatewayHeaders("testapp", "testsecret");
        RegisterValidApp();
        var acc1 = SeedAccount();
        var acc2 = SeedAccount();
        SeedSmsLogin(acc1.Id, "13800000001");
        SeedSmsLogin(acc2.Id, "13900000002");

        var result = await _controller.SearchUsers(null, "138", null, null, _userQueryService, CreateValidationService());

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminPagedResponse<AdminUserListItemResponse>>(ok.Value);
        Assert.Equal(1, response.Total);
        Assert.Contains("138", response.Items[0].Phone);
    }

    [Fact]
    public async Task SearchUsers_WithCustomPageSize_AppliesPaging()
    {
        SetGatewayHeaders("testapp", "testsecret");
        RegisterValidApp();
        for (var i = 0; i < 5; i++)
        {
            SeedAccount(nickname: $"User{i}");
        }

        var result = await _controller.SearchUsers(null, null, 1, 2, _userQueryService, CreateValidationService());

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminPagedResponse<AdminUserListItemResponse>>(ok.Value);
        Assert.Equal(5, response.Total);
        Assert.Equal(2, response.Items.Count);
        Assert.Equal(2, response.PageSize);
    }

    [Fact]
    public async Task SearchUsers_WithInvalidPage_DefaultsToOne()
    {
        SetGatewayHeaders("testapp", "testsecret");
        RegisterValidApp();
        SeedAccount();

        var result = await _controller.SearchUsers(null, null, -1, 10, _userQueryService, CreateValidationService());

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminPagedResponse<AdminUserListItemResponse>>(ok.Value);
        Assert.Equal(1, response.Page);
    }

    [Fact]
    public async Task SearchUsers_WithInvalidPageSize_DefaultsTo20()
    {
        SetGatewayHeaders("testapp", "testsecret");
        RegisterValidApp();
        SeedAccount();

        var result = await _controller.SearchUsers(null, null, 1, -5, _userQueryService, CreateValidationService());

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminPagedResponse<AdminUserListItemResponse>>(ok.Value);
        Assert.Equal(20, response.PageSize);
    }

    [Fact]
    public async Task SearchUsers_PageSizeCappedAt100()
    {
        SetGatewayHeaders("testapp", "testsecret");
        RegisterValidApp();
        SeedAccount();

        var result = await _controller.SearchUsers(null, null, 1, 500, _userQueryService, CreateValidationService());

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AdminPagedResponse<AdminUserListItemResponse>>(ok.Value);
        Assert.Equal(100, response.PageSize);
    }

    [Fact]
    public async Task GetUsersByIds_WithoutCredentials_Returns401()
    {
        SetGatewayHeaders(null, null);

        var result = await _controller.GetUsersByIds(new List<string> { Guid.NewGuid().ToString() }, _userQueryService, CreateValidationService());

        var status = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status401Unauthorized, status.StatusCode);
    }

    [Fact]
    public async Task GetUsersByIds_WithNullList_ReturnsEmptyList()
    {
        SetGatewayHeaders("testapp", "testsecret");
        RegisterValidApp();

        var result = await _controller.GetUsersByIds(null, _userQueryService, CreateValidationService());

        var ok = Assert.IsType<OkObjectResult>(result);
        var list = Assert.IsType<List<AdminUserListItemResponse>>(ok.Value);
        Assert.Empty(list);
    }

    [Fact]
    public async Task GetUsersByIds_WithEmptyList_ReturnsEmptyList()
    {
        SetGatewayHeaders("testapp", "testsecret");
        RegisterValidApp();

        var result = await _controller.GetUsersByIds(new List<string>(), _userQueryService, CreateValidationService());

        var ok = Assert.IsType<OkObjectResult>(result);
        var list = Assert.IsType<List<AdminUserListItemResponse>>(ok.Value);
        Assert.Empty(list);
    }

    [Fact]
    public async Task GetUsersByIds_WithInvalidGuids_ReturnsEmptyList()
    {
        SetGatewayHeaders("testapp", "testsecret");
        RegisterValidApp();

        var result = await _controller.GetUsersByIds(new List<string> { "not-a-guid", "also-bad" }, _userQueryService, CreateValidationService());

        var ok = Assert.IsType<OkObjectResult>(result);
        var list = Assert.IsType<List<AdminUserListItemResponse>>(ok.Value);
        Assert.Empty(list);
    }

    [Fact]
    public async Task GetUsersByIds_WithValidIds_ReturnsMatchingUsersInOrder()
    {
        SetGatewayHeaders("testapp", "testsecret");
        RegisterValidApp();
        var acc1 = SeedAccount(nickname: "Alice");
        var acc2 = SeedAccount(nickname: "Bob");
        SeedPasswordCredential(acc1.Id, "alice");
        SeedPasswordCredential(acc2.Id, "bob");

        var ids = new List<string> { acc2.Id.ToString(), acc1.Id.ToString() };
        var result = await _controller.GetUsersByIds(ids, _userQueryService, CreateValidationService());

        var ok = Assert.IsType<OkObjectResult>(result);
        var list = Assert.IsType<List<AdminUserListItemResponse>>(ok.Value);
        Assert.Equal(2, list.Count);
        // Order should match input order
        Assert.Equal(acc2.Id.ToString(), list[0].UserId);
        Assert.Equal(acc1.Id.ToString(), list[1].UserId);
    }

    [Fact]
    public async Task GetUsersByIds_WithDuplicateIds_ReturnsUniqueUsers()
    {
        SetGatewayHeaders("testapp", "testsecret");
        RegisterValidApp();
        var acc1 = SeedAccount(nickname: "Alice");

        var ids = new List<string> { acc1.Id.ToString(), acc1.Id.ToString(), acc1.Id.ToString() };
        var result = await _controller.GetUsersByIds(ids, _userQueryService, CreateValidationService());

        var ok = Assert.IsType<OkObjectResult>(result);
        var list = Assert.IsType<List<AdminUserListItemResponse>>(ok.Value);
        Assert.Single(list);
    }

    [Fact]
    public async Task GetUsersByIds_WithWhitespaceIds_FiltersThemOut()
    {
        SetGatewayHeaders("testapp", "testsecret");
        RegisterValidApp();
        var acc1 = SeedAccount(nickname: "Alice");

        var ids = new List<string> { "  ", acc1.Id.ToString(), "" };
        var result = await _controller.GetUsersByIds(ids, _userQueryService, CreateValidationService());

        var ok = Assert.IsType<OkObjectResult>(result);
        var list = Assert.IsType<List<AdminUserListItemResponse>>(ok.Value);
        Assert.Single(list);
    }

    private GatewayValidationService CreateValidationService()
    {
        return new GatewayValidationService(_appRepoMock.Object, NullLogger<GatewayValidationService>.Instance);
    }
}
