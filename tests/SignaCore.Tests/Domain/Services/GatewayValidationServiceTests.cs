using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

public class GatewayValidationServiceTests
{
    private static ILogger<GatewayValidationService> CreateLogger() => NullLogger<GatewayValidationService>.Instance;

    private static Mock<IAppRegistrationRepository> CreateAppRegRepoMock(AppRegistrationEntity? app = null)
    {
        var mock = new Mock<IAppRegistrationRepository>();
        mock.Setup(r => r.GetByAppIdAsync(It.IsAny<string>())).ReturnsAsync(app);
        return mock;
    }

    private static AppRegistrationEntity CreateActiveApp(string appId = "testapp", string appSecret = "testsecret")
    {
        return new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(appSecret),
            AppName = "Test App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            CallbackExpiresAt = DateTimeOffset.UtcNow.AddDays(1)
        };
    }

    [Fact]
    public async Task ValidateAsync_WithValidCredentials_ReturnsSuccess()
    {
        var app = CreateActiveApp();
        var repoMock = CreateAppRegRepoMock(app);
        var service = new GatewayValidationService(repoMock.Object, CreateLogger());

        var result = await service.ValidateAsync("testapp", "testsecret");

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.App);
        Assert.Equal("testapp", result.App.AppId);
    }

    [Fact]
    public async Task ValidateAsync_WithEmptyAppSecret_ReturnsFailure()
    {
        var repoMock = CreateAppRegRepoMock();
        var service = new GatewayValidationService(repoMock.Object, CreateLogger());

        var result = await service.ValidateAsync("testapp", "");

        Assert.False(result.IsSuccess);
        Assert.Equal("AppSecret is required", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithNullAppSecret_ReturnsFailure()
    {
        var repoMock = CreateAppRegRepoMock();
        var service = new GatewayValidationService(repoMock.Object, CreateLogger());

        var result = await service.ValidateAsync("testapp", null);

        Assert.False(result.IsSuccess);
        Assert.Equal("AppSecret is required", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithNonExistentAppId_ReturnsFailure()
    {
        var repoMock = CreateAppRegRepoMock(null);
        var service = new GatewayValidationService(repoMock.Object, CreateLogger());

        var result = await service.ValidateAsync("nonexistent", "secret");

        Assert.False(result.IsSuccess);
        Assert.Equal("AppId not registered", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithDisabledApp_ReturnsFailure()
    {
        var app = CreateActiveApp();
        app.IsActive = false;
        var repoMock = CreateAppRegRepoMock(app);
        var service = new GatewayValidationService(repoMock.Object, CreateLogger());

        var result = await service.ValidateAsync("testapp", "testsecret");

        Assert.False(result.IsSuccess);
        Assert.Equal("App is disabled", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithExpiredCallback_ReturnsFailure()
    {
        var app = CreateActiveApp();
        app.CallbackExpiresAt = DateTimeOffset.UtcNow.AddHours(-1);
        var repoMock = CreateAppRegRepoMock(app);
        var service = new GatewayValidationService(repoMock.Object, CreateLogger());

        var result = await service.ValidateAsync("testapp", "testsecret");

        Assert.False(result.IsSuccess);
        Assert.Equal("App registration has expired", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithNeverExpireCallback_ReturnsSuccess()
    {
        var app = CreateActiveApp();
        app.CallbackExpiresAt = null;
        app.CallbackUrl = "http://example.com/callback";
        var repoMock = CreateAppRegRepoMock(app);
        var service = new GatewayValidationService(repoMock.Object, CreateLogger());

        var result = await service.ValidateAsync("testapp", "testsecret");

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task ValidateAsync_WithWrongAppSecret_ReturnsFailure()
    {
        var app = CreateActiveApp();
        var repoMock = CreateAppRegRepoMock(app);
        var service = new GatewayValidationService(repoMock.Object, CreateLogger());

        var result = await service.ValidateAsync("testapp", "wrongsecret");

        Assert.False(result.IsSuccess);
        Assert.Equal("AppSecret mismatch", result.ErrorMessage);
    }
}
