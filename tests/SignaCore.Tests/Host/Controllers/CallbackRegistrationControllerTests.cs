using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Host.Controllers;
using SignaCore.Host.Http;
using SignaCore.Host.Models;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

public class CallbackRegistrationControllerTests
{
    private readonly Mock<IAppRegistrationRepository> _appRegistrationRepoMock = new();
    private readonly Mock<IUnitOfWork> _unitOfWorkMock = AuthTestDoubles.UnitOfWork();

    private CallbackRegistrationController CreateController(CallbackUrlValidator? validator = null) =>
        new CallbackRegistrationController(
            _appRegistrationRepoMock.Object,
            validator ?? new CallbackUrlValidator(),
            _unitOfWorkMock.Object,
            NullLogger<CallbackRegistrationController>.Instance)
            .WithHttpContext();

    private CallbackRegistrationController CreateControllerWithCredentials(string appId, string appSecret)
    {
        var controller = CreateController();
        controller.HttpContext.Request.Headers[IdentityHeaders.AppId] = appId;
        controller.HttpContext.Request.Headers[IdentityHeaders.AppSecret] = appSecret;
        return controller;
    }

    private AppRegistrationEntity SeedApp(string appId = "app-1", string secret = "real-secret")
    {
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(secret),
            AppName = "App",
            IsActive = true
        };
        _appRegistrationRepoMock
            .Setup(r => r.GetByAppIdAsync(appId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(app);
        return app;
    }

    [Fact]
    public async Task RegisterCallback_WithoutAppIdHeader_ReturnsAppIdRequiredError()
    {
        // The X-Admin-AppId / X-Admin-AppSecret headers are deliberately left unset.
        var controller = CreateController();

        var request = new RegisterCallbackRequest
        {
            CallbackUrl = "http://example.com/callback",
            TtlSeconds = 3600
        };

        var actionResult = await controller.RegisterCallback(request, TestContext.Current.CancellationToken);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<RegisterCallbackResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("AppId and AppSecret are required", response.Message);
    }

    [Fact]
    public async Task RegisterCallback_InvalidUrl_ReturnsError()
    {
        var controller = CreateControllerWithCredentials("app-1", "secret");

        var request = new RegisterCallbackRequest { CallbackUrl = "not a url", TtlSeconds = 3600 };

        var actionResult = await controller.RegisterCallback(request, TestContext.Current.CancellationToken);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<RegisterCallbackResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.StartsWith("Invalid callback URL", response.Message);
    }

    [Fact]
    public async Task RegisterCallback_AppNotRegistered_ReturnsError()
    {
        var controller = CreateControllerWithCredentials("unknown-app", "secret");

        var request = new RegisterCallbackRequest { CallbackUrl = "http://example.com/cb", TtlSeconds = 3600 };

        var actionResult = await controller.RegisterCallback(request, TestContext.Current.CancellationToken);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<RegisterCallbackResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("AppId not registered", response.Message);
    }

    [Fact]
    public async Task RegisterCallback_SecretMismatch_ReturnsError()
    {
        SeedApp();
        var controller = CreateControllerWithCredentials("app-1", "wrong-secret");

        var request = new RegisterCallbackRequest { CallbackUrl = "http://example.com/cb", TtlSeconds = 3600 };

        var actionResult = await controller.RegisterCallback(request, TestContext.Current.CancellationToken);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<RegisterCallbackResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("AppSecret mismatch", response.Message);
    }

    [Fact]
    public async Task RegisterCallback_Success_UsesDefaultTtlWhenNonPositive()
    {
        SeedApp();
        var controller = CreateControllerWithCredentials("app-1", "real-secret");

        var request = new RegisterCallbackRequest { CallbackUrl = "http://example.com/cb", TtlSeconds = 0 };

        var actionResult = await controller.RegisterCallback(request, TestContext.Current.CancellationToken);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<RegisterCallbackResponse>(ok.Value!);
        Assert.True(response.Success);
        Assert.True(response.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(IdentityConstants.DefaultCallbackTtlSeconds - 60).ToUnixTimeSeconds());
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RegisterCallback_NeverExpire_ReturnsZeroExpiresAt()
    {
        var app = SeedApp();
        var controller = CreateControllerWithCredentials("app-1", "real-secret");

        var request = new RegisterCallbackRequest { CallbackUrl = "http://example.com/cb", TtlSeconds = IdentityConstants.CallbackTtlNeverExpire };

        var actionResult = await controller.RegisterCallback(request, TestContext.Current.CancellationToken);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<RegisterCallbackResponse>(ok.Value!);
        Assert.True(response.Success);
        Assert.Equal(0, response.ExpiresAt);
        Assert.Null(app.CallbackExpiresAt);
    }

    [Fact]
    public async Task RegisterCallback_PropagatesSameActionTokenToValidationFallbackQueryAndCommit()
    {
        using var cancellation = new CancellationTokenSource();
        var resolvedToken = CancellationToken.None;
        var validator = new CallbackUrlValidator(
            allowedDomains: null,
            allowPrivateAddresses: false,
            requireHttps: false,
            (host, token) =>
            {
                Assert.Equal("public.example", host);
                resolvedToken = token;
                return Task.FromResult<IPAddress[]?>([IPAddress.Parse("8.8.8.8")]);
            });
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "app-1",
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword("real-secret"),
            AppName = "App",
            IsActive = true
        };
        _appRegistrationRepoMock
            .Setup(r => r.GetByAppIdAsync(app.AppId, cancellation.Token))
            .ReturnsAsync(app);
        _unitOfWorkMock
            .Setup(u => u.SaveChangesAsync(cancellation.Token))
            .ReturnsAsync(1);
        var controller = new CallbackRegistrationController(
                _appRegistrationRepoMock.Object,
                validator,
                _unitOfWorkMock.Object,
                NullLogger<CallbackRegistrationController>.Instance)
            .WithHttpContext();
        controller.HttpContext.Request.Headers[IdentityHeaders.AppId] = app.AppId;
        controller.HttpContext.Request.Headers[IdentityHeaders.AppSecret] = "real-secret";

        var actionResult = await controller.RegisterCallback(
            new RegisterCallbackRequest
            {
                CallbackUrl = "https://public.example/callback",
                TtlSeconds = 3600
            },
            cancellation.Token);

        var response = Assert.IsType<RegisterCallbackResponse>(AuthTestDoubles.ExtractOk(actionResult).Value);
        Assert.True(response.Success);
        Assert.Equal(cancellation.Token, resolvedToken);
        _appRegistrationRepoMock.Verify(
            r => r.GetByAppIdAsync(app.AppId, cancellation.Token),
            Times.Once);
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(cancellation.Token), Times.Once);
    }
}
