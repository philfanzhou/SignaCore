using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

/// <summary>
/// /api/auth/* 四个 controller 的测试共用的替身工厂。
/// 原先这些都长在 AuthControllerTests 里，controller 拆开后提到这里，
/// 每个测试类只装配自己那几个依赖。
/// </summary>
internal static class AuthTestDoubles
{
    public static Mock<IKeyManager> KeyManager()
    {
        var mock = new Mock<IKeyManager>();
        mock.Setup(k => k.GetCurrentKey()).Returns(new RsaSecurityKey(RSA.Create(2048)));
        mock.Setup(k => k.RefreshKeysAsync()).Returns(Task.CompletedTask);
        mock.Setup(k => k.NeedsKeyRotationAsync()).ReturnsAsync(false);
        mock.Setup(k => k.InitializationCompleted).Returns(Task.CompletedTask);
        return mock;
    }

    public static Mock<ITokenService> TokenService()
    {
        var mock = new Mock<ITokenService>();
        mock.Setup(t => t.GenerateJwtToken(It.IsAny<List<Claim>>(), It.IsAny<RsaSecurityKey>(), It.IsAny<int>(), It.IsAny<string?>()))
            .Returns("token");
        return mock;
    }

    public static Mock<IRefreshTokenService> RefreshTokenService()
    {
        var mock = new Mock<IRefreshTokenService>();
        mock.Setup(s => s.HandleRefreshTokenAsync(
                It.IsAny<string>(),
                It.IsAny<string?>(),
                It.IsAny<AccountEntity>(),
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync("refresh");
        mock.Setup(s => s.RevokeAsync(It.IsAny<string>())).ReturnsAsync(true);
        return mock;
    }

    public static Mock<IUnitOfWork> UnitOfWork()
    {
        var mock = new Mock<IUnitOfWork>();
        mock.Setup(r => r.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);
        return mock;
    }

    public static Mock<IAuditService> AuditService()
    {
        var mock = new Mock<IAuditService>();
        mock.Setup(a => a.RecordLoginAsync(
                It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
                It.IsAny<string?>(), It.IsAny<string?>()))
            .Returns(Task.CompletedTask);
        return mock;
    }

    public static Mock<IAccountLoginInfoService> AccountLoginInfoService()
    {
        var mock = new Mock<IAccountLoginInfoService>();
        mock.Setup(s => s.UpdateLoginInfoAsync(It.IsAny<AccountEntity>(), It.IsAny<string?>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);
        return mock;
    }

    public static AuthMetrics AuthMetrics()
    {
        var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
        var meter = new System.Diagnostics.Metrics.Meter("SignaCore");
        meterFactory.Setup(m => m.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>())).Returns(meter);
        return new AuthMetrics(meterFactory.Object);
    }

    public static GatewayValidationService GatewayValidator(Mock<IAppRegistrationRepository> appRegRepoMock) =>
        new(appRegRepoMock.Object, NullLogger<GatewayValidationService>.Instance);

    /// <summary>管理员身份配置，默认用户名 admin；个别测试可通过 username 覆盖。</summary>
    public static AdminIdentityOptions AdminIdentity(string username = "admin") =>
        new() { Username = username };

    /// <summary>给 controller 装一个带固定远端 IP 的 HttpContext。</summary>
    public static T WithHttpContext<T>(this T controller) where T : ControllerBase
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
        return controller;
    }

    public static OkObjectResult ExtractOk<T>(ActionResult<T> actionResult) =>
        Assert.IsType<OkObjectResult>(actionResult.Result!);
}
