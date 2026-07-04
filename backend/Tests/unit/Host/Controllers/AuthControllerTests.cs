using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Services.Sms;
using QuantumZhou.Identity.Domain.Validators;
using QuantumZhou.Identity.Host.Controllers;
using QuantumZhou.Identity.Host.Models;
using Xunit;

namespace QuantumZhou.Identity.Tests.Host.Controllers;

public class AuthControllerTests
{
    private readonly Mock<IKeyManager> _keyManagerMock;
    private readonly Mock<ITokenService> _tokenServiceMock;
    private readonly JwtOptions _jwtOptions;
    private readonly Mock<IAppRegistrationRepository> _appRegistrationRepoMock;
    private readonly Mock<IRefreshTokenService> _refreshTokenServiceMock;
    private readonly ClaimsResolver _claimsResolver;
    private readonly Mock<IUnitOfWork> _unitOfWorkMock;
    private readonly Mock<IAuditService> _auditServiceMock;
    private readonly Mock<IOtpService> _otpServiceMock;
    private readonly Mock<ISmsSender> _smsSenderMock;
    private readonly Mock<IAccountLoginInfoService> _accountLoginInfoServiceMock;

    public AuthControllerTests()
    {
        _keyManagerMock = CreateMockKeyManager();
        _tokenServiceMock = CreateMockTokenService();
        _jwtOptions = new JwtOptions
        {
            Issuer = "TestIssuer",
            Audience = "TestAudience",
            TokenExpirationHours = 2
        };
        _appRegistrationRepoMock = new Mock<IAppRegistrationRepository>();
        _refreshTokenServiceMock = CreateRefreshTokenServiceMock();
        _claimsResolver = new ClaimsResolver(NullLogger<ClaimsResolver>.Instance);
        _unitOfWorkMock = CreateUnitOfWorkMock();
        _auditServiceMock = CreateAuditServiceMock();
        _otpServiceMock = new Mock<IOtpService>();
        _smsSenderMock = new Mock<ISmsSender>();
        _accountLoginInfoServiceMock = CreateAccountLoginInfoServiceMock();
    }

    private static Mock<IKeyManager> CreateMockKeyManager()
    {
        var mock = new Mock<IKeyManager>();
        mock.Setup(k => k.GetCurrentKey()).Returns(new RsaSecurityKey(RSA.Create(2048)));
        mock.Setup(k => k.NeedsKeyRotationAsync()).ReturnsAsync(false);
        mock.Setup(k => k.InitializationCompleted).Returns(Task.CompletedTask);
        return mock;
    }

    private static Mock<ITokenService> CreateMockTokenService()
    {
        var mock = new Mock<ITokenService>();
        mock.Setup(t => t.GenerateJwtToken(It.IsAny<List<Claim>>(), It.IsAny<RsaSecurityKey>(), It.IsAny<int>()))
            .Returns("token");
        return mock;
    }

    private static Mock<IRefreshTokenService> CreateRefreshTokenServiceMock()
    {
        var mock = new Mock<IRefreshTokenService>();
        mock.Setup(s => s.HandleRefreshTokenAsync(It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<AccountEntity>(), It.IsAny<string?>()))
            .ReturnsAsync("refresh");
        mock.Setup(s => s.RevokeAsync(It.IsAny<string>())).ReturnsAsync(true);
        return mock;
    }

    private static Mock<IUnitOfWork> CreateUnitOfWorkMock()
    {
        var mock = new Mock<IUnitOfWork>();
        mock.Setup(r => r.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);
        return mock;
    }

    private static Mock<IAuditService> CreateAuditServiceMock()
    {
        var mock = new Mock<IAuditService>();
        mock.Setup(a => a.RecordLoginAsync(
                It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
                It.IsAny<string?>(), It.IsAny<string?>()))
            .Returns(Task.CompletedTask);
        return mock;
    }

    private static Mock<IAccountLoginInfoService> CreateAccountLoginInfoServiceMock()
    {
        var mock = new Mock<IAccountLoginInfoService>();
        mock.Setup(s => s.UpdateLoginInfoAsync(It.IsAny<AccountEntity>(), It.IsAny<string?>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);
        return mock;
    }

    private static AuthMetrics CreateAuthMetrics()
    {
        var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
        var meter = new System.Diagnostics.Metrics.Meter("QuantumZhou.Identity");
        meterFactory.Setup(m => m.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>())).Returns(meter);
        return new AuthMetrics(meterFactory.Object);
    }

    private static GatewayValidationService CreateGatewayValidator(Mock<IAppRegistrationRepository> appRegRepoMock)
    {
        return new GatewayValidationService(
            appRegRepoMock.Object,
            NullLogger<GatewayValidationService>.Instance);
    }

    private AuthController CreateController(IIdentityValidator[] validators)
    {
        var factory = new ValidatorFactory(validators, NullLogger<ValidatorFactory>.Instance);
        var callbackUrlValidator = new CallbackUrlValidator();
        var controller = new AuthController(
            _keyManagerMock.Object,
            _tokenServiceMock.Object,
            _jwtOptions,
            _appRegistrationRepoMock.Object,
            _refreshTokenServiceMock.Object,
            _claimsResolver,
            factory,
            null,
            CreateAuthMetrics(),
            NullLogger<AuthController>.Instance,
            CreateGatewayValidator(_appRegistrationRepoMock),
            callbackUrlValidator,
            _unitOfWorkMock.Object,
            _auditServiceMock.Object,
            _otpServiceMock.Object,
            _smsSenderMock.Object,
            _accountLoginInfoServiceMock.Object);
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
        return controller;
    }

    private static OkObjectResult ExtractOkResult<T>(ActionResult<T> actionResult)
    {
        return Assert.IsType<OkObjectResult>(actionResult.Result!);
    }

    [Fact]
    public async Task GetToken_WithUnsupportedGrantType_ReturnsUnsupportedGrantTypeMessage()
    {
        var controller = CreateController(Array.Empty<IIdentityValidator>());

        var request = new TokenRequest { GrantType = "invalid" };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("unsupported_grant_type", response.Message);
    }

    [Fact]
    public async Task GetToken_WithSmsGrantType_ReturnsSuccessAndTokens()
    {
        var accountId = Guid.NewGuid();
        var account = new AccountEntity
        {
            Id = accountId,
            Nickname = "TestUser",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        var validatorMock = new Mock<IIdentityValidator>();
        validatorMock.SetupGet(v => v.GrantType).Returns("sms");
        validatorMock.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Success(account, "Sms", "TestUser"));

        var controller = CreateController(new[] { validatorMock.Object });

        var request = new TokenRequest
        {
            GrantType = "sms",
            Phone = "13800138000",
            Code = "666666"
        };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);
        Assert.Equal("token", response.AccessToken);
        Assert.Equal("refresh", response.RefreshToken);

        _keyManagerMock.Verify(k => k.GetCurrentKey(), Times.Once);
        _tokenServiceMock.Verify(t => t.GenerateJwtToken(It.IsAny<List<Claim>>(), It.IsAny<RsaSecurityKey>(), 2), Times.Once);
        _refreshTokenServiceMock.Verify(
            s => s.HandleRefreshTokenAsync("sms", It.IsAny<string?>(), It.Is<AccountEntity>(a => a.Id == accountId), It.IsAny<string?>()),
            Times.Once);
    }

    [Fact]
    public async Task RequestSmsCode_WithEmptyPhone_ReturnsPhoneRequiredError()
    {
        var controller = CreateController(Array.Empty<IIdentityValidator>());

        var request = new SmsCodeRequest { Phone = "" };

        var actionResult = await controller.RequestSmsCode(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<SmsCodeResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("Phone number is required", response.Message);
    }

    [Fact]
    public async Task RevokeRefreshToken_WithEmptyToken_ReturnsFailure()
    {
        var controller = CreateController(Array.Empty<IIdentityValidator>());

        var request = new RevokeRequest { RefreshToken = "" };

        var actionResult = await controller.RevokeRefreshToken(request);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<RevokeResponse>(ok.Value!);
        Assert.False(response.Success);

        _refreshTokenServiceMock.Verify(s => s.RevokeAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task RegisterCallback_WithoutAppIdHeader_ReturnsAppIdRequiredError()
    {
        var controller = CreateController(Array.Empty<IIdentityValidator>());
        // Intentionally do not set X-Admin-AppId / X-Admin-AppSecret headers

        var request = new RegisterCallbackHttpRequest
        {
            CallbackUrl = "http://example.com/callback",
            TtlSeconds = 3600
        };

        var actionResult = await controller.RegisterCallback(request);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<RegisterCallbackHttpResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("AppId and AppSecret are required", response.Message);
    }
}
