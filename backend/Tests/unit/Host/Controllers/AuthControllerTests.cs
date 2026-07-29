using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Services.Sms;
using QuantumZhou.Identity.Domain.Validators;
using QuantumZhou.Identity.Host;
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
    private readonly Mock<IAccountRepository> _accountRepositoryMock;

    // Bootstrap admin config: defaults to "admin"; individual tests can override via
    // CreateBootstrapOptions(Action<AdminBootstrapOptions>).
    private readonly Mock<IOptions<AdminBootstrapOptions>> _adminBootstrapOptionsMock;

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
        _accountRepositoryMock = new Mock<IAccountRepository>();
        _adminBootstrapOptionsMock = CreateBootstrapOptions();
    }

    private static Mock<IOptions<AdminBootstrapOptions>> CreateBootstrapOptions(Action<AdminBootstrapOptions>? configure = null)
    {
        var options = new AdminBootstrapOptions { Username = "admin" };
        configure?.Invoke(options);
        var mock = new Mock<IOptions<AdminBootstrapOptions>>();
        mock.Setup(o => o.Value).Returns(options);
        return mock;
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
        return CreateController(validators, _adminBootstrapOptionsMock);
    }

    private AuthController CreateController(IIdentityValidator[] validators, Mock<IOptions<AdminBootstrapOptions>> bootstrapOptionsMock)
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
            _accountLoginInfoServiceMock.Object,
            _accountRepositoryMock.Object,
            bootstrapOptionsMock.Object);
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
        return controller;
    }

    // Class-level field populated by the token service mock callback so tests can assert claims.
    private List<Claim>? _capturedClaims;

    // Configures the token service mock to capture the claims passed to GenerateJwtToken.
    private void BeginCaptureGeneratedClaims()
    {
        _capturedClaims = null;
        _tokenServiceMock.Setup(t => t.GenerateJwtToken(It.IsAny<List<Claim>>(), It.IsAny<RsaSecurityKey>(), It.IsAny<int>()))
            .Callback((List<Claim> claims, RsaSecurityKey _, int __) => _capturedClaims = claims)
            .Returns("token");
    }

    private List<Claim> AssertCapturedClaims()
    {
        Assert.NotNull(_capturedClaims);
        return _capturedClaims;
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

    // ===== GetToken failure branches =====

    [Fact]
    public async Task GetToken_GatewayValidationFails_ReturnsFailureAndAuditsWithAppId()
    {
        var controller = CreateController(Array.Empty<IIdentityValidator>());
        controller.HttpContext.Request.Headers["X-Admin-AppId"] = "unregistered-app";
        controller.HttpContext.Request.Headers["X-Admin-AppSecret"] = "any-secret";
        // _appRegistrationRepoMock.GetByAppIdAsync returns null by default -> "AppId not registered"

        var request = new TokenRequest { GrantType = "password", Username = "alice", Password = "x" };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("AppId not registered", response.Message);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            null, "unknown", "password", "login_failure",
            It.IsAny<string?>(), It.IsAny<string?>(), "AppId not registered",
            "unregistered-app", It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task GetToken_ValidatorFails_ReturnsFailureAndAuditsUnknownFallback()
    {
        var validatorMock = new Mock<IIdentityValidator>();
        validatorMock.SetupGet(v => v.GrantType).Returns("sms");
        validatorMock.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Failure("invalid code"));
        var controller = CreateController(new[] { validatorMock.Object });

        // Username/Phone/Code all null -> failedUsername falls back to "unknown"
        var request = new TokenRequest { GrantType = "sms" };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("invalid code", response.Message);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            null, "unknown", "sms", "login_failure",
            It.IsAny<string?>(), It.IsAny<string?>(), "invalid code",
            It.IsAny<string?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task GetToken_ValidatorFails_UsesPhoneAsFailedUsername()
    {
        var validatorMock = new Mock<IIdentityValidator>();
        validatorMock.SetupGet(v => v.GrantType).Returns("sms");
        validatorMock.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Failure("invalid code"));
        var controller = CreateController(new[] { validatorMock.Object });

        var request = new TokenRequest { GrantType = "sms", Phone = "13800138000" };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        Assert.False(Assert.IsType<TokenResponse>(ok.Value!).Success);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            null, "13800138000", "sms", "login_failure",
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<string?>()), Times.Once);
    }

    // ===== RequestSmsCode branches =====

    [Fact]
    public async Task RequestSmsCode_Success_ReturnsSentAndAudits()
    {
        _otpServiceMock.Setup(o => o.GenerateAndSendAsync("13800138000", _smsSenderMock.Object))
            .ReturnsAsync("123456");
        var controller = CreateController(Array.Empty<IIdentityValidator>());

        var request = new SmsCodeRequest { Phone = "13800138000" };

        var actionResult = await controller.RequestSmsCode(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<SmsCodeResponse>(ok.Value!);
        Assert.True(response.Success);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            null, "13800138000", "sms", "sms_code_sent",
            It.IsAny<string?>(), It.IsAny<string?>(), null,
            It.IsAny<string?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task RequestSmsCode_GatewayValidationFails_ReturnsFailure()
    {
        var controller = CreateController(Array.Empty<IIdentityValidator>());
        controller.HttpContext.Request.Headers["X-Admin-AppId"] = "unregistered-app";
        controller.HttpContext.Request.Headers["X-Admin-AppSecret"] = "any-secret";

        var request = new SmsCodeRequest { Phone = "13800138000" };

        var actionResult = await controller.RequestSmsCode(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<SmsCodeResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("AppId not registered", response.Message);
        _otpServiceMock.Verify(o => o.GenerateAndSendAsync(It.IsAny<string>(), It.IsAny<ISmsSender>()), Times.Never);
    }

    [Fact]
    public async Task RequestSmsCode_OtpLocked_ReturnsLockMessage()
    {
        _otpServiceMock.Setup(o => o.GenerateAndSendAsync(It.IsAny<string>(), It.IsAny<ISmsSender>()))
            .ThrowsAsync(new InvalidOperationException("Too many attempts. Please try again in 590 seconds."));
        var controller = CreateController(Array.Empty<IIdentityValidator>());

        var request = new SmsCodeRequest { Phone = "13800138000" };

        var actionResult = await controller.RequestSmsCode(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<SmsCodeResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("Too many attempts. Please try again in 590 seconds.", response.Message);
    }

    [Fact]
    public async Task RequestSmsCode_UnexpectedException_ReturnsGenericMessage()
    {
        _otpServiceMock.Setup(o => o.GenerateAndSendAsync(It.IsAny<string>(), It.IsAny<ISmsSender>()))
            .ThrowsAsync(new Exception("smtp down"));
        var controller = CreateController(Array.Empty<IIdentityValidator>());

        var request = new SmsCodeRequest { Phone = "13800138000" };

        var actionResult = await controller.RequestSmsCode(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<SmsCodeResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("Failed to send verification code", response.Message);
    }

    // ===== RevokeRefreshToken branches =====

    [Fact]
    public async Task RevokeRefreshToken_TokenFound_ReturnsTrue()
    {
        _refreshTokenServiceMock.Setup(s => s.RevokeAsync("rt-1")).ReturnsAsync(true);
        var controller = CreateController(Array.Empty<IIdentityValidator>());

        var actionResult = await controller.RevokeRefreshToken(new RevokeRequest { RefreshToken = "rt-1" });

        var ok = ExtractOkResult(actionResult);
        Assert.True(Assert.IsType<RevokeResponse>(ok.Value!).Success);
    }

    [Fact]
    public async Task RevokeRefreshToken_TokenMissing_ReturnsFalse()
    {
        _refreshTokenServiceMock.Setup(s => s.RevokeAsync("missing")).ReturnsAsync(false);
        var controller = CreateController(Array.Empty<IIdentityValidator>());

        var actionResult = await controller.RevokeRefreshToken(new RevokeRequest { RefreshToken = "missing" });

        var ok = ExtractOkResult(actionResult);
        Assert.False(Assert.IsType<RevokeResponse>(ok.Value!).Success);
    }

    // ===== RegisterCallback branches =====

    [Fact]
    public async Task RegisterCallback_InvalidUrl_ReturnsError()
    {
        var controller = CreateController(Array.Empty<IIdentityValidator>());
        controller.HttpContext.Request.Headers["X-Admin-AppId"] = "app-1";
        controller.HttpContext.Request.Headers["X-Admin-AppSecret"] = "secret";

        var request = new RegisterCallbackHttpRequest { CallbackUrl = "not a url", TtlSeconds = 3600 };

        var actionResult = await controller.RegisterCallback(request);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<RegisterCallbackHttpResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.StartsWith("Invalid callback URL", response.Message);
    }

    [Fact]
    public async Task RegisterCallback_AppNotRegistered_ReturnsError()
    {
        var controller = CreateController(Array.Empty<IIdentityValidator>());
        controller.HttpContext.Request.Headers["X-Admin-AppId"] = "unknown-app";
        controller.HttpContext.Request.Headers["X-Admin-AppSecret"] = "secret";

        var request = new RegisterCallbackHttpRequest { CallbackUrl = "http://example.com/cb", TtlSeconds = 3600 };

        var actionResult = await controller.RegisterCallback(request);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<RegisterCallbackHttpResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("AppId not registered", response.Message);
    }

    [Fact]
    public async Task RegisterCallback_SecretMismatch_ReturnsError()
    {
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "app-1",
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword("real-secret"),
            AppName = "App",
            IsActive = true
        };
        _appRegistrationRepoMock.Setup(r => r.GetByAppIdAsync("app-1")).ReturnsAsync(app);
        var controller = CreateController(Array.Empty<IIdentityValidator>());
        controller.HttpContext.Request.Headers["X-Admin-AppId"] = "app-1";
        controller.HttpContext.Request.Headers["X-Admin-AppSecret"] = "wrong-secret";

        var request = new RegisterCallbackHttpRequest { CallbackUrl = "http://example.com/cb", TtlSeconds = 3600 };

        var actionResult = await controller.RegisterCallback(request);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<RegisterCallbackHttpResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("AppSecret mismatch", response.Message);
    }

    [Fact]
    public async Task RegisterCallback_Success_UsesDefaultTtlWhenNonPositive()
    {
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "app-1",
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword("real-secret"),
            AppName = "App",
            IsActive = true
        };
        _appRegistrationRepoMock.Setup(r => r.GetByAppIdAsync("app-1")).ReturnsAsync(app);
        var controller = CreateController(Array.Empty<IIdentityValidator>());
        controller.HttpContext.Request.Headers["X-Admin-AppId"] = "app-1";
        controller.HttpContext.Request.Headers["X-Admin-AppSecret"] = "real-secret";

        var request = new RegisterCallbackHttpRequest { CallbackUrl = "http://example.com/cb", TtlSeconds = 0 };

        var actionResult = await controller.RegisterCallback(request);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<RegisterCallbackHttpResponse>(ok.Value!);
        Assert.True(response.Success);
        Assert.True(response.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(IdentityConstants.DefaultCallbackTtlSeconds - 60).ToUnixTimeSeconds());
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RegisterCallback_NeverExpire_ReturnsZeroExpiresAt()
    {
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "app-1",
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword("real-secret"),
            AppName = "App",
            IsActive = true
        };
        _appRegistrationRepoMock.Setup(r => r.GetByAppIdAsync("app-1")).ReturnsAsync(app);
        var controller = CreateController(Array.Empty<IIdentityValidator>());
        controller.HttpContext.Request.Headers["X-Admin-AppId"] = "app-1";
        controller.HttpContext.Request.Headers["X-Admin-AppSecret"] = "real-secret";

        var request = new RegisterCallbackHttpRequest { CallbackUrl = "http://example.com/cb", TtlSeconds = IdentityConstants.CallbackTtlNeverExpire };

        var actionResult = await controller.RegisterCallback(request);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<RegisterCallbackHttpResponse>(ok.Value!);
        Assert.True(response.Success);
        Assert.Equal(0, response.ExpiresAt);
        Assert.Null(app.CallbackExpiresAt);
    }

    // ===== Bootstrap admin role injection tests =====

    [Fact]
    public async Task BootstrapAdminLogin_AlwaysGetsAdminRole()
    {
        // Arrange: bootstrap admin "admin" logs in via password grant; callback returns no roles
        // (simulates logging in from teacher_portal where the account is not a teacher).
        var account = CreateTestAccount();
        var validatorMock = CreatePasswordValidator(account, "admin");
        var controller = CreateController(new[] { validatorMock.Object });
        BeginCaptureGeneratedClaims();

        var request = new TokenRequest
        {
            GrantType = "password",
            Username = "admin",
            Password = "Qwer1234"
        };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.Contains(claims, c => c.Type == ClaimTypes.Role && c.Value == "admin");
    }

    [Fact]
    public async Task BootstrapAdminLogin_DoesNotDuplicateAdminRole()
    {
        // Arrange: bootstrap admin logs in from admin_portal; callback already returns ["admin"].
        // The injection must deduplicate so role=admin appears only once.
        var account = CreateTestAccount();
        var validatorMock = CreatePasswordValidator(account, "admin");
        var controller = CreateController(new[] { validatorMock.Object }, CreateBootstrapOptions(o => o.Username = "admin"));

        // Inject a callback service that returns role:admin (simulating admin_portal whitelist).
        var callbackMock = new Mock<ICallbackService>();
        callbackMock.Setup(c => c.FetchExternalClaimsAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(new List<Claim> { new(ClaimTypes.Role, "admin") });

        var factory = new ValidatorFactory(new[] { validatorMock.Object }, NullLogger<ValidatorFactory>.Instance);
        var controllerWithCallback = new AuthController(
            _keyManagerMock.Object, _tokenServiceMock.Object, _jwtOptions,
            _appRegistrationRepoMock.Object, _refreshTokenServiceMock.Object, _claimsResolver,
            factory, callbackMock.Object, CreateAuthMetrics(), NullLogger<AuthController>.Instance,
            CreateGatewayValidator(_appRegistrationRepoMock), new CallbackUrlValidator(),
            _unitOfWorkMock.Object, _auditServiceMock.Object, _otpServiceMock.Object,
            _smsSenderMock.Object, _accountLoginInfoServiceMock.Object, _accountRepositoryMock.Object,
            CreateBootstrapOptions(o => o.Username = "admin").Object);
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse("127.0.0.1");
        // Provide an app with a callback URL so the callback branch executes.
        // AppSecretHash must BCrypt-verify against the secret sent in the request header.
        var appReg = new AppRegistrationEntity
        {
            CallbackUrl = "http://localhost/api/auth/callback",
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword("test-app-secret")
        };
        _appRegistrationRepoMock.Setup(r => r.GetByAppIdAsync(It.IsAny<string>())).ReturnsAsync(appReg);
        httpContext.Items["X-Admin-AppId"] = "test-app-id";
        httpContext.Items["X-Admin-AppSecret"] = "test-app-secret";
        controllerWithCallback.ControllerContext = new ControllerContext { HttpContext = httpContext };

        var request = new TokenRequest { GrantType = "password", Username = "admin", Password = "Qwer1234" };
        BeginCaptureGeneratedClaims();
        var actionResult = await controllerWithCallback.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.Single(claims, c => c.Type == ClaimTypes.Role && c.Value == "admin");
    }

    [Fact]
    public async Task NonBootstrapAdminLogin_NoAdminRoleInjected()
    {
        // Arrange: a regular user (not the bootstrap admin) logs in; callback returns no roles.
        var account = CreateTestAccount();
        var validatorMock = CreatePasswordValidator(account, "regularuser");
        var controller = CreateController(new[] { validatorMock.Object });

        var request = new TokenRequest { GrantType = "password", Username = "regularuser", Password = "Qwer1234" };
        BeginCaptureGeneratedClaims();
        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.DoesNotContain(claims, c => c.Type == ClaimTypes.Role && c.Value == "admin");
    }

    [Fact]
    public async Task BootstrapAdminLogin_EmptyConfig_SkipsInjection()
    {
        // Arrange: AdminBootstrap:Username is empty (not configured); username "admin" must NOT get the role.
        var account = CreateTestAccount();
        var validatorMock = CreatePasswordValidator(account, "admin");
        var controller = CreateController(new[] { validatorMock.Object }, CreateBootstrapOptions(o => o.Username = ""));

        var request = new TokenRequest { GrantType = "password", Username = "admin", Password = "Qwer1234" };
        BeginCaptureGeneratedClaims();
        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.DoesNotContain(claims, c => c.Type == ClaimTypes.Role && c.Value == "admin");
    }

    [Fact]
    public async Task BootstrapAdminLogin_CaseInsensitive()
    {
        // Arrange: bootstrap username is "admin" (lowercase); login uses "ADMIN" (uppercase).
        var account = CreateTestAccount();
        var validatorMock = CreatePasswordValidator(account, "ADMIN");
        var controller = CreateController(new[] { validatorMock.Object }, CreateBootstrapOptions(o => o.Username = "admin"));

        var request = new TokenRequest { GrantType = "password", Username = "ADMIN", Password = "Qwer1234" };
        BeginCaptureGeneratedClaims();
        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.Contains(claims, c => c.Type == ClaimTypes.Role && c.Value == "admin");
    }

    // ===== Bootstrap admin refresh role preservation tests =====

    [Fact]
    public async Task BootstrapAdminRefresh_PreservesAdminRoleWithoutUsername()
    {
        // Arrange: bootstrap admin "admin" refreshes via refresh_token grant; request.Username is NOT set.
        // The refresh validator returns the bootstrap account; the account repository lookup for "admin"
        // returns the same account. Identity must re-inject role=admin based on account id comparison,
        // not request.Username (which is empty).
        var bootstrapAccount = CreateTestAccount();
        _accountRepositoryMock
            .Setup(r => r.GetByPasswordCredentialUsernameAsync("admin"))
            .ReturnsAsync(bootstrapAccount);

        var validatorMock = CreateRefreshValidator(bootstrapAccount);
        var controller = CreateController(new[] { validatorMock.Object });
        BeginCaptureGeneratedClaims();

        var request = new TokenRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "existing-refresh-token"
            // Username intentionally not set: refresh grant does not carry a username.
        };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.Contains(claims, c => c.Type == ClaimTypes.Role && c.Value == "admin");
        Assert.Single(claims, c => c.Type == ClaimTypes.Role && c.Value == "admin");
    }

    [Fact]
    public async Task RegularUserRefresh_WithBootstrapUsername_DoesNotReceiveAdminRole()
    {
        // Arrange: a regular (non-bootstrap) account refreshes; the request maliciously carries
        // Username = "admin" to try to escalate. The account repository lookup for "admin" returns
        // a distinct bootstrap account. Identity must NOT inject role=admin because the refresh
        // grant compares the authenticated AccountEntity.Id, not request.Username.
        var regularAccount = CreateTestAccount();
        var bootstrapAccount = CreateTestAccount();
        Assert.NotEqual(regularAccount.Id, bootstrapAccount.Id);

        _accountRepositoryMock
            .Setup(r => r.GetByPasswordCredentialUsernameAsync("admin"))
            .ReturnsAsync(bootstrapAccount);

        var validatorMock = CreateRefreshValidator(regularAccount);
        var controller = CreateController(new[] { validatorMock.Object });
        BeginCaptureGeneratedClaims();

        var request = new TokenRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "regular-refresh-token",
            Username = "admin" // malicious: client-controlled, must not grant admin role.
        };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.DoesNotContain(claims, c => c.Type == ClaimTypes.Role && c.Value == "admin");
    }

    [Fact]
    public async Task BootstrapAccountSmsLogin_DoesNotReceiveBootstrapAdminRole()
    {
        // Arrange: the SMS validator returns the bootstrap account itself; the account repository
        // lookup for "admin" returns the same account. SMS grant must NOT trigger bootstrap admin
        // injection, so role=admin is absent (callback returns no roles).
        var bootstrapAccount = CreateTestAccount();
        _accountRepositoryMock
            .Setup(r => r.GetByPasswordCredentialUsernameAsync("admin"))
            .ReturnsAsync(bootstrapAccount);

        var validatorMock = new Mock<IIdentityValidator>();
        validatorMock.SetupGet(v => v.GrantType).Returns(IdentityConstants.GrantTypeSms);
        validatorMock.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Success(bootstrapAccount, "Sms", "TestUser"));

        var controller = CreateController(new[] { validatorMock.Object });
        BeginCaptureGeneratedClaims();

        var request = new TokenRequest
        {
            GrantType = IdentityConstants.GrantTypeSms,
            Phone = "13800138000",
            Code = "666666"
        };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.DoesNotContain(claims, c => c.Type == ClaimTypes.Role && c.Value == "admin");
    }

    [Fact]
    public async Task BootstrapAccountWechatLogin_DoesNotReceiveBootstrapAdminRole()
    {
        // Arrange: the WeChat validator returns the bootstrap account itself; the account repository
        // lookup for "admin" returns the same account. wechat_code grant must NOT trigger bootstrap
        // admin injection, so role=admin is absent (callback returns no roles).
        var bootstrapAccount = CreateTestAccount();
        _accountRepositoryMock
            .Setup(r => r.GetByPasswordCredentialUsernameAsync("admin"))
            .ReturnsAsync(bootstrapAccount);

        var validatorMock = new Mock<IIdentityValidator>();
        validatorMock.SetupGet(v => v.GrantType).Returns(IdentityConstants.GrantTypeWechat);
        validatorMock.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Success(bootstrapAccount, "Wechat", "TestUser"));

        var controller = CreateController(new[] { validatorMock.Object });
        BeginCaptureGeneratedClaims();

        var request = new TokenRequest
        {
            GrantType = IdentityConstants.GrantTypeWechat,
            Code = "wechat-code"
        };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = ExtractOkResult(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.DoesNotContain(claims, c => c.Type == ClaimTypes.Role && c.Value == "admin");
    }

    private static AccountEntity CreateTestAccount()
    {
        return new AccountEntity
        {
            Id = Guid.NewGuid(),
            Nickname = "TestAdmin",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
    }

    private static Mock<IIdentityValidator> CreatePasswordValidator(AccountEntity account, string username)
    {
        var validatorMock = new Mock<IIdentityValidator>();
        validatorMock.SetupGet(v => v.GrantType).Returns("password");
        validatorMock.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Success(account, "Password", username));
        return validatorMock;
    }

    private static Mock<IIdentityValidator> CreateRefreshValidator(AccountEntity account)
    {
        var validatorMock = new Mock<IIdentityValidator>();
        validatorMock.SetupGet(v => v.GrantType).Returns(IdentityConstants.GrantTypeRefreshToken);
        validatorMock.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Success(account, "Refresh", null));
        return validatorMock;
    }
}
