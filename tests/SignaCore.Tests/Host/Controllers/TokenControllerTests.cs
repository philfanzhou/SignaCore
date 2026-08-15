using System.Security.Claims;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using SignaCore.Host.Controllers;
using SignaCore.Host.Http;
using SignaCore.Host.Models;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

public class TokenControllerTests
{
    private readonly Mock<IKeyManager> _keyManagerMock = AuthTestDoubles.KeyManager();
    private readonly Mock<ITokenService> _tokenServiceMock = AuthTestDoubles.TokenService();
    private readonly Mock<IAppRegistrationRepository> _appRegistrationRepoMock = new();
    private readonly Mock<IRefreshTokenService> _refreshTokenServiceMock = AuthTestDoubles.RefreshTokenService();
    private readonly Mock<IAuditService> _auditServiceMock = AuthTestDoubles.AuditService();
    private readonly Mock<IAccountLoginInfoService> _accountLoginInfoServiceMock = AuthTestDoubles.AccountLoginInfoService();
    private readonly Mock<IAccountRepository> _accountRepositoryMock = new();
    private readonly ClaimsResolver _claimsResolver = new(NullLogger<ClaimsResolver>.Instance);

    private readonly JwtOptions _jwtOptions = new()
    {
        Issuer = "TestIssuer",
        Audience = "TestAudience",
        TokenExpirationHours = 2
    };

    // 管理员用户名默认 admin；个别测试通过 AuthTestDoubles.AdminIdentity(...) 覆盖。
    private readonly AdminIdentityOptions _adminIdentityOptions = AuthTestDoubles.AdminIdentity();

    private TokenController CreateController(IIdentityValidator[] validators) =>
        CreateController(validators, _adminIdentityOptions);

    private TokenController CreateController(
        IIdentityValidator[] validators,
        AdminIdentityOptions adminIdentityOptions,
        ICallbackService? callbackService = null,
        AppRegistrationEntity? app = null)
    {
        var controller = new TokenController(
                CreateIssuanceService(validators, adminIdentityOptions, callbackService))
            .WithHttpContext();
        controller.HttpContext.Items[IdentityHeaders.ValidatedApp] = app ?? new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "test-app",
            AppName = "Test App",
            AppSecretHash = "not-used-by-controller",
            IsActive = true
        };
        return controller;
    }

    /// <summary>
    /// 发 token 的流程本体在 <see cref="TokenIssuanceService"/>，controller 只做传输映射。
    /// 这些用例继续从 controller 打进去：断言的是"经过完整流程后对外看到什么"。
    /// </summary>
    private TokenIssuanceService CreateIssuanceService(
        IIdentityValidator[] validators,
        AdminIdentityOptions adminIdentityOptions,
        ICallbackService? callbackService = null) =>
        new(
            _keyManagerMock.Object,
            _tokenServiceMock.Object,
            _jwtOptions,
            _refreshTokenServiceMock.Object,
            _claimsResolver,
            new ValidatorFactory(validators, NullLogger<ValidatorFactory>.Instance),
            callbackService,
            AuthTestDoubles.AuthMetrics(),
            _auditServiceMock.Object,
            _accountLoginInfoServiceMock.Object,
            _accountRepositoryMock.Object,
            adminIdentityOptions,
            NullLogger<TokenIssuanceService>.Instance);

    // 由 token service 的 mock 回调写入，供断言 claims 使用。
    private List<Claim>? _capturedClaims;

    private void BeginCaptureGeneratedClaims()
    {
        _capturedClaims = null;
        _tokenServiceMock.Setup(t => t.GenerateJwtToken(
                It.IsAny<List<Claim>>(), It.IsAny<RsaSecurityKey>(), It.IsAny<int>(), It.IsAny<string?>()))
            .Callback((List<Claim> claims, RsaSecurityKey _, int __, string? ___) => _capturedClaims = claims)
            .Returns("token");
    }

    private List<Claim> AssertCapturedClaims()
    {
        Assert.NotNull(_capturedClaims);
        return _capturedClaims;
    }

    private static AccountEntity CreateTestAccount() => new()
    {
        Id = Guid.NewGuid(),
        Nickname = "TestAdmin",
        IsActive = true,
        CreatedAt = DateTimeOffset.UtcNow
    };

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

    private static Mock<IIdentityValidator> CreateFailingValidator(string grantType, string error)
    {
        var validatorMock = new Mock<IIdentityValidator>();
        validatorMock.SetupGet(v => v.GrantType).Returns(grantType);
        validatorMock.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Failure(error));
        return validatorMock;
    }

    #region 基本流程

    [Fact]
    public async Task GetToken_WithUnsupportedGrantType_ReturnsUnsupportedGrantTypeMessage()
    {
        var controller = CreateController(Array.Empty<IIdentityValidator>());

        var request = new TokenRequest { GrantType = "invalid" };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
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

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);
        Assert.Equal("token", response.AccessToken);
        Assert.Equal("refresh", response.RefreshToken);

        _keyManagerMock.Verify(k => k.GetCurrentKey(), Times.Once);
        _tokenServiceMock.Verify(t => t.GenerateJwtToken(
            It.Is<List<Claim>>(claims => claims.Any(c =>
                c.Type == IdentityConstants.ClaimClientId && c.Value == "test-app")),
            It.IsAny<RsaSecurityKey>(), 2, It.IsAny<string?>()), Times.Once);
        _refreshTokenServiceMock.Verify(
            s => s.HandleRefreshTokenAsync(
                "sms",
                It.IsAny<string?>(),
                It.Is<AccountEntity>(a => a.Id == accountId),
                It.IsAny<string?>(),
                It.IsAny<Guid?>()),
            Times.Once);
    }

    #endregion

    #region 失败分支

    [Fact]
    public async Task GetToken_AuditsCorrelationIdProducedByMiddleware()
    {
        var controller = CreateController(new[] { CreateFailingValidator("sms", "invalid code").Object });

        // CorrelationIdMiddleware 在管道最前面把 ID 放进 HttpContext.Items，
        // 请求头上没有。Controller 必须复用它，而不是自己 Guid.NewGuid()。
        controller.HttpContext.Items[CorrelationIdMiddleware.HttpContextItemsKey] = "corr-from-middleware";

        await controller.GetToken(new TokenRequest { GrantType = "sms" }, CancellationToken.None);

        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            It.IsAny<Guid?>(), It.IsAny<string>(), "sms", "login_failure",
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>(), "corr-from-middleware"), Times.Once);
    }

    [Fact]
    public async Task GetToken_ValidatorFails_ReturnsFailureAndAuditsUnknownFallback()
    {
        var controller = CreateController(new[] { CreateFailingValidator("sms", "invalid code").Object });

        // Username/Phone/Code 全为 null -> failedUsername 兜底为 "unknown"
        var request = new TokenRequest { GrantType = "sms" };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
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
        var controller = CreateController(new[] { CreateFailingValidator("sms", "invalid code").Object });

        var request = new TokenRequest { GrantType = "sms", Phone = "13800138000" };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        Assert.False(Assert.IsType<TokenResponse>(ok.Value!).Success);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            null, "13800138000", "sms", "login_failure",
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task GetToken_ValidatorFails_NeverWritesCodeAsAuditUsername()
    {
        const string sensitiveCode = "one-time-secret-code";
        var controller = CreateController(new[]
        {
            CreateFailingValidator(IdentityConstants.GrantTypeWechat, "invalid code").Object
        });

        var actionResult = await controller.GetToken(new TokenRequest
        {
            GrantType = IdentityConstants.GrantTypeWechat,
            Code = sensitiveCode
        }, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        Assert.False(Assert.IsType<TokenResponse>(ok.Value!).Success);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            null, "unknown", IdentityConstants.GrantTypeWechat, "login_failure",
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<string?>()), Times.Once);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            It.IsAny<Guid?>(), sensitiveCode, It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<string?>()), Times.Never);
    }

    [Fact]
    public async Task GetToken_WhenCallbackObservesRequestCancellation_PropagatesCancellation()
    {
        var account = CreateTestAccount();
        var callback = new Mock<ICallbackService>();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        callback.Setup(service => service.FetchExternalClaimsAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                cancellation.Token))
            .ThrowsAsync(new OperationCanceledException(cancellation.Token));
        var controller = CreateController(
            new[] { CreatePasswordValidator(account, "user").Object },
            _adminIdentityOptions,
            callback.Object,
            new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = "test-app",
                AppName = "Test App",
                AppSecretHash = "not-used",
                CallbackUrl = "https://callback.example.com/claims",
                IsActive = true
            });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            controller.GetToken(
                new TokenRequest
                {
                    GrantType = IdentityConstants.GrantTypePassword,
                    Username = "user",
                    Password = "password"
                },
                cancellation.Token));

        _tokenServiceMock.Verify(service => service.GenerateJwtToken(
            It.IsAny<List<Claim>>(),
            It.IsAny<RsaSecurityKey>(),
            It.IsAny<int>(),
            It.IsAny<string?>()), Times.Never);
    }

    [Fact]
    public async Task RefreshTokenRotation_WhenTokenWasAlreadyConsumed_DoesNotIssueAccessToken()
    {
        var account = CreateTestAccount();
        var validatorMock = CreateRefreshValidator(account);
        _refreshTokenServiceMock
            .Setup(service => service.HandleRefreshTokenAsync(
                IdentityConstants.GrantTypeRefreshToken,
                "consumed-refresh-token",
                account,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync((string?)null);
        var controller = CreateController(new[] { validatorMock.Object });

        var actionResult = await controller.GetToken(new TokenRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "consumed-refresh-token"
        }, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("invalid_grant", response.Message);
        Assert.True(string.IsNullOrEmpty(response.AccessToken));
        _tokenServiceMock.Verify(
            service => service.GenerateJwtToken(
                It.IsAny<List<Claim>>(),
                It.IsAny<RsaSecurityKey>(),
                It.IsAny<int>(),
                It.IsAny<string?>()),
            Times.Never);
    }

    #endregion

    #region Bootstrap admin 角色注入

    [Fact]
    public async Task BootstrapAdminLogin_AlwaysGetsAdminRole()
    {
        // bootstrap admin "admin" 走 password 登录；回调不返回任何角色
        // （模拟从某个业务门户登录、而该账号在那边没有任何业务角色的场景）。
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

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.Contains(claims, c => c.Type == IdentityConstants.ClaimRole && c.Value == "admin");
    }

    [Fact]
    public async Task BootstrapAdminLogin_DoesNotDuplicateAdminRole()
    {
        // bootstrap admin 从 admin_portal 登录，回调已经返回了 ["admin"]。
        // 注入逻辑必须去重，role=admin 只能出现一次。
        var account = CreateTestAccount();
        var validatorMock = CreatePasswordValidator(account, "admin");

        var callbackMock = new Mock<ICallbackService>();
        callbackMock.Setup(c => c.FetchExternalClaimsAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<Claim> { new(IdentityConstants.ClaimRole, "admin") });

        var controller = CreateController(
            new[] { validatorMock.Object },
            AuthTestDoubles.AdminIdentity("admin"),
            callbackMock.Object);

        // 提供一个带回调 URL 的 app，让回调分支真正执行。
        // AppSecretHash 必须能 BCrypt 校验通过请求里带的 secret。
        var appReg = new AppRegistrationEntity
        {
            CallbackUrl = "http://localhost/api/auth/callback",
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword("test-app-secret")
        };
        _appRegistrationRepoMock.Setup(r => r.GetByAppIdAsync(It.IsAny<string>())).ReturnsAsync(appReg);
        controller.HttpContext.Items[IdentityHeaders.AppId] = "test-app-id";
        controller.HttpContext.Items[IdentityHeaders.AppSecret] = "test-app-secret";

        var request = new TokenRequest { GrantType = "password", Username = "admin", Password = "Qwer1234" };
        BeginCaptureGeneratedClaims();
        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.Single(claims, c => c.Type == IdentityConstants.ClaimRole && c.Value == "admin");
    }

    [Fact]
    public async Task NonBootstrapAdminLogin_NoAdminRoleInjected()
    {
        // 普通用户（非 bootstrap admin）登录，回调不返回角色。
        var account = CreateTestAccount();
        var validatorMock = CreatePasswordValidator(account, "regularuser");
        var controller = CreateController(new[] { validatorMock.Object });

        var request = new TokenRequest { GrantType = "password", Username = "regularuser", Password = "Qwer1234" };
        BeginCaptureGeneratedClaims();
        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.DoesNotContain(claims, c => c.Type == IdentityConstants.ClaimRole && c.Value == "admin");
    }

    [Fact]
    public async Task BootstrapAdminLogin_EmptyConfig_SkipsInjection()
    {
        // AdminBootstrap:Username 为空（未配置）时，用户名 "admin" 也不能拿到角色。
        var account = CreateTestAccount();
        var validatorMock = CreatePasswordValidator(account, "admin");
        var controller = CreateController(
            new[] { validatorMock.Object },
            AuthTestDoubles.AdminIdentity(string.Empty));

        var request = new TokenRequest { GrantType = "password", Username = "admin", Password = "Qwer1234" };
        BeginCaptureGeneratedClaims();
        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.DoesNotContain(claims, c => c.Type == IdentityConstants.ClaimRole && c.Value == "admin");
    }

    [Fact]
    public async Task BootstrapAdminLogin_CaseInsensitive()
    {
        // 配置的用户名是 "admin"（小写），登录用 "ADMIN"（大写）。
        var account = CreateTestAccount();
        var validatorMock = CreatePasswordValidator(account, "ADMIN");
        var controller = CreateController(
            new[] { validatorMock.Object },
            AuthTestDoubles.AdminIdentity("admin"));

        var request = new TokenRequest { GrantType = "password", Username = "ADMIN", Password = "Qwer1234" };
        BeginCaptureGeneratedClaims();
        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.Contains(claims, c => c.Type == IdentityConstants.ClaimRole && c.Value == "admin");
    }

    #endregion

    #region refresh 时的角色保持与提权防护

    [Fact]
    public async Task BootstrapAdminRefresh_PreservesAdminRoleWithoutUsername()
    {
        // bootstrap admin "admin" 走 refresh_token 刷新，request.Username 不设置。
        // refresh 校验器返回 bootstrap 账号，仓储按 "admin" 查也返回同一账号。
        // 必须基于账号 id 比对重新注入 role=admin，而不是靠 request.Username（此处为空）。
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
            // Username 刻意不设置：refresh 流程不携带用户名。
        };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.Contains(claims, c => c.Type == IdentityConstants.ClaimRole && c.Value == "admin");
        Assert.Single(claims, c => c.Type == IdentityConstants.ClaimRole && c.Value == "admin");
    }

    [Fact]
    public async Task RegularUserRefresh_WithBootstrapUsername_DoesNotReceiveAdminRole()
    {
        // 普通（非 bootstrap）账号刷新，请求里恶意带上 Username = "admin" 试图提权。
        // 仓储按 "admin" 查返回的是另一个 bootstrap 账号。必须不注入 role=admin，
        // 因为 refresh 流程比对的是已认证的 AccountEntity.Id，不是 request.Username。
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
            Username = "admin" // 恶意：客户端可控，不能据此授予 admin 角色。
        };

        var actionResult = await controller.GetToken(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.DoesNotContain(claims, c => c.Type == IdentityConstants.ClaimRole && c.Value == "admin");
    }

    [Fact]
    public async Task BootstrapAccountSmsLogin_DoesNotReceiveBootstrapAdminRole()
    {
        // SMS 校验器返回的就是 bootstrap 账号本身，仓储按 "admin" 查也返回同一账号。
        // sms 流程不得触发 bootstrap admin 注入，因此没有 role=admin（回调不返回角色）。
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

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.DoesNotContain(claims, c => c.Type == IdentityConstants.ClaimRole && c.Value == "admin");
    }

    [Fact]
    public async Task BootstrapAccountWechatLogin_DoesNotReceiveBootstrapAdminRole()
    {
        // 微信校验器返回的就是 bootstrap 账号本身，仓储按 "admin" 查也返回同一账号。
        // wechat_code 流程不得触发 bootstrap admin 注入。
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

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<TokenResponse>(ok.Value!);
        Assert.True(response.Success);

        var claims = AssertCapturedClaims();
        Assert.DoesNotContain(claims, c => c.Type == IdentityConstants.ClaimRole && c.Value == "admin");
    }

    #endregion
}
