using System.Security.Claims;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
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
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using SignaCore.Host.Controllers;
using SignaCore.Host.Http;
using SignaCore.Host.Models;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

public class TokenControllerTests : IDisposable
{
    private readonly Mock<IKeyManager> _keyManagerMock = AuthTestDoubles.KeyManager();
    private readonly Mock<ITokenService> _tokenServiceMock = AuthTestDoubles.TokenService();
    private readonly Mock<IAppRegistrationRepository> _appRegistrationRepoMock = new();
    private readonly Mock<IRefreshTokenService> _refreshTokenServiceMock = AuthTestDoubles.RefreshTokenService();
    private readonly Mock<IAuditService> _auditServiceMock = AuthTestDoubles.AuditService();
    private readonly Mock<IAccountLoginInfoService> _accountLoginInfoServiceMock = AuthTestDoubles.AccountLoginInfoService();
    private readonly Mock<IAccountRepository> _accountRepositoryMock = new();
    private readonly Mock<ILoginAttemptRepository> _loginAttemptRepositoryMock = new();
    private readonly Mock<IOtpRepository> _otpRepositoryMock = new();
    private readonly Mock<IUnitOfWork> _unitOfWorkMock = new();
    private readonly ClaimsResolver _claimsResolver = new(NullLogger<ClaimsResolver>.Instance);
    private readonly SqliteConnection _connection;
    private readonly IdentityDbContext _dbContext;

    public TokenControllerTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _dbContext = new IdentityDbContext(
            new DbContextOptionsBuilder<IdentityDbContext>().UseSqlite(_connection).Options);
        _dbContext.Database.EnsureCreated();
        _unitOfWorkMock
            .Setup(unitOfWork => unitOfWork.SaveChangesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(1);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
        _connection.Dispose();
    }

    private readonly JwtOptions _jwtOptions = new()
    {
        Issuer = "TestIssuer",
        Audience = "TestAudience",
        TokenExpirationHours = 2
    };

    // The administrator username defaults to admin; individual tests override it through
    // AuthTestDoubles.AdminIdentity(...).
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
    /// The token issuance flow itself lives in <see cref="TokenIssuanceService"/>; the controller
    /// only maps transport. These tests still enter through the controller, because what they assert
    /// is what an outside caller sees after the complete flow.
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
            _loginAttemptRepositoryMock.Object,
            _otpRepositoryMock.Object,
            _unitOfWorkMock.Object,
            _dbContext,
            adminIdentityOptions,
            NullLogger<TokenIssuanceService>.Instance);

    // Written by the token service mock's callback, so the tests can assert on the claims.
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

    [Theory]
    [InlineData("password", true)]
    [InlineData("password", false)]
    [InlineData("sms", true)]
    [InlineData("sms", false)]
    [InlineData("ldap", true)]
    [InlineData("ldap", false)]
    public async Task GetToken_LoginStatePaths_PropagateSameRequestToken(string grant, bool succeeds)
    {
        using var cancellation = new CancellationTokenSource();
        var calls = new List<string>();
        var controller = CreateCancellationController(grant, succeeds, cancellation, calls);

        var result = await controller.GetToken(new TokenRequest { GrantType = grant }, cancellation.Token);

        Assert.Equal(succeeds, Assert.IsType<TokenResponse>(AuthTestDoubles.ExtractOk(result).Value).Success);
        Assert.Equal(ExpectedLoginCalls(grant, succeeds), calls);
    }

    [Theory]
    [InlineData("password", true, "keys")]
    [InlineData("password", true, "attempt-read")]
    [InlineData("password", true, "attempt-remove")]
    [InlineData("password", true, "login-state")]
    [InlineData("password", false, "attempt-failure")]
    [InlineData("ldap", true, "keys")]
    [InlineData("ldap", true, "attempt-read")]
    [InlineData("ldap", true, "attempt-remove")]
    [InlineData("ldap", true, "login-state")]
    [InlineData("ldap", false, "attempt-failure")]
    [InlineData("sms", true, "keys")]
    [InlineData("sms", true, "login-state")]
    [InlineData("sms", false, "otp-failure")]
    public async Task GetToken_CancelledLoginStage_StopsLaterDependencies(
        string grant, bool succeeds, string cancelAt)
    {
        using var cancellation = new CancellationTokenSource();
        var calls = new List<string>();
        var controller = CreateCancellationController(grant, succeeds, cancellation, calls, cancelAt);

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            controller.GetToken(new TokenRequest { GrantType = grant }, cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        var expected = ExpectedLoginCalls(grant, succeeds);
        Assert.Equal(expected.Take(Array.IndexOf(expected, cancelAt) + 1), calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BootstrapAdminRefresh_PropagatesLookupTokenAndStopsOnCancellation(bool cancel)
    {
        using var cancellation = new CancellationTokenSource();
        var account = CreateTestAccount();
        _accountRepositoryMock.Setup(repository => repository.GetByPasswordCredentialUsernameAsync(
                "admin", It.IsAny<CancellationToken>()))
            .Callback<string, CancellationToken>((_, ct) =>
            {
                Assert.Equal(cancellation.Token, ct);
                if (cancel) cancellation.Cancel();
                ct.ThrowIfCancellationRequested();
            }).ReturnsAsync(account);
        var controller = CreateController([CreateRefreshValidator(account).Object]);
        var request = new TokenRequest { GrantType = IdentityConstants.GrantTypeRefreshToken };
        BeginCaptureGeneratedClaims();

        if (cancel)
        {
            var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                controller.GetToken(request, cancellation.Token));
            Assert.Equal(cancellation.Token, exception.CancellationToken);
            _keyManagerMock.Verify(manager => manager.RefreshKeysAsync(It.IsAny<CancellationToken>()), Times.Never);
            _accountLoginInfoServiceMock.VerifyNoOtherCalls();
            _unitOfWorkMock.VerifyNoOtherCalls();
            _tokenServiceMock.VerifyNoOtherCalls();
            _refreshTokenServiceMock.VerifyNoOtherCalls();
        }
        else
        {
            var result = await controller.GetToken(request, cancellation.Token);
            Assert.True(Assert.IsType<TokenResponse>(AuthTestDoubles.ExtractOk(result).Value).Success);
            Assert.Contains(AssertCapturedClaims(), claim => claim.Type == IdentityConstants.ClaimRole && claim.Value == "admin");
            _keyManagerMock.Verify(manager => manager.RefreshKeysAsync(cancellation.Token), Times.Once);
            _accountLoginInfoServiceMock.Verify(service => service.UpdateLoginInfoAsync(
                account, It.IsAny<string?>(), "Refresh", cancellation.Token), Times.Once);
        }
        _accountRepositoryMock.Verify(repository => repository.GetByPasswordCredentialUsernameAsync(
            "admin", cancellation.Token), Times.Once);
    }

    private static string[] ExpectedLoginCalls(string grant, bool succeeds)
    {
        if (!succeeds)
            return ["validate", grant == "sms" ? "otp-failure" : "attempt-failure", "audit", "save"];
        return grant == "sms"
            ? ["validate", "keys", "sign", "otp-consume", "login-state", "refresh", "audit", "save"]
            : ["validate", "keys", "sign", "attempt-read", "attempt-remove", "login-state", "refresh", "audit", "save"];
    }

    private TokenController CreateCancellationController(
        string grant, bool succeeds, CancellationTokenSource cancellation, List<string> calls, string? cancelAt = null)
    {
        void Observe(string stage, CancellationToken ct)
        {
            Assert.Equal(cancellation.Token, ct);
            calls.Add(stage);
            if (stage == cancelAt) cancellation.Cancel();
            ct.ThrowIfCancellationRequested();
        }

        var account = CreateTestAccount();
        var attempt = new LoginAttemptEntity { Username = "test-user" };
        var validation = succeeds
            ? ValidationResult.Success(account, grant, "test-user")
            : ValidationResult.Failure("Invalid credentials");
        if (grant == "sms")
        {
            validation = validation.WithOtpVerificationChange(new OtpVerificationChange(
                succeeds ? OtpVerificationChangeKind.Consume : OtpVerificationChangeKind.RecordFailure,
                Guid.NewGuid(), "+12025550123", "test-mac", DateTimeOffset.UtcNow, 3, DateTimeOffset.UtcNow.AddMinutes(1)));
        }
        else
        {
            validation = validation.WithLoginAttemptChange(new LoginAttemptChange(
                succeeds ? LoginAttemptChangeKind.Clear : LoginAttemptChangeKind.RecordFailure, attempt.Username));
        }
        var validator = new Mock<IIdentityValidator>();
        validator.SetupGet(value => value.GrantType).Returns(grant);
        validator.Setup(value => value.ValidateAsync(It.IsAny<ValidationRequest>()))
            .Callback<ValidationRequest>(request => Observe("validate", request.CancellationToken)).ReturnsAsync(validation);
        _keyManagerMock.Setup(manager => manager.RefreshKeysAsync(It.IsAny<CancellationToken>()))
            .Callback<CancellationToken>(ct => Observe("keys", ct)).Returns(Task.CompletedTask);
        _tokenServiceMock.Setup(service => service.GenerateJwtToken(
                It.IsAny<List<Claim>>(), It.IsAny<RsaSecurityKey>(), It.IsAny<int>(), It.IsAny<string?>()))
            .Callback(() => calls.Add("sign")).Returns("test-token");
        _loginAttemptRepositoryMock.Setup(repository => repository.GetByUsernameAsync(attempt.Username, It.IsAny<CancellationToken>()))
            .Callback<string, CancellationToken>((_, ct) => Observe("attempt-read", ct)).ReturnsAsync(attempt);
        _loginAttemptRepositoryMock.Setup(repository => repository.RemoveAsync(attempt, It.IsAny<CancellationToken>()))
            .Callback<LoginAttemptEntity, CancellationToken>((_, ct) => Observe("attempt-remove", ct)).Returns(Task.CompletedTask);
        _loginAttemptRepositoryMock.Setup(repository => repository.RecordFailureAsync(
                attempt.Username, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback<string, DateTimeOffset, CancellationToken>((_, _, ct) => Observe("attempt-failure", ct)).ReturnsAsync(attempt);
        _otpRepositoryMock.Setup(repository => repository.TryConsumeAsync(It.IsAny<Guid>(), It.IsAny<string>(),
                It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .Callback(new InvocationAction(invocation => Observe("otp-consume", (CancellationToken)invocation.Arguments[^1])))
            .ReturnsAsync(true);
        _otpRepositoryMock.Setup(repository => repository.IncrementFailedAttemptsAsync(It.IsAny<Guid>(), It.IsAny<string>(),
                It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<int>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(new InvocationAction(invocation => Observe("otp-failure", (CancellationToken)invocation.Arguments[^1])))
            .ReturnsAsync(1);
        _accountLoginInfoServiceMock.Setup(service => service.UpdateLoginInfoAsync(
                account, It.IsAny<string?>(), grant, It.IsAny<CancellationToken>()))
            .Callback<AccountEntity, string?, string, CancellationToken>((_, _, _, ct) => Observe("login-state", ct))
            .Returns(Task.CompletedTask);
        _refreshTokenServiceMock.Setup(service => service.HandleRefreshTokenAsync(
                grant, It.IsAny<string?>(), account, It.IsAny<string?>(), It.IsAny<Guid?>()))
            .Callback(() => calls.Add("refresh")).ReturnsAsync("test-refresh");
        _auditServiceMock.Setup(service => service.RecordLoginAsync(It.IsAny<Guid?>(), It.IsAny<string>(), grant,
                It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .Callback(new InvocationAction(invocation => Observe("audit", (CancellationToken)invocation.Arguments[^1])))
            .Returns(Task.CompletedTask);
        _unitOfWorkMock.Setup(unit => unit.SaveChangesAsync(It.IsAny<CancellationToken>()))
            .Callback<CancellationToken>(ct => Observe("save", ct)).ReturnsAsync(1);
        return CreateController([validator.Object]);
    }

    #region Core flow

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
        _unitOfWorkMock.Verify(
            unitOfWork => unitOfWork.SaveChangesAsync(It.IsAny<CancellationToken>()),
            Times.Once);
    }

    #endregion

    #region Failure branches

    [Fact]
    public async Task GetToken_AuditsCorrelationIdProducedByMiddleware()
    {
        var controller = CreateController(new[] { CreateFailingValidator("sms", "invalid code").Object });

        // CorrelationIdMiddleware puts the id into HttpContext.Items at the very front of the
        // pipeline; it is not on the request headers. The controller has to reuse it rather than
        // call Guid.NewGuid() of its own.
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

        // Username/Phone/Code are all null, so failedUsername falls back to "unknown".
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
        _unitOfWorkMock.Verify(
            unitOfWork => unitOfWork.SaveChangesAsync(It.IsAny<CancellationToken>()),
            Times.Once);
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
        _refreshTokenServiceMock.Verify(service => service.HandleRefreshTokenAsync(
            It.IsAny<string>(),
            It.IsAny<string?>(),
            It.IsAny<AccountEntity>(),
            It.IsAny<string?>(),
            It.IsAny<Guid?>()), Times.Never);
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
            Times.Once);
    }

    [Fact]
    public async Task RefreshTokenRotation_WhenJwtGenerationFails_LeavesPresentedTokenUntouched()
    {
        var account = CreateTestAccount();
        var validatorMock = CreateRefreshValidator(account);
        _tokenServiceMock.Setup(service => service.GenerateJwtToken(
                It.IsAny<List<Claim>>(),
                It.IsAny<RsaSecurityKey>(),
                It.IsAny<int>(),
                It.IsAny<string?>()))
            .Throws(new InvalidOperationException("signing failed"));
        var controller = CreateController(new[] { validatorMock.Object });

        await Assert.ThrowsAsync<InvalidOperationException>(() => controller.GetToken(new TokenRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "still-valid-refresh-token"
        }, CancellationToken.None));

        _refreshTokenServiceMock.Verify(service => service.HandleRefreshTokenAsync(
            It.IsAny<string>(),
            It.IsAny<string?>(),
            It.IsAny<AccountEntity>(),
            It.IsAny<string?>(),
            It.IsAny<Guid?>()), Times.Never);
    }

    #endregion

    #region Bootstrap admin role injection

    [Fact]
    public async Task BootstrapAdminLogin_AlwaysGetsAdminRole()
    {
        // The bootstrap admin "admin" signs in through password; the callback returns no roles at
        // all, simulating a sign-in from a business portal where that account holds no business
        // role.
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
        // The bootstrap admin signs in from admin_portal and the callback has already returned
        // ["admin"]. The injection has to deduplicate, so role=admin may appear only once.
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

        // Supply an app with a callback URL so the callback branch actually runs. AppSecretHash has
        // to BCrypt-verify against the secret carried on the request.
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
        // A regular user, not the bootstrap admin, signs in and the callback returns no roles.
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
        // When AdminBootstrap:Username is empty, meaning unconfigured, even the username "admin"
        // must not receive the role.
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
        // The configured username is "admin" in lower case, while the sign-in uses "ADMIN" in upper
        // case.
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

    #region Role preservation and privilege escalation defence on refresh

    [Fact]
    public async Task BootstrapAdminRefresh_PreservesAdminRoleWithoutUsername()
    {
        // The bootstrap admin "admin" refreshes through refresh_token with request.Username unset.
        // The refresh validator returns the bootstrap account, and looking "admin" up in the
        // repository returns that same account. role=admin has to be re-injected by comparing
        // account ids, not by relying on request.Username, which is empty here.
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
            // Username is deliberately unset: the refresh flow carries no username.
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
        // A regular, non-bootstrap account refreshes while maliciously carrying Username = "admin"
        // to escalate. Looking "admin" up in the repository returns a different, bootstrap account.
        // role=admin must not be injected, because the refresh flow compares the authenticated
        // AccountEntity.Id rather than request.Username.
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
            Username = "admin" // Malicious: client-controlled, never a basis for the admin role.
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
        // The SMS validator returns the bootstrap account itself, and looking "admin" up in the
        // repository returns that same account. The sms flow must not trigger the bootstrap admin
        // injection, so there is no role=admin, the callback returning no roles.
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
        // The WeChat validator returns the bootstrap account itself, and looking "admin" up in the
        // repository returns that same account. The wechat_code flow must not trigger the bootstrap
        // admin injection.
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
