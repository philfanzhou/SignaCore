using System.Diagnostics.Metrics;
using System.Security.Claims;
using System.Text.Json;
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
        AppRegistrationEntity? app = null,
        AuthMetrics? authMetrics = null)
    {
        var controller = new TokenController(
                CreateIssuanceService(validators, adminIdentityOptions, callbackService, authMetrics))
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
        ICallbackService? callbackService = null,
        AuthMetrics? authMetrics = null) =>
        new(
            _keyManagerMock.Object,
            _tokenServiceMock.Object,
            _jwtOptions,
            _refreshTokenServiceMock.Object,
            _claimsResolver,
            new ValidatorFactory(validators, NullLogger<ValidatorFactory>.Instance),
            callbackService,
            authMetrics ?? AuthTestDoubles.AuthMetrics(),
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
    [InlineData("password", true, "refresh")]
    [InlineData("sms", true, "refresh")]
    [InlineData("ldap", true, "refresh")]
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

    [Theory]
    [InlineData("password", false)]
    [InlineData("sms", false)]
    [InlineData("wechat_code", false)]
    [InlineData("ldap", false)]
    [InlineData("refresh_token", false)]
    [InlineData("refresh_token", true)]
    public async Task GetToken_RefreshWriteObservesRequestCancellation(string grant, bool exchange)
    {
        using var cancellation = new CancellationTokenSource();
        var account = CreateTestAccount();
        var validator = new Mock<IIdentityValidator>();
        validator.SetupGet(value => value.GrantType).Returns(grant);
        var validation = ValidationResult.Success(account, grant, "test-user");
        if (exchange) validation = validation.AsCrossApplicationExchange("source-app");
        validator.Setup(value => value.ValidateAsync(It.IsAny<ValidationRequest>())).ReturnsAsync(validation);
        _refreshTokenServiceMock.Setup(service => service.HandleRefreshTokenAsync(
                grant, It.IsAny<string?>(), account, It.IsAny<string?>(), It.IsAny<Guid?>(),
                It.IsAny<Guid?>(), It.IsAny<Guid?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .Callback(new InvocationAction(invocation =>
            {
                var received = (CancellationToken)invocation.Arguments[^1];
                Assert.Equal(cancellation.Token, received);
                cancellation.Cancel();
                received.ThrowIfCancellationRequested();
            }));
        var controller = CreateController([validator.Object]);

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => controller.GetToken(
            new TokenRequest { GrantType = grant }, cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Single(_refreshTokenServiceMock.Invocations);
        _auditServiceMock.VerifyNoOtherCalls();
        _unitOfWorkMock.VerifyNoOtherCalls();
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
                grant, It.IsAny<string?>(), account, It.IsAny<string?>(), It.IsAny<Guid?>(),
                It.IsAny<Guid?>(), It.IsAny<Guid?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .Callback(new InvocationAction(invocation => Observe("refresh", (CancellationToken)invocation.Arguments[^1]))).ReturnsAsync("test-refresh");
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

        // The correlation id is established by the real middleware at the very front of the
        // pipeline, not by a second Guid.NewGuid() in the controller. It flows from the request
        // header through the middleware's slot into the audit record.
        controller.HttpContext.Request.Headers["x-correlation-id"] = "corr-from-middleware";
        await CorrelationTestPipeline.EstablishAsync(controller.HttpContext);

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

    #region Legacy failure code (#609)

    private const string SmsDisabledMessage = "SMS login is disabled for this application";

    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    private static AppRegistrationEntity CreateSmsApp(SmsLoginMode mode) => new()
    {
        Id = Guid.NewGuid(),
        AppId = "test-app",
        AppName = "Test App",
        AppSecretHash = "not-used-by-controller",
        IsActive = true,
        SmsLoginMode = mode,
        SmsProfileKey = "test"
    };

    /// <summary>
    /// The real SMS validator with a bypass code configured for the requested phone, so a bypass
    /// acceptance would show up as a success if the policy check did not come first.
    /// </summary>
    private static SmsValidator CreateSmsValidator(Mock<IOtpService> otp, Mock<ISmsAdmissionService> admission) =>
        new(
            otp.Object,
            admission.Object,
            NullLogger<SmsValidator>.Instance,
            AuthTestDoubles.AuthMetrics(),
            new SmsOptions { BypassCode = "123456", BypassPhones = ["+8613800138000"] });

    private static JsonElement Serialize(TokenResponse response) =>
        JsonSerializer.SerializeToElement(response, WebJson);

    /// <summary>
    /// Under <c>Disabled</c> the SMS grant answers HTTP 200, success=false, the existing message,
    /// and <c>code=SMS_LOGIN_DISABLED</c> — also with an empty phone or code, because the policy is
    /// checked first. No admission lookup, OTP verification, bypass acceptance, token issuance,
    /// refresh-token write, or login-state change happens; the one login_failure audit row, the
    /// single save, and the failure metrics are exactly the existing ones.
    /// </summary>
    [Theory]
    [InlineData("13800138000", "123456")]
    [InlineData(null, null)]
    [InlineData("13800138000", "")]
    public async Task GetToken_SmsGrantUnderDisabledPolicy_ReturnsTheStableCode(string? phone, string? code)
    {
        var otp = new Mock<IOtpService>();
        var admission = new Mock<ISmsAdmissionService>();
        using var meter = new Meter("SignaCore");
        var meterFactory = new Mock<IMeterFactory>();
        meterFactory.Setup(factory => factory.Create(It.IsAny<MeterOptions>())).Returns(meter);
        var failures = new List<(string? GrantType, string? Reason)>();
        var durations = 0;
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (ReferenceEquals(instrument.Meter, meter)) l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<int>((instrument, _, tags, _) =>
        {
            if (instrument.Name != "auth.login.failure") return;
            var values = tags.ToArray().ToDictionary(tag => tag.Key, tag => tag.Value as string);
            failures.Add((values["grant_type"], values["reason"]));
        });
        listener.SetMeasurementEventCallback<double>((instrument, _, _, _) =>
        {
            if (instrument.Name == "auth.login.duration") durations++;
        });
        listener.Start();
        var controller = CreateController(
            [CreateSmsValidator(otp, admission)],
            _adminIdentityOptions,
            app: CreateSmsApp(SmsLoginMode.Disabled),
            authMetrics: new AuthMetrics(meterFactory.Object));

        var actionResult = await controller.GetToken(new TokenRequest
        {
            GrantType = IdentityConstants.GrantTypeSms,
            Phone = phone,
            Code = code
        }, CancellationToken.None);

        var response = Assert.IsType<TokenResponse>(AuthTestDoubles.ExtractOk(actionResult).Value);
        Assert.False(response.Success);
        Assert.Equal(SmsDisabledMessage, response.Message);
        Assert.Equal(LegacyAuthResponseCodes.SmsLoginDisabled, response.Code);
        Assert.Equal("SMS_LOGIN_DISABLED", Serialize(response).GetProperty("code").GetString());
        Assert.True(string.IsNullOrEmpty(response.AccessToken));
        Assert.True(string.IsNullOrEmpty(response.RefreshToken));
        Assert.Null(response.UserInfo);

        otp.VerifyNoOtherCalls();
        admission.VerifyNoOtherCalls();
        _tokenServiceMock.VerifyNoOtherCalls();
        _refreshTokenServiceMock.VerifyNoOtherCalls();
        _accountLoginInfoServiceMock.VerifyNoOtherCalls();
        _otpRepositoryMock.VerifyNoOtherCalls();
        _auditServiceMock.Verify(audit => audit.RecordLoginAsync(
            null, phone ?? "unknown", IdentityConstants.GrantTypeSms, "login_failure",
            It.IsAny<string?>(), It.IsAny<string?>(), SmsDisabledMessage,
            "test-app", It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Once);
        _auditServiceMock.Verify(audit => audit.RecordLoginAsync(
            It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Once);
        _unitOfWorkMock.Verify(
            unitOfWork => unitOfWork.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
        Assert.Equal([(IdentityConstants.GrantTypeSms, SmsDisabledMessage)], failures);
        Assert.Equal(1, durations);
    }

    /// <summary>
    /// The code comes only from the typed reason. A failure with the very same message text and
    /// OAuth code but no reason — and the LDAP/WeChat policy rejections that share
    /// <c>unauthorized_client</c> — carry no <c>code</c> property at all.
    /// </summary>
    [Theory]
    [InlineData("sms", "SMS login is disabled for this application")]
    [InlineData("ldap", "LDAP login is disabled for this application")]
    [InlineData("wechat_code", "WeChat login is disabled for this application")]
    [InlineData("refresh_token", "SMS login is disabled for this application")]
    public async Task GetToken_FailureWithoutTheTypedReason_OmitsTheCode(string grantType, string message)
    {
        var validator = new Mock<IIdentityValidator>();
        validator.SetupGet(v => v.GrantType).Returns(grantType);
        validator.Setup(v => v.ValidateAsync(It.IsAny<ValidationRequest>()))
            .ReturnsAsync(ValidationResult.Failure(message, OAuthErrorCodes.UnauthorizedClient));
        var controller = CreateController([validator.Object]);

        var actionResult = await controller.GetToken(new TokenRequest { GrantType = grantType }, CancellationToken.None);

        var response = Assert.IsType<TokenResponse>(AuthTestDoubles.ExtractOk(actionResult).Value);
        Assert.False(response.Success);
        Assert.Equal(message, response.Message);
        Assert.Null(response.Code);
        Assert.False(Serialize(response).TryGetProperty("code", out _));
    }

    /// <summary>
    /// Under an enabled mode the later SMS failures keep their existing message and carry no code.
    /// </summary>
    [Theory]
    [InlineData(SmsLoginMode.ManualApproval, "13800138000", "", "Phone or code cannot be empty")]
    [InlineData(SmsLoginMode.AutoProvision, "12345", "654321", "Invalid mainland China mobile number")]
    [InlineData(SmsLoginMode.ManualApproval, "13800138000", "654321", "SMS account is not authorized for this application")]
    public async Task GetToken_SmsFailureUnderAnEnabledPolicy_OmitsTheCode(
        SmsLoginMode mode, string phone, string code, string message)
    {
        var controller = CreateController(
            [CreateSmsValidator(new Mock<IOtpService>(), new Mock<ISmsAdmissionService>())],
            _adminIdentityOptions,
            app: CreateSmsApp(mode));

        var actionResult = await controller.GetToken(new TokenRequest
        {
            GrantType = IdentityConstants.GrantTypeSms,
            Phone = phone,
            Code = code
        }, CancellationToken.None);

        var response = Assert.IsType<TokenResponse>(AuthTestDoubles.ExtractOk(actionResult).Value);
        Assert.False(response.Success);
        Assert.Equal(message, response.Message);
        Assert.False(Serialize(response).TryGetProperty("code", out _));
    }

    [Fact]
    public async Task GetToken_SuccessAndUnsupportedGrant_OmitTheCode()
    {
        var account = CreateTestAccount();
        var controller = CreateController([CreatePasswordValidator(account, "alice").Object]);

        var success = Assert.IsType<TokenResponse>(AuthTestDoubles.ExtractOk(await controller.GetToken(
            new TokenRequest { GrantType = "password", Username = "alice", Password = "pw" },
            CancellationToken.None)).Value);
        var unsupported = Assert.IsType<TokenResponse>(AuthTestDoubles.ExtractOk(await controller.GetToken(
            new TokenRequest { GrantType = "no_such_grant" },
            CancellationToken.None)).Value);

        Assert.True(success.Success);
        Assert.False(Serialize(success).TryGetProperty("code", out _));
        Assert.False(unsupported.Success);
        Assert.Equal("unsupported_grant_type", unsupported.Message);
        Assert.False(Serialize(unsupported).TryGetProperty("code", out _));
    }

    /// <summary>
    /// The optional property is written only when set; every existing field keeps its name and
    /// position, and a null code is omitted rather than written as null.
    /// </summary>
    [Fact]
    public void LegacyResponses_OmitANullCode_AndWriteASetOne()
    {
        var withoutCode = JsonSerializer.Serialize(new TokenResponse { Success = false, Message = "x" }, WebJson);
        var withCode = JsonSerializer.Serialize(
            new TokenResponse { Success = false, Message = "x", Code = LegacyAuthResponseCodes.SmsLoginDisabled }, WebJson);
        var smsWithout = JsonSerializer.Serialize(new SmsCodeResponse { Success = false, Message = "x" }, WebJson);
        var smsWith = JsonSerializer.Serialize(
            new SmsCodeResponse { Success = false, Message = "x", Code = LegacyAuthResponseCodes.SmsLoginDisabled }, WebJson);

        Assert.Equal(
            "{\"success\":false,\"message\":\"x\",\"accessToken\":\"\",\"refreshToken\":\"\",\"expiresIn\":0,\"expiresAt\":0,\"userInfo\":null}",
            withoutCode);
        Assert.Equal(
            "{\"success\":false,\"message\":\"x\",\"accessToken\":\"\",\"refreshToken\":\"\",\"expiresIn\":0,\"expiresAt\":0,\"userInfo\":null,\"code\":\"SMS_LOGIN_DISABLED\"}",
            withCode);
        Assert.Equal("{\"success\":false,\"message\":\"x\"}", smsWithout);
        Assert.Equal("{\"success\":false,\"message\":\"x\",\"code\":\"SMS_LOGIN_DISABLED\"}", smsWith);
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
