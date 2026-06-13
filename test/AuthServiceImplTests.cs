using System.Security.Claims;
using System.Security.Cryptography;
using Grpc.Core;
using Grpc.Core.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using QuantumZhou.Identity.Contract.Protos;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Validators;
using QuantumZhou.Identity.Service;
using Xunit;

namespace QuantumZhou.Identity.Tests;

public class AuthServiceImplTests
{
    private static IdentityDbContext CreateInMemoryContext()
    {
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        return new IdentityDbContext(options);
    }

    private static JwtOptions CreateJwtOptions() => new() { Issuer = "TestIssuer", Audience = "TestAudience", TokenExpirationHours = 2 };
    private static RefreshTokenOptions CreateRefreshTokenOptions() => new() { RefreshTokenExpirationDays = 7 };
    private static Mock<IKeyManager> CreateMockKeyManager()
    {
        var mock = new Mock<IKeyManager>();
        mock.Setup(k => k.GetCurrentKey()).Returns(new RsaSecurityKey(RSA.Create(2048)));
        mock.Setup(k => k.NeedsKeyRotationAsync()).ReturnsAsync(false);
        mock.Setup(k => k.InitializationCompleted).Returns(Task.CompletedTask);
        return mock;
    }

    private static ILogger<AuthServiceImpl> CreateLogger() => NullLogger<AuthServiceImpl>.Instance;
    private static IPasswordHasher CreatePasswordHasher() => new BCryptPasswordHasher(new PasswordHasherOptions());
    private static IPasswordPolicy CreatePasswordPolicy() => new DefaultPasswordPolicy();
    private static Mock<IAccountRepository> CreateAccountRepoMock()
    {
        var mock = new Mock<IAccountRepository>();
        mock.Setup(r => r.AddAsync(It.IsAny<AccountEntity>())).Returns(Task.CompletedTask);
        mock.Setup(r => r.GetByIdAsync(It.IsAny<Guid>())).ReturnsAsync((Guid id) => new AccountEntity { Id = id, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
        return mock;
    }
    private static Mock<IPasswordCredentialRepository> CreatePasswordCredentialRepoMock()
    {
        var mock = new Mock<IPasswordCredentialRepository>();
        mock.Setup(r => r.AddAsync(It.IsAny<PasswordCredentialEntity>())).Returns(Task.CompletedTask);
        mock.Setup(r => r.ExistsByUsernameAsync(It.IsAny<string>())).ReturnsAsync(false);
        return mock;
    }
    private static Mock<IRefreshTokenRepository> CreateRefreshTokenRepoMock()
    {
        var mock = new Mock<IRefreshTokenRepository>();
        mock.Setup(r => r.AddAsync(It.IsAny<RefreshTokenEntity>())).Returns(Task.CompletedTask);
        return mock;
    }
    private static Mock<IAppRegistrationRepository> CreateAppRegistrationRepoMock(IdentityDbContext context)
    {
        var mock = new Mock<IAppRegistrationRepository>();
        mock.Setup(r => r.GetByAppIdAsync(It.IsAny<string>()))
            .Returns((string appId) => context.AppRegistrations.FirstOrDefaultAsync(a => a.AppId == appId));
        mock.Setup(r => r.AddAsync(It.IsAny<AppRegistrationEntity>())).Returns(Task.CompletedTask);
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
        mock.Setup(a => a.RecordLoginAsync(It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>()))
            .Returns(Task.CompletedTask);
        mock.Setup(a => a.RecordActionAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<object?>(), It.IsAny<object?>()))
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

    private static ServerCallContext CreateMockServerCallContext() =>
        TestServerCallContext.Create(
            "/auth/Auth/GetToken",
            "localhost",
            DateTime.UtcNow.AddHours(1),
            new Metadata(),
            CancellationToken.None,
            "127.0.0.1",
            new AuthContext("localhost", new Dictionary<string, List<AuthProperty>>()),
            null,
            null,
            null,
            null);

    private static void SetupAppRegistration(IdentityDbContext context, string appId = "testapp", string appSecret = "testsecret")
    {
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(appSecret),
            AppName = "Test App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
    }

    private static Mock<ITokenService> CreateMockTokenService()
    {
        var mock = new Mock<ITokenService>();
        mock.Setup(t => t.GenerateJwtToken(It.IsAny<List<Claim>>(), It.IsAny<RsaSecurityKey>(), It.IsAny<int>())).Returns("mock_jwt_token");
        return mock;
    }

    private static GatewayValidationService CreateGatewayValidator(Mock<IAppRegistrationRepository> appRegRepoMock)
    {
        return new GatewayValidationService(
            appRegRepoMock.Object,
            NullLogger<GatewayValidationService>.Instance);
    }

    private static AuthServiceImpl CreateService(
        IdentityDbContext context,
        Mock<IAppRegistrationRepository>? appRegRepoMock = null,
        Mock<IRefreshTokenRepository>? refreshTokenRepoMock = null,
        ICallbackService? callbackService = null)
    {
        var appRegMock = appRegRepoMock ?? CreateAppRegistrationRepoMock(context);
        var refreshTokenMock = refreshTokenRepoMock ?? CreateRefreshTokenRepoMock();
        var validators = Array.Empty<IIdentityValidator>();
        var factory = new ValidatorFactory(validators, NullLogger<ValidatorFactory>.Instance);
        var claimsResolver = new ClaimsResolver(NullLogger<ClaimsResolver>.Instance);
        var auditServiceMock = CreateAuditServiceMock();
        return new AuthServiceImpl(
            CreateMockKeyManager().Object,
            CreateMockTokenService().Object,
            CreateJwtOptions(),
            CreateRefreshTokenOptions(),
            appRegMock.Object,
            refreshTokenMock.Object,
            claimsResolver,
            factory,
            callbackService,
            CreateAuthMetrics(),
            CreateLogger(),
            CreateGatewayValidator(appRegMock),
            CreatePasswordPolicy(),
            CreatePasswordHasher(),
            CreateAccountRepoMock().Object,
            CreatePasswordCredentialRepoMock().Object,
            CreateUnitOfWorkMock().Object,
            auditServiceMock.Object);
    }

    private static AuthServiceImpl CreateServiceWithPasswordValidator(
        Mock<IAppRegistrationRepository> appRegRepoMock,
        Mock<IRefreshTokenRepository> refreshTokenRepoMock,
        Mock<IAccountRepository> accountRepoMock,
        Mock<IPasswordCredentialRepository> passwordRepoMock,
        IPasswordHasher hasher)
    {
        var validators = new IIdentityValidator[] { new PasswordValidator(passwordRepoMock.Object, accountRepoMock.Object, new Mock<ILoginAttemptRepository>().Object, CreateUnitOfWorkMock().Object, hasher, NullLogger<PasswordValidator>.Instance) };
        var factory = new ValidatorFactory(validators, NullLogger<ValidatorFactory>.Instance);
        var claimsResolver = new ClaimsResolver(NullLogger<ClaimsResolver>.Instance);
        return new AuthServiceImpl(
            CreateMockKeyManager().Object,
            CreateMockTokenService().Object,
            CreateJwtOptions(),
            CreateRefreshTokenOptions(),
            appRegRepoMock.Object,
            refreshTokenRepoMock.Object,
            claimsResolver,
            factory,
            null,
            CreateAuthMetrics(),
            CreateLogger(),
            CreateGatewayValidator(appRegRepoMock),
            CreatePasswordPolicy(),
            CreatePasswordHasher(),
            accountRepoMock.Object,
            passwordRepoMock.Object,
            CreateUnitOfWorkMock().Object,
            CreateAuditServiceMock().Object);
    }

    private static AuthServiceImpl CreateServiceWithRefreshTokenValidator(
        Mock<IAppRegistrationRepository> appRegRepoMock,
        Mock<IRefreshTokenRepository> refreshTokenRepoMock,
        Mock<IAccountRepository> accountRepoMock)
    {
        var validators = new IIdentityValidator[] { new RefreshTokenValidator(refreshTokenRepoMock.Object, accountRepoMock.Object, NullLogger<RefreshTokenValidator>.Instance) };
        var factory = new ValidatorFactory(validators, NullLogger<ValidatorFactory>.Instance);
        var claimsResolver = new ClaimsResolver(NullLogger<ClaimsResolver>.Instance);
        return new AuthServiceImpl(
            CreateMockKeyManager().Object,
            CreateMockTokenService().Object,
            CreateJwtOptions(),
            CreateRefreshTokenOptions(),
            appRegRepoMock.Object,
            refreshTokenRepoMock.Object,
            claimsResolver,
            factory,
            null,
            CreateAuthMetrics(),
            CreateLogger(),
            CreateGatewayValidator(appRegRepoMock),
            CreatePasswordPolicy(),
            CreatePasswordHasher(),
            accountRepoMock.Object,
            CreatePasswordCredentialRepoMock().Object,
            CreateUnitOfWorkMock().Object,
            CreateAuditServiceMock().Object);
    }

    [Fact]
    public async Task GetTokenAsync_WithValidPasswordCredentials_ReturnsSuccess()
    {
        var context = CreateInMemoryContext();
        var accountId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });

        var passwordHash = CreatePasswordHasher().HashPassword("correctpassword");
        context.PasswordCredentials.Add(new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = accountId, Username = "testuser", PasswordHash = passwordHash, CreatedAt = DateTimeOffset.UtcNow });
        SetupAppRegistration(context);
        await context.SaveChangesAsync();

        var hasher = CreatePasswordHasher();
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
        accountRepoMock.Setup(r => r.UpdateAsync(It.IsAny<AccountEntity>())).Returns(Task.CompletedTask);
        var passwordRepoMock = new Mock<IPasswordCredentialRepository>();
        passwordRepoMock.Setup(r => r.GetByUsernameAsync("testuser")).ReturnsAsync(new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = accountId, Username = "testuser", PasswordHash = passwordHash, CreatedAt = DateTimeOffset.UtcNow });
        var appRegRepoMock = CreateAppRegistrationRepoMock(context);
        var refreshTokenRepoMock = CreateRefreshTokenRepoMock();

        var service = CreateServiceWithPasswordValidator(appRegRepoMock, refreshTokenRepoMock, accountRepoMock, passwordRepoMock, hasher);

        var request = new GetTokenRequest { GrantType = "password", AppId = "testapp", AppSecret = "testsecret", Password = new PasswordCredential { Username = "testuser", Password = "correctpassword" } };

        var response = await service.GetToken(request, CreateMockServerCallContext());

        Assert.True(response.Success);
        Assert.NotNull(response.AccessToken);
        Assert.NotNull(response.RefreshToken);
        Assert.NotEmpty(response.RefreshToken);
        Assert.Equal(7200, response.ExpiresIn);
    }

    [Fact]
    public async Task GetTokenAsync_WithWrongPassword_ReturnsFailure()
    {
        var context = CreateInMemoryContext();
        var accountId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });

        var passwordHash = CreatePasswordHasher().HashPassword("correctpassword");
        context.PasswordCredentials.Add(new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = accountId, Username = "testuser", PasswordHash = passwordHash, CreatedAt = DateTimeOffset.UtcNow });
        SetupAppRegistration(context);
        await context.SaveChangesAsync();

        var hasher = CreatePasswordHasher();
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
        var passwordRepoMock = new Mock<IPasswordCredentialRepository>();
        passwordRepoMock.Setup(r => r.GetByUsernameAsync("testuser")).ReturnsAsync(new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = accountId, Username = "testuser", PasswordHash = passwordHash, CreatedAt = DateTimeOffset.UtcNow });
        var appRegRepoMock = CreateAppRegistrationRepoMock(context);
        var refreshTokenRepoMock = CreateRefreshTokenRepoMock();

        var service = CreateServiceWithPasswordValidator(appRegRepoMock, refreshTokenRepoMock, accountRepoMock, passwordRepoMock, hasher);

        var request = new GetTokenRequest { GrantType = "password", AppId = "testapp", AppSecret = "testsecret", Password = new PasswordCredential { Username = "testuser", Password = "wrongpassword" } };

        var response = await service.GetToken(request, CreateMockServerCallContext());

        Assert.False(response.Success);
        Assert.Contains("Wrong username or password", response.Message);
    }

    [Fact]
    public async Task GetTokenAsync_WithNonExistentUser_ReturnsFailure()
    {
        var context = CreateInMemoryContext();
        SetupAppRegistration(context);
        await context.SaveChangesAsync();

        var passwordRepoMock = new Mock<IPasswordCredentialRepository>();
        passwordRepoMock.Setup(r => r.GetByUsernameAsync(It.IsAny<string>())).ReturnsAsync((PasswordCredentialEntity?)null);
        var accountRepoMock = new Mock<IAccountRepository>();
        var appRegRepoMock = CreateAppRegistrationRepoMock(context);
        var refreshTokenRepoMock = CreateRefreshTokenRepoMock();

        var hasher = CreatePasswordHasher();
        var service = CreateServiceWithPasswordValidator(appRegRepoMock, refreshTokenRepoMock, accountRepoMock, passwordRepoMock, hasher);

        var request = new GetTokenRequest { GrantType = "password", AppId = "testapp", AppSecret = "testsecret", Password = new PasswordCredential { Username = "nonexistent", Password = "password" } };

        var response = await service.GetToken(request, CreateMockServerCallContext());

        Assert.False(response.Success);
        Assert.Contains("Wrong username or password", response.Message);
    }

    [Fact]
    public async Task GetTokenAsync_WithDisabledAccount_ReturnsFailure()
    {
        var context = CreateInMemoryContext();
        var accountId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = false, CreatedAt = DateTimeOffset.UtcNow });

        var passwordHash = CreatePasswordHasher().HashPassword("password");
        context.PasswordCredentials.Add(new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = accountId, Username = "inactiveuser", PasswordHash = passwordHash, CreatedAt = DateTimeOffset.UtcNow });
        SetupAppRegistration(context);
        await context.SaveChangesAsync();

        var hasher = CreatePasswordHasher();
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(new AccountEntity { Id = accountId, IsActive = false, CreatedAt = DateTimeOffset.UtcNow });
        var passwordRepoMock = new Mock<IPasswordCredentialRepository>();
        passwordRepoMock.Setup(r => r.GetByUsernameAsync("inactiveuser")).ReturnsAsync(new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = accountId, Username = "inactiveuser", PasswordHash = passwordHash, CreatedAt = DateTimeOffset.UtcNow });
        var appRegRepoMock = CreateAppRegistrationRepoMock(context);
        var refreshTokenRepoMock = CreateRefreshTokenRepoMock();

        var service = CreateServiceWithPasswordValidator(appRegRepoMock, refreshTokenRepoMock, accountRepoMock, passwordRepoMock, hasher);

        var request = new GetTokenRequest { GrantType = "password", AppId = "testapp", AppSecret = "testsecret", Password = new PasswordCredential { Username = "inactiveuser", Password = "password" } };

        var response = await service.GetToken(request, CreateMockServerCallContext());

        Assert.False(response.Success);
        Assert.Contains("Account is disabled", response.Message);
    }

    [Fact]
    public async Task GetTokenAsync_WithRefreshToken_ReturnsSuccess()
    {
        var context = CreateInMemoryContext();
        var accountId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });

        var refreshToken = new RefreshTokenEntity { Id = Guid.NewGuid(), AccountId = accountId, TokenValue = "valid_refresh_token", ExpiresAt = DateTimeOffset.UtcNow.AddDays(1), IsRevoked = false, CreatedAt = DateTimeOffset.UtcNow };
        context.RefreshTokens.Add(refreshToken);

        SetupAppRegistration(context);
        await context.SaveChangesAsync();

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("valid_refresh_token")).ReturnsAsync(refreshToken);
        refreshTokenRepoMock.Setup(r => r.AddAsync(It.IsAny<RefreshTokenEntity>())).Returns(Task.CompletedTask);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
        accountRepoMock.Setup(r => r.UpdateAsync(It.IsAny<AccountEntity>())).Returns(Task.CompletedTask);
        var appRegRepoMock = CreateAppRegistrationRepoMock(context);

        var service = CreateServiceWithRefreshTokenValidator(appRegRepoMock, refreshTokenRepoMock, accountRepoMock);

        var request = new GetTokenRequest { GrantType = "refresh_token", AppId = "testapp", AppSecret = "testsecret", RefreshToken = new RefreshTokenCredential { RefreshToken = "valid_refresh_token" } };

        var response = await service.GetToken(request, CreateMockServerCallContext());

        Assert.True(response.Success);
        Assert.NotNull(response.AccessToken);
        Assert.NotNull(response.RefreshToken);
        Assert.NotEmpty(response.RefreshToken);
        Assert.Equal(7200, response.ExpiresIn);
    }

    [Fact]
    public async Task GetTokenAsync_WithUnsupportedGrantType_ReturnsFailure()
    {
        var context = CreateInMemoryContext();
        SetupAppRegistration(context);
        await context.SaveChangesAsync();

        var appRegRepoMock = CreateAppRegistrationRepoMock(context);
        var service = CreateService(context, appRegRepoMock);

        var request = new GetTokenRequest { GrantType = "unsupported_type", AppId = "testapp", AppSecret = "testsecret" };

        var response = await service.GetToken(request, CreateMockServerCallContext());

        Assert.False(response.Success);
        Assert.Contains("Unsupported grant_type", response.Message);
    }

    [Fact]
    public async Task GetTokenAsync_WithInvalidGatewayCredentials_ReturnsFailure()
    {
        var context = CreateInMemoryContext();
        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.GetByAppIdAsync("testapp")).ReturnsAsync((AppRegistrationEntity?)null);
        var service = CreateService(context, appRegRepoMock);

        var request = new GetTokenRequest { GrantType = "password", AppId = "testapp", AppSecret = "wrongsecret" };

        var response = await service.GetToken(request, CreateMockServerCallContext());

        Assert.False(response.Success);
    }

    [Fact]
    public async Task RegisterCallbackAsync_WithValidAppId_ReturnsSuccess()
    {
        var context = CreateInMemoryContext();

        var app = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "valid_app_id", AppSecretHash = BCrypt.Net.BCrypt.HashPassword("valid_secret"), AppName = "Valid App", CallbackUrl = "http://valid.example.com/callback", IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        context.AppRegistrations.Add(app);
        await context.SaveChangesAsync();

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.GetByAppIdAsync("valid_app_id")).ReturnsAsync(app);
        var service = CreateService(context, appRegRepoMock);

        var request = new RegisterCallbackRequest { AppId = "valid_app_id", AppSecret = "valid_secret", CallbackUrl = "http://valid.example.com/callback", TtlSeconds = 3600 };

        var response = await service.RegisterCallback(request, CreateMockServerCallContext());

        Assert.True(response.Success);
        Assert.NotEmpty(response.Message);
    }

    [Fact]
    public async Task RegisterCallbackAsync_WithNeverExpireTtl_SetsCallbackExpiresAtToNull()
    {
        var context = CreateInMemoryContext();

        var app = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "never_expire_app", AppSecretHash = BCrypt.Net.BCrypt.HashPassword("valid_secret"), AppName = "Never Expire App", CallbackUrl = "http://valid.example.com/callback", IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        context.AppRegistrations.Add(app);
        await context.SaveChangesAsync();

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.GetByAppIdAsync("never_expire_app")).ReturnsAsync(app);
        var service = CreateService(context, appRegRepoMock);

        var request = new RegisterCallbackRequest { AppId = "never_expire_app", AppSecret = "valid_secret", CallbackUrl = "http://valid.example.com/callback", TtlSeconds = -1 };

        var response = await service.RegisterCallback(request, CreateMockServerCallContext());

        Assert.True(response.Success);
        Assert.Null(app.CallbackExpiresAt);
        Assert.Equal(0, response.ExpiresAt);
    }

    [Fact]
    public async Task RegisterCallbackAsync_WithMissingAppId_ReturnsFailure()
    {
        var context = CreateInMemoryContext();
        var service = CreateService(context);

        var request = new RegisterCallbackRequest { AppId = "", AppSecret = "secret", CallbackUrl = "http://example.com/callback" };

        var response = await service.RegisterCallback(request, CreateMockServerCallContext());

        Assert.False(response.Success);
        Assert.Contains("required", response.Message);
    }

    [Fact]
    public async Task RegisterCallbackAsync_WithWrongAppSecret_ReturnsFailure()
    {
        var context = CreateInMemoryContext();
        var app = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "valid_app_id", AppSecretHash = BCrypt.Net.BCrypt.HashPassword("valid_secret"), AppName = "Valid App", IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        context.AppRegistrations.Add(app);
        await context.SaveChangesAsync();

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.GetByAppIdAsync("valid_app_id")).ReturnsAsync(app);
        var service = CreateService(context, appRegRepoMock);

        var request = new RegisterCallbackRequest { AppId = "valid_app_id", AppSecret = "wrong_secret", CallbackUrl = "http://example.com/callback" };

        var response = await service.RegisterCallback(request, CreateMockServerCallContext());

        Assert.False(response.Success);
        Assert.Contains("mismatch", response.Message);
    }

    [Fact]
    public async Task RevokeRefreshTokenAsync_WithValidToken_ReturnsSuccess()
    {
        var context = CreateInMemoryContext();
        var accountId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });

        var refreshToken = new RefreshTokenEntity { Id = Guid.NewGuid(), AccountId = accountId, TokenValue = "token_to_revoke", ExpiresAt = DateTimeOffset.UtcNow.AddDays(1), IsRevoked = false, CreatedAt = DateTimeOffset.UtcNow };
        context.RefreshTokens.Add(refreshToken);
        await context.SaveChangesAsync();

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("token_to_revoke")).ReturnsAsync(refreshToken);
        var appRegRepoMock = CreateAppRegistrationRepoMock(context);
        var service = CreateService(context, appRegRepoMock, refreshTokenRepoMock);

        var request = new RevokeRefreshTokenRequest { RefreshToken = "token_to_revoke" };

        var response = await service.RevokeRefreshToken(request, CreateMockServerCallContext());

        Assert.True(response.Success);
        Assert.True(refreshToken.IsRevoked);
    }

    [Fact]
    public async Task RevokeRefreshTokenAsync_WithEmptyToken_ReturnsFailure()
    {
        var context = CreateInMemoryContext();
        var service = CreateService(context);

        var request = new RevokeRefreshTokenRequest { RefreshToken = "" };

        var response = await service.RevokeRefreshToken(request, CreateMockServerCallContext());

        Assert.False(response.Success);
    }

    [Fact]
    public async Task RevokeRefreshTokenAsync_WithNonExistentToken_ReturnsFailure()
    {
        var context = CreateInMemoryContext();
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("nonexistent")).ReturnsAsync((RefreshTokenEntity?)null);
        var appRegRepoMock = CreateAppRegistrationRepoMock(context);
        var service = CreateService(context, appRegRepoMock, refreshTokenRepoMock);

        var request = new RevokeRefreshTokenRequest { RefreshToken = "nonexistent" };

        var response = await service.RevokeRefreshToken(request, CreateMockServerCallContext());

        Assert.False(response.Success);
    }
}
