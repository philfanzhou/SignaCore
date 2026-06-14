using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Grpc.Core;
using Grpc.Core.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using QuantumZhou.Identity.Contract.Protos;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Services.Sms;
using QuantumZhou.Identity.Domain.Validators;
using QuantumZhou.Identity.Service;
using Xunit;

namespace QuantumZhou.Identity.Tests.Integration;

public class AuthServiceImplIntegrationTests : IAsyncLifetime
{
    private SqliteConnection? _connection;
    private IdentityDbContext? _dbContext;
    private ServiceProvider? _serviceProvider;

    public Task InitializeAsync()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        var services = new ServiceCollection();

        services.AddDbContext<IdentityDbContext>(options =>
            options.UseSqlite(_connection));

        services.AddSingleton(new JwtOptions { Issuer = "TestIssuer", Audience = "TestAudience", TokenExpirationHours = 2 });
        services.AddSingleton(new RefreshTokenOptions { RefreshTokenExpirationDays = 7 });
        services.AddSingleton(new PasswordHasherOptions { WorkFactor = 4 });
        services.AddSingleton<IPasswordHasher, BCryptPasswordHasher>();
        services.AddSingleton<ITokenService, JwtTokenService>();
        services.AddSingleton<IPasswordPolicy, DefaultPasswordPolicy>();
        services.AddHttpClient();

        var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
        var meter = new System.Diagnostics.Metrics.Meter("TestMeter");
        meterFactory.Setup(m => m.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>())).Returns(meter);
        services.AddSingleton(meterFactory);
        services.AddSingleton(new AuthMetrics(meterFactory.Object));

        services.AddScoped<IAccountRepository, AccountRepository>();
        services.AddScoped<IPasswordCredentialRepository, PasswordCredentialRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IAppRegistrationRepository, AppRegistrationRepository>();
        services.AddScoped<ILoginAttemptRepository, LoginAttemptRepository>();
        services.AddScoped<ILoginHistoryRepository, LoginHistoryRepository>();
        services.AddScoped<IAuditLogRepository, AuditLogRepository>();
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IOtpRepository, OtpRepository>();
        services.AddScoped<IUnitOfWork, EfCoreUnitOfWork>();

        services.AddScoped<IIdentityValidator, PasswordValidator>();
        services.AddScoped<IIdentityValidator, RefreshTokenValidator>();
        services.AddScoped<ValidatorFactory>();
        services.AddScoped<ClaimsResolver>();
        services.AddScoped<ICallbackService, CallbackService>();

        services.AddLogging();

        _serviceProvider = services.BuildServiceProvider();

        _dbContext = _serviceProvider.GetRequiredService<IdentityDbContext>();
        _dbContext.Database.EnsureCreated();

        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        _lastScope?.Dispose();

        if (_dbContext != null)
        {
            await _dbContext.Database.EnsureDeletedAsync();
            await _dbContext.DisposeAsync();
        }

        if (_serviceProvider != null)
        {
            await _serviceProvider.DisposeAsync();
        }

        if (_connection != null)
        {
            await _connection.CloseAsync();
            await _connection.DisposeAsync();
        }
    }

    private IServiceScope? _lastScope;

    private AuthServiceImpl CreateService()
    {
        var scope = _serviceProvider!.CreateScope();
        _lastScope = scope;
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var keyManager = CreateMockKeyManager();
        var tokenService = new JwtTokenService(scope.ServiceProvider.GetRequiredService<JwtOptions>());
        var jwtOptions = scope.ServiceProvider.GetRequiredService<JwtOptions>();
        var refreshTokenOptions = scope.ServiceProvider.GetRequiredService<RefreshTokenOptions>();
        var claimsResolver = scope.ServiceProvider.GetRequiredService<ClaimsResolver>();
        var validatorFactory = scope.ServiceProvider.GetRequiredService<ValidatorFactory>();
        var authMetrics = scope.ServiceProvider.GetRequiredService<AuthMetrics>();
        var logger = NullLogger<AuthServiceImpl>.Instance;
        var passwordPolicy = scope.ServiceProvider.GetRequiredService<IPasswordPolicy>();
        var passwordHasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
        var accountRepository = scope.ServiceProvider.GetRequiredService<IAccountRepository>();
        var passwordCredentialRepository = scope.ServiceProvider.GetRequiredService<IPasswordCredentialRepository>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var appRegRepository = scope.ServiceProvider.GetRequiredService<IAppRegistrationRepository>();
        var refreshTokenRepository = scope.ServiceProvider.GetRequiredService<IRefreshTokenRepository>();
        var gatewayValidator = new GatewayValidationService(appRegRepository, NullLogger<GatewayValidationService>.Instance);
        var auditService = scope.ServiceProvider.GetRequiredService<IAuditService>();
        var callbackUrlValidator = scope.ServiceProvider.GetRequiredService<CallbackUrlValidator>();
        var otpService = scope.ServiceProvider.GetRequiredService<IOtpService>();
        var smsSender = scope.ServiceProvider.GetRequiredService<ISmsSender>();

        return new AuthServiceImpl(keyManager, tokenService, jwtOptions, refreshTokenOptions, appRegRepository, refreshTokenRepository, claimsResolver, validatorFactory, null, authMetrics, logger, gatewayValidator, callbackUrlValidator, passwordPolicy, passwordHasher, accountRepository, passwordCredentialRepository, unitOfWork, auditService, otpService, smsSender);
    }

    private IKeyManager CreateMockKeyManager()
    {
        var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = "test-key-id" };
        var mock = new Mock<IKeyManager>();
        mock.Setup(k => k.GetCurrentKey()).Returns(key);
        return mock.Object;
    }

    private static ServerCallContext CreateServerCallContext()
    {
        return TestServerCallContext.Create(
            "/auth/Auth/GetToken",
            "localhost",
            DateTime.UtcNow.AddHours(1),
            new Metadata(),
            CancellationToken.None,
            "127.0.0.1",
            new AuthContext("localhost", new Dictionary<string, List<AuthProperty>>()),
            null, null, null, null);
    }

    [Fact]
    public async Task FullPasswordLoginFlow_RegisterApp_CreateAccount_Login_GetToken()
    {
        using var scope = _serviceProvider!.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

        var appId = $"test_app_{Guid.NewGuid():N}";
        var appSecret = "test_secret_123";
        var appRegistration = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(appSecret),
            AppName = "Test App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        dbContext.AppRegistrations.Add(appRegistration);

        var accountId = Guid.NewGuid();
        var account = new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        dbContext.Accounts.Add(account);

        var username = $"testuser_{Guid.NewGuid():N}";
        var password = "SecurePassword123!";
        var passwordCredential = new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(password),
            CreatedAt = DateTimeOffset.UtcNow
        };
        dbContext.PasswordCredentials.Add(passwordCredential);

        await dbContext.SaveChangesAsync();

        var service = CreateService();

        var request = new GetTokenRequest
        {
            GrantType = "password",
            AppId = appId,
            AppSecret = appSecret,
            Password = new PasswordCredential { Username = username, Password = password }
        };

        var response = await service.GetToken(request, CreateServerCallContext());

        Assert.True(response.Success, $"Login failed: {response.Message}");
        Assert.NotNull(response.AccessToken);
        Assert.NotEmpty(response.AccessToken);
        Assert.NotNull(response.RefreshToken);
        Assert.NotEmpty(response.RefreshToken);
        Assert.Equal(7200, response.ExpiresIn);

        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.ReadJwtToken(response.AccessToken);
        Assert.Equal("TestIssuer", jwtToken.Issuer);
        Assert.Contains("TestAudience", jwtToken.Audiences);
        Assert.Contains(jwtToken.Claims, c => c.Type == ClaimTypes.NameIdentifier && c.Value == accountId.ToString());
    }

    [Fact]
    public async Task RefreshTokenFlow_Login_GetRefreshToken_UseRefreshToken_GetNewToken()
    {
        using var scope = _serviceProvider!.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

        var appId = $"test_app_{Guid.NewGuid():N}";
        var appSecret = "test_secret_456";
        var appRegistration = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(appSecret),
            AppName = "Test App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        dbContext.AppRegistrations.Add(appRegistration);

        var accountId = Guid.NewGuid();
        var account = new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        dbContext.Accounts.Add(account);

        var username = $"refreshuser_{Guid.NewGuid():N}";
        var password = "SecurePassword123!";
        var passwordCredential = new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(password),
            CreatedAt = DateTimeOffset.UtcNow
        };
        dbContext.PasswordCredentials.Add(passwordCredential);

        await dbContext.SaveChangesAsync();

        var service = CreateService();

        var loginRequest = new GetTokenRequest
        {
            GrantType = "password",
            AppId = appId,
            AppSecret = appSecret,
            Password = new PasswordCredential { Username = username, Password = password }
        };

        var loginResponse = await service.GetToken(loginRequest, CreateServerCallContext());
        Assert.True(loginResponse.Success, $"Initial login failed: {loginResponse.Message}");

        var refreshToken = loginResponse.RefreshToken;
        Assert.NotNull(refreshToken);
        Assert.NotEmpty(refreshToken);

        var refreshRequest = new GetTokenRequest
        {
            GrantType = "refresh_token",
            AppId = appId,
            AppSecret = appSecret,
            RefreshToken = new RefreshTokenCredential { RefreshToken = refreshToken }
        };

        var refreshResponse = await service.GetToken(refreshRequest, CreateServerCallContext());

        Assert.True(refreshResponse.Success, $"Refresh token failed: {refreshResponse.Message}");
        Assert.NotNull(refreshResponse.AccessToken);
        Assert.NotEmpty(refreshResponse.AccessToken);
        Assert.NotNull(refreshResponse.RefreshToken);
        Assert.NotEmpty(refreshResponse.RefreshToken);
        Assert.NotEqual(refreshToken, refreshResponse.RefreshToken);

        var revokedRequest = new RevokeRefreshTokenRequest { RefreshToken = refreshToken };
        var revokeResponse = await service.RevokeRefreshToken(revokedRequest, CreateServerCallContext());
        Assert.True(revokeResponse.Success);
    }

    [Fact]
    public void JwksEndpoint_ReturnsValidKey()
    {
        var rsa = RSA.Create(2048);
        var keyId = "test-jwks-key-id";
        var key = new RsaSecurityKey(rsa) { KeyId = keyId };
        var mockKeyManager = new Mock<IKeyManager>();
        mockKeyManager.Setup(k => k.GetCurrentKey()).Returns(key);

        var parameters = rsa.ExportParameters(false);

        var jwk = new
        {
            kty = "RSA",
            use = "sig",
            kid = key.KeyId,
            alg = "RS256",
            n = Base64UrlEncoder.Encode(parameters.Modulus!),
            e = Base64UrlEncoder.Encode(parameters.Exponent!)
        };

        Assert.Equal("RSA", jwk.kty);
        Assert.Equal("sig", jwk.use);
        Assert.Equal(keyId, jwk.kid);
        Assert.Equal("RS256", jwk.alg);
        Assert.NotNull(jwk.n);
        Assert.NotEmpty(jwk.n);
        Assert.NotNull(jwk.e);
        Assert.NotEmpty(jwk.e);
    }
}
