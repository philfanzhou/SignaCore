using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Grpc.Core;
using Grpc.Core.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
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
using QuantumZhou.Identity.Domain.Services.Sms;
using QuantumZhou.Identity.Domain.Validators;
using QuantumZhou.Identity.Service;
using Xunit;

namespace QuantumZhou.Identity.Tests.Integration;

public class RegistrationIntegrationTests : IAsyncLifetime
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

        var smsOptions = new SmsOptions
        {
            OtpTtlSeconds = 300,
            MaxAttempts = 5,
            LockoutSeconds = 600
        };
        services.AddSingleton(smsOptions);

        var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
        var meter = new System.Diagnostics.Metrics.Meter("TestMeter");
        meterFactory.Setup(m => m.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>())).Returns(meter);
        services.AddSingleton(meterFactory.Object);
        services.AddSingleton(new AuthMetrics(meterFactory.Object));

        services.AddScoped<IAccountRepository, AccountRepository>();
        services.AddScoped<IPasswordCredentialRepository, PasswordCredentialRepository>();
        services.AddScoped<IUserLoginRepository, UserLoginRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IAppRegistrationRepository, AppRegistrationRepository>();
        services.AddScoped<IOtpRepository, OtpRepository>();
        services.AddScoped<ILoginAttemptRepository, LoginAttemptRepository>();
        services.AddScoped<ILoginHistoryRepository, LoginHistoryRepository>();
        services.AddScoped<IAuditLogRepository, AuditLogRepository>();
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IUnitOfWork, EfCoreUnitOfWork>();

        services.AddScoped<IIdentityValidator, PasswordValidator>();
        services.AddScoped<IIdentityValidator, SmsValidator>();
        services.AddScoped<IIdentityValidator, RefreshTokenValidator>();
        services.AddScoped<ValidatorFactory>();
        services.AddScoped<ClaimsResolver>();
        services.AddScoped<ICallbackService, CallbackService>();
        services.AddSingleton<CallbackUrlValidator>();

        services.AddScoped<IOtpService>(sp =>
        {
            var mock = new Mock<IOtpService>();
            mock.Setup(o => o.VerifyAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(true);
            return mock.Object;
        });

        services.AddSingleton<ISmsSender, LoggingSmsSender>();

        services.AddLogging();

        _serviceProvider = services.BuildServiceProvider();

        _dbContext = _serviceProvider.GetRequiredService<IdentityDbContext>();
        _dbContext.Database.EnsureCreated();

        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
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

    private AuthServiceImpl CreateService(out IServiceScope scope)
    {
        scope = _serviceProvider!.CreateScope();
        var keyManager = CreateMockKeyManager();
        var tokenService = new JwtTokenService(_serviceProvider!.GetRequiredService<JwtOptions>());
        var jwtOptions = _serviceProvider!.GetRequiredService<JwtOptions>();
        var refreshTokenOptions = _serviceProvider!.GetRequiredService<RefreshTokenOptions>();
        var claimsResolver = scope.ServiceProvider.GetRequiredService<ClaimsResolver>();
        var validatorFactory = scope.ServiceProvider.GetRequiredService<ValidatorFactory>();
        var authMetrics = _serviceProvider!.GetRequiredService<AuthMetrics>();
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

        return new AuthServiceImpl(
            keyManager,
            tokenService,
            jwtOptions,
            refreshTokenOptions,
            appRegRepository,
            refreshTokenRepository,
            claimsResolver,
            validatorFactory,
            null,
            authMetrics,
            logger,
            gatewayValidator,
            callbackUrlValidator,
            passwordPolicy,
            passwordHasher,
            accountRepository,
            passwordCredentialRepository,
            unitOfWork,
            auditService,
            otpService,
            smsSender);
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

    private async Task SeedAppRegistrationAsync(string appId, string appSecret)
    {
        var appRegistration = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(appSecret),
            AppName = "Test App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        _dbContext!.AppRegistrations.Add(appRegistration);
        await _dbContext.SaveChangesAsync();
    }

    [Fact]
    public async Task SmsAutoRegistration_NewUser_LoginCreatesAccount_ReturnsToken()
    {
        var appId = $"test_app_{Guid.NewGuid():N}";
        var appSecret = "test_secret_sms";
        await SeedAppRegistrationAsync(appId, appSecret);

        var service = CreateService(out var scope);

        var phone = $"138{Guid.NewGuid():N}".Substring(0, 11);
        var request = new GetTokenRequest
        {
            GrantType = "sms",
            AppId = appId,
            AppSecret = appSecret,
            Sms = new SmsCredential { Phone = phone, Code = "123456" }
        };

        var response = await service.GetToken(request, CreateServerCallContext());

        Assert.True(response.Success, $"SMS auto-registration failed: {response.Message}");
        Assert.NotNull(response.AccessToken);
        Assert.NotEmpty(response.AccessToken);
        Assert.NotNull(response.RefreshToken);
        Assert.NotEmpty(response.RefreshToken);
        Assert.Equal("Sms", response.UserInfo.AuthMethod);

        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.ReadJwtToken(response.AccessToken);
        Assert.Equal("TestIssuer", jwtToken.Issuer);
        Assert.Contains("TestAudience", jwtToken.Audiences);

        var accountId = Guid.Parse(response.UserInfo.UserId);
        Assert.NotEqual(Guid.Empty, accountId);

        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var account = await dbContext.Accounts.FindAsync(accountId);
        Assert.NotNull(account);
        Assert.True(account!.IsActive);

        var userLogin = await dbContext.UserLogins
            .FirstOrDefaultAsync(ul => ul.AccountId == accountId && ul.ProviderName == "Sms" && ul.ProviderUserId == phone);
        Assert.NotNull(userLogin);
    }

}
