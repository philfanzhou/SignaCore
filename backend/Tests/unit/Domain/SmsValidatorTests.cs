using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services.Sms;
using QuantumZhou.Identity.Domain.Validators;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain.Validators;

public class SmsValidatorTests
{
    private static ILogger<SmsValidator> CreateLogger() => NullLogger<SmsValidator>.Instance;

    private static Mock<IOtpService> CreateOtpServiceMock(bool verified = true)
    {
        var mock = new Mock<IOtpService>();
        mock.Setup(o => o.VerifyAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(verified);
        return mock;
    }

    private static Mock<IUserLoginRepository> CreateUserLoginRepoMock()
    {
        var mock = new Mock<IUserLoginRepository>();
        return mock;
    }

    private static Mock<IUnitOfWork> CreateUnitOfWorkMock()
    {
        var mock = new Mock<IUnitOfWork>();
        mock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);
        return mock;
    }

    private static AuthMetrics CreateAuthMetrics()
    {
        var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
        var meter = new System.Diagnostics.Metrics.Meter("QuantumZhou.Identity");
        meterFactory.Setup(m => m.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>())).Returns(meter);
        return new AuthMetrics(meterFactory.Object);
    }

    private static SmsOptions CreateSmsOptions(string? bypassCode = null) => new() { BypassCode = bypassCode };

    [Fact]
    public async Task ValidateAsync_WithValidSmsCode_ReturnsSuccess()
    {
        var accountId = Guid.NewGuid();
        var account = new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow };

        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByLoginProviderAsync(IdentityConstants.AuthMethodSms, "13800138000")).ReturnsAsync(account);

        var validator = new SmsValidator(
            accountRepoMock.Object,
            CreateOtpServiceMock(verified: true).Object,
            CreateUserLoginRepoMock().Object,
            CreateUnitOfWorkMock().Object,
            CreateLogger(),
            CreateAuthMetrics(),
            CreateSmsOptions());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeSms,
            Phone = "13800138000",
            Code = "valid_code"
        });

        Assert.True(result.IsSuccess);
        Assert.Equal(IdentityConstants.AuthMethodSms, result.AuthMethod);
        Assert.Equal(accountId, result.Account!.Id);
    }

    [Fact]
    public async Task ValidateAsync_WithWrongSmsCode_ReturnsFailure()
    {
        var accountRepoMock = new Mock<IAccountRepository>();

        var validator = new SmsValidator(
            accountRepoMock.Object,
            CreateOtpServiceMock(verified: false).Object,
            CreateUserLoginRepoMock().Object,
            CreateUnitOfWorkMock().Object,
            CreateLogger(),
            CreateAuthMetrics(),
            CreateSmsOptions());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeSms,
            Phone = "13800138000",
            Code = "wrong_code"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Wrong or expired verification code", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithEmptyPhoneOrCode_ReturnsFailure()
    {
        var accountRepoMock = new Mock<IAccountRepository>();
        var validator = new SmsValidator(
            accountRepoMock.Object,
            CreateOtpServiceMock().Object,
            CreateUserLoginRepoMock().Object,
            CreateUnitOfWorkMock().Object,
            CreateLogger(),
            CreateAuthMetrics(),
            CreateSmsOptions());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeSms,
            Phone = "",
            Code = "123456"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Phone or code cannot be empty", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithUnregisteredPhone_AutoRegistersAndReturnsSuccess()
    {
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByLoginProviderAsync(IdentityConstants.AuthMethodSms, "13800138000")).ReturnsAsync((AccountEntity?)null);

        AccountEntity? createdAccount = null;
        accountRepoMock.Setup(r => r.AddAsync(It.IsAny<AccountEntity>()))
            .Callback<AccountEntity>(a => createdAccount = a);

        UserLoginEntity? createdUserLogin = null;
        var userLoginRepoMock = CreateUserLoginRepoMock();
        userLoginRepoMock.Setup(r => r.AddAsync(It.IsAny<UserLoginEntity>()))
            .Callback<UserLoginEntity>(ul => createdUserLogin = ul);

        var uowMock = CreateUnitOfWorkMock();

        var validator = new SmsValidator(
            accountRepoMock.Object,
            CreateOtpServiceMock(verified: true).Object,
            userLoginRepoMock.Object,
            uowMock.Object,
            CreateLogger(),
            CreateAuthMetrics(),
            CreateSmsOptions());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeSms,
            Phone = "13800138000",
            Code = "valid_code"
        });

        Assert.True(result.IsSuccess);
        Assert.Equal(IdentityConstants.AuthMethodSms, result.AuthMethod);
        Assert.NotNull(result.Account);
        Assert.NotNull(createdAccount);
        Assert.True(createdAccount.IsActive);
        Assert.NotNull(createdUserLogin);
        Assert.Equal(IdentityConstants.AuthMethodSms, createdUserLogin.ProviderName);
        Assert.Equal("13800138000", createdUserLogin.ProviderUserId);
        Assert.Equal(createdAccount.Id, createdUserLogin.AccountId);
        Assert.Equal(createdAccount.Id, result.Account.Id);

        uowMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ValidateAsync_WithInactiveAccount_ReturnsFailure()
    {
        var accountId = Guid.NewGuid();
        var account = new AccountEntity { Id = accountId, IsActive = false, CreatedAt = DateTimeOffset.UtcNow };

        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByLoginProviderAsync(IdentityConstants.AuthMethodSms, "13800138000")).ReturnsAsync(account);

        var validator = new SmsValidator(
            accountRepoMock.Object,
            CreateOtpServiceMock(verified: true).Object,
            CreateUserLoginRepoMock().Object,
            CreateUnitOfWorkMock().Object,
            CreateLogger(),
            CreateAuthMetrics(),
            CreateSmsOptions());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeSms,
            Phone = "13800138000",
            Code = "valid_code"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Account is disabled", result.ErrorMessage);
    }

    [Fact]
    public void GrantType_ReturnsSms()
    {
        var accountRepoMock = new Mock<IAccountRepository>();
        var validator = new SmsValidator(
            accountRepoMock.Object,
            CreateOtpServiceMock().Object,
            CreateUserLoginRepoMock().Object,
            CreateUnitOfWorkMock().Object,
            CreateLogger(),
            CreateAuthMetrics(),
            CreateSmsOptions());

        Assert.Equal(IdentityConstants.GrantTypeSms, validator.GrantType);
    }
}
