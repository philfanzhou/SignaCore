using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services.WeChat;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests.Domain.Validators;

public class WechatValidatorTests
{
    private static ILogger<WechatValidator> CreateLogger() => NullLogger<WechatValidator>.Instance;

    [Fact]
    public async Task ValidateAsync_WithValidWechatCode_ReturnsSuccess()
    {
        var accountId = Guid.NewGuid();
        var account = new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow };

        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByLoginProviderAsync(IdentityConstants.AuthMethodWechat, "test_openid")).ReturnsAsync(account);

        var wechatMock = new Mock<IWechatApiClient>();
        wechatMock.Setup(w => w.CodeToSessionAsync("valid_code")).ReturnsAsync("test_openid");

        var validator = new WechatValidator(accountRepoMock.Object, wechatMock.Object, CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeWechat,
            Code = "valid_code"
        });

        Assert.True(result.IsSuccess);
        Assert.Equal(IdentityConstants.AuthMethodWechat, result.AuthMethod);
        Assert.Equal(accountId, result.Account!.Id);
    }

    [Fact]
    public async Task ValidateAsync_WithEmptyWechatCode_ReturnsFailure()
    {
        var wechatMock = new Mock<IWechatApiClient>();
        var accountRepoMock = new Mock<IAccountRepository>();
        var validator = new WechatValidator(accountRepoMock.Object, wechatMock.Object, CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeWechat,
            Code = ""
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("WeChat code cannot be empty", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithUnboundWechat_ReturnsFailure()
    {
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByLoginProviderAsync(IdentityConstants.AuthMethodWechat, "unbound_openid")).ReturnsAsync((AccountEntity?)null);

        var wechatMock = new Mock<IWechatApiClient>();
        wechatMock.Setup(w => w.CodeToSessionAsync("unbound_code")).ReturnsAsync("unbound_openid");

        var validator = new WechatValidator(accountRepoMock.Object, wechatMock.Object, CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeWechat,
            Code = "unbound_code"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("WeChat is not bound to any account", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithInactiveAccount_ReturnsFailure()
    {
        var accountId = Guid.NewGuid();
        var account = new AccountEntity { Id = accountId, IsActive = false, CreatedAt = DateTimeOffset.UtcNow };

        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByLoginProviderAsync(IdentityConstants.AuthMethodWechat, "test_openid")).ReturnsAsync(account);

        var wechatMock = new Mock<IWechatApiClient>();
        wechatMock.Setup(w => w.CodeToSessionAsync("valid_code")).ReturnsAsync("test_openid");

        var validator = new WechatValidator(accountRepoMock.Object, wechatMock.Object, CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeWechat,
            Code = "valid_code"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Account is disabled", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithFailedWechatApi_ReturnsFailure()
    {
        var wechatMock = new Mock<IWechatApiClient>();
        wechatMock.Setup(w => w.CodeToSessionAsync(It.IsAny<string>())).ReturnsAsync((string?)null);
        var accountRepoMock = new Mock<IAccountRepository>();

        var validator = new WechatValidator(accountRepoMock.Object, wechatMock.Object, CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeWechat,
            Code = "invalid_code"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("WeChat authentication failed", result.ErrorMessage);
    }

    [Fact]
    public void GrantType_ReturnsWechatCode()
    {
        var wechatMock = new Mock<IWechatApiClient>();
        var accountRepoMock = new Mock<IAccountRepository>();
        var validator = new WechatValidator(accountRepoMock.Object, wechatMock.Object, CreateLogger());

        Assert.Equal(IdentityConstants.GrantTypeWechat, validator.GrantType);
    }
}
