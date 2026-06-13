using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain.Validators;
using Xunit;

namespace QuantumZhou.Identity.Tests;

public class RefreshTokenValidatorTests
{
    private static IdentityDbContext CreateInMemoryContext()
    {
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        return new IdentityDbContext(options);
    }

    private static ILogger<RefreshTokenValidator> CreateLogger() => NullLogger<RefreshTokenValidator>.Instance;

    [Fact]
    public async Task ValidateAsync_WithValidRefreshToken_ReturnsSuccess()
    {
        var context = CreateInMemoryContext();
        var accountId = Guid.NewGuid();
        var account = new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        context.Accounts.Add(account);

        var refreshToken = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            TokenValue = "valid_refresh_token",
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            IsRevoked = false,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        context.RefreshTokens.Add(refreshToken);
        await context.SaveChangesAsync();

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("valid_refresh_token")).ReturnsAsync(refreshToken);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(account);

        var validator = new RefreshTokenValidator(refreshTokenRepoMock.Object, accountRepoMock.Object, CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "valid_refresh_token"
        });

        Assert.True(result.IsSuccess);
        Assert.Equal(IdentityConstants.AuthMethodRefreshToken, result.AuthMethod);
        Assert.Equal(accountId, result.Account!.Id);
    }

    [Fact]
    public async Task ValidateAsync_WithExpiredRefreshToken_ReturnsFailure()
    {
        var context = CreateInMemoryContext();
        var accountId = Guid.NewGuid();
        var account = new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        context.Accounts.Add(account);

        var refreshToken = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            TokenValue = "expired_refresh_token",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(-1),
            IsRevoked = false,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        context.RefreshTokens.Add(refreshToken);
        await context.SaveChangesAsync();

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("expired_refresh_token")).ReturnsAsync(refreshToken);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(account);

        var validator = new RefreshTokenValidator(refreshTokenRepoMock.Object, accountRepoMock.Object, CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "expired_refresh_token"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Refresh token has expired", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithRevokedRefreshToken_ReturnsFailure()
    {
        var context = CreateInMemoryContext();
        var accountId = Guid.NewGuid();
        var account = new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        context.Accounts.Add(account);

        var refreshToken = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            TokenValue = "revoked_refresh_token",
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            IsRevoked = true,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        context.RefreshTokens.Add(refreshToken);
        await context.SaveChangesAsync();

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("revoked_refresh_token")).ReturnsAsync(refreshToken);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(account);

        var validator = new RefreshTokenValidator(refreshTokenRepoMock.Object, accountRepoMock.Object, CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "revoked_refresh_token"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Refresh token has been revoked", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithEmptyRefreshToken_ReturnsFailure()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        var accountRepoMock = new Mock<IAccountRepository>();

        var validator = new RefreshTokenValidator(refreshTokenRepoMock.Object, accountRepoMock.Object, CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = ""
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Refresh token cannot be empty", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithNonexistentRefreshToken_ReturnsFailure()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync(It.IsAny<string>())).ReturnsAsync((RefreshTokenEntity?)null);
        var accountRepoMock = new Mock<IAccountRepository>();

        var validator = new RefreshTokenValidator(refreshTokenRepoMock.Object, accountRepoMock.Object, CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "nonexistent_token"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Invalid refresh token", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithInactiveAccount_ReturnsFailure()
    {
        var accountId = Guid.NewGuid();
        var account = new AccountEntity
        {
            Id = accountId,
            IsActive = false,
            CreatedAt = DateTimeOffset.UtcNow
        };

        var refreshToken = new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            TokenValue = "valid_refresh_token",
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            IsRevoked = false,
            CreatedAt = DateTimeOffset.UtcNow,
        };

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("valid_refresh_token")).ReturnsAsync(refreshToken);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(account);

        var validator = new RefreshTokenValidator(refreshTokenRepoMock.Object, accountRepoMock.Object, CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "valid_refresh_token"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Account is disabled", result.ErrorMessage);
    }

    [Fact]
    public void GrantType_ReturnsRefreshToken()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        var accountRepoMock = new Mock<IAccountRepository>();

        var validator = new RefreshTokenValidator(refreshTokenRepoMock.Object, accountRepoMock.Object, CreateLogger());

        Assert.Equal(IdentityConstants.GrantTypeRefreshToken, validator.GrantType);
    }
}
