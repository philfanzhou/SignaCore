using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain.Validators;
using QuantumZhou.Identity.Domain.Services.Ldap;
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

    private static RefreshTokenValidator CreateValidator(
        IRefreshTokenRepository refreshTokenRepository,
        IAccountRepository accountRepository) =>
        new(
            refreshTokenRepository,
            accountRepository,
            new Mock<ILdapAccountService>().Object,
            new Mock<ILdapDirectoryClient>().Object,
            CreateLogger());

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
            AppId = "app-1"
        };
        context.RefreshTokens.Add(refreshToken);
        await context.SaveChangesAsync();

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("valid_refresh_token")).ReturnsAsync(refreshToken);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(account);

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "valid_refresh_token",
            AppId = "app-1"
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
            AppId = "app-1"
        };
        context.RefreshTokens.Add(refreshToken);
        await context.SaveChangesAsync();

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("expired_refresh_token")).ReturnsAsync(refreshToken);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(account);

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

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

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

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

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

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

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

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
            AppId = "app-1"
        };

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("valid_refresh_token")).ReturnsAsync(refreshToken);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(account);

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "valid_refresh_token",
            AppId = "app-1"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Account is disabled", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithCrossAppExchange_ReturnsFailure()
    {
        // A refresh token is an application-bound credential. A second application must
        // start its own login flow instead of exchanging another app's refresh token.
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
            TokenValue = "cross_app_refresh_token",
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            IsRevoked = false,
            CreatedAt = DateTimeOffset.UtcNow,
            AppId = "user_portal_app_id"
        };
        context.RefreshTokens.Add(refreshToken);
        await context.SaveChangesAsync();

        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.GetByTokenValueAsync("cross_app_refresh_token")).ReturnsAsync(refreshToken);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(accountId)).ReturnsAsync(account);

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = "cross_app_refresh_token",
            AppId = "second_app_id"
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("Refresh token is not valid for this application", result.ErrorMessage);
        accountRepoMock.Verify(r => r.GetByIdAsync(It.IsAny<Guid>()), Times.Never);
    }

    [Fact]
    public void GrantType_ReturnsRefreshToken()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        var accountRepoMock = new Mock<IAccountRepository>();

        var validator = CreateValidator(refreshTokenRepoMock.Object, accountRepoMock.Object);

        Assert.Equal(IdentityConstants.GrantTypeRefreshToken, validator.GrantType);
    }

    [Fact]
    public async Task ValidateAsync_AutoProvisionGrant_DoesNotSurviveSwitchToManualMode()
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "app-1",
            LdapLoginMode = LdapLoginMode.ManualApproval
        };
        var credential = new LdapCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            DirectoryKey = "corp",
            ObjectGuid = Guid.NewGuid(),
            UserPrincipalName = "alice@corp.example.com"
        };
        var token = new RefreshTokenEntity
        {
            AccountId = account.Id,
            TokenValue = "ldap-refresh",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AppId = app.AppId,
            LdapCredentialId = credential.Id
        };
        var tokenRepository = new Mock<IRefreshTokenRepository>();
        tokenRepository.Setup(repository => repository.GetByTokenValueAsync(token.TokenValue)).ReturnsAsync(token);
        var accountRepository = new Mock<IAccountRepository>();
        accountRepository.Setup(repository => repository.GetByIdAsync(account.Id)).ReturnsAsync(account);
        var ldapAccounts = new Mock<ILdapAccountService>();
        ldapAccounts.Setup(service => service.GetCredentialAsync(credential.Id)).ReturnsAsync(credential);
        ldapAccounts.Setup(service => service.GetAccessAsync(app.Id, credential.Id)).ReturnsAsync(
            new AppLdapAccessEntity
            {
                AppRegistrationId = app.Id,
                LdapCredentialId = credential.Id,
                ApprovalSource = LdapAccessApprovalSource.AutoProvision,
                IsActive = true
            });
        var directoryClient = new Mock<ILdapDirectoryClient>();
        var validator = new RefreshTokenValidator(
            tokenRepository.Object,
            accountRepository.Object,
            ldapAccounts.Object,
            directoryClient.Object,
            CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypeRefreshToken,
            RefreshToken = token.TokenValue,
            AppId = app.AppId,
            App = app
        });

        Assert.False(result.IsSuccess);
        Assert.Equal("LDAP access has been revoked", result.ErrorMessage);
        directoryClient.Verify(client => client.IsUserEnabledAsync(
            It.IsAny<string>(), It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
