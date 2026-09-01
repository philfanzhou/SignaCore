using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests;

public class PasswordValidatorTests
{
    private static IPasswordHasher CreatePasswordHasher() => new BCryptPasswordHasher(new PasswordHasherOptions());

    private static ILogger<PasswordValidator> CreateLogger() => NullLogger<PasswordValidator>.Instance;

    private static Mock<ILoginAttemptRepository> CreateLoginAttemptRepoMock()
    {
        var mock = new Mock<ILoginAttemptRepository>();
        mock.Setup(r => r.GetByUsernameAsync(It.IsAny<string>())).ReturnsAsync((LoginAttemptEntity?)null);
        mock.Setup(r => r.RecordFailureAsync(
                It.IsAny<string>(),
                It.IsAny<DateTimeOffset>()))
            .ReturnsAsync((
                string username,
                DateTimeOffset utcNow,
                CancellationToken _) => new LoginAttemptEntity
            {
                Id = Guid.NewGuid(),
                Username = username,
                LastAttemptAt = utcNow,
                FailedAttempts = 1
            });
        return mock;
    }

    private static Mock<IUnitOfWork> CreateUnitOfWorkMock()
    {
        var mock = new Mock<IUnitOfWork>();
        mock.Setup(r => r.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);
        return mock;
    }

    [Fact]
    public async Task ValidateAsync_WithValidCredentials_ReturnsSuccess()
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        var credential = new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = account.Id, Username = "testuser", PasswordHash = CreatePasswordHasher().HashPassword("password"), CreatedAt = DateTimeOffset.UtcNow };

        var passwordRepoMock = new Mock<IPasswordCredentialRepository>();
        passwordRepoMock.Setup(r => r.GetByUsernameAsync("testuser")).ReturnsAsync(credential);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(account.Id)).ReturnsAsync(account);

        var validator = new PasswordValidator(
            passwordRepoMock.Object,
            accountRepoMock.Object,
            CreateLoginAttemptRepoMock().Object,
            CreateUnitOfWorkMock().Object,
            CreatePasswordHasher(),
            CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest { GrantType = "password", Username = "testuser", Password = "password" });

        Assert.True(result.IsSuccess);
        Assert.Equal(IdentityConstants.AuthMethodPassword, result.AuthMethod);
        Assert.NotNull(result.Account);
        Assert.Equal(account.Id, result.Account.Id);
    }

    [Fact]
    public async Task ValidateAsync_WithInvalidPassword_ReturnsFailure()
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        var credential = new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = account.Id, Username = "testuser", PasswordHash = CreatePasswordHasher().HashPassword("password"), CreatedAt = DateTimeOffset.UtcNow };

        var passwordRepoMock = new Mock<IPasswordCredentialRepository>();
        passwordRepoMock.Setup(r => r.GetByUsernameAsync("testuser")).ReturnsAsync(credential);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(account.Id)).ReturnsAsync(account);

        var validator = new PasswordValidator(
            passwordRepoMock.Object,
            accountRepoMock.Object,
            CreateLoginAttemptRepoMock().Object,
            CreateUnitOfWorkMock().Object,
            CreatePasswordHasher(),
            CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest { GrantType = "password", Username = "testuser", Password = "wrongpassword" });

        Assert.False(result.IsSuccess);
        Assert.Equal("Wrong username or password", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithNonexistentUser_ReturnsFailure()
    {
        var passwordRepoMock = new Mock<IPasswordCredentialRepository>();
        passwordRepoMock.Setup(r => r.GetByUsernameAsync(It.IsAny<string>())).ReturnsAsync((PasswordCredentialEntity?)null);
        var accountRepoMock = new Mock<IAccountRepository>();

        var validator = new PasswordValidator(
            passwordRepoMock.Object,
            accountRepoMock.Object,
            CreateLoginAttemptRepoMock().Object,
            CreateUnitOfWorkMock().Object,
            CreatePasswordHasher(),
            CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest { GrantType = "password", Username = "nonexistent", Password = "password" });

        Assert.False(result.IsSuccess);
        Assert.Equal("Wrong username or password", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithEmptyCredentials_ReturnsFailure()
    {
        var passwordRepoMock = new Mock<IPasswordCredentialRepository>();
        var accountRepoMock = new Mock<IAccountRepository>();
        var validator = new PasswordValidator(
            passwordRepoMock.Object,
            accountRepoMock.Object,
            CreateLoginAttemptRepoMock().Object,
            CreateUnitOfWorkMock().Object,
            CreatePasswordHasher(),
            CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest { GrantType = "password", Username = "", Password = "" });

        Assert.False(result.IsSuccess);
        Assert.Equal("Username or password cannot be empty", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithInactiveAccount_ReturnsFailure()
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = false, CreatedAt = DateTimeOffset.UtcNow };
        var credential = new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = account.Id, Username = "inactiveuser", PasswordHash = CreatePasswordHasher().HashPassword("password"), CreatedAt = DateTimeOffset.UtcNow };

        var passwordRepoMock = new Mock<IPasswordCredentialRepository>();
        passwordRepoMock.Setup(r => r.GetByUsernameAsync("inactiveuser")).ReturnsAsync(credential);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(account.Id)).ReturnsAsync(account);

        var validator = new PasswordValidator(
            passwordRepoMock.Object,
            accountRepoMock.Object,
            CreateLoginAttemptRepoMock().Object,
            CreateUnitOfWorkMock().Object,
            CreatePasswordHasher(),
            CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest { GrantType = "password", Username = "inactiveuser", Password = "password" });

        Assert.False(result.IsSuccess);
        Assert.Equal("Account is disabled", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithLockedAccount_ReturnsFailure()
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        var credential = new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = account.Id, Username = "lockeduser", PasswordHash = CreatePasswordHasher().HashPassword("password"), CreatedAt = DateTimeOffset.UtcNow };

        var passwordRepoMock = new Mock<IPasswordCredentialRepository>();
        passwordRepoMock.Setup(r => r.GetByUsernameAsync("lockeduser")).ReturnsAsync(credential);
        var accountRepoMock = new Mock<IAccountRepository>();
        accountRepoMock.Setup(r => r.GetByIdAsync(account.Id)).ReturnsAsync(account);

        var loginAttemptRepoMock = new Mock<ILoginAttemptRepository>();
        loginAttemptRepoMock.Setup(r => r.GetByUsernameAsync("lockeduser")).ReturnsAsync(new LoginAttemptEntity
        {
            Id = Guid.NewGuid(),
            Username = "lockeduser",
            FailedAttempts = 5,
            LockoutUntil = DateTimeOffset.UtcNow.AddMinutes(10),
            LastAttemptAt = DateTimeOffset.UtcNow
        });

        var validator = new PasswordValidator(
            passwordRepoMock.Object,
            accountRepoMock.Object,
            loginAttemptRepoMock.Object,
            CreateUnitOfWorkMock().Object,
            CreatePasswordHasher(),
            CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest { GrantType = "password", Username = "lockeduser", Password = "password" });

        Assert.False(result.IsSuccess);
        Assert.Contains("locked", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }
}
