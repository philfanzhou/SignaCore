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

        var loginAttemptRepository = CreateLoginAttemptRepoMock();
        var validator = new PasswordValidator(
            passwordRepoMock.Object,
            accountRepoMock.Object,
            loginAttemptRepository.Object,
            CreatePasswordHasher(),
            CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest { GrantType = "password", Username = "testuser", Password = "wrongpassword" });

        Assert.False(result.IsSuccess);
        Assert.Equal("Wrong username or password", result.ErrorMessage);
        Assert.Equal(LoginAttemptChangeKind.RecordFailure, result.LoginAttemptChange?.Kind);
        Assert.Equal("testuser", result.LoginAttemptChange?.Username);
        loginAttemptRepository.Verify(repository => repository.RecordFailureAsync(
            It.IsAny<string>(),
            It.IsAny<DateTimeOffset>(),
            It.IsAny<CancellationToken>()), Times.Never);
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
            CreatePasswordHasher(),
            CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest { GrantType = "password", Username = "lockeduser", Password = "password" });

        Assert.False(result.IsSuccess);
        Assert.Contains("locked", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateAsync_WithValidCredentialsAndPriorFailure_ReturnsDeferredClear()
    {
        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        var credential = new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            Username = "testuser",
            PasswordHash = CreatePasswordHasher().HashPassword("password"),
            CreatedAt = DateTimeOffset.UtcNow
        };
        var passwordRepository = new Mock<IPasswordCredentialRepository>();
        passwordRepository.Setup(repository => repository.GetByUsernameAsync("testuser"))
            .ReturnsAsync(credential);
        var accountRepository = new Mock<IAccountRepository>();
        accountRepository.Setup(repository => repository.GetByIdAsync(account.Id))
            .ReturnsAsync(account);
        var loginAttemptRepository = new Mock<ILoginAttemptRepository>();
        loginAttemptRepository.Setup(repository => repository.GetByUsernameAsync("testuser"))
            .ReturnsAsync(new LoginAttemptEntity
            {
                Id = Guid.NewGuid(),
                Username = "testuser",
                FailedAttempts = 1,
                LastAttemptAt = DateTimeOffset.UtcNow
            });
        var validator = new PasswordValidator(
            passwordRepository.Object,
            accountRepository.Object,
            loginAttemptRepository.Object,
            CreatePasswordHasher(),
            CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            GrantType = IdentityConstants.GrantTypePassword,
            Username = "testuser",
            Password = "password"
        });

        Assert.True(result.IsSuccess);
        Assert.Equal(LoginAttemptChangeKind.Clear, result.LoginAttemptChange?.Kind);
        Assert.Equal("testuser", result.LoginAttemptChange?.Username);
        loginAttemptRepository.Verify(repository => repository.RemoveAsync(
            It.IsAny<LoginAttemptEntity>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Theory]
    [InlineData("success")]
    [InlineData("clear-failures")]
    [InlineData("locked")]
    [InlineData("missing-credential")]
    [InlineData("missing-account")]
    [InlineData("inactive-account")]
    [InlineData("wrong-password")]
    public async Task ValidateAsync_ForwardsRequestCancellationThroughEachBranch(string scenario)
    {
        using var cancellation = new CancellationTokenSource();
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = scenario != "inactive-account" };
        var credential = new PasswordCredentialEntity
        {
            AccountId = account.Id,
            Username = "testuser",
            PasswordHash = "unused-by-mock"
        };
        var attempts = new Mock<ILoginAttemptRepository>(MockBehavior.Strict);
        var passwords = new Mock<IPasswordCredentialRepository>(MockBehavior.Strict);
        var accounts = new Mock<IAccountRepository>(MockBehavior.Strict);
        var hasher = new Mock<IPasswordHasher>(MockBehavior.Strict);
        attempts.Setup(repository => repository.GetByUsernameAsync("testuser", cancellation.Token))
            .ReturnsAsync(scenario is "locked" or "clear-failures" ? new LoginAttemptEntity
            {
                FailedAttempts = 1,
                LockoutUntil = scenario == "locked" ? DateTimeOffset.UtcNow.AddMinutes(10) : null
            } : null);
        passwords.Setup(repository => repository.GetByUsernameAsync("testuser", cancellation.Token))
            .ReturnsAsync(scenario == "missing-credential" ? null : credential);
        accounts.Setup(repository => repository.GetByIdAsync(account.Id, cancellation.Token))
            .ReturnsAsync(scenario == "missing-account" ? null : account);
        hasher.Setup(service => service.VerifyPassword("input", credential.PasswordHash))
            .Returns(scenario != "wrong-password");
        var validator = new PasswordValidator(
            passwords.Object, accounts.Object, attempts.Object, hasher.Object, CreateLogger());

        var result = await validator.ValidateAsync(new ValidationRequest
        {
            Username = "testuser",
            Password = "input",
            CancellationToken = cancellation.Token
        });

        Assert.Equal(scenario is "success" or "clear-failures", result.IsSuccess);
        Assert.Equal(scenario switch
        {
            "clear-failures" => LoginAttemptChangeKind.Clear,
            "wrong-password" => LoginAttemptChangeKind.RecordFailure,
            _ => (LoginAttemptChangeKind?)null
        }, result.LoginAttemptChange?.Kind);
        attempts.Verify(repository => repository.GetByUsernameAsync("testuser", cancellation.Token), Times.Once);
        passwords.Verify(repository => repository.GetByUsernameAsync("testuser", cancellation.Token),
            scenario == "locked" ? Times.Never() : Times.Once());
        accounts.Verify(repository => repository.GetByIdAsync(account.Id, cancellation.Token),
            scenario is "locked" or "missing-credential" ? Times.Never() : Times.Once());
        hasher.Verify(service => service.VerifyPassword("input", credential.PasswordHash),
            scenario is "success" or "clear-failures" or "wrong-password" ? Times.Once() : Times.Never());
        attempts.VerifyNoOtherCalls();
        passwords.VerifyNoOtherCalls();
        accounts.VerifyNoOtherCalls();
        hasher.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData("login-attempt")]
    [InlineData("credential")]
    [InlineData("account")]
    public async Task ValidateAsync_WhenReadObservesCancellation_StopsBeforeSubsequentWork(string boundary)
    {
        using var cancellation = new CancellationTokenSource();
        var accountId = Guid.NewGuid();
        var attempts = new Mock<ILoginAttemptRepository>(MockBehavior.Strict);
        var passwords = new Mock<IPasswordCredentialRepository>(MockBehavior.Strict);
        var accounts = new Mock<IAccountRepository>(MockBehavior.Strict);
        var hasher = new Mock<IPasswordHasher>(MockBehavior.Strict);
        attempts.Setup(repository => repository.GetByUsernameAsync("testuser", cancellation.Token))
            .Returns(() => ReadAsync<LoginAttemptEntity>("login-attempt", null));
        passwords.Setup(repository => repository.GetByUsernameAsync("testuser", cancellation.Token))
            .Returns(() => ReadAsync("credential", new PasswordCredentialEntity { AccountId = accountId }));
        accounts.Setup(repository => repository.GetByIdAsync(accountId, cancellation.Token))
            .Returns(() => ReadAsync("account", new AccountEntity { Id = accountId, IsActive = true }));
        var validator = new PasswordValidator(
            passwords.Object, accounts.Object, attempts.Object, hasher.Object, CreateLogger());

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => validator.ValidateAsync(
            new ValidationRequest
            {
                Username = "testuser",
                Password = "input",
                CancellationToken = cancellation.Token
            }));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        attempts.Verify(repository => repository.GetByUsernameAsync("testuser", cancellation.Token), Times.Once);
        passwords.Verify(repository => repository.GetByUsernameAsync("testuser", cancellation.Token),
            boundary == "login-attempt" ? Times.Never() : Times.Once());
        accounts.Verify(repository => repository.GetByIdAsync(accountId, cancellation.Token),
            boundary == "account" ? Times.Once() : Times.Never());
        attempts.VerifyNoOtherCalls();
        passwords.VerifyNoOtherCalls();
        accounts.VerifyNoOtherCalls();
        hasher.VerifyNoOtherCalls();

        Task<T?> ReadAsync<T>(string currentBoundary, T? result) where T : class
        {
            if (boundary == currentBoundary)
            {
                cancellation.Cancel();
                return Task.FromCanceled<T?>(cancellation.Token);
            }

            return Task.FromResult(result);
        }
    }
}
