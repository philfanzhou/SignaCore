using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;

namespace SignaCore.Domain.Validators;

public class PasswordValidator : IIdentityValidator
{
    private readonly IPasswordCredentialRepository _passwordCredentialRepository;
    private readonly IAccountRepository _accountRepository;
    private readonly ILoginAttemptRepository _loginAttemptRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ILogger<PasswordValidator> _logger;

    public PasswordValidator(
        IPasswordCredentialRepository passwordCredentialRepository,
        IAccountRepository accountRepository,
        ILoginAttemptRepository loginAttemptRepository,
        IUnitOfWork unitOfWork,
        IPasswordHasher passwordHasher,
        ILogger<PasswordValidator> logger)
    {
        _passwordCredentialRepository = passwordCredentialRepository;
        _accountRepository = accountRepository;
        _loginAttemptRepository = loginAttemptRepository;
        _unitOfWork = unitOfWork;
        _passwordHasher = passwordHasher;
        _logger = logger;
    }

    public string GrantType => IdentityConstants.GrantTypePassword;

    public async Task<ValidationResult> ValidateAsync(ValidationRequest request)
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            _logger.LogWarning("Password validation failed: username or password is empty");
            return ValidationResult.Failure("Username or password cannot be empty", OAuthErrorCodes.InvalidRequest);
        }

        var loginAttempt = await _loginAttemptRepository.GetByUsernameAsync(request.Username);
        if (loginAttempt?.LockoutUntil != null && loginAttempt.LockoutUntil > DateTimeOffset.UtcNow)
        {
            _logger.LogWarning(
                "Password validation failed: account is locked out, Username={Username}, LockoutUntil={LockoutUntil}",
                request.Username, loginAttempt.LockoutUntil);
            return ValidationResult.Failure(
                $"Account is locked. Try again after {loginAttempt.LockoutUntil:HH:mm:ss} UTC.");
        }

        var credential = await _passwordCredentialRepository.GetByUsernameAsync(request.Username);

        if (credential == null)
        {
            _logger.LogWarning("Password validation failed: username not found, Username={Username}", request.Username);
            return ValidationResult.Failure("Wrong username or password");
        }

        var account = await _accountRepository.GetByIdAsync(credential.AccountId);
        if (account == null || !account.IsActive)
        {
            _logger.LogWarning("Password validation failed: account not found or disabled, Username={Username}", request.Username);
            return ValidationResult.Failure("Account is disabled");
        }

        if (!_passwordHasher.VerifyPassword(request.Password, credential.PasswordHash))
        {
            _logger.LogWarning("Password validation failed: wrong password, Username={Username}", request.Username);
            await RecordFailedAttemptAsync(request.Username);
            return ValidationResult.Failure("Wrong username or password");
        }

        if (loginAttempt != null && loginAttempt.FailedAttempts > 0)
        {
            await _loginAttemptRepository.RemoveAsync(loginAttempt);
            await _unitOfWork.SaveChangesAsync();
        }

        _logger.LogInformation("Password validated successfully: Username={Username}", request.Username);
        return ValidationResult.Success(account, IdentityConstants.AuthMethodPassword, credential.Username);
    }

    private async Task RecordFailedAttemptAsync(string username)
    {
        var now = DateTimeOffset.UtcNow;
        var loginAttempt = await _loginAttemptRepository.RecordFailureAsync(username, now);
        if (loginAttempt.LockoutUntil > now)
        {
            _logger.LogWarning(
                "Account locked due to too many failed attempts, Username={Username}, LockoutUntil={LockoutUntil}",
                username,
                loginAttempt.LockoutUntil);
        }
    }
}
