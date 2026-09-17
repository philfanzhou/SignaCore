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
    private readonly IPasswordHasher _passwordHasher;
    private readonly PasswordDecoyHash _decoyHash;
    private readonly ILogger<PasswordValidator> _logger;

    public PasswordValidator(
        IPasswordCredentialRepository passwordCredentialRepository,
        IAccountRepository accountRepository,
        ILoginAttemptRepository loginAttemptRepository,
        IPasswordHasher passwordHasher,
        PasswordDecoyHash decoyHash,
        ILogger<PasswordValidator> logger)
    {
        _passwordCredentialRepository = passwordCredentialRepository;
        _accountRepository = accountRepository;
        _loginAttemptRepository = loginAttemptRepository;
        _passwordHasher = passwordHasher;
        _decoyHash = decoyHash;
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

        var loginAttempt = await _loginAttemptRepository.GetByUsernameAsync(request.Username, request.CancellationToken);
        if (loginAttempt?.LockoutUntil != null && loginAttempt.LockoutUntil > DateTimeOffset.UtcNow)
        {
            // The decoy verification keeps the locked-out branch on the same BCrypt workload as the
            // wrong-password branch, so the failure timing does not reveal the account state. Its
            // result is deliberately discarded: the lockout decision was already made.
            _ = _passwordHasher.VerifyPassword(request.Password, _decoyHash.Value);
            _logger.LogWarning(
                "Password validation failed: account is locked out, Username={Username}, LockoutUntil={LockoutUntil}",
                LogValueSanitizer.Sanitize(request.Username), loginAttempt.LockoutUntil);
            return ValidationResult.Failure(
                $"Account is locked. Try again after {loginAttempt.LockoutUntil:HH:mm:ss} UTC.");
        }

        var credential = await _passwordCredentialRepository.GetByUsernameAsync(request.Username, request.CancellationToken);

        if (credential == null)
        {
            _ = _passwordHasher.VerifyPassword(request.Password, _decoyHash.Value);
            _logger.LogWarning("Password validation failed: username not found, Username={Username}",
                LogValueSanitizer.Sanitize(request.Username));
            return ValidationResult.Failure("Wrong username or password");
        }

        var account = await _accountRepository.GetByIdAsync(credential.AccountId, request.CancellationToken);
        if (account == null || !account.IsActive)
        {
            _ = _passwordHasher.VerifyPassword(request.Password, _decoyHash.Value);
            _logger.LogWarning("Password validation failed: account not found or disabled, Username={Username}",
                LogValueSanitizer.Sanitize(request.Username));
            return ValidationResult.Failure("Account is disabled");
        }

        if (!_passwordHasher.VerifyPassword(request.Password, credential.PasswordHash))
        {
            _logger.LogWarning("Password validation failed: wrong password, Username={Username}",
                LogValueSanitizer.Sanitize(request.Username));
            return ValidationResult.Failure("Wrong username or password")
                .WithLoginAttemptChange(new LoginAttemptChange(
                    LoginAttemptChangeKind.RecordFailure,
                    request.Username));
        }

        var result = ValidationResult.Success(
            account,
            IdentityConstants.AuthMethodPassword,
            credential.Username,
            passwordCredentialId: credential.Id);
        if (loginAttempt != null && loginAttempt.FailedAttempts > 0)
        {
            result.WithLoginAttemptChange(new LoginAttemptChange(
                LoginAttemptChangeKind.Clear,
                request.Username));
        }

        _logger.LogInformation("Password validated successfully: Username={Username}",
            LogValueSanitizer.Sanitize(request.Username));
        return result;
    }
}
