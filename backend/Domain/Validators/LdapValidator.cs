using Microsoft.Extensions.Logging;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain.Services.Ldap;

namespace QuantumZhou.Identity.Domain.Validators;

public sealed class LdapValidator : IIdentityValidator
{
    private const string InvalidCredentialsMessage = "Wrong username or password";
    private readonly LdapOptions _options;
    private readonly ILdapDirectoryClient _directoryClient;
    private readonly ILdapAccountService _accountService;
    private readonly IAccountRepository _accountRepository;
    private readonly ILoginAttemptRepository _loginAttemptRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly AuthMetrics _metrics;
    private readonly ILogger<LdapValidator> _logger;

    public LdapValidator(
        LdapOptions options,
        ILdapDirectoryClient directoryClient,
        ILdapAccountService accountService,
        IAccountRepository accountRepository,
        ILoginAttemptRepository loginAttemptRepository,
        IUnitOfWork unitOfWork,
        AuthMetrics metrics,
        ILogger<LdapValidator> logger)
    {
        _options = options;
        _directoryClient = directoryClient;
        _accountService = accountService;
        _accountRepository = accountRepository;
        _loginAttemptRepository = loginAttemptRepository;
        _unitOfWork = unitOfWork;
        _metrics = metrics;
        _logger = logger;
    }

    public string GrantType => IdentityConstants.GrantTypeLdap;

    public async Task<ValidationResult> ValidateAsync(ValidationRequest request)
    {
        if (!_options.Enabled || request.App == null ||
            request.App.LdapLoginMode == LdapLoginMode.Disabled)
        {
            return ValidationResult.Failure("LDAP login is disabled for this application");
        }

        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return ValidationResult.Failure("Username or password cannot be empty");
        }

        LdapDirectoryOptions directory;
        try
        {
            directory = _directoryClient.ResolveDirectory(request.Username);
        }
        catch (KeyNotFoundException)
        {
            return ValidationResult.Failure(InvalidCredentialsMessage);
        }

        try
        {
            return request.App.LdapLoginMode == LdapLoginMode.ManualApproval
                ? await ValidateManualAsync(request, directory)
                : await ValidateAutomaticAsync(request, directory);
        }
        catch (LdapDirectoryUnavailableException exception)
        {
            _logger.LogError(exception, "LDAP directory unavailable: DirectoryKey={DirectoryKey}", directory.Key);
            return ValidationResult.Failure("Directory service unavailable");
        }
    }

    private async Task<ValidationResult> ValidateManualAsync(
        ValidationRequest request,
        LdapDirectoryOptions directory)
    {
        var credential = await _accountService.FindCredentialByLoginAsync(directory.Key, request.Username!);
        if (credential == null)
        {
            _logger.LogWarning("LDAP login rejected before bind: identity is not registered for manual admission");
            return ValidationResult.Failure(InvalidCredentialsMessage);
        }

        var access = await _accountService.GetAccessAsync(request.App!.Id, credential.Id);
        if (access is not { IsActive: true, ApprovalSource: LdapAccessApprovalSource.Admin })
        {
            _logger.LogWarning(
                "LDAP login rejected before bind: no administrator approval, AppId={AppId}, CredentialId={CredentialId}",
                request.App.AppId,
                credential.Id);
            return ValidationResult.Failure(InvalidCredentialsMessage);
        }

        var account = await _accountRepository.GetByIdAsync(credential.AccountId);
        if (account is not { IsActive: true })
        {
            return ValidationResult.Failure("Account is disabled");
        }

        var bindError = await ValidateBindAsync(
            credential.DirectoryKey,
            credential.ObjectGuid,
            credential.UserPrincipalName,
            request.Password!,
            request.CancellationToken);
        return bindError == null
            ? ValidationResult.Success(
                account,
                IdentityConstants.AuthMethodLdap,
                credential.UserPrincipalName,
                credential.Id)
            : ValidationResult.Failure(bindError);
    }

    private async Task<ValidationResult> ValidateAutomaticAsync(
        ValidationRequest request,
        LdapDirectoryOptions directory)
    {
        var identity = await _directoryClient.FindUserAsync(
            directory.Key,
            request.Username!,
            request.CancellationToken);
        if (identity is not { IsEnabled: true })
        {
            return ValidationResult.Failure(InvalidCredentialsMessage);
        }

        var existingCredential = await _accountService.GetCredentialByObjectGuidAsync(
            identity.DirectoryKey,
            identity.ObjectGuid);
        if (existingCredential != null)
        {
            var existingAccount = await _accountRepository.GetByIdAsync(existingCredential.AccountId);
            if (existingAccount is not { IsActive: true })
            {
                return ValidationResult.Failure("Account is disabled");
            }

            var existingAccess = await _accountService.GetAccessAsync(request.App!.Id, existingCredential.Id);
            if (existingAccess is { IsActive: false })
            {
                _logger.LogWarning(
                    "LDAP login rejected before password bind: application access was explicitly revoked, AppId={AppId}, CredentialId={CredentialId}",
                    request.App.AppId,
                    existingCredential.Id);
                return ValidationResult.Failure(InvalidCredentialsMessage);
            }
        }

        var bindError = await ValidateBindAsync(
            directory.Key,
            identity.ObjectGuid,
            identity.UserPrincipalName,
            request.Password!,
            request.CancellationToken);
        if (bindError != null)
        {
            return ValidationResult.Failure(bindError);
        }

        var result = await _accountService.ProvisionAsync(
            identity,
            request.App!,
            LdapAccessApprovalSource.AutoProvision,
            null,
            request.CancellationToken);
        if (!result.Account.IsActive)
        {
            return ValidationResult.Failure("Account is disabled");
        }

        if (!result.Access.IsActive)
        {
            return ValidationResult.Failure("LDAP access has been revoked");
        }

        if (result.AccountCreated)
        {
            _metrics.RecordAccountCreation("auto_register_ldap");
        }

        return ValidationResult.Success(
            result.Account,
            IdentityConstants.AuthMethodLdap,
            identity.UserPrincipalName,
            result.Credential.Id);
    }

    private async Task<string?> ValidateBindAsync(
        string directoryKey,
        Guid objectGuid,
        string userPrincipalName,
        string password,
        CancellationToken cancellationToken)
    {
        var keyPrefix = directoryKey.Length <= 20 ? directoryKey : directoryKey[..20];
        var attemptKey = $"ldap:{keyPrefix}:{objectGuid:N}";
        var attempt = await _loginAttemptRepository.GetByUsernameAsync(attemptKey);
        if (attempt?.LockoutUntil > DateTimeOffset.UtcNow)
        {
            return "Account is temporarily locked";
        }

        var validation = await _directoryClient.ValidateCredentialsAsync(
            directoryKey,
            userPrincipalName,
            password,
            cancellationToken);
        if (validation != LdapCredentialValidationResult.Success)
        {
            await _loginAttemptRepository.RecordFailureAsync(attemptKey, DateTimeOffset.UtcNow);
            return InvalidCredentialsMessage;
        }

        if (attempt != null)
        {
            await _loginAttemptRepository.RemoveAsync(attempt);
            await _unitOfWork.SaveChangesAsync(cancellationToken);
        }

        return null;
    }
}
