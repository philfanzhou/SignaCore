using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services.Ldap;

namespace SignaCore.Domain.Validators;

public sealed class LdapValidator : IIdentityValidator
{
    private const string InvalidCredentialsMessage = "Wrong username or password";
    private readonly LdapOptions _options;
    private readonly ILdapDirectoryClient _directoryClient;
    private readonly ILdapAccountService _accountService;
    private readonly IAccountRepository _accountRepository;
    private readonly ILoginAttemptRepository _loginAttemptRepository;
    private readonly AuthMetrics _metrics;
    private readonly ILogger<LdapValidator> _logger;

    public LdapValidator(
        LdapOptions options,
        ILdapDirectoryClient directoryClient,
        ILdapAccountService accountService,
        IAccountRepository accountRepository,
        ILoginAttemptRepository loginAttemptRepository,
        AuthMetrics metrics,
        ILogger<LdapValidator> logger)
    {
        _options = options;
        _directoryClient = directoryClient;
        _accountService = accountService;
        _accountRepository = accountRepository;
        _loginAttemptRepository = loginAttemptRepository;
        _metrics = metrics;
        _logger = logger;
    }

    public string GrantType => IdentityConstants.GrantTypeLdap;

    public async Task<ValidationResult> ValidateAsync(ValidationRequest request)
    {
        if (!_options.Enabled || request.App == null ||
            request.App.LdapLoginMode == LdapLoginMode.Disabled)
        {
            return ValidationResult.Failure(
                "LDAP login is disabled for this application", OAuthErrorCodes.UnauthorizedClient);
        }

        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return ValidationResult.Failure(
                "Username or password cannot be empty", OAuthErrorCodes.InvalidRequest);
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
            return ValidationResult.Failure(
                "Directory service unavailable", OAuthErrorCodes.TemporarilyUnavailable);
        }
    }

    private async Task<ValidationResult> ValidateManualAsync(
        ValidationRequest request,
        LdapDirectoryOptions directory)
    {
        var credential = await _accountService.FindCredentialByLoginAsync(directory.Key, request.Username!, request.CancellationToken);
        if (credential == null)
        {
            _logger.LogWarning("LDAP login rejected before bind: identity is not registered for manual admission");
            return ValidationResult.Failure(InvalidCredentialsMessage);
        }

        var access = await _accountService.GetAccessAsync(request.App!.Id, credential.Id, request.CancellationToken);
        if (access is not { IsActive: true, ApprovalSource: LdapAccessApprovalSource.Admin })
        {
            _logger.LogWarning(
                "LDAP login rejected before bind: no administrator approval, AppId={AppId}, CredentialId={CredentialId}",
                request.App.AppId,
                credential.Id);
            return ValidationResult.Failure(InvalidCredentialsMessage);
        }

        var account = await _accountRepository.GetByIdAsync(credential.AccountId, request.CancellationToken);
        if (account is not { IsActive: true })
        {
            return ValidationResult.Failure("Account is disabled");
        }

        var bind = await ValidateBindAsync(
            credential.DirectoryKey,
            credential.ObjectGuid,
            credential.UserPrincipalName,
            request.Password!,
            request.CancellationToken);
        var result = bind.Error == null
            ? ValidationResult.Success(
                account,
                IdentityConstants.AuthMethodLdap,
                credential.UserPrincipalName,
                credential.Id)
            : ValidationResult.Failure(bind.Error);
        return result.WithLoginAttemptChange(bind.LoginAttemptChange);
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
            identity.ObjectGuid,
            request.CancellationToken);
        if (existingCredential != null)
        {
            var existingAccount = await _accountRepository.GetByIdAsync(existingCredential.AccountId, request.CancellationToken);
            if (existingAccount is not { IsActive: true })
            {
                return ValidationResult.Failure("Account is disabled");
            }

            var existingAccess = await _accountService.GetAccessAsync(request.App!.Id, existingCredential.Id, request.CancellationToken);
            if (existingAccess is { IsActive: false })
            {
                _logger.LogWarning(
                    "LDAP login rejected before password bind: application access was explicitly revoked, AppId={AppId}, CredentialId={CredentialId}",
                    request.App.AppId,
                    existingCredential.Id);
                return ValidationResult.Failure(InvalidCredentialsMessage);
            }
        }

        var bind = await ValidateBindAsync(
            directory.Key,
            identity.ObjectGuid,
            identity.UserPrincipalName,
            request.Password!,
            request.CancellationToken);
        if (bind.Error != null)
        {
            return ValidationResult.Failure(bind.Error)
                .WithLoginAttemptChange(bind.LoginAttemptChange);
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
            result.Credential.Id)
            .WithLoginAttemptChange(bind.LoginAttemptChange);
    }

    private async Task<BindValidationResult> ValidateBindAsync(
        string directoryKey,
        Guid objectGuid,
        string userPrincipalName,
        string password,
        CancellationToken cancellationToken)
    {
        var keyPrefix = directoryKey.Length <= 20 ? directoryKey : directoryKey[..20];
        var attemptKey = $"ldap:{keyPrefix}:{objectGuid:N}";
        var attempt = await _loginAttemptRepository.GetByUsernameAsync(attemptKey, cancellationToken);
        if (attempt?.LockoutUntil > DateTimeOffset.UtcNow)
        {
            return new BindValidationResult("Account is temporarily locked", null);
        }

        var validation = await _directoryClient.ValidateCredentialsAsync(
            directoryKey,
            userPrincipalName,
            password,
            cancellationToken);
        if (validation != LdapCredentialValidationResult.Success)
        {
            return new BindValidationResult(
                InvalidCredentialsMessage,
                new LoginAttemptChange(LoginAttemptChangeKind.RecordFailure, attemptKey));
        }

        return new BindValidationResult(
            null,
            attempt == null
                ? null
                : new LoginAttemptChange(LoginAttemptChangeKind.Clear, attemptKey));
    }

    private sealed record BindValidationResult(
        string? Error,
        LoginAttemptChange? LoginAttemptChange);
}
