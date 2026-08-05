using Microsoft.Extensions.Logging;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Domain.Services.Ldap;

namespace QuantumZhou.Identity.Domain.Validators;

public class RefreshTokenValidator : IIdentityValidator
{
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IAccountRepository _accountRepository;
    private readonly ILdapAccountService _ldapAccountService;
    private readonly ILdapDirectoryClient _ldapDirectoryClient;
    private readonly ILogger<RefreshTokenValidator> _logger;

    public RefreshTokenValidator(
        IRefreshTokenRepository refreshTokenRepository,
        IAccountRepository accountRepository,
        ILdapAccountService ldapAccountService,
        ILdapDirectoryClient ldapDirectoryClient,
        ILogger<RefreshTokenValidator> logger)
    {
        _refreshTokenRepository = refreshTokenRepository;
        _accountRepository = accountRepository;
        _ldapAccountService = ldapAccountService;
        _ldapDirectoryClient = ldapDirectoryClient;
        _logger = logger;
    }

    public string GrantType => IdentityConstants.GrantTypeRefreshToken;

    public async Task<ValidationResult> ValidateAsync(ValidationRequest request)
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            _logger.LogWarning("Refresh token validation failed: token is empty");
            return ValidationResult.Failure("Refresh token cannot be empty");
        }

        var refreshToken = await _refreshTokenRepository.GetByTokenValueAsync(request.RefreshToken);

        if (refreshToken == null)
        {
            _logger.LogWarning("Refresh token validation failed: invalid token");
            return ValidationResult.Failure("Invalid refresh token");
        }

        if (refreshToken.IsRevoked)
        {
            _logger.LogWarning("Refresh token validation failed: token revoked, AccountId={AccountId}", refreshToken.AccountId);
            return ValidationResult.Failure("Refresh token has been revoked");
        }

        if (refreshToken.ExpiresAt < DateTimeOffset.UtcNow)
        {
            _logger.LogWarning("Refresh token validation failed: token expired, AccountId={AccountId}", refreshToken.AccountId);
            return ValidationResult.Failure("Refresh token has expired");
        }

        if (string.IsNullOrWhiteSpace(refreshToken.AppId)
            || string.IsNullOrWhiteSpace(request.AppId)
            || IdentityValueNormalizer.Normalize(refreshToken.AppId) !=
                IdentityValueNormalizer.Normalize(request.AppId))
        {
            _logger.LogWarning(
                "Refresh token application binding mismatch: TokenAppId={TokenAppId}, RequestAppId={RequestAppId}, AccountId={AccountId}",
                refreshToken.AppId, request.AppId, refreshToken.AccountId);
            return ValidationResult.Failure("Refresh token is not valid for this application");
        }

        var account = await _accountRepository.GetByIdAsync(refreshToken.AccountId);
        if (account == null || !account.IsActive)
        {
            _logger.LogWarning("Refresh token validation failed: account not found or disabled, AccountId={AccountId}", refreshToken.AccountId);
            return ValidationResult.Failure("Account is disabled");
        }

        if (refreshToken.LdapCredentialId.HasValue)
        {
            var ldapResult = await ValidateLdapAdmissionAsync(
                request,
                refreshToken.LdapCredentialId.Value);
            if (!ldapResult.IsSuccess)
            {
                return ValidationResult.Failure(ldapResult.ErrorMessage!);
            }

            return ValidationResult.Success(
                account,
                IdentityConstants.AuthMethodRefreshToken,
                ldapResult.Credential!.UserPrincipalName,
                refreshToken.LdapCredentialId);
        }

        _logger.LogInformation("Refresh token validated successfully: AccountId={AccountId}, AppId={AppId}", refreshToken.AccountId, request.AppId ?? "N/A");
        return ValidationResult.Success(account, IdentityConstants.AuthMethodRefreshToken);
    }

    private async Task<(bool IsSuccess, string? ErrorMessage, LdapCredentialEntity? Credential)> ValidateLdapAdmissionAsync(
        ValidationRequest request,
        Guid credentialId)
    {
        if (request.App == null || request.App.LdapLoginMode == LdapLoginMode.Disabled)
        {
            return (false, "LDAP login is disabled for this application", null);
        }

        var credential = await _ldapAccountService.GetCredentialAsync(credentialId);
        if (credential == null)
        {
            return (false, "LDAP access has been revoked", null);
        }

        var access = await _ldapAccountService.GetAccessAsync(request.App.Id, credentialId);
        var admitted = access is { IsActive: true } &&
            (request.App.LdapLoginMode == LdapLoginMode.AutoProvision ||
             access.ApprovalSource == LdapAccessApprovalSource.Admin);
        if (!admitted)
        {
            return (false, "LDAP access has been revoked", null);
        }

        try
        {
            if (!await _ldapDirectoryClient.IsUserEnabledAsync(
                    credential.DirectoryKey,
                    credential.ObjectGuid,
                    request.CancellationToken))
            {
                return (false, "LDAP account is disabled", null);
            }
        }
        catch (LdapDirectoryUnavailableException exception)
        {
            _logger.LogError(exception, "LDAP directory unavailable during refresh validation");
            return (false, "Directory service unavailable", null);
        }

        return (true, null, credential);
    }
}
