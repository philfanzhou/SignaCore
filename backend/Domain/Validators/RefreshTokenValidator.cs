using Microsoft.Extensions.Logging;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Repositories;

namespace QuantumZhou.Identity.Domain.Validators;

public class RefreshTokenValidator : IIdentityValidator
{
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IAccountRepository _accountRepository;
    private readonly ILogger<RefreshTokenValidator> _logger;

    public RefreshTokenValidator(IRefreshTokenRepository refreshTokenRepository, IAccountRepository accountRepository, ILogger<RefreshTokenValidator> logger)
    {
        _refreshTokenRepository = refreshTokenRepository;
        _accountRepository = accountRepository;
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

        _logger.LogInformation("Refresh token validated successfully: AccountId={AccountId}, AppId={AppId}", refreshToken.AccountId, request.AppId ?? "N/A");
        return ValidationResult.Success(account, IdentityConstants.AuthMethodRefreshToken);
    }
}
