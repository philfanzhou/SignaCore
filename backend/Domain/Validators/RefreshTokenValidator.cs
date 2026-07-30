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

        // AppId binding is intentionally NOT enforced here. The refresh token itself is
        // the secret (possession = ownership), and the endpoint already requires a valid
        // AppId/AppSecret pair for gateway validation. Dropping the cross-app restriction
        // enables the SSO flow: a refresh token issued by user_portal can be exchanged by
        // teacher_portal (using teacher_portal's AppId) to mint a token carrying the
        // teacher role via teacher_portal's callback.
        if (!string.IsNullOrEmpty(refreshToken.AppId) && !string.IsNullOrEmpty(request.AppId)
            && IdentityValueNormalizer.Normalize(refreshToken.AppId) !=
                IdentityValueNormalizer.Normalize(request.AppId))
        {
            _logger.LogInformation(
                "Cross-app refresh token exchange: TokenAppId={TokenAppId}, RequestAppId={RequestAppId}, AccountId={AccountId}",
                refreshToken.AppId, request.AppId, refreshToken.AccountId);
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
