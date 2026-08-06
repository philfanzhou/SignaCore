using System.Security.Cryptography;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;

namespace QuantumZhou.Identity.Domain.Services;

public class RefreshTokenService : IRefreshTokenService
{
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly RefreshTokenOptions _refreshTokenOptions;

    public RefreshTokenService(
        IRefreshTokenRepository refreshTokenRepository,
        IUnitOfWork unitOfWork,
        RefreshTokenOptions refreshTokenOptions)
    {
        _refreshTokenRepository = refreshTokenRepository;
        _unitOfWork = unitOfWork;
        _refreshTokenOptions = refreshTokenOptions;
    }

    public async Task<string?> HandleRefreshTokenAsync(
        string grantType,
        string? existingRefreshToken,
        AccountEntity account,
        string? appId,
        Guid? ldapCredentialId = null,
        Guid? smsUserLoginId = null)
    {
        if (grantType is IdentityConstants.GrantTypePassword or IdentityConstants.GrantTypeSms or
            IdentityConstants.GrantTypeWechat or IdentityConstants.GrantTypeLdap)
        {
            return await GenerateRefreshTokenAsync(account, RequireAppId(appId), ldapCredentialId, smsUserLoginId);
        }

        if (grantType == IdentityConstants.GrantTypeRefreshToken && !string.IsNullOrEmpty(existingRefreshToken))
        {
            var replacement = CreateRefreshToken(account, RequireAppId(appId), ldapCredentialId, smsUserLoginId);
            return await _refreshTokenRepository.TryRotateAsync(existingRefreshToken, replacement)
                ? replacement.TokenValue
                : null;
        }

        return null;
    }

    private static string RequireAppId(string? appId) =>
        !string.IsNullOrWhiteSpace(appId)
            ? appId
            : throw new InvalidOperationException("A validated AppId is required to issue or rotate refresh tokens.");

    public async Task<bool> RevokeAsync(string token)
    {
        return await _refreshTokenRepository.TryRevokeAsync(token);
    }

    private async Task<string> GenerateRefreshTokenAsync(
        AccountEntity account,
        string appId,
        Guid? ldapCredentialId,
        Guid? smsUserLoginId)
    {
        var refreshToken = CreateRefreshToken(account, appId, ldapCredentialId, smsUserLoginId);
        await _refreshTokenRepository.AddAsync(refreshToken);
        await _unitOfWork.SaveChangesAsync();
        return refreshToken.TokenValue;
    }

    private RefreshTokenEntity CreateRefreshToken(AccountEntity account, string appId, Guid? ldapCredentialId, Guid? smsUserLoginId)
    {
        return new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            TokenValue = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(_refreshTokenOptions.RefreshTokenExpirationDays),
            IsRevoked = false,
            AppId = appId,
            LdapCredentialId = ldapCredentialId,
            SmsUserLoginId = smsUserLoginId
        };
    }
}
