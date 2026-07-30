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

    public async Task<string?> HandleRefreshTokenAsync(string grantType, string? existingRefreshToken, AccountEntity account, string? appId)
    {
        if (grantType is IdentityConstants.GrantTypePassword or IdentityConstants.GrantTypeSms or IdentityConstants.GrantTypeWechat)
        {
            return await GenerateRefreshTokenAsync(account, appId);
        }

        if (grantType == IdentityConstants.GrantTypeRefreshToken && !string.IsNullOrEmpty(existingRefreshToken))
        {
            var replacement = CreateRefreshToken(account, appId);
            return await _refreshTokenRepository.TryRotateAsync(existingRefreshToken, replacement)
                ? replacement.TokenValue
                : null;
        }

        return null;
    }

    public async Task<bool> RevokeAsync(string token)
    {
        return await _refreshTokenRepository.TryRevokeAsync(token);
    }

    private async Task<string> GenerateRefreshTokenAsync(AccountEntity account, string? appId)
    {
        var refreshToken = CreateRefreshToken(account, appId);
        await _refreshTokenRepository.AddAsync(refreshToken);
        await _unitOfWork.SaveChangesAsync();
        return refreshToken.TokenValue;
    }

    private RefreshTokenEntity CreateRefreshToken(AccountEntity account, string? appId)
    {
        return new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            TokenValue = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(_refreshTokenOptions.RefreshTokenExpirationDays),
            IsRevoked = false,
            AppId = appId
        };
    }
}
