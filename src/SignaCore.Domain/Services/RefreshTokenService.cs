using System.Security.Cryptography;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;

namespace SignaCore.Domain.Services;

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
        Guid? smsUserLoginId = null,
        Guid? wechatUserLoginId = null)
    {
        if (grantType is IdentityConstants.GrantTypePassword or IdentityConstants.GrantTypeSms or
            IdentityConstants.GrantTypeWechat or IdentityConstants.GrantTypeLdap)
        {
            return await GenerateRefreshTokenAsync(
                account, RequireAppId(appId), ldapCredentialId, smsUserLoginId, wechatUserLoginId);
        }

        if (grantType == IdentityConstants.GrantTypeRefreshToken && !string.IsNullOrEmpty(existingRefreshToken))
        {
            var (rawToken, replacement) = CreateRefreshToken(
                account, RequireAppId(appId), ldapCredentialId, smsUserLoginId, wechatUserLoginId);
            return await _refreshTokenRepository.TryRotateAsync(existingRefreshToken, replacement)
                ? rawToken
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

    public async Task<bool> RevokeForAppAsync(string token, string appId)
    {
        return await _refreshTokenRepository.TryRevokeForAppAsync(token, appId);
    }

    private async Task<string> GenerateRefreshTokenAsync(
        AccountEntity account,
        string appId,
        Guid? ldapCredentialId,
        Guid? smsUserLoginId,
        Guid? wechatUserLoginId)
    {
        var (rawToken, refreshToken) = CreateRefreshToken(
            account, appId, ldapCredentialId, smsUserLoginId, wechatUserLoginId);
        await _refreshTokenRepository.AddAsync(refreshToken);
        await _unitOfWork.SaveChangesAsync();
        return rawToken;
    }

    private (string RawToken, RefreshTokenEntity Entity) CreateRefreshToken(
        AccountEntity account,
        string appId,
        Guid? ldapCredentialId,
        Guid? smsUserLoginId,
        Guid? wechatUserLoginId)
    {
        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        return (rawToken, new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            TokenValue = RefreshTokenDigest.Compute(rawToken),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(_refreshTokenOptions.RefreshTokenExpirationDays),
            IsRevoked = false,
            AppId = appId,
            LdapCredentialId = ldapCredentialId,
            SmsUserLoginId = smsUserLoginId,
            WechatUserLoginId = wechatUserLoginId
        });
    }
}
