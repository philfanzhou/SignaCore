using System.Security.Cryptography;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;

namespace SignaCore.Domain.Services;

public class RefreshTokenService : IRefreshTokenService
{
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly RefreshTokenOptions _refreshTokenOptions;

    public RefreshTokenService(
        IRefreshTokenRepository refreshTokenRepository,
        RefreshTokenOptions refreshTokenOptions)
    {
        _refreshTokenRepository = refreshTokenRepository;
        _refreshTokenOptions = refreshTokenOptions;
    }

    public async Task<string?> HandleRefreshTokenAsync(
        string grantType,
        string? existingRefreshToken,
        AccountEntity account,
        string? appId,
        Guid? ldapCredentialId = null,
        Guid? smsUserLoginId = null,
        Guid? wechatUserLoginId = null,
        string? exchangedFromAppId = null)
    {
        if (grantType is IdentityConstants.GrantTypePassword or IdentityConstants.GrantTypeSms or
            IdentityConstants.GrantTypeWechat or IdentityConstants.GrantTypeLdap)
        {
            return await GenerateRefreshTokenAsync(
                account, RequireAppId(appId), ldapCredentialId, smsUserLoginId, wechatUserLoginId);
        }

        if (grantType == IdentityConstants.GrantTypeRefreshToken && !string.IsNullOrEmpty(existingRefreshToken))
        {
            // A cross-application exchange issues without rotating: the presented token is the
            // source application's session credential, and rotating it would revoke it, so opening
            // a session in the target application would have the side effect of ending the source
            // one — and only visibly so once the source side's access token expired.
            if (!string.IsNullOrWhiteSpace(exchangedFromAppId))
            {
                return await GenerateRefreshTokenAsync(
                    account, RequireAppId(appId), ldapCredentialId, smsUserLoginId, wechatUserLoginId,
                    exchangedFromAppId);
            }

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

    public async Task<bool> RevokeAsync(string token, CancellationToken cancellationToken = default)
    {
        return await _refreshTokenRepository.TryRevokeAsync(token, cancellationToken);
    }

    public async Task<bool> RevokeForAppAsync(
        string token,
        string appId,
        CancellationToken cancellationToken = default)
    {
        return await _refreshTokenRepository.TryRevokeForAppAsync(token, appId, cancellationToken);
    }

    private async Task<string> GenerateRefreshTokenAsync(
        AccountEntity account,
        string appId,
        Guid? ldapCredentialId,
        Guid? smsUserLoginId,
        Guid? wechatUserLoginId,
        string? sourceAppId = null)
    {
        var (rawToken, refreshToken) = CreateRefreshToken(
            account, appId, ldapCredentialId, smsUserLoginId, wechatUserLoginId, sourceAppId);
        await _refreshTokenRepository.AddAsync(refreshToken);
        return rawToken;
    }

    private (string RawToken, RefreshTokenEntity Entity) CreateRefreshToken(
        AccountEntity account,
        string appId,
        Guid? ldapCredentialId,
        Guid? smsUserLoginId,
        Guid? wechatUserLoginId,
        string? sourceAppId = null)
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
            WechatUserLoginId = wechatUserLoginId,
            SourceAppId = sourceAppId
        });
    }
}
