using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services;

public interface IRefreshTokenService
{
    Task<string?> HandleRefreshTokenAsync(
        string grantType,
        string? existingRefreshToken,
        AccountEntity account,
        string? appId,
        Guid? ldapCredentialId = null,
        Guid? smsUserLoginId = null,
        Guid? wechatUserLoginId = null);
    Task<bool> RevokeAsync(string token);

    /// <summary>Revokes only if the token was issued to <paramref name="appId"/> (RFC 7009 §2.1).</summary>
    Task<bool> RevokeForAppAsync(string token, string appId);
}
