using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services;

public interface IRefreshTokenService
{
    /// <summary>
    /// Issues the refresh token for a successful grant. A refresh grant normally rotates: the
    /// presented token is revoked and replaced. When <paramref name="exchangedFromAppId"/> is set the
    /// grant is a cross-application exchange, and the presented token — which belongs to another
    /// application's session — is left alone. See docs/adr/0003-cross-application-refresh-grant.md.
    /// </summary>
    Task<string?> HandleRefreshTokenAsync(
        string grantType,
        string? existingRefreshToken,
        AccountEntity account,
        string? appId,
        Guid? ldapCredentialId = null,
        Guid? smsUserLoginId = null,
        Guid? wechatUserLoginId = null,
        string? exchangedFromAppId = null);
    Task<bool> RevokeAsync(string token);

    /// <summary>Revokes only if the token was issued to <paramref name="appId"/> (RFC 7009 §2.1).</summary>
    Task<bool> RevokeForAppAsync(string token, string appId);
}
