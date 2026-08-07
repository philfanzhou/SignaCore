using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IRefreshTokenRepository
{
    Task<RefreshTokenEntity?> GetByTokenValueAsync(string tokenValue);
    Task<bool> TryRevokeAsync(string tokenValue);

    /// <summary>
    /// Revokes the token only when it was issued to <paramref name="appId"/>. RFC 7009 §2.1 requires
    /// the server to verify the token belongs to the client making the request, so that possession of
    /// another client's token is not by itself enough to end that client's session.
    /// </summary>
    Task<bool> TryRevokeForAppAsync(string tokenValue, string appId);
    Task<bool> TryRotateAsync(string tokenValue, RefreshTokenEntity replacement);
    Task AddAsync(RefreshTokenEntity refreshToken);
    Task RemoveRangeAsync(IEnumerable<RefreshTokenEntity> tokens);
    Task<int> RemoveExpiredAndRevokedAsync();
}
