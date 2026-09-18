using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IRefreshTokenRepository
{
    Task<RefreshTokenEntity?> GetByTokenValueAsync(
        string tokenValue,
        CancellationToken cancellationToken = default);
    Task<bool> TryRevokeAsync(
        string tokenValue,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the token only when it was issued to <paramref name="appId"/>. RFC 7009 §2.1 requires
    /// the server to verify the token belongs to the client making the request, so that possession of
    /// another client's token is not by itself enough to end that client's session.
    /// </summary>
    Task<bool> TryRevokeForAppAsync(
        string tokenValue,
        string appId,
        CancellationToken cancellationToken = default);
    Task<bool> TryRotateAsync(
        string tokenValue,
        RefreshTokenEntity replacement,
        CancellationToken cancellationToken = default);
    Task AddAsync(
        RefreshTokenEntity refreshToken,
        CancellationToken cancellationToken = default);
    /// <summary>
    /// The minimal session-scoped whole-family revocation of <c>EV-15</c>/<c>EV-06</c>: a
    /// conditional update over interactive rows only, with the first revocation fact staying
    /// authoritative. Minimal by the #68/#72/#294 three-way agreement; the family write API
    /// (#294) collects it when that slice merges.
    /// </summary>
    Task<int> RevokeInteractiveBySessionAsync(
        Guid identitySessionId,
        CancellationToken cancellationToken = default);

    Task RemoveRangeAsync(
        IEnumerable<RefreshTokenEntity> tokens,
        CancellationToken cancellationToken = default);
    Task<int> RemoveExpiredAndRevokedAsync(CancellationToken cancellationToken = default);
}
