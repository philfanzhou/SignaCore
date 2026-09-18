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

    Task RemoveRangeAsync(
        IEnumerable<RefreshTokenEntity> tokens,
        CancellationToken cancellationToken = default);
    Task<int> RemoveExpiredAndRevokedAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every unrevoked member of the interactive family whose root id is
    /// <paramref name="rootId"/> (<c>EV-24</c>): a conditional update over interactive rows only,
    /// so an already-revoked member keeps the first fact and a legacy singleton id matches nothing.
    /// Returns the number of members this call revoked.
    /// </summary>
    Task<int> RevokeFamilyAsync(
        Guid rootId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every unrevoked interactive refresh token bound to <paramref name="identitySessionId"/>
    /// (<c>EV-06</c>/<c>EV-15</c>): legacy rows have no session and are structurally out of reach.
    /// Returns the number of members this call revoked.
    /// </summary>
    Task<int> RevokeBySessionAsync(
        Guid identitySessionId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes whole interactive families that are past every member's usable deadline and that no
    /// retained authorization code links to — children before roots, because the restrictive
    /// self-reference makes a single-statement whole-family delete provider-asymmetric. Returns
    /// the deleted member count.
    /// </summary>
    Task<int> RemoveInteractiveFamiliesAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}
